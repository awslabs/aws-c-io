/*
* Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
*  http://aws.amazon.com/apache2.0
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/

#include <aws/io/host_resolver.h>
#include <aws/common/thread.h>
#include <aws/common/rw_lock.h>
#include <aws/common/hash_table.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/lru_cache.h>

const int64_t NS_PER_SEC = 1000000000;

int aws_host_address_copy(struct aws_host_address *from, struct aws_host_address *to) {
    to->allocator = from->allocator;
    to->address = aws_string_from_array_new(to->allocator, aws_string_bytes(from->address), from->address->len);
    to->host = from->host;
    to->record_type = from->record_type;
    to->use_count = from->use_count;
    to->connection_failure_count = from->connection_failure_count;
    to->expiry = from->expiry;
    to->weight = from->weight;

    if (to->address) {
        return AWS_OP_SUCCESS;
    }

    return AWS_OP_ERR;
}

void aws_host_address_clean_up(struct aws_host_address *address) {
    aws_string_destroy((void *)address->address);
    AWS_ZERO_STRUCT(*address);
}

void aws_host_resolver_clean_up(struct aws_host_resolver *resolver) {
    assert(resolver->vtable.destroy);
    resolver->vtable.destroy(resolver);
}

int aws_host_resolver_resolve_host(struct aws_host_resolver *resolver, const struct aws_string *host_name,
                                   aws_on_host_resolved_result *res, struct aws_host_resolution_config *config, void *user_data) {
    assert(resolver->vtable.resolve_host);
    return resolver->vtable.resolve_host(resolver, host_name, res, config, user_data);
}

int aws_host_resolver_purge_cache(struct aws_host_resolver *resolver) {
    assert(resolver->vtable.purge_cache);
    return resolver->vtable.purge_cache(resolver);
}

int aws_host_resolver_record_connection_failure(struct aws_host_resolver *resolver, struct aws_host_address *address) {
    assert(resolver->vtable.record_connection_failure);
    return resolver->vtable.record_connection_failure(resolver, address);
}


struct default_host_resolver {
    struct aws_allocator *allocator;
    struct aws_lru_cache host_table;
    struct aws_rw_lock host_lock;
};

struct host_entry {
    struct aws_allocator *allocator;
    struct aws_host_resolver *resolver;
    struct aws_thread resolver_thread;
    struct aws_rw_lock entry_lock;
    struct aws_lru_cache aaaa_records;
    struct aws_lru_cache a_records;
    struct aws_lru_cache failed_connection_aaaa_records;
    struct aws_lru_cache failed_connection_a_records;
    struct aws_mutex semaphore_mutex;
    struct aws_condition_variable condition_variable;
    const struct aws_string *host_name;
    struct aws_host_resolution_config *resolution_config;
    struct aws_linked_list pending_resolution_callbacks;
    int64_t resolve_frequency_ns;
    /* this member will be a monotonic increasing value and not protected by a memory barrier. 
       Let it tear, we don't care, we just want to see a change. This at least assumes cache coherency for 
       the target architecture, which these days is a fairly safe assumption. Where it's not a safe assumption,
       we don't have multiple cores available anyways. */
    volatile uint64_t last_use;
    volatile bool keep_active;
};

static int resolver_purge_cache(struct aws_host_resolver *resolver) {
    struct default_host_resolver *default_host_resolver = resolver->impl;
    aws_rw_lock_wlock(&default_host_resolver->host_lock);
    aws_lru_cache_clear(&default_host_resolver->host_table);
    aws_rw_lock_wunlock(&default_host_resolver->host_lock);

    return AWS_OP_SUCCESS;
}

static void resolver_destroy(struct aws_host_resolver *resolver) {
    struct default_host_resolver *default_host_resolver = resolver->impl;
    aws_lru_cache_clean_up(&default_host_resolver->host_table);
    aws_mem_release(resolver->allocator, default_host_resolver);
    AWS_ZERO_STRUCT(*resolver);
}

/* this only ever gets called after resolution has already run. */
static inline void process_host_entry (struct host_entry *entry) {
    size_t timestamp = 0;
    aws_sys_clock_get_ticks(&timestamp);

    size_t aaaa_record_count = aws_lru_cache_get_element_count(&entry->aaaa_records);
    size_t expired_records = 0;

    /* since this only ever gets called after resolution has already run, we're in a dns outage
     * if everything is expired. Leave an element so we can keep trying. */
    struct aws_host_address *lru_element = aws_lru_cache_use_lru_element(&entry->aaaa_records);
    while (lru_element && expired_records < aaaa_record_count - 1) {
        if (lru_element->expiry < timestamp) {
            expired_records++;
            aws_lru_cache_remove(&entry->aaaa_records, lru_element->address);
        }

        lru_element = aws_lru_cache_use_lru_element(&entry->aaaa_records);
    }

    size_t a_record_count = aws_lru_cache_get_element_count(&entry->a_records);

    expired_records = 0;
    lru_element = aws_lru_cache_use_lru_element(&entry->a_records);
    while (lru_element && expired_records < a_record_count - 1) {
        if (lru_element->expiry < timestamp) {
            expired_records++;
            aws_lru_cache_remove(&entry->a_records, lru_element->address);
        }

        lru_element = aws_lru_cache_use_lru_element(&entry->a_records);
    }

    /* if we don't have any known good addresses, take the least recently used, but not expired address with a history of
     * spotty behavior and upgrade it for reuse. If it's expired, leave it and let the resolve fail.
     * Better to fail than accidentally give a kids' app an IP address to somebody's adult website when the
     * IP address gets rebound to a different endpoint. The moral of the story
     * here is to not disable SSL verification! */
    if (!aaaa_record_count) {
        lru_element = aws_lru_cache_use_lru_element(&entry->failed_connection_aaaa_records);
        while (lru_element) {
            if (timestamp > lru_element->expiry) {
                struct aws_host_address *to_add = aws_mem_acquire(entry->allocator, sizeof(struct aws_host_address));

                if (to_add && !aws_host_address_copy(lru_element, to_add)) {
                    aws_lru_cache_put(&entry->aaaa_records, to_add->address, to_add);
                    aws_lru_cache_remove(&entry->failed_connection_aaaa_records, lru_element->address);
                    break;
                }
            }
            lru_element = aws_lru_cache_use_lru_element(&entry->failed_connection_aaaa_records);
        }
    }

    if (!a_record_count) {
        lru_element = aws_lru_cache_use_lru_element(&entry->failed_connection_a_records);
        while (lru_element) {
            if (timestamp > lru_element->expiry) {
                struct aws_host_address *to_add = aws_mem_acquire(entry->allocator, sizeof(struct aws_host_address));

                if (to_add && !aws_host_address_copy(lru_element, to_add)) {
                    aws_lru_cache_put(&entry->a_records, to_add->address, to_add);
                    aws_lru_cache_remove(&entry->failed_connection_a_records, lru_element->address);
                    break;
                }
            }
            lru_element = aws_lru_cache_use_lru_element(&entry->failed_connection_a_records);
        }
    }
}

static int resolver_record_connection_failure(struct aws_host_resolver *resolver, struct aws_host_address *address) {
    struct default_host_resolver *default_host_resolver = resolver->impl;

    aws_rw_lock_rlock(&default_host_resolver->host_lock);

    struct host_entry *host_entry = NULL;
    if (aws_lru_cache_find(&default_host_resolver->host_table, address->host, (void **)&host_entry)) {
        goto error_host_table_cleanup;
    }

    if (host_entry) {
        struct aws_host_address *cached_address = NULL;

        aws_rw_lock_wlock(&host_entry->entry_lock);
        struct aws_lru_cache *address_table = address->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA ?
                                              &host_entry->aaaa_records : &host_entry->a_records;

        struct aws_lru_cache *failed_table = address->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA ?
                        &host_entry->failed_connection_aaaa_records : &host_entry->failed_connection_a_records;

        aws_lru_cache_find(address_table, address->address, (void **)&cached_address);

        struct aws_host_address *address_cpy = NULL;
        if (cached_address) {
            address_cpy = aws_mem_acquire(resolver->allocator, sizeof(struct aws_host_address));

            if (!address_cpy || aws_host_address_copy(address, address_cpy)) {
                goto error_host_entry_cleanup;
            }

            if (aws_lru_cache_remove(address_table, address->address)) {
                goto error_host_entry_cleanup;
            }

            address_cpy->connection_failure_count += 1;

            if (aws_lru_cache_put(failed_table, address_cpy->host, address_cpy)) {
                goto error_host_entry_cleanup;
            }
        }
        else {
            if (aws_lru_cache_find(failed_table, address->address, (void **)&cached_address)) {
                goto error_host_entry_cleanup;
            }

            if (cached_address) {
                cached_address->connection_failure_count += 1;
            }
        }
        aws_rw_lock_wunlock(&host_entry->entry_lock);
        aws_rw_lock_runlock(&default_host_resolver->host_lock);
        return AWS_OP_SUCCESS;

    error_host_entry_cleanup:
        if (address_cpy) {
            aws_host_address_clean_up(address_cpy);
            aws_mem_release(resolver->allocator, address_cpy);
        }
        aws_rw_lock_wunlock(&host_entry->entry_lock);
        return AWS_OP_ERR;

    }

error_host_table_cleanup:
    aws_rw_lock_runlock(&default_host_resolver->host_lock);
    return AWS_OP_ERR;
}

struct pending_callback {
    aws_on_host_resolved_result *callback;
    void *user_data;
    struct aws_linked_list_node node;
};

static void resolver_thread_fn(void *arg) {
    struct host_entry *host_entry = arg;

    uint64_t last_updated = 0;
    size_t unsolicited_resolve_count = 0;
    size_t unsolicited_resolve_max = host_entry->resolution_config->max_ttl;
    struct aws_array_list address_list;
    aws_array_list_init_dynamic(&address_list, host_entry->allocator, 4, sizeof(struct aws_host_address));

    while (host_entry->keep_active && unsolicited_resolve_count < unsolicited_resolve_max) {
        if (last_updated != host_entry->last_use) {
            unsolicited_resolve_count = 0;
        }

        ++unsolicited_resolve_count;
        last_updated = host_entry->last_use;

        /* resolve and then process each record */
        int err_code = host_entry->resolution_config->impl(host_entry->allocator, host_entry->host_name,
                                            &address_list, host_entry->resolution_config->impl_data);
        uint64_t timestamp = 0;
        aws_sys_clock_get_ticks(&timestamp);

        if (!err_code) {
            uint64_t new_expiry = timestamp + host_entry->resolution_config->max_ttl * NS_PER_SEC;

            for (size_t i = 0; i < aws_array_list_length(&address_list); ++i) {
                struct aws_host_address *fresh_resolved_address = NULL;
                aws_array_list_get_at_ptr(&address_list, (void **)&fresh_resolved_address, i);

                struct aws_lru_cache *address_table = fresh_resolved_address->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA ?
                                                      &host_entry->aaaa_records : &host_entry->a_records;

                aws_rw_lock_wlock(&host_entry->entry_lock);
                struct aws_host_address *address_to_cache = NULL;
                aws_lru_cache_find(address_table, fresh_resolved_address->address, (void **)&address_to_cache);
                bool found = false;

                if (address_to_cache) {
                    address_to_cache->expiry = new_expiry;
                    found = true;
                }
                else {
                    struct aws_lru_cache *failed_address_table = fresh_resolved_address->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA ?
                                    &host_entry->failed_connection_aaaa_records : &host_entry->failed_connection_a_records;
                    aws_lru_cache_find(failed_address_table, fresh_resolved_address->address, (void **)&address_to_cache);

                    if (address_to_cache) {
                        address_to_cache->expiry = new_expiry;
                        found = true;
                    }
                }

                if (!found) {
                    address_to_cache = aws_mem_acquire(host_entry->allocator, sizeof(struct aws_host_address));

                    if (address_to_cache) {
                        aws_host_address_copy(fresh_resolved_address, address_to_cache);
                        address_to_cache->expiry = new_expiry;
                        aws_lru_cache_put(address_table, address_to_cache->address, address_to_cache);
                    }
                }
                aws_rw_lock_wunlock(&host_entry->entry_lock);

                aws_host_address_clean_up(fresh_resolved_address);
            }

            aws_array_list_clear(&address_list);
        }

        /* process and clean_up records in the entry. occasionally, failed connect records will be upgraded
         * for retry. */
        aws_rw_lock_wlock(&host_entry->entry_lock);
        process_host_entry(host_entry);
        aws_rw_lock_wunlock(&host_entry->entry_lock);

        /* now notify any subscribers that are waiting on resolutions. */
        aws_rw_lock_rlock(&host_entry->entry_lock);
        while (!aws_linked_list_empty(&host_entry->pending_resolution_callbacks)) {
            struct aws_linked_list_node *resolution_callback_node = aws_linked_list_front(&host_entry->pending_resolution_callbacks);
            struct pending_callback *pending_callback = aws_container_of(resolution_callback_node,  struct pending_callback, node);
            struct aws_host_address *aaaa_address = aws_lru_cache_use_lru_element(&host_entry->aaaa_records);
            struct aws_host_address *a_address = aws_lru_cache_use_lru_element(&host_entry->a_records);

            if (aaaa_address || a_address) {
                struct aws_host_address *address_array[2];
                AWS_ZERO_ARRAY(address_array);
                struct aws_array_list callback_address_list;
                aws_array_list_init_static(&callback_address_list, address_array, 2,
                                           sizeof(struct aws_host_address *));

                if (aaaa_address) {
                    aaaa_address->use_count += 1;
                    aws_array_list_push_back(&callback_address_list, &aaaa_address);
                }
                if (a_address) {
                    a_address->use_count += 1;
                    aws_array_list_push_back(&callback_address_list, &a_address);
                }

                pending_callback->callback(host_entry->resolver, host_entry->host_name, AWS_OP_SUCCESS,
                                           &callback_address_list, pending_callback->user_data);
                aws_array_list_clean_up(&callback_address_list);
            }
            else {
                pending_callback->callback(host_entry->resolver, host_entry->host_name, err_code,
                                           NULL, pending_callback->user_data);
            }
            aws_linked_list_pop_front(&host_entry->pending_resolution_callbacks);
            aws_mem_release(host_entry->allocator, pending_callback);
        }
        aws_rw_lock_runlock(&host_entry->entry_lock);
        aws_mutex_lock(&host_entry->semaphore_mutex);

        /* we don't actually care about spurious wakeups here. */
        aws_condition_variable_wait_for(&host_entry->condition_variable, &host_entry->semaphore_mutex,
                                             host_entry->resolve_frequency_ns + timestamp);

        aws_mutex_unlock(&host_entry->semaphore_mutex);
    }

    aws_array_list_clean_up(&address_list);
}

static void on_host_key_removed(void *key) {
    aws_string_destroy(key);
}

static void on_host_value_removed(void *value) {
    struct host_entry *host_entry = value;

    if (host_entry->keep_active) {
        host_entry->keep_active = false;
        aws_condition_variable_notify_one(&host_entry->condition_variable);
        aws_thread_join(&host_entry->resolver_thread);
        aws_thread_clean_up(&host_entry->resolver_thread);
    }

    aws_lru_cache_clean_up(&host_entry->aaaa_records);
    aws_lru_cache_clean_up(&host_entry->a_records);
    aws_lru_cache_clean_up(&host_entry->failed_connection_a_records);
    aws_lru_cache_clean_up(&host_entry->failed_connection_aaaa_records);
    aws_mem_release(host_entry->allocator, host_entry);
}

static void on_address_value_removed(void *value) {
    struct aws_host_address *host_address = value;
    struct aws_allocator *allocator = host_address->allocator;
    aws_host_address_clean_up(host_address);
    aws_mem_release(allocator, host_address);
}

static int default_resolve_host(struct aws_host_resolver *resolver, const struct aws_string *host_name,
                                aws_on_host_resolved_result *res, struct aws_host_resolution_config *config, void *user_data) {

    uint64_t timestamp = 0;
    aws_sys_clock_get_ticks(&timestamp);

    struct default_host_resolver *default_host_resolver = resolver->impl;
    aws_rw_lock_rlock(&default_host_resolver->host_lock);

    struct host_entry *host_entry = NULL;
    aws_lru_cache_find(&default_host_resolver->host_table, host_name, (void **)&host_entry);

    if (!host_entry) {
        aws_rw_lock_runlock(&default_host_resolver->host_lock);
        struct host_entry *new_host_entry = aws_mem_acquire(default_host_resolver->allocator, sizeof(struct host_entry));

        if (!new_host_entry) {
            return AWS_OP_ERR;
        }

        new_host_entry->resolver = resolver;
        new_host_entry->allocator = default_host_resolver->allocator;
        new_host_entry->last_use = timestamp;
        new_host_entry->resolve_frequency_ns = NS_PER_SEC;
        new_host_entry->host_name = host_name;
        aws_lru_cache_init(&new_host_entry->a_records, new_host_entry->allocator, aws_hash_string, aws_string_eq,
                           NULL, on_address_value_removed, config->max_ttl);
        aws_lru_cache_init(&new_host_entry->aaaa_records, new_host_entry->allocator, aws_hash_string, aws_string_eq,
                           NULL, on_address_value_removed, config->max_ttl);
        aws_lru_cache_init(&new_host_entry->failed_connection_a_records, new_host_entry->allocator, aws_hash_string, aws_string_eq,
                           NULL, on_address_value_removed, config->max_ttl);
        aws_lru_cache_init(&new_host_entry->failed_connection_aaaa_records, new_host_entry->allocator, aws_hash_string, aws_string_eq,
                           NULL, on_address_value_removed, config->max_ttl);
        aws_linked_list_init(&new_host_entry->pending_resolution_callbacks);

        struct pending_callback *pending_callback = aws_mem_acquire(default_host_resolver->allocator, sizeof(struct pending_callback));
        pending_callback->user_data = user_data;
        pending_callback->callback = res;
        aws_linked_list_push_back(&new_host_entry->pending_resolution_callbacks, &pending_callback->node);

        /*add the current callback here */
        aws_rw_lock_init(&new_host_entry->entry_lock);
        new_host_entry->keep_active = true;
        new_host_entry->resolution_config = config;
        aws_mutex_init(&new_host_entry->semaphore_mutex);
        aws_condition_variable_init(&new_host_entry->condition_variable);
        aws_thread_init(&new_host_entry->resolver_thread, default_host_resolver->allocator);

        aws_rw_lock_wlock(&default_host_resolver->host_lock);

        aws_lru_cache_find(&default_host_resolver->host_table, host_name, (void **)&host_entry);

        if (host_entry) {
            aws_rw_lock_wunlock(&default_host_resolver->host_lock);
            aws_rw_lock_rlock(&default_host_resolver->host_lock);
            aws_lru_cache_find(&default_host_resolver->host_table, host_name, (void **)&host_entry);

            /* cleanup new_host_entry */

            if (host_entry) {
                return AWS_OP_ERR;
            }
        }
        else {
            host_entry = new_host_entry;
            const struct aws_string *host_string_copy =
                    aws_string_from_array_new(default_host_resolver->allocator, aws_string_bytes(host_name), host_name->len);
            aws_lru_cache_put(&default_host_resolver->host_table, host_string_copy, host_entry);
            aws_thread_launch(&new_host_entry->resolver_thread, resolver_thread_fn, host_entry, NULL);
            aws_rw_lock_wunlock(&default_host_resolver->host_lock);
            return AWS_OP_SUCCESS;
        }

    }

    host_entry->last_use = timestamp;
    aws_rw_lock_wlock(&host_entry->entry_lock);

    /* if we don't have any good addresses, give the system a chance to upgrade some of the failed connection addresses. */
    size_t aaaa_count = aws_lru_cache_get_element_count(&host_entry->aaaa_records);
    size_t a_count = aws_lru_cache_get_element_count(&host_entry->a_records);

    size_t aaaa_failed_count = aws_lru_cache_get_element_count(&host_entry->failed_connection_aaaa_records);
    size_t a_failed_count = aws_lru_cache_get_element_count(&host_entry->failed_connection_a_records);

    if ((!aaaa_count && aaaa_failed_count) || (!a_count && a_failed_count)) {
        process_host_entry(host_entry);
    }

    struct aws_host_address *aaaa_record = aws_lru_cache_use_lru_element(&host_entry->aaaa_records);
    struct aws_host_address *a_record = aws_lru_cache_use_lru_element(&host_entry->a_records);

    if (aaaa_record || a_record) {
        struct aws_host_address *address_array[2];
        AWS_ZERO_ARRAY(address_array);
        struct aws_array_list callback_address_list;
        aws_array_list_init_static(&callback_address_list, address_array, 2,
                                   sizeof(struct aws_host_address *));

        if (aaaa_record) {
            aws_array_list_push_back(&callback_address_list, &aaaa_record);
        }
        if (a_record) {
            aws_array_list_push_back(&callback_address_list, &a_record);
        }

        res(host_entry->resolver, host_entry->host_name, AWS_OP_SUCCESS,
                                   &callback_address_list, user_data);
    }
    else {
        struct pending_callback *pending_callback = aws_mem_acquire(default_host_resolver->allocator, sizeof(struct pending_callback));
        pending_callback->user_data = user_data;
        pending_callback->callback = res;
        aws_linked_list_push_back(&host_entry->pending_resolution_callbacks, &pending_callback->node);
    }

    if (!host_entry->keep_active) {
        aws_thread_clean_up(&host_entry->resolver_thread);
        aws_thread_init(&host_entry->resolver_thread, default_host_resolver->allocator);
        host_entry->keep_active = true;
        aws_thread_launch(&host_entry->resolver_thread, resolver_thread_fn, host_entry, NULL);
    }
    aws_rw_lock_wunlock(&host_entry->entry_lock);

    aws_rw_lock_runlock(&default_host_resolver->host_lock);

    return AWS_OP_SUCCESS;
}

static struct aws_host_resolver_vtable vtable = {
        .purge_cache = resolver_purge_cache,
        .resolve_host = default_resolve_host,
        .record_connection_failure = resolver_record_connection_failure,
        .destroy = resolver_destroy,
};

int aws_host_resolver_default_init(struct aws_host_resolver *resolver, struct aws_allocator *allocator, size_t max_entries) {

    struct default_host_resolver *default_host_resolver = aws_mem_acquire(allocator, sizeof(struct default_host_resolver));

    if (!default_host_resolver) {
        return AWS_OP_ERR;
    }

    default_host_resolver->allocator = allocator;
    aws_rw_lock_init(&default_host_resolver->host_lock);
    if (aws_lru_cache_init(&default_host_resolver->host_table, allocator, aws_hash_string, aws_string_eq,
                            on_host_key_removed, on_host_value_removed, max_entries)) {
        aws_mem_release(allocator, default_host_resolver);
        return AWS_OP_ERR;
    }

    resolver->vtable = vtable;
    resolver->allocator = allocator;
    resolver->impl = default_host_resolver;

    return AWS_OP_SUCCESS;
}
