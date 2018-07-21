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

void aws_host_resolver_destroy(struct aws_host_resolver *resolver) {
    assert(resolver->vtable.destroy);
    resolver->vtable.destroy(resolver);
}

int aws_host_resolver_resolve_host(struct aws_host_resolver *resolver, const struct aws_string *host_name,
                                   on_host_resolved_result res, struct aws_host_resolution_config *config, void *user_data) {
    assert(resolver->vtable.resolve_host);
    return resolver->vtable.resolve_host(resolver, host_name, res, config, user_data);
}

AWS_IO_API int aws_host_resolver_purge_cache(struct aws_host_resolver *resolver) {
    assert(resolver->vtable.purge_cache);
    return resolver->vtable.purge_cache(resolver);
}

struct default_host_resolver {
    struct aws_allocator *allocator;
    struct aws_lru_cache host_table;
    struct aws_rw_lock host_lock;
};

struct host_entry {
    struct aws_allocator *allocator;
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
    uint64_t resolve_frequency_ns;
    /* this member will be a monotonic increasing value and not protected by a memory barrier. 
       Let it tear, we don't care, we just want to see a change. This at least assumes cache coherency for 
       the target architecture, which these days is a fairly safe assumption. Where it's not a safe assumption,
       we don't have multiple cores available anyways. */
    volatile uint64_t last_use;
    volatile bool keep_active;
};

static void on_host_key_removed(void *key) {

}

static void on_host_value_removed(void *value) {

}

static void on_address_key_removed(void *key) {

}

static void on_address_value_removed(void *value) {

}

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

struct background_resolve_data {
    struct aws_allocator *allocator;
    const struct aws_string *host_name;
    uint64_t max_ttl_sec;
    on_host_resolved_result  resolved_result;
    struct aws_host_resolver *resolver;
    struct aws_host_resolution_config *config;
    void *user_data;
};

struct iteration_data {
    struct aws_array_list *good_addresses;
    struct aws_array_list *ttl_removal_candidates;
    struct aws_array_list *connect_failure_removal_candidates;
    uint64_t current_clock_time;
};

static int iterate_address_table(void * user_data, struct aws_hash_element *element) {
    struct iteration_data *iteration_data = user_data;
    struct aws_host_address *address = element->value;

    if (address->expiry < iteration_data->current_clock_time) {
        aws_array_list_push_back(iteration_data->ttl_removal_candidates, &address);
    }
        /* For now if connection failure count is more than 50% percent of the time, make it a candidate for removal.
         * TODO: Where did this number come from? I pulled it out of my ass. We need to go back and do some research on what the
         * best number is. */
    else if (address->use_count > 0 && address->connection_failure_count > (address->use_count >> 1)) {
        aws_array_list_push_back(iteration_data->connect_failure_removal_candidates, &address);
    }
    else {
        aws_array_list_push_back(iteration_data->good_addresses, &element->value);
    }

    return AWS_COMMON_HASH_TABLE_ITER_CONTINUE;
}

struct predicate_data {
    uint64_t last_updated;
    struct host_entry *host_entry;
};

static bool resolver_predicate(void *arg) {
    struct predicate_data *predicate_data = arg;

    /* wait for an update on this */
    return !predicate_data->host_entry->keep_active || predicate_data->host_entry->last_use != predicate_data->last_updated;
}

static void resolver_thread_fn(void *arg) {
    struct host_entry *host_entry = arg;

    uint64_t last_updated = 0;
    size_t unsolicited_resolve_count = 0;
    size_t unsolicited_resolve_max = host_entry->resolution_config->max_ttl;
    struct aws_array_list address_list;
    aws_array_list_init_dynamic(&address_list, host_entry->allocator, 4, sizeof(struct aws_host_address));

    while (host_entry->keep_active) {
        if (unsolicited_resolve_count < unsolicited_resolve_max || last_updated != host_entry->last_use) {
            ++unsolicited_resolve_count;
            last_updated = host_entry->last_use;
            
            if (!host_entry->resolution_config->impl(host_entry->allocator, host_entry->host_name,
                                                     &address_list, host_entry->resolution_config->impl_data)) {
                uint64_t timestamp = 0;
                aws_sys_clock_get_ticks(&timestamp);
                uint64_t new_expiry = timestamp + host_entry->resolution_config->max_ttl * 1000000000;

                for (size_t i = 0; i < aws_array_list_length(&address_list); ++i) {
                    struct aws_host_address *host_address = NULL;
                    aws_array_list_get_at_ptr(&address_list, (void **)&host_address, i);

                    struct aws_lru_cache *address_table = host_address->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA ?
                                                          &host_entry->aaaa_records : &host_entry->a_records;


                    aws_rw_lock_wlock(&host_entry->entry_lock);
                    struct aws_host_address *table_address = NULL;
                    aws_lru_cache_find(address_table, host_address->host, (void **)&table_address);
                    bool found = false;

                    if (table_address) {
                        table_address->expiry = new_expiry;
                        found = true;
                    }
                    else {
                        struct aws_lru_cache *failed_address_table = host_address->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA ?
                                        &host_entry->failed_connection_aaaa_records : &host_entry->failed_connection_a_records;
                        aws_lru_cache_find(failed_address_table, host_address->host, (void **)&table_address);

                        if (table_address) {
                            table_address->expiry = new_expiry;
                            found = true;
                        }
                    }

                    if (!found) {
                        table_address = aws_mem_acquire(host_entry->allocator, sizeof(struct aws_host_address));

                        if (table_address) {
                            aws_host_address_copy(host_address, table_address);
                            table_address->expiry = new_expiry;
                            aws_lru_cache_put(address_table, table_address->address, table_address);
                        }
                    }
                    aws_rw_lock_wunlock(&host_entry->entry_lock);

                    aws_host_address_clean_up(host_address);
                }

                aws_array_list_clear(&address_list);
            }
        }
        else {
            aws_mutex_lock(&host_entry->semaphore_mutex);

            struct predicate_data predicate_data = {
                    .last_updated = last_updated,
                    .host_entry = host_entry,
            };

            aws_condition_variable_wait_for_pred(&host_entry->condition_variable, &host_entry->semaphore_mutex,
                                                 1000000000, resolver_predicate, &predicate_data);
            unsolicited_resolve_count = 0;
        }
    }
}

static int resolver_resolve_host(struct aws_host_resolver *resolver, const struct aws_string *host_name,
                                 on_host_resolved_result res, struct aws_host_resolution_config *config, void *user_data) {
    struct posix_host_resolver *posix_host_resolver = resolver->impl;

    aws_mutex_lock(&posix_host_resolver->cache_mutex);
    struct aws_linked_list *address_list = NULL;

    int err_code = aws_lru_cache_find(&posix_host_resolver->local_cache, host_name, (void **)&address_list);
    if (err_code) {
        aws_mutex_unlock(&posix_host_resolver->cache_mutex);
        return err_code;
    }

    if (address_list) {
        /* copy and invoke callback. */
    }

    aws_mutex_unlock(&posix_host_resolver->cache_mutex);

    return AWS_OP_ERR;
}

static struct aws_host_resolver_vtable vtable = {
        .purge_cache = resolver_purge_cache,
        .resolve_host = resolver_resolve_host,
        .destroy = resolver_destroy,
};

int aws_host_resolver_default_init(struct aws_host_resolver *resolver, struct aws_allocator *allocator, size_t max_entries) {

    struct posix_host_resolver *posix_host_resolver = aws_mem_acquire(allocator, sizeof(struct posix_host_resolver));

    if (!posix_host_resolver) {
        return AWS_OP_ERR;
    }

    if (!aws_lru_cache_init(&posix_host_resolver->local_cache, allocator, aws_hash_string, aws_string_eq,
                            on_host_key_removed, on_host_value_removed, max_entries)) {
        aws_mem_release(allocator, posix_host_resolver);
        return AWS_OP_ERR;
    }

    posix_host_resolver->cache_mutex = AWS_MUTEX_INIT;
    resolver->vtable = vtable;
    resolver->allocator = allocator;
    resolver->impl = posix_host_resolver;

    return AWS_OP_SUCCESS;
}


