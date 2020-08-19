/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/host_resolver.h>

#include <aws/common/atomics.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/hash_table.h>
#include <aws/common/lru_cache.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/thread.h>

#include <aws/io/logging.h>

const uint64_t NS_PER_SEC = 1000000000;

int aws_host_address_copy(const struct aws_host_address *from, struct aws_host_address *to) {
    to->allocator = from->allocator;
    to->address = aws_string_new_from_string(to->allocator, from->address);

    if (!to->address) {
        return AWS_OP_ERR;
    }

    to->host = aws_string_new_from_string(to->allocator, from->host);

    if (!to->host) {
        aws_string_destroy((void *)to->address);
        return AWS_OP_ERR;
    }

    to->record_type = from->record_type;
    to->use_count = from->use_count;
    to->connection_failure_count = from->connection_failure_count;
    to->expiry = from->expiry;
    to->weight = from->weight;

    return AWS_OP_SUCCESS;
}

void aws_host_address_move(struct aws_host_address *from, struct aws_host_address *to) {
    to->allocator = from->allocator;
    to->address = from->address;
    to->host = from->host;
    to->record_type = from->record_type;
    to->use_count = from->use_count;
    to->connection_failure_count = from->connection_failure_count;
    to->expiry = from->expiry;
    to->weight = from->weight;
    AWS_ZERO_STRUCT(*from);
}

void aws_host_address_clean_up(struct aws_host_address *address) {
    if (address->address) {
        aws_string_destroy((void *)address->address);
    }
    if (address->host) {
        aws_string_destroy((void *)address->host);
    }
    AWS_ZERO_STRUCT(*address);
}

int aws_host_resolver_resolve_host(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    aws_on_host_resolved_result_fn *res,
    struct aws_host_resolution_config *config,
    void *user_data) {
    AWS_ASSERT(resolver->vtable && resolver->vtable->resolve_host);
    return resolver->vtable->resolve_host(resolver, host_name, res, config, user_data);
}

int aws_host_resolver_purge_cache(struct aws_host_resolver *resolver) {
    AWS_ASSERT(resolver->vtable && resolver->vtable->purge_cache);
    return resolver->vtable->purge_cache(resolver);
}

int aws_host_resolver_record_connection_failure(struct aws_host_resolver *resolver, struct aws_host_address *address) {
    AWS_ASSERT(resolver->vtable && resolver->vtable->record_connection_failure);
    return resolver->vtable->record_connection_failure(resolver, address);
}

enum default_resolver_state {
    DRS_ACTIVE,
    DRS_SHUTTING_DOWN,
};

struct default_host_resolver {
    struct aws_allocator *allocator;

    /*
     * Mutually exclusion for the whole resolver, includes member data and all host_entry_table operations.  Once
     * an entry is retrieved, this lock MAY be dropped but certain logic may hold both the resolver and the entry lock.
     * The two locks must be taken in that order.
     */
    struct aws_mutex resolver_lock;

    /* host_entry->host_name (string) -> host_entry */
    struct aws_hash_table host_entry_table;

    enum default_resolver_state state;

    uint32_t pending_host_entry_shutdown_completion_callbacks;
};

struct host_entry {
    /* should be immutable post-creation */
    struct aws_allocator *allocator;
    struct aws_host_resolver *resolver;
    struct aws_thread resolver_thread;
    const struct aws_string *host_name;
    int64_t resolve_frequency_ns;
    struct aws_host_resolution_config resolution_config;

    /* synchronized data and its lock */
    struct aws_mutex entry_lock;
    struct aws_condition_variable entry_signal;
    struct aws_cache *aaaa_records;
    struct aws_cache *a_records;
    struct aws_cache *failed_connection_aaaa_records;
    struct aws_cache *failed_connection_a_records;
    struct aws_linked_list pending_resolution_callbacks;
    uint32_t resolves_since_last_request;
    uint64_t last_resolve_request_timestamp_ns;
    enum default_resolver_state state;
};

static void s_shutdown_host_entry(struct host_entry *entry) {
    aws_mutex_lock(&entry->entry_lock);
    entry->state = DRS_SHUTTING_DOWN;
    aws_mutex_unlock(&entry->entry_lock);
}

/*
 * resolver lock must be held before calling this function
 */
static void s_clear_default_resolver_entry_table(struct default_host_resolver *resolver) {
    struct aws_hash_table *table = &resolver->host_entry_table;
    for (struct aws_hash_iter iter = aws_hash_iter_begin(table); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        struct host_entry *entry = iter.element.value;
        s_shutdown_host_entry(entry);
    }

    aws_hash_table_clear(table);
}

static int resolver_purge_cache(struct aws_host_resolver *resolver) {
    struct default_host_resolver *default_host_resolver = resolver->impl;
    aws_mutex_lock(&default_host_resolver->resolver_lock);
    s_clear_default_resolver_entry_table(default_host_resolver);
    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    return AWS_OP_SUCCESS;
}

static void s_cleanup_default_resolver(struct aws_host_resolver *resolver) {
    struct default_host_resolver *default_host_resolver = resolver->impl;

    aws_hash_table_clean_up(&default_host_resolver->host_entry_table);
    aws_mutex_clean_up(&default_host_resolver->resolver_lock);

    aws_simple_completion_callback *shutdown_callback = resolver->shutdown_options.shutdown_callback_fn;
    void *shutdown_completion_user_data = resolver->shutdown_options.shutdown_callback_user_data;

    aws_mem_release(resolver->allocator, resolver);

    /* invoke shutdown completion finally */
    if (shutdown_callback != NULL) {
        shutdown_callback(shutdown_completion_user_data);
    }

    aws_global_thread_tracker_decrement();
}

static void resolver_destroy(struct aws_host_resolver *resolver) {
    struct default_host_resolver *default_host_resolver = resolver->impl;

    bool cleanup_resolver = false;

    aws_mutex_lock(&default_host_resolver->resolver_lock);
    s_clear_default_resolver_entry_table(default_host_resolver);
    default_host_resolver->state = DRS_SHUTTING_DOWN;
    if (default_host_resolver->pending_host_entry_shutdown_completion_callbacks == 0) {
        cleanup_resolver = true;
    }
    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    if (cleanup_resolver) {
        s_cleanup_default_resolver(resolver);
    }
}

struct pending_callback {
    aws_on_host_resolved_result_fn *callback;
    void *user_data;
    struct aws_linked_list_node node;
};

static void s_clean_up_host_entry(struct host_entry *entry) {
    if (entry == NULL) {
        return;
    }

    if (!aws_linked_list_empty(&entry->pending_resolution_callbacks)) {
        aws_raise_error(AWS_IO_DNS_HOST_REMOVED_FROM_CACHE);
    }

    while (!aws_linked_list_empty(&entry->pending_resolution_callbacks)) {
        struct aws_linked_list_node *resolution_callback_node =
            aws_linked_list_pop_front(&entry->pending_resolution_callbacks);
        struct pending_callback *pending_callback =
            AWS_CONTAINER_OF(resolution_callback_node, struct pending_callback, node);

        pending_callback->callback(
            entry->resolver, entry->host_name, AWS_IO_DNS_HOST_REMOVED_FROM_CACHE, NULL, pending_callback->user_data);

        aws_mem_release(entry->allocator, pending_callback);
    }

    aws_cache_destroy(entry->aaaa_records);
    aws_cache_destroy(entry->a_records);
    aws_cache_destroy(entry->failed_connection_a_records);
    aws_cache_destroy(entry->failed_connection_aaaa_records);
    aws_string_destroy((void *)entry->host_name);
    aws_mem_release(entry->allocator, entry);
}

static void s_on_host_entry_shutdown_completion(void *user_data) {
    struct host_entry *entry = user_data;
    struct aws_host_resolver *resolver = entry->resolver;
    struct default_host_resolver *default_host_resolver = resolver->impl;

    s_clean_up_host_entry(entry);

    bool cleanup_resolver = false;

    aws_mutex_lock(&default_host_resolver->resolver_lock);
    --default_host_resolver->pending_host_entry_shutdown_completion_callbacks;
    if (default_host_resolver->state == DRS_SHUTTING_DOWN &&
        default_host_resolver->pending_host_entry_shutdown_completion_callbacks == 0) {
        cleanup_resolver = true;
    }
    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    if (cleanup_resolver) {
        s_cleanup_default_resolver(resolver);
    }
}

/* this only ever gets called after resolution has already run. We expect that the entry's lock
   has been aquired for writing before this function is called and released afterwards. */
static inline void process_records(
    struct aws_allocator *allocator,
    struct aws_cache *records,
    struct aws_cache *failed_records) {
    uint64_t timestamp = 0;
    aws_sys_clock_get_ticks(&timestamp);

    size_t record_count = aws_cache_get_element_count(records);
    size_t expired_records = 0;

    /* since this only ever gets called after resolution has already run, we're in a dns outage
     * if everything is expired. Leave an element so we can keep trying. */
    for (size_t index = 0; index < record_count && expired_records < record_count - 1; ++index) {
        struct aws_host_address *lru_element = aws_lru_cache_use_lru_element(records);

        if (lru_element->expiry < timestamp) {
            AWS_LOGF_DEBUG(
                AWS_LS_IO_DNS,
                "static: purging expired record %s for %s",
                lru_element->address->bytes,
                lru_element->host->bytes);
            expired_records++;
            aws_cache_remove(records, lru_element->address);
        }
    }

    record_count = aws_cache_get_element_count(records);
    AWS_LOGF_TRACE(AWS_LS_IO_DNS, "static: remaining record count for host %d", (int)record_count);

    /* if we don't have any known good addresses, take the least recently used, but not expired address with a history
     * of spotty behavior and upgrade it for reuse. If it's expired, leave it and let the resolve fail. Better to fail
     * than accidentally give a kids' app an IP address to somebody's adult website when the IP address gets rebound to
     * a different endpoint. The moral of the story here is to not disable SSL verification! */
    if (!record_count) {
        size_t failed_count = aws_cache_get_element_count(failed_records);
        for (size_t index = 0; index < failed_count; ++index) {
            struct aws_host_address *lru_element = aws_lru_cache_use_lru_element(failed_records);

            if (timestamp < lru_element->expiry) {
                struct aws_host_address *to_add = aws_mem_acquire(allocator, sizeof(struct aws_host_address));

                if (to_add && !aws_host_address_copy(lru_element, to_add)) {
                    AWS_LOGF_INFO(
                        AWS_LS_IO_DNS,
                        "static: promoting spotty record %s for %s back to good list",
                        lru_element->address->bytes,
                        lru_element->host->bytes);
                    if (aws_cache_put(records, to_add->address, to_add)) {
                        aws_mem_release(allocator, to_add);
                        continue;
                    }
                    /* we only want to promote one per process run.*/
                    aws_cache_remove(failed_records, lru_element->address);
                    break;
                }

                if (to_add) {
                    aws_mem_release(allocator, to_add);
                }
            }
        }
    }
}

static int resolver_record_connection_failure(struct aws_host_resolver *resolver, struct aws_host_address *address) {
    struct default_host_resolver *default_host_resolver = resolver->impl;

    AWS_LOGF_INFO(
        AWS_LS_IO_DNS,
        "id=%p: recording failure for record %s for %s, moving to bad list",
        (void *)resolver,
        address->address->bytes,
        address->host->bytes);

    aws_mutex_lock(&default_host_resolver->resolver_lock);

    struct aws_hash_element *element = NULL;
    if (aws_hash_table_find(&default_host_resolver->host_entry_table, address->host, &element)) {
        aws_mutex_unlock(&default_host_resolver->resolver_lock);
        return AWS_OP_ERR;
    }

    struct host_entry *host_entry = NULL;
    if (element != NULL) {
        host_entry = element->value;
        AWS_FATAL_ASSERT(host_entry);
    }

    if (host_entry) {
        struct aws_host_address *cached_address = NULL;

        aws_mutex_lock(&host_entry->entry_lock);
        aws_mutex_unlock(&default_host_resolver->resolver_lock);
        struct aws_cache *address_table =
            address->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA ? host_entry->aaaa_records : host_entry->a_records;

        struct aws_cache *failed_table = address->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA
                                             ? host_entry->failed_connection_aaaa_records
                                             : host_entry->failed_connection_a_records;

        aws_cache_find(address_table, address->address, (void **)&cached_address);

        struct aws_host_address *address_copy = NULL;
        if (cached_address) {
            address_copy = aws_mem_acquire(resolver->allocator, sizeof(struct aws_host_address));

            if (!address_copy || aws_host_address_copy(cached_address, address_copy)) {
                goto error_host_entry_cleanup;
            }

            if (aws_cache_remove(address_table, cached_address->address)) {
                goto error_host_entry_cleanup;
            }

            address_copy->connection_failure_count += 1;

            if (aws_cache_put(failed_table, address_copy->address, address_copy)) {
                goto error_host_entry_cleanup;
            }
        } else {
            if (aws_cache_find(failed_table, address->address, (void **)&cached_address)) {
                goto error_host_entry_cleanup;
            }

            if (cached_address) {
                cached_address->connection_failure_count += 1;
            }
        }
        aws_mutex_unlock(&host_entry->entry_lock);
        return AWS_OP_SUCCESS;

    error_host_entry_cleanup:
        if (address_copy) {
            aws_host_address_clean_up(address_copy);
            aws_mem_release(resolver->allocator, address_copy);
        }
        aws_mutex_unlock(&host_entry->entry_lock);
        return AWS_OP_ERR;
    }

    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    return AWS_OP_SUCCESS;
}

/*
 * A bunch of convenience functions for the host resolver background thread function
 */

static struct aws_host_address *s_find_cached_address_aux(
    struct aws_cache *primary_records,
    struct aws_cache *fallback_records,
    const struct aws_string *address) {

    struct aws_host_address *found = NULL;
    aws_cache_find(primary_records, address, (void **)&found);
    if (found == NULL) {
        aws_cache_find(fallback_records, address, (void **)&found);
    }

    return found;
}

/*
 * Looks in both the good and failed connection record sets for a given host record
 */
static struct aws_host_address *s_find_cached_address(
    struct host_entry *entry,
    const struct aws_string *address,
    enum aws_address_record_type record_type) {

    switch (record_type) {
        case AWS_ADDRESS_RECORD_TYPE_AAAA:
            return s_find_cached_address_aux(entry->aaaa_records, entry->failed_connection_aaaa_records, address);

        case AWS_ADDRESS_RECORD_TYPE_A:
            return s_find_cached_address_aux(entry->a_records, entry->failed_connection_a_records, address);

        default:
            return NULL;
    }
}

static struct aws_host_address *s_get_lru_address_aux(
    struct aws_cache *primary_records,
    struct aws_cache *fallback_records) {

    struct aws_host_address *address = aws_lru_cache_use_lru_element(primary_records);
    if (address == NULL) {
        aws_lru_cache_use_lru_element(fallback_records);
    }

    return address;
}

/*
 * Looks in both the good and failed connection record sets for the LRU host record
 */
static struct aws_host_address *s_get_lru_address(struct host_entry *entry, enum aws_address_record_type record_type) {
    switch (record_type) {
        case AWS_ADDRESS_RECORD_TYPE_AAAA:
            return s_get_lru_address_aux(entry->aaaa_records, entry->failed_connection_aaaa_records);

        case AWS_ADDRESS_RECORD_TYPE_A:
            return s_get_lru_address_aux(entry->a_records, entry->failed_connection_a_records);

        default:
            return NULL;
    }
}

static void s_clear_address_list(struct aws_array_list *address_list) {
    for (size_t i = 0; i < aws_array_list_length(address_list); ++i) {
        struct aws_host_address *address = NULL;
        aws_array_list_get_at_ptr(address_list, (void **)&address, i);
        aws_host_address_clean_up(address);
    }

    aws_array_list_clear(address_list);
}

static void s_update_address_cache(
    struct host_entry *host_entry,
    struct aws_array_list *address_list,
    uint64_t new_expiration) {

    for (size_t i = 0; i < aws_array_list_length(address_list); ++i) {
        struct aws_host_address *fresh_resolved_address = NULL;
        aws_array_list_get_at_ptr(address_list, (void **)&fresh_resolved_address, i);

        struct aws_host_address *address_to_cache =
            s_find_cached_address(host_entry, fresh_resolved_address->address, fresh_resolved_address->record_type);

        if (address_to_cache) {
            address_to_cache->expiry = new_expiration;
            AWS_LOGF_TRACE(
                AWS_LS_IO_DNS,
                "static: updating expiry for %s for host %s to %llu",
                address_to_cache->address->bytes,
                host_entry->host_name->bytes,
                (unsigned long long)new_expiration);
        } else {
            address_to_cache = aws_mem_acquire(host_entry->allocator, sizeof(struct aws_host_address));

            if (address_to_cache) {
                aws_host_address_move(fresh_resolved_address, address_to_cache);
                address_to_cache->expiry = new_expiration;

                struct aws_cache *address_table = address_to_cache->record_type == AWS_ADDRESS_RECORD_TYPE_AAAA
                                                      ? host_entry->aaaa_records
                                                      : host_entry->a_records;

                aws_cache_put(address_table, address_to_cache->address, address_to_cache);

                AWS_LOGF_DEBUG(
                    AWS_LS_IO_DNS,
                    "static: new address resolved %s for host %s caching",
                    address_to_cache->address->bytes,
                    host_entry->host_name->bytes);
            }
        }
    }
}

static void s_copy_address_into_callback_set(
    struct aws_host_address *address,
    struct aws_array_list *callback_addresses,
    const struct aws_string *host_name) {

    if (address) {
        address->use_count += 1;

        /*
         * This is the worst.
         *
         * We have to copy the cache address while we still have a write lock.  Otherwise, connection failures
         * can sneak in and destroy our address by moving the address to/from the various lru caches.
         *
         * But there's no nice copy construction into an array list, so we get to
         *   (1) Push a zeroed dummy element onto the array list
         *   (2) Get its pointer
         *   (3) Call aws_host_address_copy onto it.  If that fails, pop the dummy element.
         */
        struct aws_host_address dummy;
        AWS_ZERO_STRUCT(dummy);

        if (aws_array_list_push_back(callback_addresses, &dummy)) {
            return;
        }

        struct aws_host_address *dest_copy = NULL;
        aws_array_list_get_at_ptr(
            callback_addresses, (void **)&dest_copy, aws_array_list_length(callback_addresses) - 1);
        AWS_FATAL_ASSERT(dest_copy != NULL);

        if (aws_host_address_copy(address, dest_copy)) {
            aws_array_list_pop_back(callback_addresses);
            return;
        }

        AWS_LOGF_TRACE(
            AWS_LS_IO_DNS,
            "static: vending address %s for host %s to caller",
            address->address->bytes,
            host_name->bytes);
    }
}

static bool s_host_entry_finished_pred(void *user_data) {
    struct host_entry *entry = user_data;

    return entry->state == DRS_SHUTTING_DOWN;
}

static void resolver_thread_fn(void *arg) {
    struct host_entry *host_entry = arg;

    size_t unsolicited_resolve_max = host_entry->resolution_config.max_ttl;
    if (unsolicited_resolve_max == 0) {
        unsolicited_resolve_max = 1;
    }

    struct aws_array_list address_list;
    if (aws_array_list_init_dynamic(&address_list, host_entry->allocator, 4, sizeof(struct aws_host_address))) {
        return;
    }

    bool keep_going = false;
    /* It's technically possible for a host entry to get shutdown before running even once */
    aws_mutex_lock(&host_entry->entry_lock);
    keep_going = host_entry->state == DRS_ACTIVE;
    aws_mutex_unlock(&host_entry->entry_lock);
    while (keep_going) {

        AWS_LOGF_TRACE(AWS_LS_IO_DNS, "static, resolving %s", aws_string_c_str(host_entry->host_name));

        /* resolve and then process each record */
        int err_code = AWS_ERROR_SUCCESS;
        if (host_entry->resolution_config.impl(
                host_entry->allocator, host_entry->host_name, &address_list, host_entry->resolution_config.impl_data)) {

            err_code = aws_last_error();
        }
        uint64_t timestamp = 0;
        aws_sys_clock_get_ticks(&timestamp);
        uint64_t new_expiry = timestamp + (host_entry->resolution_config.max_ttl * NS_PER_SEC);

        struct aws_linked_list pending_resolve_copy;
        aws_linked_list_init(&pending_resolve_copy);

        /*
         * Within the lock we
         *  (1) Update the cache with the newly resolved addresses
         *  (2) Process all held addresses looking for expired or promotable ones
         *  (3) Prep for callback invocations
         */
        aws_mutex_lock(&host_entry->entry_lock);

        if (!err_code) {
            s_update_address_cache(host_entry, &address_list, new_expiry);
        }

        /*
         * process and clean_up records in the entry. occasionally, failed connect records will be upgraded
         * for retry.
         */
        process_records(host_entry->allocator, host_entry->aaaa_records, host_entry->failed_connection_aaaa_records);
        process_records(host_entry->allocator, host_entry->a_records, host_entry->failed_connection_a_records);

        aws_linked_list_swap_contents(&pending_resolve_copy, &host_entry->pending_resolution_callbacks);

        aws_mutex_unlock(&host_entry->entry_lock);

        /*
         * Clean up resolved addressed outside of the lock
         */
        s_clear_address_list(&address_list);

        struct aws_host_address address_array[2];
        AWS_ZERO_ARRAY(address_array);

        /*
         * Perform the actual subscriber notifications
         */
        while (!aws_linked_list_empty(&pending_resolve_copy)) {
            struct aws_linked_list_node *resolution_callback_node = aws_linked_list_pop_front(&pending_resolve_copy);
            struct pending_callback *pending_callback =
                AWS_CONTAINER_OF(resolution_callback_node, struct pending_callback, node);

            struct aws_array_list callback_address_list;
            aws_array_list_init_static(&callback_address_list, address_array, 2, sizeof(struct aws_host_address));

            aws_mutex_lock(&host_entry->entry_lock);
            s_copy_address_into_callback_set(
                s_get_lru_address(host_entry, AWS_ADDRESS_RECORD_TYPE_AAAA),
                &callback_address_list,
                host_entry->host_name);
            s_copy_address_into_callback_set(
                s_get_lru_address(host_entry, AWS_ADDRESS_RECORD_TYPE_A),
                &callback_address_list,
                host_entry->host_name);
            aws_mutex_unlock(&host_entry->entry_lock);

            AWS_ASSERT(err_code != AWS_ERROR_SUCCESS || aws_array_list_length(&callback_address_list) > 0);

            if (aws_array_list_length(&callback_address_list) > 0) {
                pending_callback->callback(
                    host_entry->resolver,
                    host_entry->host_name,
                    AWS_OP_SUCCESS,
                    &callback_address_list,
                    pending_callback->user_data);

            } else {
                pending_callback->callback(
                    host_entry->resolver, host_entry->host_name, err_code, NULL, pending_callback->user_data);
            }

            s_clear_address_list(&callback_address_list);

            aws_mem_release(host_entry->allocator, pending_callback);
        }

        aws_mutex_lock(&host_entry->entry_lock);

        ++host_entry->resolves_since_last_request;

        /* we don't actually care about spurious wakeups here. */
        aws_condition_variable_wait_for_pred(
            &host_entry->entry_signal,
            &host_entry->entry_lock,
            host_entry->resolve_frequency_ns,
            s_host_entry_finished_pred,
            host_entry);

        aws_mutex_unlock(&host_entry->entry_lock);

        struct default_host_resolver *resolver = host_entry->resolver->impl;
        aws_mutex_lock(&resolver->resolver_lock);
        aws_mutex_lock(&host_entry->entry_lock);

        if (host_entry->resolves_since_last_request > unsolicited_resolve_max) {
            host_entry->state = DRS_SHUTTING_DOWN;
        }

        keep_going = host_entry->state == DRS_ACTIVE;

        aws_mutex_unlock(&host_entry->entry_lock);

        if (!keep_going) {
            aws_hash_table_remove(&resolver->host_entry_table, host_entry->host_name, NULL, NULL);
        }

        aws_mutex_unlock(&resolver->resolver_lock);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_DNS,
        "static: Either no requests have been made for an address for %s for the duration "
        "of the ttl, or this thread is being forcibly shutdown. Killing thread.",
        host_entry->host_name->bytes)

    aws_array_list_clean_up(&address_list);

    /* please don't fail */
    aws_thread_current_at_exit(s_on_host_entry_shutdown_completion, host_entry);
}

static void on_address_value_removed(void *value) {
    struct aws_host_address *host_address = value;

    AWS_LOGF_DEBUG(
        AWS_LS_IO_DNS,
        "static: purging address %s for host %s from "
        "the cache due to cache eviction or shutdown",
        host_address->address->bytes,
        host_address->host->bytes);

    struct aws_allocator *allocator = host_address->allocator;
    aws_host_address_clean_up(host_address);
    aws_mem_release(allocator, host_address);
}

/*
 * The resolver lock must be held before calling this function
 */
static inline int create_and_init_host_entry(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    aws_on_host_resolved_result_fn *res,
    struct aws_host_resolution_config *config,
    uint64_t timestamp,
    void *user_data) {

    struct host_entry *new_host_entry = aws_mem_calloc(resolver->allocator, 1, sizeof(struct host_entry));
    if (!new_host_entry) {
        return AWS_OP_ERR;
    }

    new_host_entry->resolver = resolver;
    new_host_entry->allocator = resolver->allocator;
    new_host_entry->last_resolve_request_timestamp_ns = timestamp;
    new_host_entry->resolves_since_last_request = 0;
    new_host_entry->resolve_frequency_ns = NS_PER_SEC;
    new_host_entry->state = DRS_ACTIVE;

    bool thread_init = false;
    struct pending_callback *pending_callback = NULL;
    const struct aws_string *host_string_copy = aws_string_new_from_string(resolver->allocator, host_name);
    if (AWS_UNLIKELY(!host_string_copy)) {
        goto setup_host_entry_error;
    }

    new_host_entry->host_name = host_string_copy;
    new_host_entry->a_records = aws_cache_new_lru(
        new_host_entry->allocator,
        aws_hash_string,
        aws_hash_callback_string_eq,
        NULL,
        on_address_value_removed,
        config->max_ttl);
    if (AWS_UNLIKELY(!new_host_entry->a_records)) {
        goto setup_host_entry_error;
    }

    new_host_entry->aaaa_records = aws_cache_new_lru(
        new_host_entry->allocator,
        aws_hash_string,
        aws_hash_callback_string_eq,
        NULL,
        on_address_value_removed,
        config->max_ttl);
    if (AWS_UNLIKELY(!new_host_entry->aaaa_records)) {
        goto setup_host_entry_error;
    }

    new_host_entry->failed_connection_a_records = aws_cache_new_lru(
        new_host_entry->allocator,
        aws_hash_string,
        aws_hash_callback_string_eq,
        NULL,
        on_address_value_removed,
        config->max_ttl);
    if (AWS_UNLIKELY(!new_host_entry->failed_connection_a_records)) {
        goto setup_host_entry_error;
    }

    new_host_entry->failed_connection_aaaa_records = aws_cache_new_lru(
        new_host_entry->allocator,
        aws_hash_string,
        aws_hash_callback_string_eq,
        NULL,
        on_address_value_removed,
        config->max_ttl);
    if (AWS_UNLIKELY(!new_host_entry->failed_connection_aaaa_records)) {
        goto setup_host_entry_error;
    }

    aws_linked_list_init(&new_host_entry->pending_resolution_callbacks);

    pending_callback = aws_mem_acquire(resolver->allocator, sizeof(struct pending_callback));

    if (AWS_UNLIKELY(!pending_callback)) {
        goto setup_host_entry_error;
    }

    /*add the current callback here */
    pending_callback->user_data = user_data;
    pending_callback->callback = res;
    aws_linked_list_push_back(&new_host_entry->pending_resolution_callbacks, &pending_callback->node);

    aws_mutex_init(&new_host_entry->entry_lock);
    new_host_entry->resolution_config = *config;
    aws_condition_variable_init(&new_host_entry->entry_signal);

    if (aws_thread_init(&new_host_entry->resolver_thread, resolver->allocator)) {
        goto setup_host_entry_error;
    }

    thread_init = true;
    struct default_host_resolver *default_host_resolver = resolver->impl;
    if (AWS_UNLIKELY(
            aws_hash_table_put(&default_host_resolver->host_entry_table, host_string_copy, new_host_entry, NULL))) {
        goto setup_host_entry_error;
    }

    aws_thread_launch(&new_host_entry->resolver_thread, resolver_thread_fn, new_host_entry, NULL);
    ++default_host_resolver->pending_host_entry_shutdown_completion_callbacks;

    return AWS_OP_SUCCESS;

setup_host_entry_error:

    if (thread_init) {
        aws_thread_clean_up(&new_host_entry->resolver_thread);
    }

    s_clean_up_host_entry(new_host_entry);

    return AWS_OP_ERR;
}

static int default_resolve_host(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    aws_on_host_resolved_result_fn *res,
    struct aws_host_resolution_config *config,
    void *user_data) {

    int result = AWS_OP_SUCCESS;

    AWS_LOGF_DEBUG(AWS_LS_IO_DNS, "id=%p: Host resolution requested for %s", (void *)resolver, host_name->bytes);

    uint64_t timestamp = 0;
    aws_sys_clock_get_ticks(&timestamp);

    struct default_host_resolver *default_host_resolver = resolver->impl;
    aws_mutex_lock(&default_host_resolver->resolver_lock);

    struct aws_hash_element *element = NULL;
    /* we don't care about the error code here, only that the host_entry was found or not. */
    aws_hash_table_find(&default_host_resolver->host_entry_table, host_name, &element);

    struct host_entry *host_entry = NULL;
    if (element != NULL) {
        host_entry = element->value;
        AWS_FATAL_ASSERT(host_entry != NULL);
    }

    if (!host_entry) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_DNS,
            "id=%p: No cached entries found for %s starting new resolver thread.",
            (void *)resolver,
            host_name->bytes);

        result = create_and_init_host_entry(resolver, host_name, res, config, timestamp, user_data);
        aws_mutex_unlock(&default_host_resolver->resolver_lock);

        return result;
    }

    aws_mutex_lock(&host_entry->entry_lock);
    host_entry->last_resolve_request_timestamp_ns = timestamp;
    host_entry->resolves_since_last_request = 0;

    struct aws_host_address *aaaa_record = aws_lru_cache_use_lru_element(host_entry->aaaa_records);
    struct aws_host_address *a_record = aws_lru_cache_use_lru_element(host_entry->a_records);
    struct aws_host_address address_array[2];
    AWS_ZERO_ARRAY(address_array);
    struct aws_array_list callback_address_list;
    aws_array_list_init_static(&callback_address_list, address_array, 2, sizeof(struct aws_host_address));

    if ((aaaa_record || a_record)) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_DNS,
            "id=%p: cached entries found for %s returning to caller.",
            (void *)resolver,
            host_name->bytes);

        /* these will all need to be copied so that we don't hold the lock during the callback. */
        if (aaaa_record) {
            struct aws_host_address aaaa_record_cpy;
            if (!aws_host_address_copy(aaaa_record, &aaaa_record_cpy)) {
                aws_array_list_push_back(&callback_address_list, &aaaa_record_cpy);
                AWS_LOGF_TRACE(
                    AWS_LS_IO_DNS,
                    "id=%p: vending address %s for host %s to caller",
                    (void *)resolver,
                    aaaa_record->address->bytes,
                    host_entry->host_name->bytes);
            }
        }
        if (a_record) {
            struct aws_host_address a_record_cpy;
            if (!aws_host_address_copy(a_record, &a_record_cpy)) {
                aws_array_list_push_back(&callback_address_list, &a_record_cpy);
                AWS_LOGF_TRACE(
                    AWS_LS_IO_DNS,
                    "id=%p: vending address %s for host %s to caller",
                    (void *)resolver,
                    a_record->address->bytes,
                    host_entry->host_name->bytes);
            }
        }
        aws_mutex_unlock(&host_entry->entry_lock);
        aws_mutex_unlock(&default_host_resolver->resolver_lock);

        /* we don't want to do the callback WHILE we hold the lock someone may reentrantly call us. */
        if (aws_array_list_length(&callback_address_list)) {
            res(resolver, host_name, AWS_OP_SUCCESS, &callback_address_list, user_data);
        } else {
            res(resolver, host_name, aws_last_error(), NULL, user_data);
            result = AWS_OP_ERR;
        }

        for (size_t i = 0; i < aws_array_list_length(&callback_address_list); ++i) {
            struct aws_host_address *address_ptr = NULL;
            aws_array_list_get_at_ptr(&callback_address_list, (void **)&address_ptr, i);
            aws_host_address_clean_up(address_ptr);
        }

        aws_array_list_clean_up(&callback_address_list);

        return result;
    }

    struct pending_callback *pending_callback =
        aws_mem_acquire(default_host_resolver->allocator, sizeof(struct pending_callback));
    if (pending_callback != NULL) {
        pending_callback->user_data = user_data;
        pending_callback->callback = res;
        aws_linked_list_push_back(&host_entry->pending_resolution_callbacks, &pending_callback->node);
    } else {
        result = AWS_OP_ERR;
    }

    aws_mutex_unlock(&host_entry->entry_lock);
    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    return result;
}

static size_t default_get_host_address_count(
    struct aws_host_resolver *host_resolver,
    const struct aws_string *host_name,
    uint32_t flags) {

    struct default_host_resolver *default_host_resolver = host_resolver->impl;
    size_t address_count = 0;

    aws_mutex_lock(&default_host_resolver->resolver_lock);

    struct aws_hash_element *element = NULL;
    aws_hash_table_find(&default_host_resolver->host_entry_table, host_name, &element);
    if (element != NULL) {
        struct host_entry *host_entry = element->value;
        if (host_entry != NULL) {
            aws_mutex_lock(&host_entry->entry_lock);

            if ((flags & AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A) != 0) {
                address_count += aws_cache_get_element_count(host_entry->a_records);
            }

            if ((flags & AWS_GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA) != 0) {
                address_count += aws_cache_get_element_count(host_entry->aaaa_records);
            }

            aws_mutex_unlock(&host_entry->entry_lock);
        }
    }

    aws_mutex_unlock(&default_host_resolver->resolver_lock);

    return address_count;
}

static struct aws_host_resolver_vtable s_vtable = {
    .purge_cache = resolver_purge_cache,
    .resolve_host = default_resolve_host,
    .record_connection_failure = resolver_record_connection_failure,
    .get_host_address_count = default_get_host_address_count,
    .destroy = resolver_destroy,
};

static void s_aws_host_resolver_destroy(struct aws_host_resolver *resolver) {
    AWS_ASSERT(resolver->vtable && resolver->vtable->destroy);
    resolver->vtable->destroy(resolver);
}

struct aws_host_resolver *aws_host_resolver_new_default(
    struct aws_allocator *allocator,
    size_t max_entries,
    struct aws_event_loop_group *el_group,
    struct aws_shutdown_callback_options *shutdown_options) {
    /* NOTE: we don't use el_group yet, but we will in the future. Also, we
      don't want host resolvers getting cleaned up after el_groups; this will force that
      in bindings, and encourage it in C land. */
    (void)el_group;
    AWS_ASSERT(el_group);

    struct aws_host_resolver *resolver = NULL;
    struct default_host_resolver *default_host_resolver = NULL;
    if (!aws_mem_acquire_many(
            allocator,
            2,
            &resolver,
            sizeof(struct aws_host_resolver),
            &default_host_resolver,
            sizeof(struct default_host_resolver))) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*resolver);
    AWS_ZERO_STRUCT(*default_host_resolver);

    AWS_LOGF_INFO(
        AWS_LS_IO_DNS,
        "id=%p: Initializing default host resolver with %llu max host entries.",
        (void *)resolver,
        (unsigned long long)max_entries);

    resolver->vtable = &s_vtable;
    resolver->allocator = allocator;
    resolver->impl = default_host_resolver;

    default_host_resolver->allocator = allocator;
    default_host_resolver->pending_host_entry_shutdown_completion_callbacks = 0;
    default_host_resolver->state = DRS_ACTIVE;
    aws_mutex_init(&default_host_resolver->resolver_lock);

    aws_global_thread_tracker_increment();

    if (aws_hash_table_init(
            &default_host_resolver->host_entry_table,
            allocator,
            max_entries,
            aws_hash_string,
            aws_hash_callback_string_eq,
            NULL,
            NULL)) {
        goto on_error;
    }

    aws_ref_count_init(&resolver->ref_count, resolver, (aws_simple_completion_callback *)s_aws_host_resolver_destroy);

    if (shutdown_options != NULL) {
        resolver->shutdown_options = *shutdown_options;
    }

    return resolver;

on_error:

    s_cleanup_default_resolver(resolver);

    return NULL;
}

struct aws_host_resolver *aws_host_resolver_acquire(struct aws_host_resolver *resolver) {
    if (resolver != NULL) {
        aws_ref_count_acquire(&resolver->ref_count);
    }

    return resolver;
}

void aws_host_resolver_release(struct aws_host_resolver *resolver) {
    if (resolver != NULL) {
        aws_ref_count_release(&resolver->ref_count);
    }
}

size_t aws_host_resolver_get_host_address_count(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    uint32_t flags) {
    return resolver->vtable->get_host_address_count(resolver, host_name, flags);
}
