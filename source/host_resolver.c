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
    struct aws_thread resolver_thread;
    struct aws_rw_lock entry_lock;
    struct aws_lru_cache aaaa_records;
    struct aws_lru_cache a_records;
    struct aws_lru_cache failed_connection_aaaa_records;
    struct aws_lru_cache failed_connection_a_records;

    const struct aws_string *host_name;
    uint64_t resolve_frequency_ns;
    /* this member will be a monotonic increasing value and not protected by a memory barrier. 
       Let it tear, we don't care, we just want to see a change. This at least assumes cache coherency for 
       the target architecture, which these days is a fairly safe assumption. Where it's not a safe assumption,
       we don't have multiple cores available anyways. */
    volatile uint64_t last_use;
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
    struct aws_host_resolution_config *config,
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

static void resolver_thread_fn(void *arg) {
    struct background_resolve_data *resolve_data = arg;

    struct aws_array_list resolver_output;
    aws_array_list_init_dynamic(&resolver_output, resolve_data->allocator, 4, sizeof(struct aws_host_address *));
    int err_code = resolve_data->config->impl(resolve_data->allocator, resolve_data->host_name, &resolver_output,
                                              resolve_data->config->impl_data);

    aws_mutex_lock(&posix_host_resolver->cache_mutex);
    struct aws_hash_table *address_table = NULL;

    if (aws_lru_cache_find(&posix_host_resolver->local_cache, resolve_data->host_name, (void **) &address_table)) {
        goto cleanup;
    }

    if (!address_table) {
        address_table = aws_mem_acquire(resolve_data->allocator, sizeof(struct aws_hash_table));
        if (aws_hash_table_init(address_table, resolve_data->allocator, 4, aws_hash_string, aws_string_eq, NULL,
                                on_address_value_removed)) {
            aws_mem_release(resolve_data->allocator, address_table);
            aws_mutex_unlock(&posix_host_resolver->cache_mutex);
            goto cleanup;
        }

        aws_lru_cache_put(&posix_host_resolver->local_cache, resolve_data->host_name, address_table);
    }

    if (!err_code) {
        for (size_t i = 0; aws_array_list_length(&resolver_output), ++i;) {
            struct aws_host_address *host_address = NULL;
            aws_array_list_get_at(&resolver_output, &host_address, i);
            uint64_t current_time;
            aws_sys_clock_get_ticks(&current_time);
            host_address->expiry = current_time + (resolve_data->max_ttl_sec * 1000000000);


            struct aws_hash_element *element = NULL;
            int was_created = 0;
            aws_hash_table_create(address_table, host_address->address, &element, &was_created);

            if (was_created) {
                host_address->use_count = 0;
                host_address->connection_failure_count = 0;
                element->value = host_address;
            } else {
                struct aws_host_address *old_value = element->value;
                host_address->use_count = old_value->use_count;
                host_address->connection_failure_count = old_value->connection_failure_count;
                on_address_value_removed(element->value);
                element->value = host_address;
            }
        }
    }

    /* NOTE: fair warning: I know this is a lib for everyone to use everywhere, but the next section is optimized for
     * AWS data center configurations, but it's most likely what you want anyways. */
    size_t address_count = aws_hash_table_get_entry_count(address_table);
    struct aws_host_address good_addresses[address_count];
    struct aws_array_list good_address_list;
    aws_array_list_init_static(&good_address_list, &good_addresses, address_count, sizeof(struct aws_host_address *));

    struct aws_host_address ttl_removal_candidates[address_count];
    struct aws_array_list ttl_removal_candidate_list;
    aws_array_list_init_static(&ttl_removal_candidate_list, &ttl_removal_candidates, address_count,
                               sizeof(struct aws_host_address *));

    struct aws_host_address connection_failure_removal_candidates[address_count];
    struct aws_array_list connection_failure_removal_candidate_list;
    aws_array_list_init_static(&connection_failure_removal_candidate_list, &connection_failure_removal_candidates,
                               address_count, sizeof(struct aws_host_address *));

    uint64_t current_time = 0;
    aws_sys_clock_get_ticks(&current_time);

    struct iteration_data iter_data = {
            .ttl_removal_candidates = &ttl_removal_candidate_list,
            .current_clock_time = current_time,
            .connect_failure_removal_candidates = &connection_failure_removal_candidate_list,
            .good_addresses = &good_address_list
    };

    aws_hash_table_foreach(address_table, iterate_address_table, resolve_data);

    size_t connect_failure_candidate_count = aws_array_list_length(&connection_failure_removal_candidate_list);
    size_t ttl_removal_candidate_count = aws_array_list_length(&ttl_removal_candidate_list);
    size_t good_address_count = aws_array_list_length(&good_address_list);

    /* if we don't have any good addresses, the TTLs get ignored until we get some new ones. This is to prevent a DNS outage bringing
     * the system down. */
    if (good_address_count > 0) {
        for (size_t i = 0; i < ttl_removal_candidate_count; ++i) {
            struct aws_host_address *expired_address = NULL;
            aws_array_list_get_at(&ttl_removal_candidate_list, &expired_address, i);
            aws_array_list_push_back(&good_address_list, &expired_address);
            good_address_count += 1;
        }
    }

    size_t total_address_count = connect_failure_candidate_count + good_address_count;

    /* only remove up to one availability zone's worth of addresses because of connection problems. There are many regions
     * with 3 azs, but some only have 2. Since this is only to mitigate the impact of an az being down and the dns records
     * not being updated yet, we'll just use a factor of 2 to figure out how many to purge. If we have a local connection issue,
     * who cares? we'll have a ton of latency to resolve later anyways so no point optimizing that here. */
    size_t to_keep = connect_failure_candidate_count > (total_address_count >> 1) ?
                     total_address_count >> 1 : total_address_count >> 1;

    for (size_t i = 0; i < to_remove; ++i) {

    }

    struct aws_host_address *used_address =
            resolve_data->resolved_result(resolve_data->resolver, resolve_data->host_name, AWS_OP_SUCCESS,
                                          &address_list, resolve_data->user_data);

    if (used_address) {
        used_address->use_count += 1;
    }

    aws_mutex_unlock(&posix_host_resolver->cache_mutex);
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


