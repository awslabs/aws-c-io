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
#include <aws/common/lru_cache.h>
#include <aws/common/mutex.h>
#include <aws/common/clock.h>

#include <netdb.h>
#include <arpa/inet.h>

struct posix_host_resolver {
    struct aws_lru_cache local_cache;
    struct aws_mutex cache_mutex;
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
    struct posix_host_resolver *posix_resolver = resolver->impl;
    aws_mutex_lock(&posix_resolver->cache_mutex);
    aws_lru_cache_clear(&posix_resolver->local_cache);
    aws_mutex_unlock(&posix_resolver->cache_mutex);

    return AWS_OP_SUCCESS;
}

static void resolver_destroy(struct aws_host_resolver *resolver) {
    struct posix_host_resolver *posix_host_resolver = resolver->impl;
    aws_lru_cache_clean_up(&posix_host_resolver->local_cache);
    aws_mem_release(resolver->allocator, posix_host_resolver);
    AWS_ZERO_STRUCT(*resolver);
}

struct background_resolve_data {
    struct aws_allocator *allocator;
    const struct aws_string *host_name;
    uint64_t max_ttl_sec;
    on_host_resolved_result  resolved_result;
    struct aws_host_resolver *resolver;
    void *user_data;
};

struct iteration_data {
    struct aws_array_list output;
    struct aws_hash_table *address_table;
    struct background_resolve_data *resolve_data;
};

static int iterate_address_table(void * user_data, struct aws_hash_element *element) {
    struct iteration_data *iteration_data = user_data;

}

static void resolver_thread_fn(void *arg) {
    struct background_resolve_data *resolve_data = arg;
    struct posix_host_resolver *posix_host_resolver = resolve_data->resolver->impl;
    struct addrinfo *result = NULL;

    size_t hostname_len = resolve_data->host_name->len;
    char hostname_cstr[hostname_len + 1];
    hostname_cstr[hostname_len] = 0;
    memcpy(hostname_cstr, aws_string_bytes(resolve_data->host_name), hostname_len);

    struct addrinfo hints;
    AWS_ZERO_STRUCT(hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = 0;
    hints.ai_protocol = 0;
    hints.ai_flags = 0;

    int err_code = getaddrinfo(hostname_cstr, NULL, &hints, &result);

    if (err_code) {
        /*error do something about it*/
    }

    aws_mutex_lock(&posix_host_resolver->cache_mutex);
    struct aws_hash_table *address_table = NULL;

    if (aws_lru_cache_find(&posix_host_resolver->local_cache, resolve_data->host_name, (void **)&address_table)) {
        goto cleanup;
    }

    if (!address_table) {
        address_table = aws_mem_acquire(resolve_data->allocator, sizeof(struct aws_hash_table));
        if (aws_hash_table_init(address_table, resolve_data->allocator, 4, aws_hash_string, aws_string_eq, NULL, on_address_value_removed)) {
            aws_mem_release(resolve_data->allocator, address_table);
            aws_mutex_unlock(&posix_host_resolver->cache_mutex);
            goto cleanup;
        }

        aws_lru_cache_put(&posix_host_resolver->local_cache, resolve_data->host_name, address_table);
    }

    struct addrinfo *iter = NULL;
    /* max string length for ipv6. */
    socklen_t max_len = 39;
    char address_buffer[max_len];

    for (iter = result; iter != NULL; iter = iter->ai_next) {
        struct aws_host_address *host_address = aws_mem_acquire(resolve_data->allocator, sizeof(struct aws_host_address));

        if (!host_address) {
            aws_mutex_unlock(&posix_host_resolver->cache_mutex);
            goto cleanup;
        }

        AWS_ZERO_ARRAY(address_buffer);

        if (iter->ai_family == AF_INET6) {
            host_address->record_type = AWS_ADDRESS_RECORD_TYPE_AAAA;
        }
        else {
            host_address->record_type = AWS_ADDRESS_RECORD_TYPE_A;
        }

        uint64_t current_time;
        aws_sys_clock_get_ticks(&current_time);
        host_address->expiry = current_time + (resolve_data->max_ttl_sec * 1000000000);

        if (inet_ntop(iter->ai_family, iter->ai_addr, address_buffer, max_len)) {
            const struct aws_string *address =
                    aws_string_from_array_new(resolve_data->allocator, (const uint8_t *)address_buffer, strlen(address_buffer));
            host_address->address = address;
            host_address->weight = 0;

            struct aws_hash_element *element = NULL;
            int was_created = 0;
            aws_hash_table_create(address_table, address, &element, &was_created);

            if (was_created) {
                host_address->use_count = 0;
                host_address->connection_failure_count = 0;
                element->value = host_address;
            }
            else {
                struct aws_host_address *old_value = element->value;
                host_address->use_count = old_value->use_count;
                host_address->connection_failure_count = old_value->connection_failure_count;
                on_address_value_removed(element->value);
                element->value = host_address;
            }
        }
        else {
           aws_mem_release(resolve_data->allocator, host_address);
        }
    }

    /* now iterate all records in the host address list, we can delete up to one AZ zone's worth of failed connection
     * records (but never more), also if TTL is expired, AND the dns query failed, don't go deleting records. */
    resolve_data->address_count = aws_hash_table_get_entry_count(address_table);
    struct aws_host_address addresses[resolve_data->address_count];
    struct aws_array_list address_list;
    aws_array_list_init_static(&address_list, &addresses, resolve_data->address_count, sizeof(struct aws_host_address));

    aws_hash_table_foreach(address_table, iterate_address_table, resolve_data);

    aws_mutex_unlock(&posix_host_resolver->cache_mutex);


cleanup:
    if (result) {
        freeaddrinfo(result);
    }
}

static int resolver_resolve_host(struct aws_host_resolver *resolver, const struct aws_string *host_name,
                                   uint64_t max_ttl, on_host_resolved_result res, void *user_data) {
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




