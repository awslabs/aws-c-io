#ifndef AWS_IO_HOST_RESOLVER_H
#define AWS_IO_HOST_RESOLVER_H
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

#include <aws/io/io.h>
#include <aws/common/string.h>
#include <aws/common/lru_cache.h>
#include <aws/common/mutex.h>

typedef enum aws_address_record_type {
    AWS_ADDRESS_RECORD_TYPE_A,
    AWS_ADDRESS_RECORD_TYPE_AAAA
} aws_address_record_type;

struct aws_host_address {
    struct aws_allocator *allocator;
    struct aws_string address;
    aws_address_record_type record_type;
    uint64_t expiry;
};

typedef void(*on_host_resolved_result)(const struct aws_string *host_name, int err_code, const struct aws_array_list *host_addresses, void *user_data);

struct aws_host_resolver;

struct aws_host_resolver_vtable {
    void(*destroy)(struct aws_host_resolver *resolver);
    int(*resolve_host)(struct aws_host_resolver * resolver, const struct aws_string *host_name, uint64_t ttl, on_host_resolved_result res, void *user_data);
};

struct aws_host_resolver {
    struct aws_host_resolver_vtable vtable;
    struct aws_allocator *allocator;
    struct aws_lru_cache local_cache;
    struct aws_mutex cache_mutex;
    void *impl;
};

#ifdef __cplusplus
extern "C" {
#endif

AWS_IO_API struct aws_host_resolver *aws_host_resolver_default_new(struct aws_allocator *allocator);

AWS_IO_API void aws_host_resolver_destroy(struct aws_host_resolver *);

AWS_IO_API int aws_host_resolver_resolve_host(struct aws_host_resolver *resolver, const struct aws_string *host_name,
                                              uint64_t max_ttl, on_host_resolved_result res, void *user_data);

AWS_IO_API int aws_host_resolver_purge_cache(struct aws_host_resolver *resolver);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_HOST_RESOLVER_H */