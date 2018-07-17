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

typedef enum aws_address_record_type {
    AWS_ADDRESS_RECORD_TYPE_A,
    AWS_ADDRESS_RECORD_TYPE_AAAA
} aws_address_record_type;

struct aws_host_address {
    struct aws_allocator *allocator;
    const struct aws_string *host;
    const struct aws_string *address;
    aws_address_record_type record_type;
    uint64_t expiry;
    /* This next section is strictly for mitigating the impact of sticky hosts that aren't performing well. */
    /*for use in DNS-based load balancing.*/
    size_t use_count;
      /* give a hint on when to remove a bad host from service. */
    size_t connection_failure_count;
    /* we don't implement this yet, but we will asap. */
    uint8_t weight;
};


typedef struct aws_host_address*(*on_host_resolved_result)(struct aws_host_resolver *resolver, const struct aws_string *host_name, int err_code, const struct aws_array_list *host_addresses, void *user_data);

typedef int(*aws_resolve_host_implementation)(struct aws_allocator *allocator, const struct aws_string *host_name, struct aws_array_list *output_addresses, void *user_data);

struct aws_host_resolution_config {
    aws_resolve_host_implementation impl;
    size_t max_ttl;
    void *impl_data;
};

struct aws_host_resolver_vtable {
    void(*destroy)(struct aws_host_resolver *resolver);
    int(*resolve_host)(struct aws_host_resolver * resolver, const struct aws_string *host_name,
                       on_host_resolved_result res, struct aws_host_resolution_config *config, void *user_data);
    int(*purge_cache)(struct aws_host_resolver * resolver);
};

struct aws_host_resolver {
    struct aws_allocator *allocator;
    void *impl;
    struct aws_host_resolver_vtable vtable;
};

#ifdef __cplusplus
extern "C" {
#endif

/** WARNING! do not call this function directly: it blocks. Provide a pointer to this function for other resolution functions. */
AWS_IO_API int aws_default_dns_resolve(struct aws_allocator *allocator, const struct aws_string *host_name, struct aws_array_list *output_addresses, void *user_data);

AWS_IO_API int aws_host_address_copy(struct aws_host_address *from, struct aws_host_address *to);
AWS_IO_API void aws_host_address_clean_up(struct aws_host_address *address);

AWS_IO_API int aws_host_resolver_default_init(struct aws_host_resolver *resolver, struct aws_allocator *allocator, size_t max_entries);

AWS_IO_API void aws_host_resolver_destroy(struct aws_host_resolver *);

AWS_IO_API int aws_host_resolver_resolve_host(struct aws_host_resolver *resolver, const struct aws_string *host_name,
                                              on_host_resolved_result res, struct aws_host_resolution_config *config, void *user_data);

AWS_IO_API int aws_host_resolver_record_connection_failure(struct aws_host_resolver *resolver, struct aws_host_address *address);


AWS_IO_API int aws_host_resolver_purge_cache(struct aws_host_resolver *resolver);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_HOST_RESOLVER_H */
