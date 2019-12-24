#ifndef AWS_IO_DNS_H
#define AWS_IO_DNS_H
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

struct aws_array_list;
struct aws_event_loop_group;
struct aws_string;

/*
 * ToDo: Conceptually split cache from resolution service
 */

enum aws_dns_record_type {
    AWS_DNS_RECORD_TYPE_A,   /* ipv4 address */
    AWS_DNS_RECORD_TYPE_AAAA /* ipv6 address */
};

struct aws_dns_record {
    struct aws_string *data;
    enum aws_dns_record_type type;
};

enum aws_dns_query_cache_read_mode { AWS_DQCRM_NORMAL, AWS_DQCRM_SKIP, AWS_DQCRM_SPREAD_N };

struct aws_dns_query_cache_read_options {
    enum aws_dns_query_cache_read_mode mode;
    uint32_t spread_mode_count;
};

enum aws_dns_query_cache_write_mode { AWS_DQCWM_NORMAL, AWS_DQCWM_SKIP };

enum aws_dns_query_cache_write_operation { AWS_DQCWM_APPEND, AWS_DQCWM_REPLACE };

struct aws_dns_query_cache_write_options {
    enum aws_dns_query_cache_write_mode mode;
    enum aws_dns_query_cache_write_operation operation;
};

enum aws_dns_query_resolve_mode {
    AWS_DQRM_GETADDRINFO,
    AWS_DQRM_RECURSIVE_FROM_ROOT,
    AWS_DQRM_RECURSIVE_FROM_NEAREST_ANCESTOR
};

struct aws_dns_query_resolve_options {
    enum aws_dns_query_resolve_mode mode;
};

typedef void (*on_query_resolution_fn)(struct aws_array_list *records, int error_code, void *user_data);

struct aws_dns_query {

    struct aws_dns_query_cache_read_options *cache_read_options;
    struct aws_dns_query_cache_write_options *cache_write_options;
    struct aws_dns_query_resolve_options *resolve_options;

    struct aws_byte_cursor host_name;

    enum aws_dns_record_type *record_types;
    uint32_t record_type_count;

    on_query_resolution_fn *on_query_resolution;
    void *user_data;
};

struct aws_dns_options {
    struct aws_event_loop_group *elg;
};

struct aws_dns;

AWS_EXTERN_C_BEGIN

/**
 * Creates a new domain name service with a ref count of 1
 */
AWS_IO_API struct aws_dns *aws_dns_new(struct aws_allocator *allocator, struct aws_dns_options *options);

/**
 * Adds 1 to the ref count of a domain name service
 */
AWS_IO_API void aws_dns_acquire(struct aws_dns *service);

/**
 * Decrements 1 from the ref count of a domain name service.  If the ref count drops to zero, the service will be
 * destroyed.
 */
AWS_IO_API void aws_dns_release(struct aws_dns *service);

/**
 * Submits a query to the domain name service.
 */
AWS_IO_API int aws_dns_query(struct aws_dns *service, struct aws_dns_query *query);

/**
 * Copies a dns record from `from` to `to`.
 */
AWS_IO_API int aws_dns_record_copy(const struct aws_dns_record *from, struct aws_dns_record *to);

/**
 * Cleans up the memory for a dns record, but does not free the struct itself
 */
AWS_IO_API void aws_dns_record_clean_up(struct aws_dns_record *record);

AWS_EXTERN_C_END

#endif /* AWS_IO_DNS_H */
