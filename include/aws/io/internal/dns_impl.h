#ifndef AWS_IO_DNS_IMPL_H
#define AWS_IO_DNS_IMPL_H
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

#include <aws/io/dns.h>

struct aws_address_cache_entry {
    struct aws_allocator *allocator;
    struct aws_linked_list_node node;
    struct aws_dns_record record;
    uint64_t expiration_timestamp;
};

struct aws_dns_query_record {
    struct aws_dns_query_cache_read_options cache_read_options;
    struct aws_dns_query_cache_write_options cache_write_options;
    struct aws_dns_query_resolve_options resolve_options;

    struct aws_string *host_address;
    enum aws_dns_record_type_flags record_types;

    on_query_resolution_fn *on_query_resolved;
    void *user_data;
};

AWS_EXTERN_C_BEGIN

AWS_EXTERN_C_END

#endif /* AWS_IO_DNS_IMPL_H */
