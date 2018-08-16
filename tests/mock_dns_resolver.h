#ifndef AWS_MOCK_DNS_RESOLVER_H
#define AWS_MOCK_DNS_RESOLVER_H
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
#include <aws/common/array_list.h>
#include <aws/io/io.h>

struct aws_string;

struct mock_dns_resolver {
    struct aws_array_list address_list;
    size_t index;
    size_t max_resolves;
    size_t resolve_count;
};

int mock_dns_resolver_init(struct mock_dns_resolver *resolver, size_t max_resolves, struct aws_allocator *allocator);

void mock_dns_resolver_clean_up(struct mock_dns_resolver *resolver);

int mock_dns_resolver_append_address_list(struct mock_dns_resolver *resolver, struct aws_array_list *addresses);

int mock_dns_resolve(
    struct aws_allocator *allocator,
    const struct aws_string *host_name,
    struct aws_array_list *output_addresses,
    void *user_data);

#endif /* AWS_MOCK_DNS_RESOLVER_H */
