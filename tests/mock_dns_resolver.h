#ifndef AWS_MOCK_DNS_RESOLVER_H
#define AWS_MOCK_DNS_RESOLVER_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
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
