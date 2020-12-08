/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include "mock_dns_resolver.h"

#include <aws/io/host_resolver.h>

int mock_dns_resolver_init(struct mock_dns_resolver *resolver, size_t max_resolves, struct aws_allocator *allocator) {
    resolver->index = 0;
    resolver->max_resolves = max_resolves;
    resolver->resolve_count = 0;
    return aws_array_list_init_dynamic(&resolver->address_list, allocator, 2, sizeof(struct aws_array_list));
}

void mock_dns_resolver_clean_up(struct mock_dns_resolver *resolver) {
    for (size_t i = 0; i < aws_array_list_length(&resolver->address_list); ++i) {
        struct aws_array_list *temp = NULL;
        aws_array_list_get_at_ptr(&resolver->address_list, (void **)&temp, i);

        for (size_t j = 0; j < aws_array_list_length(temp); ++j) {
            struct aws_host_address *temp_address = NULL;
            aws_array_list_get_at_ptr(temp, (void **)&temp_address, j);
            aws_host_address_clean_up(temp_address);
        }
        aws_array_list_clean_up(temp);
    }

    aws_array_list_clean_up(&resolver->address_list);
}

int mock_dns_resolver_append_address_list(struct mock_dns_resolver *resolver, struct aws_array_list *addresses) {
    return aws_array_list_push_back(&resolver->address_list, addresses);
}

int mock_dns_resolve(
    struct aws_allocator *allocator,
    const struct aws_string *host_name,
    struct aws_array_list *output_addresses,
    void *user_data) {

    (void)allocator;
    (void)host_name;
    struct mock_dns_resolver *mock_resolver = user_data;

    if (mock_resolver->resolve_count == mock_resolver->max_resolves) {
        return aws_raise_error(AWS_IO_DNS_QUERY_FAILED);
    }

    struct aws_array_list *iteration_list = NULL;
    if (aws_array_list_get_at_ptr(&mock_resolver->address_list, (void **)&iteration_list, mock_resolver->index)) {
        return aws_raise_error(AWS_ERROR_UNKNOWN);
    }
    mock_resolver->index = (mock_resolver->index + 1) % aws_array_list_length(&mock_resolver->address_list);
    mock_resolver->resolve_count += 1;

    if (aws_array_list_length(iteration_list) == 0) {
        return aws_raise_error(AWS_IO_DNS_QUERY_FAILED);
    }

    for (size_t i = 0; i < aws_array_list_length(iteration_list); ++i) {
        struct aws_host_address *temp_address = NULL;
        aws_array_list_get_at_ptr(iteration_list, (void **)&temp_address, i);
        struct aws_host_address address_cpy;
        aws_host_address_copy(temp_address, &address_cpy);
        aws_array_list_push_back(output_addresses, &address_cpy);
    }

    return AWS_OP_SUCCESS;
}
