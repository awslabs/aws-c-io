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

#include <aws/common/string.h>

#include <arpa/inet.h>
#include <netdb.h>

int aws_default_dns_resolve(
    struct aws_allocator *allocator,
    const struct aws_string *host_name,
    struct aws_array_list *output_addresses,
    void *user_data) {

    (void)user_data;
    struct addrinfo *result = NULL;
    struct addrinfo *iter = NULL;
    /* max string length for ipv6. */
    socklen_t max_len = INET6_ADDRSTRLEN;
    char address_buffer[max_len];

    size_t hostname_len = host_name->len;
    const char *hostname_cstr = (const char *)aws_string_bytes(host_name);

    struct addrinfo hints;
    AWS_ZERO_STRUCT(hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ALL | AI_V4MAPPED;

    int err_code = getaddrinfo(hostname_cstr, NULL, &hints, &result);

    if (err_code) {
        goto clean_up;
    }

    for (iter = result; iter != NULL; iter = iter->ai_next) {
        struct aws_host_address host_address;

        AWS_ZERO_ARRAY(address_buffer);

        if (iter->ai_family == AF_INET6) {
            host_address.record_type = AWS_ADDRESS_RECORD_TYPE_AAAA;
            inet_ntop(iter->ai_family, &((struct sockaddr_in6 *)iter->ai_addr)->sin6_addr, address_buffer, max_len);
        } else {
            host_address.record_type = AWS_ADDRESS_RECORD_TYPE_A;
            inet_ntop(iter->ai_family, &((struct sockaddr_in *)iter->ai_addr)->sin_addr, address_buffer, max_len);
        }

        size_t address_len = strlen(address_buffer);
        const struct aws_string *address =
            aws_string_new_from_array(allocator, (const uint8_t *)address_buffer, address_len);

        if (!address) {
            goto clean_up;
        }

        const struct aws_string *host_cpy =
            aws_string_new_from_array(allocator, (const uint8_t *)hostname_cstr, hostname_len);

        if (!host_cpy) {
            aws_string_destroy((void *)address);
            goto clean_up;
        }

        host_address.address = address;
        host_address.weight = 0;
        host_address.allocator = allocator;
        host_address.use_count = 0;
        host_address.connection_failure_count = 0;
        host_address.host = host_cpy;

        if (aws_array_list_push_back(output_addresses, &host_address)) {
            aws_host_address_clean_up(&host_address);
            goto clean_up;
        }
    }

    freeaddrinfo(result);
    return AWS_OP_SUCCESS;

clean_up:
    if (result) {
        freeaddrinfo(result);
    }

    if (err_code) {
        switch (err_code) {
            case EAI_FAIL:
            case EAI_AGAIN:
                return aws_raise_error(AWS_IO_DNS_QUERY_FAILED);
            case EAI_MEMORY:
                return aws_raise_error(AWS_ERROR_OOM);
            case EAI_NONAME:
            case EAI_SERVICE:
                return aws_raise_error(AWS_IO_DNS_INVALID_NAME);
            default:
                return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
        }
    }

    return AWS_OP_ERR;
}
