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

/* don't move this below the Windows.h include!!!!*/
#include <winsock2.h>
#include <ws2tcpip.h>

#include <aws/io/host_resolver.h>

#include <aws/common/string.h>


static bool s_wsa_init = false;

int aws_default_dns_resolve(struct aws_allocator *allocator, const struct aws_string *host_name, struct aws_array_list *output_addresses, void *user_data) {
    (void)user_data;
    ADDRINFOA *result = NULL;
    const char *hostname_cstr = (const char *)aws_string_bytes(host_name);  

    if (!s_wsa_init) {
        /* request latest, it will fallback if it doesn't have it.*/
        WORD requested_version = MAKEWORD(2, 2);
        WSADATA wsa_data;
        WSAStartup(requested_version, &wsa_data);
        s_wsa_init = true;
    }
    
    ADDRINFOA hints;
    AWS_ZERO_STRUCT(hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_protocol = IPPROTO_TCP;

    int res_error = GetAddrInfoA(hostname_cstr, NULL, &hints, &result);

    if (res_error) {
        goto clean_up;
    }

    /* max string length for ipv6. */
    char address_buffer[INET6_ADDRSTRLEN];
    socklen_t max_ip_addrlen = INET6_ADDRSTRLEN;

    for (ADDRINFOA *iter = result; iter != NULL; iter = iter->ai_next) {
        struct aws_host_address host_address;
        AWS_ZERO_ARRAY(address_buffer);
        host_address.allocator = allocator;

        if (iter->ai_family == AF_INET6) {
            host_address.record_type = AWS_ADDRESS_RECORD_TYPE_AAAA;
            InetNtopA(iter->ai_family, &((struct sockaddr_in6 *)iter->ai_addr)->sin6_addr, address_buffer, max_ip_addrlen);
        }
        else {
            host_address.record_type = AWS_ADDRESS_RECORD_TYPE_A;
            InetNtopA(iter->ai_family, &((struct sockaddr_in *)iter->ai_addr)->sin_addr, address_buffer, max_ip_addrlen);
        }        
       
        const struct aws_string *address =
        aws_string_from_array_new(allocator, (const uint8_t *)address_buffer, strlen(address_buffer));

        if (!address) {
           goto clean_up;
        }

        host_address.host = aws_string_from_array_new(allocator, aws_string_bytes(host_name), host_name->len);
        if (!host_address.host) {
           aws_string_destroy((void *)host_address.host);
           goto clean_up;
        }

        host_address.address = address;
        host_address.weight = 0;

        host_address.use_count = 0;
        host_address.connection_failure_count = 0;

        if (aws_array_list_push_back(output_addresses, &host_address)) {
            aws_host_address_clean_up(&host_address);
            goto clean_up;
        }        
    }

    FreeAddrInfoA(result);
    return AWS_OP_SUCCESS;

clean_up:
    if (result) {
        FreeAddrInfoA(result);
    }

    if (res_error) {
        switch (res_error) {
        case WSATRY_AGAIN:
        case WSANO_DATA:
        case WSANO_RECOVERY:
            return aws_raise_error(AWS_IO_DNS_QUERY_FAILED);
        case WSA_NOT_ENOUGH_MEMORY:
            return aws_raise_error(AWS_ERROR_OOM);
        case WSAHOST_NOT_FOUND:  
        case WSATYPE_NOT_FOUND:
            return aws_raise_error(AWS_IO_DNS_INVALID_NAME);
        default:
            return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
        }
    }

    return AWS_OP_ERR;
}
