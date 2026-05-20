/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IO_SOCKS5_H
#define AWS_IO_SOCKS5_H

#include <aws/io/io.h>

struct aws_socks5_proxy_config;
struct aws_socks5_proxy_negotiation_strategy;

struct aws_socks5_proxy_negotiation_basic_auth_options {
    struct aws_byte_cursor username;
    struct aws_byte_cursor password;
};

struct aws_socks5_proxy_options {
    struct aws_byte_cursor proxy_host;
    uint16_t proxy_port;

    struct aws_socks5_proxy_negotiation_strategy *negotiation_strategy;

    uint32_t negotiation_timeout_ms;
};

AWS_EXTERN_C_BEGIN

AWS_IO_API struct aws_socks5_proxy_config *aws_socks5_proxy_config_new(
    struct aws_allocator *allocator,
    struct aws_socks5_proxy_options *options);

AWS_IO_API struct aws_socks5_proxy_config *aws_socks5_proxy_config_acquire(struct aws_socks5_proxy_config *config);

AWS_IO_API struct aws_socks5_proxy_config *aws_socks5_proxy_config_release(struct aws_socks5_proxy_config *config);

AWS_IO_API struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_new_basic_auth(
    struct aws_allocator *allocator,
    struct aws_socks5_proxy_negotiation_basic_auth_options *options);

AWS_IO_API struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_new_no_auth(
    struct aws_allocator *allocator);

AWS_IO_API struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_acquire(
    struct aws_socks5_proxy_negotiation_strategy *strategy);

AWS_IO_API struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_release(
    struct aws_socks5_proxy_negotiation_strategy *strategy);

AWS_EXTERN_C_END

#endif /* AWS_IO_SOCKS5_H */
