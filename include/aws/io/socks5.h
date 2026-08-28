/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IO_SOCKS5_H
#define AWS_IO_SOCKS5_H

#include <aws/io/io.h>

#include <aws/common/byte_buf.h>

/**
 * Types and APIs for creating a proxy config capable of establishing a tunnel through
 * a SOCKS5 proxy.
 */

struct aws_socks5_proxy_negotiation_strategy;

/**
 * Configuration options for basic authentication
 */
struct aws_socks5_proxy_negotiation_basic_auth_options {

    /**
     * Username to use in the basic auth sub-negotiation
     */
    struct aws_byte_cursor username;

    /**
     * Password to use in the basic auth sub-inegotiation
     */
    struct aws_byte_cursor password;
};

AWS_EXTERN_C_BEGIN

/**
 * Creates a new SOCKS5 authentication strategy that performs basic authentication
 *
 * @param allocator allocator to use
 * @param options basic authentication options
 * @return a new SOCKS5 authentication strategy
 */
AWS_IO_API struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_new_basic_auth(
    struct aws_allocator *allocator,
    struct aws_socks5_proxy_negotiation_basic_auth_options *options);

/**
 * Creates a new SOCKS5 authentication strategy that performs no authentication
 *
 * @param allocator allocator to use
 * @return a new SOCKS5 authentication strategy
 */
AWS_IO_API struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_new_no_auth(
    struct aws_allocator *allocator);

/**
 * Adds a reference to a SOCKS5 negotiation strategy
 *
 * @param strategy strategy to add a reference to
 * @return the strategy param value
 */
AWS_IO_API struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_acquire(
    struct aws_socks5_proxy_negotiation_strategy *strategy);

/**
 * Removes a reference from a SOCKS5 negotiation strategy
 *
 * @param strategy strategy to remove a reference from
 * @return NULL
 */
AWS_IO_API struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_release(
    struct aws_socks5_proxy_negotiation_strategy *strategy);

AWS_EXTERN_C_END

#endif /* AWS_IO_SOCKS5_H */
