/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IO_L4PROXY_H
#define AWS_IO_L4PROXY_H

#include <aws/io/io.h>

struct aws_l4_proxy_config;
struct aws_l4_proxy_channel_handler;
struct aws_l4_proxy_channel_handler_options;
struct aws_connection_remote;

/**
 * APIs related to l4 proxy configurations.  An l4 proxy configuration is an opaque, heavyweight
 * object capable of creating a channel handler that can negotiate a connection through a proxy server.
 */

AWS_EXTERN_C_BEGIN

/**
 * Adds a reference to a proxy config object
 *
 * @param config the configuration to take a reference to
 * @return rhe config param value
 */
AWS_IO_API struct aws_l4_proxy_config *aws_l4_proxy_config_acquire(struct aws_l4_proxy_config *config);

/**
 * Removes a reference from a proxy config object
 *
 * @param config the configuration to remove a reference from
 * @return rhe config param value
 */
AWS_IO_API struct aws_l4_proxy_config *aws_l4_proxy_config_release(struct aws_l4_proxy_config *config);

/**
 * Creates a new channel handler that will negotiate a tunnel based on the proxy config
 *
 * @param config proxy config to use for tunnel negotiation
 * @param options additional channel handle options
 * @return a new channel handler for proxy negotiation
 */
AWS_IO_API struct aws_l4_proxy_channel_handler *aws_l4_proxy_config_new_channel_handler(
    struct aws_l4_proxy_config *config,
    struct aws_l4_proxy_channel_handler_options *options);

/**
 * Retrieves the configured proxy endpoint information
 *
 * @param config proxy configuration to query
 * @param new_remote output parameter containing the proxy remote information
 */
AWS_IO_API void aws_l4_proxy_config_get_proxy_address(
    struct aws_l4_proxy_config *config,
    struct aws_connection_remote *new_remote);

AWS_EXTERN_C_END

#endif /* AWS_IO_L4PROXY_H */
