/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IO_L4PROXY_H
#define AWS_IO_L4PROXY_H

#include <aws/io/io.h>

struct aws_l4_proxy_config;
struct aws_l4_proxy_channel_handler;
struct aws_socket_options;

struct aws_connection_remote {
    struct aws_byte_cursor host;
    uint32_t port;
};

AWS_EXTERN_C_BEGIN

AWS_IO_API struct aws_l4_proxy_config *aws_l4_proxy_config_acquire(struct aws_l4_proxy_config *config);

AWS_IO_API struct aws_l4_proxy_config *aws_l4_proxy_config_release(struct aws_l4_proxy_config *config);

AWS_IO_API struct aws_l4_proxy_channel_handler *aws_l4_proxy_config_new_channel_handler(struct aws_l4_proxy_config *config);

AWS_IO_API void aws_l4_proxy_config_get_proxy_address(struct aws_l4_proxy_config *config, struct aws_connection_remote *new_remote);

AWS_IO_API int aws_l4_proxy_channel_handler_set_remote(struct aws_l4_proxy_channel_handler *channel_handler, struct aws_connection_remote *remote);

AWS_EXTERN_C_END

#endif /* AWS_IO_L4PROXY_H */
