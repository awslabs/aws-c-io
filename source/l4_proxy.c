/**
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/l4_proxy.h>
#include <aws/io/private/l4_proxy_impl.h>

void aws_l4_proxy_config_clean_up(struct aws_l4_proxy_config *config) {
    aws_byte_buf_clean_up(&config->proxy_host);
}

struct aws_l4_proxy_config *aws_l4_proxy_config_release(struct aws_l4_proxy_config *config) {
    if (config) {
        aws_ref_count_release(&config->ref_count);
    }

    return NULL;
}

struct aws_l4_proxy_config *aws_l4_proxy_config_acquire(struct aws_l4_proxy_config *config) {
    if (config) {
        aws_ref_count_acquire(&config->ref_count);
    }

    return config;
}

struct aws_l4_proxy_channel_handler *aws_l4_proxy_config_new_channel_handler(struct aws_l4_proxy_config *config) {
    return config->vtable->new_channel_handler(config);
}

void aws_l4_proxy_config_get_proxy_address(struct aws_l4_proxy_config *config, struct aws_connection_remote *new_remote) {
    AWS_ZERO_STRUCT(*new_remote);

    new_remote->host = aws_byte_cursor_from_buf(&config->proxy_host);
    new_remote->port = config->proxy_port;
}

int aws_l4_proxy_channel_handler_set_remote(struct aws_l4_proxy_channel_handler *channel_handler, struct aws_connection_remote *remote) {
    (void)channel_handler;
    (void)remote;

    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}