#ifndef AWS_IO_PRIVATE_SOCKET_H
#define AWS_IO_PRIVATE_SOCKET_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/socket.h>

int aws_socket_init_poll_based(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    const struct aws_socket_options *options);

int aws_socket_init_completion_port_based(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    const struct aws_socket_options *options);

#endif /* #ifndef AWS_IO_PRIVATE_SOCKET_H */