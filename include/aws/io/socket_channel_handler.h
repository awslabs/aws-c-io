#ifndef AWS_IO_SOCKET_CHANNEL_HANDLER_H
#define AWS_IO_SOCKET_CHANNEL_HANDLER_H
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

#include <aws/io/io.h>

struct aws_socket;
struct aws_channel_handler;
struct aws_channel_slot;
struct aws_event_loop;

AWS_EXTERN_C_BEGIN
/**
 * Socket handlers should be the first slot/handler in a channel. It interacts directly with the channel's event loop
 * for read and write notifications. max_read_size is the maximum amount of data it will read from the socket
 * before a context switch (a continuation task will be scheduled).
 */
AWS_IO_API struct aws_channel_handler *aws_socket_handler_new(
    struct aws_allocator *allocator,
    struct aws_socket *socket,
    struct aws_channel_slot *slot,
    size_t max_read_size);

AWS_EXTERN_C_END

#endif /* AWS_IO_SOCKET_CHANNEL_HANDLER_H */
