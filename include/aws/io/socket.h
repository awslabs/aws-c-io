#ifndef AWS_IO_SOCKET_H
#define AWS_IO_SOCKET_H

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
#include <stdbool.h>

typedef enum aws_socket_domain {
    AWS_SOCKET_IPV4,
    AWS_SOCKET_IPV6,
    AWS_SOCKET_LOCAL,

} aws_socket_domain;

typedef enum aws_socket_type {
    AWS_SOCKET_STREAM,
    AWS_SOCKET_DGRAM
} aws_socket_type;

struct aws_socket_options {
    aws_socket_type type;
    aws_socket_domain domain;
    uint32_t linger_time;
    uint32_t read_timeout;
    uint32_t send_timeout;
    uint32_t connect_timeout;
    bool keepalive;
};

struct aws_socket;
struct aws_event_loop;

struct aws_socket_creation_args {
    void(*on_incoming_connection)(struct aws_socket *socket, struct aws_socket *new_socket, void *ctx);
    void(*on_connection_established)(struct aws_socket *socket, void *ctx);
    void(*on_error)(struct aws_socket *socket, int err_code, void *ctx);
    void *ctx;
};

struct aws_socket_endpoint {
    char address[48];
    char socket_name[108];
    char port[10];
};

struct aws_socket {
    struct aws_allocator *allocator;
    struct aws_socket_endpoint local_endpoint;
    struct aws_socket_endpoint remote_endpoint;
    struct aws_socket_options options;
    struct aws_io_handle io_handle;
    struct aws_socket_creation_args creation_args;
    struct aws_event_loop *connection_loop;
    int state;
};

#ifdef __cplusplus
extern "C" {
#endif

AWS_IO_API int aws_socket_init(struct aws_socket *socket, struct aws_allocator *alloc,
                                        struct aws_socket_options *options,
                                        struct aws_event_loop *connection_loop,
                                        struct aws_socket_creation_args *creation_args);

AWS_IO_API void aws_socket_clean_up(struct aws_socket *socket);

AWS_IO_API int aws_socket_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint);

AWS_IO_API int aws_socket_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint);
AWS_IO_API int aws_socket_listen(struct aws_socket *socket, int backlog_size);
AWS_IO_API int aws_socket_start_accept(struct aws_socket *socket);
AWS_IO_API int aws_socket_stop_accept(struct aws_socket *socket);
AWS_IO_API int aws_socket_shutdown(struct aws_socket *socket);
AWS_IO_API struct aws_io_handle *aws_socket_get_io_handle(struct aws_socket *socket);
AWS_IO_API int aws_socket_set_options(struct aws_socket *socket, struct aws_socket_options *options);

#ifdef __cplusplus
}
#endif

#endif /*AWS_IO_SOCKET_H */
