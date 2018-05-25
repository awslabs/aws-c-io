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
#include "channel.h"

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
    void(*on_incoming_connection)(struct aws_socket *socket, struct aws_socket *new_socket, void *user_data);
    void(*on_connection_established)(struct aws_socket *socket, void *user_data);
    void(*on_error)(struct aws_socket *socket, int err_code, void *user_data);
    void *user_data;
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

struct aws_byte_buf;

#ifdef __cplusplus
extern "C" {
#endif
/**
 * Initializes a socket object with socket options, an event loop to use for non-blocking operations, and callbacks to invoke
   upon completion of asynchronous operations. If you are using UDP or LOCAL, `connection_loop` may be `NULL`.
 */
AWS_IO_API int aws_socket_init(struct aws_socket *socket, struct aws_allocator *alloc,
                                        struct aws_socket_options *options,
                                        struct aws_event_loop *connection_loop,
                                        struct aws_socket_creation_args *creation_args);

/**
 * Shuts down any pending operations on the socket, and cleans up state. The socket object can be re initialized after this operation.
 */
AWS_IO_API void aws_socket_clean_up(struct aws_socket *socket);

/**
 * Connects to a remote endpoint. In UDP, this simply binds the socket to a remote address for use with `aws_socket_write()`,
 * and if the operation is successful, the socket can immediately be used for write operations.
 *
 * In TCP, this will function will not block. If the return value is successful, then you must wait on the `on_connection_established()`
 * callback to be invoked before using the socket.
 *
 * For LOCAL (Unix Domain Sockets or Named Pipes), the socket will be immediately ready for use upon a successful return.
 */
AWS_IO_API int aws_socket_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint);

/**
 * Binds the socket to a local address. In UDP mode, the socket is ready for `aws_socket_read()` operations. In connection oriented
 * modes, you still must call `aws_socket_listen()` and `aws_socket_start_accept()` before using the socket.
 */
AWS_IO_API int aws_socket_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint);

/**
 * TCP and LOCAL only. Sets up the socket to listen on the address bound to in `aws_socket_bind()`.
 */
AWS_IO_API int aws_socket_listen(struct aws_socket *socket, int backlog_size);

/**
 * TCP and LOCAL only. The socket will begin accepting new connections. This is an asynchronous operation. New connections will
 * arrive via the `on_incoming_connection()` callback.
 */
AWS_IO_API int aws_socket_start_accept(struct aws_socket *socket);

/**
 * TCP and LOCAL only. The socket will shutdown the listener. It is safe to call `aws_socket_start_accept()` again after this
 * operation.
 */
AWS_IO_API int aws_socket_stop_accept(struct aws_socket *socket);

/**
 * Calls `close()` on the socket and unregisters all io operations from the event loop.
 */
AWS_IO_API int aws_socket_shutdown(struct aws_socket *socket);

/**
 * Calls `shutdown()` on the socket based on direction.
 */
AWS_IO_API int aws_socket_half_close(struct aws_socket *socket, aws_channel_direction dir);

/**
 * Fetches the underlying io handle for use in event loop registrations and channel handlers.
 */
AWS_IO_API struct aws_io_handle *aws_socket_get_io_handle(struct aws_socket *socket);

/**
 * Sets new socket options on the underlying socket. This is mainly useful in context of accepting a new connection via:
 * `on_incoming_connection()`.
 */
AWS_IO_API int aws_socket_set_options(struct aws_socket *socket, struct aws_socket_options *options);

/**
 * Reads from the socket. This call is non-blocking and will return `AWS_IO_SOCKET_READ_WOULD_BLOCK` if no data is available.
 * `read` is the amount of data read into `buffer`.
 */
AWS_IO_API int aws_socket_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *read);

/**
 * Writes to the socket. This call is non-blocking and will return `AWS_IO_SOCKET_WRITE_WOULD_BLOCK` if no data could be written.
 * `written` is the amount of data read from `buffer` and successfully written to `socket`.
 */
AWS_IO_API int aws_socket_write(struct aws_socket *socket, const struct aws_byte_buf *buffer, size_t *written);

/**
 * Gets the latest error from the socket. If no error has occurred AWS_OP_SUCCESS will be returned. This function does not
 * raise any errors to the installed error handlers.
 */
AWS_IO_API int aws_socket_get_error(struct aws_socket *socket);

/**
 * Returns true if the socket is still open (doesn't mean connected or listening, only that it hasn't had close() called.
 */
AWS_IO_API bool aws_socket_is_open(struct aws_socket *socket);

#ifdef __cplusplus
}
#endif

#endif /*AWS_IO_SOCKET_H */
