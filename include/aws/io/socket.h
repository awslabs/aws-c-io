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

#include <aws/io/channel.h>
#include <aws/io/io.h>

enum aws_socket_domain {
    AWS_SOCKET_IPV4,
    AWS_SOCKET_IPV6,
    /* Unix domain sockets (or at least something like them) */
    AWS_SOCKET_LOCAL,
};

enum aws_socket_type {
    AWS_SOCKET_STREAM,
    AWS_SOCKET_DGRAM,
};

struct aws_socket_options {
    enum aws_socket_type type;
    enum aws_socket_domain domain;
    uint32_t linger_time;
    uint16_t keep_alive_interval;
    uint16_t keep_alive_timeout;
    uint32_t connect_timeout;
    bool keepalive;
};

struct aws_socket;
struct aws_event_loop;

struct aws_socket_creation_args {
    /**
     * Called in server mode when an incoming connection has been received. new_socket will need to be assigned
     * to an event loop before IO operations can be used.
     */
    void (*on_incoming_connection)(struct aws_socket *socket, struct aws_socket *new_socket, void *user_data);
    /**
     * Called in client mode when an outgoing connection has succeeded. In this case socket has already been assigned
     * to the event loop specified in aws_socket_connect().
     */
    void (*on_connection_established)(struct aws_socket *socket, void *user_data);
    /**
     * Called for connection level errors, either in client in server mode. This will never be invoked once IO operations
     * have begun.
     */
    void (*on_error)(struct aws_socket *socket, int err_code, void *user_data);
    void *user_data;
};

/**
 * Callback for when the data passed to a call to aws_socket_write() has either completed or failed.
 * On success, error_code will be AWS_OP_SUCCESS.
 */
typedef void(aws_socket_on_data_written_fn)(struct aws_socket *socket, int error_code,
        struct aws_byte_cursor *data_written, void *user_data);
/**
 * Callback for when socket is either readable (edge-triggered) or when an error has occurred. If the socket is
 * readable, error_code will be AWS_OP_SUCCESS.
 */
typedef void(aws_socket_on_readable_fn)(struct aws_socket *socket, int error_code, void *user_data);

struct aws_socket_endpoint {
    char address[40];
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
    struct aws_event_loop *event_loop;
    int state;
    aws_socket_on_readable_fn *readable_fn;
    void *readable_user_data;
    void *impl;
};

struct aws_byte_buf;
struct aws_byte_cursor;

/* These are hacks for working around headers and functions we need for IO work but aren't directly includable or linkable.
   these are purposely not exported. These functions only get called internally. The awkward aws_ prefixes are just in case
   someone includes this header somewhere they were able to get these definitions included. */
#ifdef _WIN32
typedef void(*aws_ms_fn_ptr)(void);

void aws_check_and_init_winsock(void);
aws_ms_fn_ptr aws_winsock_get_connectex_fn(void);
aws_ms_fn_ptr aws_winsock_get_acceptex_fn(void);
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initializes a socket object with socket options, an event loop to use for non-blocking operations, and callbacks to
 invoke upon completion of asynchronous operations. If you are using UDP or LOCAL, `connection_loop` may be `NULL`.
 */
AWS_IO_API int aws_socket_init(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    struct aws_socket_options *options,
    struct aws_socket_creation_args *creation_args);

/**
 * Shuts down any pending operations on the socket, and cleans up state. The socket object can be re initialized after
 * this operation.
 */
AWS_IO_API void aws_socket_clean_up(struct aws_socket *socket);

/**
 * Connects to a remote endpoint. In UDP, this simply binds the socket to a remote address for use with
 * `aws_socket_write()`, and if the operation is successful, the socket can immediately be used for write operations.
 *
 * In TCP, this will function will not block. If the return value is successful, then you must wait on the
 * `on_connection_established()` callback to be invoked before using the socket.
 *
 * For LOCAL (Unix Domain Sockets or Named Pipes), the socket will be immediately ready for use upon a successful
 * return.
 */
AWS_IO_API int aws_socket_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *event_loop);

/**
 * Binds the socket to a local address. In UDP mode, the socket is ready for `aws_socket_read()` operations. In
 * connection oriented modes, you still must call `aws_socket_listen()` and `aws_socket_start_accept()` before using the
 * socket.
 */
AWS_IO_API int aws_socket_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint);

/**
 * TCP and LOCAL only. Sets up the socket to listen on the address bound to in `aws_socket_bind()`.
 */
AWS_IO_API int aws_socket_listen(struct aws_socket *socket, int backlog_size);

/**
 * TCP and LOCAL only. The socket will begin accepting new connections. This is an asynchronous operation. New
 * connections will arrive via the `on_incoming_connection()` callback.
 */
AWS_IO_API int aws_socket_start_accept(struct aws_socket *socket, struct aws_event_loop *accept_loop);

/**
 * TCP and LOCAL only. The socket will shutdown the listener. It is safe to call `aws_socket_start_accept()` again after
 * this operation.
 */
AWS_IO_API int aws_socket_stop_accept(struct aws_socket *socket);

/**
 * Calls `close()` on the socket and unregisters all io operations from the event loop.
 */
AWS_IO_API int aws_socket_shutdown(struct aws_socket *socket);

/**
 * Calls `shutdown()` on the socket based on direction.
 */
AWS_IO_API int aws_socket_half_close(struct aws_socket *socket, enum aws_channel_direction dir);

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
 * Assigns the socket to the event-loop. The socket will begin receiving read/write/error notifications after this call.
 *
 * Note: If you called connect for TCP or Unix Domain Sockets and received a connection_success callback, this has already
 * happened. You only need to call this function when:
 *
 * a.) This socket is a server socket (e.g. a result of a call to start_accept())
 * b.) This socket is a UDP socket.
 */
AWS_IO_API int aws_socket_assign_to_event_loop(struct aws_socket *socket, struct aws_event_loop *event_loop);

/**
 * Gets the event-loop the socket is assigned to.
 */
AWS_IO_API struct aws_event_loop *aws_socket_get_event_loop(struct aws_socket *socket);

/**
 * Subscribes on_readable to notifications when the socket goes readable (edge-triggered). Errors will also be recieved in
 * the callback.
 *
 * Note! This function is technically not thread safe, but we do not enforce which thread you call from.
 * It's your responsibility to either call this in safely (e.g. just don't call it in parallel from multiple threads) or
 * schedule a task to call it. If you call it before your first call to read, it will be fine.
 */
AWS_IO_API int aws_socket_subscribe_to_readable_events(struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable, void *user_data);

/**
 * Reads from the socket. This call is non-blocking and will return `AWS_IO_SOCKET_READ_WOULD_BLOCK` if no data is
 * available. `read` is the amount of data read into `buffer`.
 *
 * Use aws_socket_subscribe_to_readable_events() to receive notifications of when the socket goes readable.
 *
 * NOTE! This function must be called from the event-loop used in aws_socket_assign_to_event_loop
 */
AWS_IO_API int aws_socket_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read);

/**
 * Writes to the socket. This call is non-blocking and will attempt to write as much as it can, but will queue any remaining
 * portion of the data for write when available. written_fn will be invoked once the entire cursor has been written, or
 * the write failed or was cancelled.
 *
 * NOTE! This function must be called from the event-loop used in aws_socket_assign_to_event_loop
 */
AWS_IO_API int aws_socket_write(struct aws_socket *socket, struct aws_byte_cursor *cursor, 
    aws_socket_on_data_written_fn *written_fn, void *user_data);

/**
 * Gets the latest error from the socket. If no error has occurred AWS_OP_SUCCESS will be returned. This function does
 * not raise any errors to the installed error handlers.
 */
AWS_IO_API int aws_socket_get_error(struct aws_socket *socket);

/**
 * Returns true if the socket is still open (doesn't mean connected or listening, only that it hasn't had close()
 * called.
 */
AWS_IO_API bool aws_socket_is_open(struct aws_socket *socket);

#ifdef __cplusplus
}
#endif

#endif /*AWS_IO_SOCKET_H */
