#ifndef AWS_IO_SOCKET_IMPL_H
#define AWS_IO_SOCKET_IMPL_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/io.h>
#include <aws/io/socket.h>

/* These are hacks for working around headers and functions we need for IO work but aren't directly includable or
   linkable. these are purposely not exported. These functions only get called internally. The awkward aws_ prefixes are
   just in case someone includes this header somewhere they were able to get these definitions included. */
#ifdef _WIN32
typedef void (*aws_ms_fn_ptr)(void);

void aws_check_and_init_winsock(void);
aws_ms_fn_ptr aws_winsock_get_connectex_fn(void);
aws_ms_fn_ptr aws_winsock_get_acceptex_fn(void);
#endif

int aws_socket_init_posix(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    const struct aws_socket_options *options);

int aws_socket_init_winsock(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    const struct aws_socket_options *options);

int aws_socket_init_apple_nw_socket(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    const struct aws_socket_options *options);
struct aws_byte_buf;
struct aws_byte_cursor;
struct aws_string;

struct aws_socket_vtable {
    void (*socket_cleanup_fn)(struct aws_socket *socket);
    int (*socket_connect_fn)(
        struct aws_socket *socket,
        const struct aws_socket_endpoint *remote_endpoint,
        struct aws_event_loop *event_loop,
        aws_socket_on_connection_result_fn *on_connection_result,
        aws_socket_retrieve_tls_options_fn *retrieve_tls_options,
        void *user_data);
    int (*socket_bind_fn)(
        struct aws_socket *socket,
        const struct aws_socket_endpoint *local_endpoint,
        aws_socket_retrieve_tls_options_fn *retrieve_tls_options,
        void *user_data);
    int (*socket_listen_fn)(struct aws_socket *socket, int backlog_size);
    int (*socket_start_accept_fn)(
        struct aws_socket *socket,
        struct aws_event_loop *accept_loop,
        aws_socket_on_accept_result_fn *on_accept_result,
        void *user_data);
    int (*socket_stop_accept_fn)(struct aws_socket *socket);
    int (*socket_close_fn)(struct aws_socket *socket);
    int (*socket_shutdown_dir_fn)(struct aws_socket *socket, enum aws_channel_direction dir);
    int (*socket_set_options_fn)(struct aws_socket *socket, const struct aws_socket_options *options);
    int (*socket_assign_to_event_loop_fn)(struct aws_socket *socket, struct aws_event_loop *event_loop);
    int (*socket_subscribe_to_readable_events_fn)(
        struct aws_socket *socket,
        aws_socket_on_readable_fn *on_readable,
        void *user_data);
    int (*socket_read_fn)(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read);
    int (*socket_write_fn)(
        struct aws_socket *socket,
        const struct aws_byte_cursor *cursor,
        aws_socket_on_write_completed_fn *written_fn,
        void *user_data);
    int (*socket_get_error_fn)(struct aws_socket *socket);
    bool (*socket_is_open_fn)(struct aws_socket *socket);
    struct aws_byte_buf (*socket_get_protocol_fn)(const struct aws_socket *socket);
    struct aws_string *(*socket_get_server_name_fn)(const struct aws_socket *socket);
};
#endif // AWS_IO_SOCKET_IMPL_H
