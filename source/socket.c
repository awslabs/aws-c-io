/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/socket.h>


void aws_socket_clean_up(struct aws_socket *socket) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_cleanup_fn);
    socket->vtable->socket_cleanup_fn(socket);
}

int aws_socket_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *event_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_connect_fn);
    AWS_PRECONDITION(socket->event_loop_style & event_loop->vtable->event_loop_style);
    return socket->vtable->socket_connect_fn(socket, remote_endpoint, event_loop, on_connection_result, user_data);
}

int aws_socket_bind(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_bind_fn);
    return socket->vtable->socket_bind_fn(socket, local_endpoint);
}

int aws_socket_listen(struct aws_socket *socket, int backlog_size) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_listen_fn);
    return socket->vtable->socket_listen_fn(socket, backlog_size);
}

int aws_socket_start_accept(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    aws_socket_on_accept_result_fn *on_accept_result,
    void *user_data) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_listen_fn);
    return socket->vtable->socket_start_accept_fn(socket, accept_loop, on_accept_result, user_data);
}

int aws_socket_stop_accept(struct aws_socket *socket) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_stop_accept_fn);
    return socket->vtable->socket_stop_accept_fn(socket);
}

int aws_socket_close(struct aws_socket *socket) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_close_fn);
    return socket->vtable->socket_close_fn(socket);
}

int aws_socket_shutdown_dir(struct aws_socket *socket, enum aws_channel_direction dir) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_shutdown_dir_fn);
    return socket->vtable->socket_shutdown_dir_fn(socket, dir);
}

int aws_socket_set_options(struct aws_socket *socket, const struct aws_socket_options *options) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_set_options_fn);
    return socket->vtable->socket_set_options_fn(socket, options);
}

int aws_socket_assign_to_event_loop(struct aws_socket *socket, struct aws_event_loop *event_loop) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_assign_to_event_loop_fn);
    AWS_PRECONDITION(socket->event_loop_style & event_loop->vtable->event_loop_style);
    return socket->vtable->socket_assign_to_event_loop_fn(socket, event_loop);
}

struct aws_event_loop *aws_socket_get_event_loop(struct aws_socket *socket) {
    return socket->event_loop;
}

int aws_socket_subscribe_to_readable_events(
    struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable,
    void *user_data) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_subscribe_to_readable_events_fn);
    return socket->vtable->socket_subscribe_to_readable_events_fn(socket, on_readable, user_data);
}

int aws_socket_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_read_fn);
    return socket->vtable->socket_read_fn(socket, buffer, amount_read);
}

int aws_socket_write(
    struct aws_socket *socket,
    const struct aws_byte_cursor *cursor,
    aws_socket_on_write_completed_fn *written_fn,
    void *user_data) {

    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_write_fn);
    return socket->vtable->socket_write_fn(socket, cursor, written_fn, user_data);
}

int aws_socket_get_error(struct aws_socket *socket) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_get_error_fn);
    return socket->vtable->socket_get_error_fn(socket);
}

bool aws_socket_is_open(struct aws_socket *socket) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_is_open_fn);
    return socket->vtable->socket_is_open_fn(socket);
}
