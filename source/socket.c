/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/platform.h>
#include <aws/io/private/socket.h>

struct aws_socket_options aws_socket_options_default_tcp_ipv6(enum aws_event_loop_style el_style) {
    struct aws_socket_options options = {
        .domain = AWS_SOCKET_IPV6,
        .type = AWS_SOCKET_STREAM,
        .connect_timeout_ms = 3000,
    };
    options.event_loop_style = el_style;

    return options;
}

struct aws_socket_options aws_socket_options_default_tcp_ipv4(enum aws_event_loop_style el_style) {
    struct aws_socket_options options = {
        .domain = AWS_SOCKET_IPV4,
        .type = AWS_SOCKET_STREAM,
        .connect_timeout_ms = 3000,
    };
    options.event_loop_style = el_style;

    return options;
}

struct aws_socket_options aws_socket_options_default_udp_ipv6(enum aws_event_loop_style el_style) {
    struct aws_socket_options options = {
        .domain = AWS_SOCKET_IPV6,
        .type = AWS_SOCKET_DGRAM,
        .connect_timeout_ms = 3000,
    };
    options.event_loop_style = el_style;

    return options;
}

struct aws_socket_options aws_socket_options_default_udp_ipv4(enum aws_event_loop_style el_style) {
    struct aws_socket_options options = {
        .domain = AWS_SOCKET_IPV4,
        .type = AWS_SOCKET_DGRAM,
        .connect_timeout_ms = 3000,
    };
    options.event_loop_style = el_style;

    return options;
}

struct aws_socket_options aws_socket_options_default_local(enum aws_event_loop_style el_style) {
    struct aws_socket_options options = {
        .domain = AWS_SOCKET_LOCAL,
        .type = AWS_SOCKET_STREAM,
        .connect_timeout_ms = 3000,
    };
    options.event_loop_style = el_style;

    return options;
}

int aws_socket_init(struct aws_socket *socket, struct aws_allocator *alloc, const struct aws_socket_options *options) {

    AWS_FATAL_PRECONDITION(
        options->event_loop_style & AWS_EVENT_LOOP_STYLE_POLL_BASED ||
        options->event_loop_style & AWS_EVENT_LOOP_STYLE_COMPLETION_PORT_BASED);

    AWS_ZERO_STRUCT(*socket);
    socket->event_loop_style = options->event_loop_style;

    if (options->event_loop_style & AWS_EVENT_LOOP_STYLE_POLL_BASED) {
        return aws_socket_init_poll_based(socket, alloc, options);
    }

    if (options->event_loop_style & AWS_EVENT_LOOP_STYLE_COMPLETION_PORT_BASED) {
        return aws_socket_init_completion_port_based(socket, alloc, options);
    }

    /* this is logically impossible given the precondition above. */
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}

/* on a platform without both socket types, we need to define the symbols for that type of socket so the linker will be
 * happy. */
#if !defined(AWS_USE_DISPATCH_QUEUE) && !defined(AWS_USE_IO_COMPLETION_PORTS)
int aws_socket_init_completion_port_based(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    const struct aws_socket_options *options) {
    (void)socket;
    (void)alloc;
    (void)options;

    AWS_FATAL_ASSERT(!"This socket type is not implemented for this build configuration. You have selected a "
                      "completion based socket, but no completion based implementation is available");
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
}
#endif /* !AWS_USE_DISPATCH_QUEUE && !AWS_USE_IO_COMPLETION_PORTS */

void aws_socket_clean_up(struct aws_socket *socket) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_cleanup_fn);
    socket->vtable->socket_cleanup_fn(socket);
}

int aws_socket_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *event_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    aws_socket_retrieve_tls_options_fn *retrieve_tls_options,
    void *user_data) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_connect_fn);
    AWS_PRECONDITION(socket->event_loop_style & event_loop->vtable->event_loop_style);
    return socket->vtable->socket_connect_fn(
        socket, remote_endpoint, event_loop, on_connection_result, retrieve_tls_options, user_data);
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
