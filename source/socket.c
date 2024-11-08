/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/assert.h>
#include <aws/common/uuid.h>
#include <aws/io/logging.h>
#include <aws/io/socket.h>

// socket vtables, defined in socket implementation files.
extern struct aws_socket_vtable g_posix_socket_vtable;
extern struct aws_socket_vtable g_winsock_vtable;
// TODO: support extern struct aws_socket_vtable g_apple_nw_vtable;

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

static enum aws_socket_impl_type aws_socket_get_default_impl_type(void);
static int aws_socket_impl_type_validate_platform(enum aws_socket_impl_type type);
int aws_socket_init(struct aws_socket *socket, struct aws_allocator *alloc, const struct aws_socket_options *options) {

    // 1. get socket type & validate type is avliable the platform
    enum aws_socket_impl_type type = options->impl_type;
    if (type == AWS_SIT_PLATFORM_DEFAULT) {
        type = aws_socket_get_default_impl_type();
    }

    if (aws_socket_impl_type_validate_platform(type)) {
        AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "Invalid event loop type on the platform.");
        return AWS_ERROR_PLATFORM_NOT_SUPPORTED;
    }

    // 2. setup vtable based on socket type
    switch (type) {
        case AWS_SIT_POSIX:
#ifdef g_posix_socket_vtable
            socket->vtable = &g_posix_socket_vtable;
#endif
            break;
        case AWS_SIT_WINSOCK:
#ifdef g_winsock_vtable
            socket->vtable = &g_winsock_vtable;
            break;
#endif
        case AWS_SIT_APPLE_NETWORK_FRAMEWORK:
            AWS_ASSERT(false && "Invalid socket implementation on platform.");
            // TODO:
            // Apple network framework is not supported yet.
            // socket->vtable = g_apple_nw_vtable;
            break;
        default:
            AWS_ASSERT(false && "Invalid socket implementation on platform.");
    }

    // 3. init the socket
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_init_fn);
    return socket->vtable->socket_init_fn(socket, alloc, options);
}

int aws_socket_get_bound_address(const struct aws_socket *socket, struct aws_socket_endpoint *out_address) {
    if (socket->local_endpoint.address[0] == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p fd=%d: Socket has no local address. Socket must be bound first.",
            (void *)socket,
            socket->io_handle.data.fd);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }
    *out_address = socket->local_endpoint;
    return AWS_OP_SUCCESS;
}

void aws_socket_endpoint_init_local_address_for_test(struct aws_socket_endpoint *endpoint) {
    (void)endpoint;
    struct aws_uuid uuid;
    AWS_FATAL_ASSERT(aws_uuid_init(&uuid) == AWS_OP_SUCCESS);
    char uuid_str[AWS_UUID_STR_LEN] = {0};
    struct aws_byte_buf uuid_buf = aws_byte_buf_from_empty_array(uuid_str, sizeof(uuid_str));
    AWS_FATAL_ASSERT(aws_uuid_to_str(&uuid, &uuid_buf) == AWS_OP_SUCCESS);

#if defined(AWS_USE_KQUEUE) || defined(AWS_USE_EPOLL)
    snprintf(endpoint->address, sizeof(endpoint->address), "testsock" PRInSTR ".sock", AWS_BYTE_BUF_PRI(uuid_buf));
    return;
#endif

#if defined(AWS_USE_IO_COMPLETION_PORTS)
    snprintf(endpoint->address, sizeof(endpoint->address), "\\\\.\\pipe\\testsock" PRInSTR, AWS_BYTE_BUF_PRI(uuid_buf));
    return;
#endif
}

/**
 * Return the default socket implementation type. If the return value is `AWS_SIT_PLATFORM_DEFAULT`, the function failed
 * to retrieve the default type value.
 */
static enum aws_socket_impl_type aws_socket_get_default_impl_type(void) {
    enum aws_socket_impl_type type = AWS_SIT_PLATFORM_DEFAULT;
// override default socket
#ifdef AWS_USE_APPLE_NETWORK_FRAMEWORK
    type = AWS_SIT_APPLE_NETWORK_FRAMEWORK;
#endif // AWS_USE_APPLE_NETWORK_FRAMEWORK
    if (type != AWS_SIT_PLATFORM_DEFAULT) {
        return type;
    }
/**
 * Ideally we should use the platform definition (e.x.: AWS_OS_APPLE) here, however the platform
 * definition was declared in aws-c-common. We probably do not want to introduce extra dependency here.
 */
#if defined(AWS_ENABLE_KQUEUE) || defined(AWS_ENABLE_EPOLL)
    return AWS_SIT_POSIX;
#endif
#ifdef AWS_ENABLE_DISPATCH_QUEUE
    return AWS_SIT_APPLE_NETWORK_FRAMEWORK;
#endif
#ifdef AWS_ENABLE_IO_COMPLETION_PORTS
    return AWS_SIT_WINSOCK;
#else
    return AWS_SIT_PLATFORM_DEFAULT;
#endif
}

static int aws_socket_impl_type_validate_platform(enum aws_socket_impl_type type) {
    switch (type) {
        case AWS_SIT_POSIX:
#if !defined(AWS_ENABLE_EPOLL) || !defined(AWS_ENABLE_KQUEUE)
            AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "Posix socket is not supported on the platform.");
            return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
#endif // AWS_SIT_POSIX
            break;
        case AWS_SIT_WINSOCK:
#ifndef AWS_ENABLE_IO_COMPLETION_PORTS
            AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "WINSOCK is not supported on the platform.");
            return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
#endif // AWS_ENABLE_IO_COMPLETION_PORTS
            break;
        case AWS_SIT_APPLE_NETWORK_FRAMEWORK:
#ifndef AWS_ENABLE_DISPATCH_QUEUE
            AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "Apple Network Framework is not supported on the platform.");
            return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
#endif // AWS_ENABLE_DISPATCH_QUEUE
            break;
        default:
            AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "Invalid socket implementation type.");
            return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
            break;
    }
    return AWS_OP_SUCCESS;
}
