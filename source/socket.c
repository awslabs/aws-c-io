/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/assert.h>
#include <aws/common/uuid.h>
#include <aws/io/logging.h>
#include <aws/io/private/socket_impl.h>
#include <aws/io/socket.h>

void aws_socket_clean_up(struct aws_socket *socket) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_cleanup_fn);
    socket->vtable->socket_cleanup_fn(socket);
}

int aws_socket_connect(struct aws_socket *socket, struct aws_socket_connect_options *socket_connect_options) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_connect_fn);
    return socket->vtable->socket_connect_fn(socket, socket_connect_options);
}

int aws_socket_bind(struct aws_socket *socket, struct aws_socket_bind_options *socket_bind_options) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_bind_fn);
    return socket->vtable->socket_bind_fn(socket, socket_bind_options);
}

int aws_socket_listen(struct aws_socket *socket, int backlog_size) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_listen_fn);
    return socket->vtable->socket_listen_fn(socket, backlog_size);
}

int aws_socket_start_accept(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    struct aws_socket_listener_options options) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_start_accept_fn);
    return socket->vtable->socket_start_accept_fn(socket, accept_loop, options);
}

int aws_socket_stop_accept(struct aws_socket *socket) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_stop_accept_fn);
    return socket->vtable->socket_stop_accept_fn(socket);
}

int aws_socket_close(struct aws_socket *socket) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_close_fn);
    return socket->vtable->socket_close_fn(socket);
}

int aws_socket_set_close_complete_callback(
    struct aws_socket *socket,
    aws_socket_on_shutdown_complete_fn fn,
    void *user_data) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_set_close_callback);
    return socket->vtable->socket_set_close_callback(socket, fn, user_data);
}

int aws_socket_set_cleanup_complete_callback(
    struct aws_socket *socket,
    aws_socket_on_shutdown_complete_fn fn,
    void *user_data) {
    AWS_PRECONDITION(socket->vtable && socket->vtable->socket_set_cleanup_callback);
    return socket->vtable->socket_set_cleanup_callback(socket, fn, user_data);
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

/**
 * Return the default socket implementation type. If the return value is `AWS_SOCKET_IMPL_PLATFORM_DEFAULT`, the
 * function failed to retrieve the default type value.
 */
enum aws_socket_impl_type aws_socket_get_default_impl_type(void) {
// override default socket
#ifdef AWS_USE_APPLE_NETWORK_FRAMEWORK
    return AWS_SOCKET_IMPL_APPLE_NETWORK_FRAMEWORK;
#else // ! AWS_USE_APPLE_NETWORK_FRAMEWORK
/**
 * Ideally we should use the platform definition (e.x.: AWS_OS_APPLE) here, however the platform
 * definition was declared in aws-c-common. We probably do not want to introduce extra dependency here.
 */
#    if defined(AWS_ENABLE_KQUEUE) || defined(AWS_ENABLE_EPOLL)
    return AWS_SOCKET_IMPL_POSIX;
#    elif defined(AWS_ENABLE_DISPATCH_QUEUE)
    return AWS_SOCKET_IMPL_APPLE_NETWORK_FRAMEWORK;
#    elif defined(AWS_ENABLE_IO_COMPLETION_PORTS)
    return AWS_SOCKET_IMPL_WINSOCK;
#    else
    AWS_FATAL_ASSERT(
        true && "Invalid default socket impl type. Please check make sure the library is compiled the correct ");
    return AWS_SOCKET_IMPL_PLATFORM_DEFAULT;
#    endif
#endif
}

static int aws_socket_impl_type_validate_platform(enum aws_socket_impl_type type);
int aws_socket_init(struct aws_socket *socket, struct aws_allocator *alloc, const struct aws_socket_options *options) {

    // 1. get socket type & validate type is available on the platform
    enum aws_socket_impl_type type = options->impl_type;
    if (type == AWS_SOCKET_IMPL_PLATFORM_DEFAULT) {
        type = aws_socket_get_default_impl_type();
    }

    if (aws_socket_impl_type_validate_platform(type)) {
        AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "Invalid event loop type on the platform.");
        return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
    }

    // 2. setup vtable based on socket type
    switch (type) {
        case AWS_SOCKET_IMPL_POSIX:
            return aws_socket_init_posix(socket, alloc, options);
        case AWS_SOCKET_IMPL_WINSOCK:
            return aws_socket_init_winsock(socket, alloc, options);
        case AWS_SOCKET_IMPL_APPLE_NETWORK_FRAMEWORK:
            return aws_socket_init_apple_nw_socket(socket, alloc, options);
        default:
            AWS_ASSERT(false && "Invalid socket implementation on platform.");
            return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
    }
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

    enum aws_socket_impl_type socket_type = aws_socket_get_default_impl_type();
    if (socket_type == AWS_SOCKET_IMPL_APPLE_NETWORK_FRAMEWORK) {
        snprintf(endpoint->address, sizeof(endpoint->address), "testsock" PRInSTR ".local", AWS_BYTE_BUF_PRI(uuid_buf));
    } else if (socket_type == AWS_SOCKET_IMPL_POSIX) {
        snprintf(endpoint->address, sizeof(endpoint->address), "testsock" PRInSTR ".sock", AWS_BYTE_BUF_PRI(uuid_buf));
    } else if (socket_type == AWS_SOCKET_IMPL_WINSOCK) {
        snprintf(
            endpoint->address, sizeof(endpoint->address), "\\\\.\\pipe\\testsock" PRInSTR, AWS_BYTE_BUF_PRI(uuid_buf));
    }
}

static int aws_socket_impl_type_validate_platform(enum aws_socket_impl_type type) {
    switch (type) {
        case AWS_SOCKET_IMPL_POSIX:
#if !defined(AWS_ENABLE_EPOLL) && !defined(AWS_ENABLE_KQUEUE)
            AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "Posix socket is not supported on the platform.");
            return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
#endif // AWS_SOCKET_IMPL_POSIX
            break;
        case AWS_SOCKET_IMPL_WINSOCK:
#ifndef AWS_ENABLE_IO_COMPLETION_PORTS
            AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "WINSOCK is not supported on the platform.");
            return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
#endif // AWS_ENABLE_IO_COMPLETION_PORTS
            break;
        case AWS_SOCKET_IMPL_APPLE_NETWORK_FRAMEWORK:
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

#if !defined(AWS_ENABLE_EPOLL) && !defined(AWS_ENABLE_KQUEUE)
int aws_socket_init_posix(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    const struct aws_socket_options *options) {
    (void)socket;
    (void)alloc;
    (void)options;
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "Posix socket is not supported on the platform.");
    return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
}
#endif // !AWS_ENABLE_EPOLL && !AWS_ENABLE_KQUEUE

#ifndef AWS_ENABLE_IO_COMPLETION_PORTS
int aws_socket_init_winsock(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    const struct aws_socket_options *options) {
    (void)socket;
    (void)alloc;
    (void)options;
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "WINSOCK is not supported on the platform.");
    return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
}
#endif

#ifndef AWS_ENABLE_DISPATCH_QUEUE
int aws_socket_init_apple_nw_socket(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    const struct aws_socket_options *options) {
    (void)socket;
    (void)alloc;
    (void)options;
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "Apple Network Framework is not supported on the platform.");
    return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
}
#endif
