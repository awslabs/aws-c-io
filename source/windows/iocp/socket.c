/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/* clang is just a naive little idealist and doesn't understand that it can't just
go around re-ordering windows header files.
keep the bellow includes where they are. Also, sorry about the C++ style comments
below, clang-format doesn't work (at least on my version) with the c-style comments.*/

// clang-format off
#include <WS2tcpip.h>
#include <MSWSock.h>
#include <Mstcpip.h>
// clang-format on

#include <aws/io/socket.h>

#include <aws/common/byte_buf.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/uuid.h>

#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/io/pipe.h>

#include <aws/io/io.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4221) /* aggregate initializer using local variable addresses */
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

/* due to the windows' team apparently lack of ability to handle header ordering properly
   we can't include ntstatus.h. Just define this, it's used for Connect and Accept callbacks.
   it maps directly to nt's STATUS_CANCELLED */
#define IO_OPERATION_CANCELLED 0xC0000120
#define IO_STATUS_CONNECTION_REFUSED 0xC0000236
#define IO_STATUS_TIMEOUT 0x00000102
#define IO_NETWORK_UNREACHABLE 0xC000023C
#define IO_HOST_UNREACHABLE 0xC000023D
#define IO_CONNECTION_ABORTED 0xC0000241
#define IO_PIPE_BROKEN 0xC000014B
#define SOME_ERROR_CODE_THAT_MEANS_INVALID_PATH 0x00000003
#define IO_STATUS_BUFFER_OVERFLOW 0x80000005
#define STATUS_INVALID_ADDRESS_COMPONENT 0xC0000207

#define PIPE_BUFFER_SIZE 512

struct socket_vtable {
    int (*connection_success)(struct aws_socket *socket);
    void (*connection_error)(struct aws_socket *socket, int error_code);
    int (*close)(struct aws_socket *socket);
    int (*connect)(
        struct aws_socket *socket,
        const struct aws_socket_endpoint *remote_endpoint,
        struct aws_event_loop *connect_loop,
        aws_socket_on_connection_result_fn *on_connection_result,
        void *user_data);
    int (*start_accept)(
        struct aws_socket *socket,
        struct aws_event_loop *accept_loop,
        aws_socket_on_accept_result_fn *on_accept_result,
        void *user_data);
    int (*stop_accept)(struct aws_socket *socket);
    int (*bind)(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint);
    int (*listen)(struct aws_socket *socket, int backlog_size);
    int (*read)(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read);
    int (*subscribe_to_read)(struct aws_socket *socket, aws_socket_on_readable_fn *on_readable, void *user_data);
};

static int s_ipv4_stream_connection_success(struct aws_socket *socket);
static int s_ipv6_stream_connection_success(struct aws_socket *socket);
static void s_connection_error(struct aws_socket *socket, int error_code);
static int s_local_and_udp_connection_success(struct aws_socket *socket);
static int s_ipv4_stream_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *connect_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data);
static int s_ipv4_dgram_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *connect_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data);
static int s_ipv6_stream_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *connect_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data);
static int s_ipv6_dgram_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *connect_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data);
static int s_local_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *connect_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data);
static int s_tcp_start_accept(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    aws_socket_on_accept_result_fn *on_accept_result,
    void *user_data);
static int s_local_start_accept(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    aws_socket_on_accept_result_fn *on_accept_result,
    void *user_data);
static int s_stream_stop_accept(struct aws_socket *socket);
static int s_dgram_start_accept(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    aws_socket_on_accept_result_fn *on_accept_result,
    void *user_data);
static int s_dgram_stop_accept(struct aws_socket *socket);

static int s_tcp_listen(struct aws_socket *socket, int backlog_size);
static int s_udp_listen(struct aws_socket *socket, int backlog_size);
static int s_local_listen(struct aws_socket *socket, int backlog_size);
static int s_tcp_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read);
static int s_local_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read);
static int s_dgram_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read);
static int s_socket_close(struct aws_socket *socket);
static int s_local_close(struct aws_socket *socket);
static int s_ipv4_stream_bind(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint);
static int s_ipv4_dgram_bind(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint);
static int s_ipv6_stream_bind(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint);
static int s_ipv6_dgram_bind(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint);
static int s_local_bind(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint);

static int s_stream_subscribe_to_read(
    struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable,
    void *user_data);
static int s_dgram_subscribe_to_read(
    struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable,
    void *user_data);

static int s_determine_socket_error(int error);

/* Why build this V-table instead of doing that beautiful posix code I just read?
   I'm glad you asked...... because winsock is nothing like posix and certainly not
   as well thought out. There were so many branches to handle three entirely different
   APIs we decided it was less painful to just have a bunch of function pointers in a table
   than to want to gouge our eyes out while looking at a ridiculous number of branches. */
static struct socket_vtable vtables[3][2] = {
    [AWS_SOCKET_IPV4] =
        {
            [AWS_SOCKET_STREAM] =
                {
                    .connection_success = s_ipv4_stream_connection_success,
                    .connection_error = s_connection_error,
                    .connect = s_ipv4_stream_connect,
                    .start_accept = s_tcp_start_accept,
                    .stop_accept = s_stream_stop_accept,
                    .bind = s_ipv4_stream_bind,
                    .listen = s_tcp_listen,
                    .read = s_tcp_read,
                    .close = s_socket_close,
                    .subscribe_to_read = s_stream_subscribe_to_read,
                },
            [AWS_SOCKET_DGRAM] =
                {
                    .connection_success = s_local_and_udp_connection_success,
                    .connection_error = s_connection_error,
                    .connect = s_ipv4_dgram_connect,
                    .start_accept = s_dgram_start_accept,
                    .stop_accept = s_dgram_stop_accept,
                    .bind = s_ipv4_dgram_bind,
                    .listen = s_udp_listen,
                    .read = s_dgram_read,
                    .close = s_socket_close,
                    .subscribe_to_read = s_dgram_subscribe_to_read,
                },
        },
    [AWS_SOCKET_IPV6] =
        {
            [AWS_SOCKET_STREAM] =
                {
                    .connection_success = s_ipv6_stream_connection_success,
                    .connection_error = s_connection_error,
                    .connect = s_ipv6_stream_connect,
                    .start_accept = s_tcp_start_accept,
                    .stop_accept = s_stream_stop_accept,
                    .bind = s_ipv6_stream_bind,
                    .listen = s_tcp_listen,
                    .read = s_tcp_read,
                    .close = s_socket_close,
                    .subscribe_to_read = s_stream_subscribe_to_read,
                },
            [AWS_SOCKET_DGRAM] =
                {
                    .connection_success = s_local_and_udp_connection_success,
                    .connection_error = s_connection_error,
                    .connect = s_ipv6_dgram_connect,
                    .start_accept = s_dgram_start_accept,
                    .stop_accept = s_dgram_stop_accept,
                    .bind = s_ipv6_dgram_bind,
                    .listen = s_udp_listen,
                    .read = s_dgram_read,
                    .close = s_socket_close,
                    .subscribe_to_read = s_dgram_subscribe_to_read,
                },
        },
    [AWS_SOCKET_LOCAL] =
        {
            [AWS_SOCKET_STREAM] =
                {
                    .connection_success = s_local_and_udp_connection_success,
                    .connection_error = s_connection_error,
                    .connect = s_local_connect,
                    .start_accept = s_local_start_accept,
                    .stop_accept = s_stream_stop_accept,
                    .bind = s_local_bind,
                    .listen = s_local_listen,
                    .read = s_local_read,
                    .close = s_local_close,
                    .subscribe_to_read = s_stream_subscribe_to_read,
                },
            [AWS_SOCKET_DGRAM] = {0},
        },
};

/* When socket is connected, any of the CONNECT_*** flags might be set.
   Otherwise, only one state flag is active at a time. */
enum socket_state {
    INIT = 0x01,
    CONNECTING = 0x02,
    CONNECTED_READ = 0x04,
    CONNECTED_WRITE = 0x08,
    CONNECTED_WAITING_ON_READABLE = 0x10,
    BOUND = 0x20,
    LISTENING = 0x40,
    TIMEDOUT = 0x80,
    CLOSED = 0x0100,
    ERRORED = 0x0200,
};

static int s_convert_domain(enum aws_socket_domain domain) {
    switch (domain) {
        case AWS_SOCKET_IPV4:
            return AF_INET;
        case AWS_SOCKET_IPV6:
            return AF_INET6;
        case AWS_SOCKET_LOCAL:
            return AF_UNIX;
        default:
            AWS_ASSERT(0);
            return AF_INET;
    }
}

static int s_convert_type(enum aws_socket_type type) {
    switch (type) {
        case AWS_SOCKET_STREAM:
            return SOCK_STREAM;
        case AWS_SOCKET_DGRAM:
            return SOCK_DGRAM;
        default:
            AWS_ASSERT(0);
            return SOCK_STREAM;
    }
}

#define SOCK_STORAGE_SIZE (sizeof(struct sockaddr_storage) + 16)

struct socket_connect_args {
    struct aws_allocator *allocator;
    struct aws_socket *socket;
    struct aws_task timeout_task;
};

struct io_operation_data {
    struct aws_allocator *allocator;
    struct aws_socket *socket;
    struct aws_overlapped signal;
    struct aws_linked_list_node node;
    struct aws_task sequential_task_storage;
    bool in_use;
};

struct iocp_socket {
    struct socket_vtable *vtable;
    struct io_operation_data *read_io_data;
    struct aws_socket *incoming_socket;
    uint8_t accept_buffer[SOCK_STORAGE_SIZE * 2];
    struct socket_connect_args *connect_args;
    struct aws_linked_list pending_io_operations;
    bool stop_accept;
};

static int s_create_socket(struct aws_socket *sock, const struct aws_socket_options *options) {
    SOCKET handle = socket(s_convert_domain(options->domain), s_convert_type(options->type), 0);
    if (handle == INVALID_SOCKET) {
        int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKET, "id=static: socket() call failed with WSAError %d", wsa_err);
        return aws_raise_error(s_determine_socket_error(wsa_err));
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: initializing with domain %d and type %d",
        (void *)sock,
        (void *)handle,
        options->domain,
        options->type);
    u_long non_blocking = 1;
    if (ioctlsocket(handle, FIONBIO, &non_blocking) != 0) {
        int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKET, "id=static: ioctlsocket() call failed with WSAError %d", wsa_err);
        aws_raise_error(s_determine_socket_error(wsa_err));
        goto error;
    }

    sock->io_handle.data.handle = (HANDLE)handle;
    sock->io_handle.additional_data = NULL;
    if (aws_socket_set_options(sock, options)) {
        goto error;
    }
    return AWS_OP_SUCCESS;

error:
    closesocket(handle);
    sock->io_handle.data.handle = (HANDLE)INVALID_SOCKET;
    return AWS_OP_ERR;
}

static int s_socket_init(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    const struct aws_socket_options *options,
    bool create_underlying_socket) {
    AWS_ASSERT(options->domain <= AWS_SOCKET_LOCAL);
    AWS_ASSERT(options->type <= AWS_SOCKET_DGRAM);
    AWS_ZERO_STRUCT(*socket);

    struct iocp_socket *impl = aws_mem_calloc(alloc, 1, sizeof(struct iocp_socket));
    if (!impl) {
        return AWS_OP_ERR;
    }

    impl->vtable = &vtables[options->domain][options->type];
    if (!impl->vtable || !impl->vtable->read) {
        aws_mem_release(alloc, impl);
        socket->impl = NULL;
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
    }

    impl->read_io_data = aws_mem_calloc(alloc, 1, sizeof(struct io_operation_data));
    if (!impl->read_io_data) {
        aws_mem_release(alloc, impl);
        socket->impl = NULL;
        return AWS_OP_ERR;
    }

    impl->read_io_data->allocator = alloc;
    impl->read_io_data->socket = socket;
    impl->read_io_data->in_use = false;
    aws_linked_list_init(&impl->pending_io_operations);

    socket->allocator = alloc;
    socket->io_handle.data.handle = INVALID_HANDLE_VALUE;
    socket->state = INIT;
    socket->impl = impl;
    socket->options = *options;

    if (options->domain != AWS_SOCKET_LOCAL && create_underlying_socket) {
        if (s_create_socket(socket, options)) {
            aws_mem_release(alloc, impl->read_io_data);
            aws_mem_release(alloc, impl);
            socket->impl = NULL;
            return AWS_OP_ERR;
        }
    }
    return AWS_OP_SUCCESS;
}

int aws_socket_init(struct aws_socket *socket, struct aws_allocator *alloc, const struct aws_socket_options *options) {
    AWS_ASSERT(options);

    aws_check_and_init_winsock();

    int err = s_socket_init(socket, alloc, options, true);

    return err;
}

void aws_socket_clean_up(struct aws_socket *socket) {
    if (!socket->impl) {
        /* protect from double clean */
        return;
    }
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p, handle=%p: cleaning up socket.",
        (void *)socket,
        (void *)socket->io_handle.data.handle);
    struct iocp_socket *socket_impl = socket->impl;
    socket_impl->vtable->close(socket);

    if (socket_impl->incoming_socket) {
        aws_socket_clean_up(socket_impl->incoming_socket);
        aws_mem_release(socket->allocator, socket_impl->incoming_socket);
    }

    if (socket_impl->read_io_data) {
        aws_mem_release(socket->allocator, socket_impl->read_io_data);
    }

    aws_mem_release(socket->allocator, socket->impl);
    AWS_ZERO_STRUCT(*socket);
    socket->io_handle.data.handle = INVALID_HANDLE_VALUE;
}

int aws_socket_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *event_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data) {
    struct iocp_socket *socket_impl = socket->impl;
    if (socket->options.type != AWS_SOCKET_DGRAM) {
        AWS_ASSERT(on_connection_result);
        if (socket->state != INIT) {
            socket->state = ERRORED;
            return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
        }
    } else { /* UDP socket */
        /* UDP sockets jump to CONNECT_READ if bind is called first */
        if (socket->state != CONNECTED_READ && socket->state != INIT) {
            socket->state = ERRORED;
            return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
        }
    }

    if (aws_socket_validate_port_for_connect(remote_endpoint->port, socket->options.domain)) {
        return AWS_OP_ERR;
    }

    return socket_impl->vtable->connect(socket, remote_endpoint, event_loop, on_connection_result, user_data);
}

int aws_socket_bind(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint) {
    if (socket->state != INIT) {
        socket->state = ERRORED;
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    if (aws_socket_validate_port_for_bind(local_endpoint->port, socket->options.domain)) {
        return AWS_OP_ERR;
    }

    struct iocp_socket *socket_impl = socket->impl;
    return socket_impl->vtable->bind(socket, local_endpoint);
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

/* Update IPV4 or IPV6 socket->local_endpoint based on the results of getsockname() */
static int s_update_local_endpoint_ipv4_ipv6(struct aws_socket *socket) {
    struct aws_socket_endpoint tmp_endpoint;
    AWS_ZERO_STRUCT(tmp_endpoint);

    struct sockaddr_storage address;
    AWS_ZERO_STRUCT(address);
    socklen_t address_size = sizeof(address);
    if (getsockname((SOCKET)socket->io_handle.data.handle, (struct sockaddr *)&address, &address_size) != 0) {
        int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: getsockname() failed with error %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            wsa_err);
        return aws_raise_error(s_determine_socket_error(wsa_err));
    }

    if (address.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&address;
        tmp_endpoint.port = ntohs(s->sin_port);
        if (InetNtopA(AF_INET, &s->sin_addr, tmp_endpoint.address, sizeof(tmp_endpoint.address)) == NULL) {
            int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: determining local endpoint failed",
                (void *)socket,
                (void *)socket->io_handle.data.handle);
            return aws_raise_error(s_determine_socket_error(wsa_err));
        }
    } else if (address.ss_family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&address;
        tmp_endpoint.port = ntohs(s->sin6_port);
        if (InetNtopA(AF_INET6, &s->sin6_addr, tmp_endpoint.address, sizeof(tmp_endpoint.address)) == NULL) {
            int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: determining local endpoint failed",
                (void *)socket,
                (void *)socket->io_handle.data.handle);
            return aws_raise_error(s_determine_socket_error(wsa_err));
        }
    } else {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: unknown ADDRESS_FAMILY %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            address.ss_family);
        return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
    }

    socket->local_endpoint = tmp_endpoint;
    return AWS_OP_SUCCESS;
}

int aws_socket_listen(struct aws_socket *socket, int backlog_size) {
    struct iocp_socket *socket_impl = socket->impl;
    return socket_impl->vtable->listen(socket, backlog_size);
}

int aws_socket_start_accept(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    aws_socket_on_accept_result_fn *on_accept_result,
    void *user_data) {
    struct iocp_socket *socket_impl = socket->impl;
    return socket_impl->vtable->start_accept(socket, accept_loop, on_accept_result, user_data);
}

int aws_socket_stop_accept(struct aws_socket *socket) {
    struct iocp_socket *socket_impl = socket->impl;
    return socket_impl->vtable->stop_accept(socket);
}

int aws_socket_close(struct aws_socket *socket) {
    struct iocp_socket *socket_impl = socket->impl;
    return socket_impl->vtable->close(socket);
}

int aws_socket_shutdown_dir(struct aws_socket *socket, enum aws_channel_direction dir) {
    int how = dir == AWS_CHANNEL_DIR_READ ? 0 : 1;

    if (shutdown((SOCKET)socket->io_handle.data.handle, how)) {
        int aws_error = s_determine_socket_error(WSAGetLastError());
        return aws_raise_error(aws_error);
    }

    if (dir == AWS_CHANNEL_DIR_READ) {
        socket->state &= ~CONNECTED_READ;
    } else {
        socket->state &= ~CONNECTED_WRITE;
    }

    return AWS_OP_SUCCESS;
}

int aws_socket_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read) {
    struct iocp_socket *socket_impl = socket->impl;
    AWS_ASSERT(socket->readable_fn);

    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: Read can only be called from the owning event-loop's thread.",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (!(socket->state & CONNECTED_READ)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: Attempt to read from an unconnected socket.",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    return socket_impl->vtable->read(socket, buffer, amount_read);
}

int aws_socket_subscribe_to_readable_events(
    struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable,
    void *user_data) {
    struct iocp_socket *socket_impl = socket->impl;
    AWS_ASSERT(socket->event_loop);
    AWS_ASSERT(!socket->readable_fn);

    if (!(socket->state & CONNECTED_READ)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: Attempt to subscribe to an unconnected socket.",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    return socket_impl->vtable->subscribe_to_read(socket, on_readable, user_data);
}

static int s_determine_socket_error(int error) {
    switch (error) {
        case WSAECONNREFUSED:
        case IO_STATUS_CONNECTION_REFUSED:
            return AWS_IO_SOCKET_CONNECTION_REFUSED;
        case WSAETIMEDOUT:
        case IO_STATUS_TIMEOUT:
            return AWS_IO_SOCKET_TIMEOUT;
        case IO_PIPE_BROKEN:
        case ERROR_BROKEN_PIPE:
            return AWS_IO_SOCKET_CLOSED;
        case STATUS_INVALID_ADDRESS_COMPONENT:
        case WSAEADDRNOTAVAIL:
            return AWS_IO_SOCKET_INVALID_ADDRESS;
        case WSAEADDRINUSE:
            return AWS_IO_SOCKET_ADDRESS_IN_USE;
        case WSAENETUNREACH:
        case IO_NETWORK_UNREACHABLE:
        case IO_HOST_UNREACHABLE:
            return AWS_IO_SOCKET_NO_ROUTE_TO_HOST;
        case WSAENETDOWN:
            return AWS_IO_SOCKET_NETWORK_DOWN;
        case WSAECONNABORTED:
        case IO_CONNECTION_ABORTED:
            return AWS_IO_SOCKET_CONNECT_ABORTED;
        case WSAENOBUFS:
            return AWS_ERROR_OOM;
        case WSAEMFILE:
            return AWS_ERROR_MAX_FDS_EXCEEDED;
        case WSAENAMETOOLONG:
        case WSA_INVALID_PARAMETER:
        case SOME_ERROR_CODE_THAT_MEANS_INVALID_PATH:
            return AWS_ERROR_FILE_INVALID_PATH;
        case WSAEAFNOSUPPORT:
            return AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY;
        case WSAEACCES:
            return AWS_ERROR_NO_PERMISSION;
        default:
            return AWS_IO_SOCKET_NOT_CONNECTED;
    }
}

static inline int s_process_tcp_sock_options(struct aws_socket *socket) {
    if (aws_socket_set_options(socket, &socket->options)) {
        aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

/* called when an IPV4 tcp socket successfully has connected. */
static int s_ipv4_stream_connection_success(struct aws_socket *socket) {
    struct iocp_socket *socket_impl = socket->impl;

    if (s_process_tcp_sock_options(socket)) {
        goto error;
    }

    int connect_result = 0;
    socklen_t result_length = sizeof(connect_result);
    if (getsockopt(
            (SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_ERROR, (char *)&connect_result, &result_length) < 0) {
        int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to determine connection error %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            wsa_err);
        aws_raise_error(s_determine_socket_error(wsa_err));
        goto error;
    }

    if (connect_result) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: connection error %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            connect_result);
        aws_raise_error(s_determine_socket_error(connect_result));
        goto error;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p handle=%p: connection success", (void *)socket, (void *)socket->io_handle.data.handle);

    if (s_update_local_endpoint_ipv4_ipv6(socket)) {
        goto error;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: local endpoint %s:%u",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        socket->local_endpoint.address,
        socket->local_endpoint.port);

    setsockopt((SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
    socket->state = CONNECTED_WRITE | CONNECTED_READ;

    socket->connection_result_fn(socket, AWS_ERROR_SUCCESS, socket->connect_accept_user_data);

    return AWS_OP_SUCCESS;
error:
    socket->state = ERRORED;
    socket_impl->vtable->connection_error(socket, aws_last_error());
    return AWS_OP_ERR;
}

/* called upon a successful TCP over IPv6 connection. */
static int s_ipv6_stream_connection_success(struct aws_socket *socket) {
    struct iocp_socket *socket_impl = socket->impl;

    if (s_process_tcp_sock_options(socket)) {
        goto error;
    }

    int connect_result = 0;
    socklen_t result_length = sizeof(connect_result);
    if (getsockopt(
            (SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_ERROR, (char *)&connect_result, &result_length) < 0) {
        int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to determine connection error %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            wsa_err);
        aws_raise_error(s_determine_socket_error(wsa_err));
        goto error;
    }

    if (connect_result) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: connection error %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            connect_result);
        aws_raise_error(s_determine_socket_error(connect_result));
        goto error;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p handle=%p: connection success", (void *)socket, (void *)socket->io_handle.data.handle);

    if (s_update_local_endpoint_ipv4_ipv6(socket)) {
        goto error;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: local endpoint %s:%u",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        socket->local_endpoint.address,
        socket->local_endpoint.port);

    setsockopt((SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);

    socket->state = CONNECTED_WRITE | CONNECTED_READ;

    socket->connection_result_fn(socket, AWS_ERROR_SUCCESS, socket->connect_accept_user_data);

    return AWS_OP_SUCCESS;

error:
    socket->state = ERRORED;
    socket_impl->vtable->connection_error(socket, aws_last_error());
    return AWS_OP_ERR;
}

/* Outgoing UDP and Named pipe connections. */
static int s_local_and_udp_connection_success(struct aws_socket *socket) {
    socket->state = CONNECTED_WRITE | CONNECTED_READ;

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p handle=%p: connection success", (void *)socket, (void *)socket->io_handle.data.handle);
    if (socket->connection_result_fn) {
        socket->connection_result_fn(socket, AWS_ERROR_SUCCESS, socket->connect_accept_user_data);
    }

    return AWS_OP_SUCCESS;
}

static void s_connection_error(struct aws_socket *socket, int error) {
    socket->state = ERRORED;

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: connection error with code %d",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        error);

    if (socket->connection_result_fn) {
        socket->connection_result_fn(socket, error, socket->connect_accept_user_data);
    } else if (socket->accept_result_fn) {
        socket->accept_result_fn(socket, error, NULL, socket->connect_accept_user_data);
    }
}

/* Named Pipes and TCP connection callbacks from the event loop. */
void s_socket_connection_completion(
    struct aws_event_loop *event_loop,
    struct aws_overlapped *overlapped,
    int status_code,
    size_t num_bytes_transferred) {
    (void)num_bytes_transferred;
    (void)event_loop;

    struct io_operation_data *operation_data = AWS_CONTAINER_OF(overlapped, struct io_operation_data, signal);
    struct socket_connect_args *socket_args = overlapped->user_data;

    AWS_LOGF_TRACE(AWS_LS_IO_SOCKET, "static: connect completion triggered on event-loop %p", (void *)event_loop);

    if (!operation_data->socket) {
        aws_mem_release(operation_data->allocator, operation_data);
        return;
    }

    if (status_code == IO_OPERATION_CANCELLED) {
        operation_data->in_use = false;
        return;
    }

    if (socket_args->socket) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: connect completion triggered. Socket has not timed out yet: proceeding with connection",
            (void *)socket_args->socket,
            (void *)socket_args->socket->io_handle.data.handle);
        struct iocp_socket *socket_impl = socket_args->socket->impl;

        struct aws_socket *socket = socket_args->socket;
        socket->readable_fn = NULL;
        socket->readable_user_data = NULL;
        socket_impl->connect_args = NULL;
        socket_args->socket = NULL;

        if (!status_code) {
            socket_impl->vtable->connection_success(socket);
        } else {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: connect completion triggered with error %d",
                (void *)socket,
                (void *)socket->io_handle.data.handle,
                status_code);
            int error = s_determine_socket_error(status_code);
            socket_impl->vtable->connection_error(socket, error);
        }
    }

    if (operation_data->socket) {
        operation_data->in_use = false;
    } else {
        aws_mem_release(operation_data->allocator, operation_data);
    }
}

/* outgoing tcp connection. If this task runs before `s_socket_connection_completion()`, then the
   connection is considered timedout. */
static void s_handle_socket_timeout(struct aws_task *task, void *args, aws_task_status status) {
    (void)task;
    (void)status;
    struct socket_connect_args *socket_args = args;

    AWS_LOGF_TRACE(AWS_LS_IO_SOCKET, "task_id=%p: timeout task triggered, evaluating timeouts.", (void *)task);
    if (socket_args->socket) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: timed out, shutting down.",
            (void *)socket_args->socket,
            (void *)socket_args->socket->io_handle.data.handle);
        socket_args->socket->state = TIMEDOUT;
        struct aws_socket *socket = socket_args->socket;
        int error_code = AWS_IO_SOCKET_TIMEOUT;

        /* since the task is canceled the event-loop is gone and the iocp will not trigger, so go ahead
           and tell the socket cleanup stuff that the iocp handle is no longer pending operations. */
        if (status == AWS_TASK_STATUS_CANCELED) {
            struct iocp_socket *iocp_socket = socket->impl;
            iocp_socket->read_io_data->in_use = false;
            error_code = AWS_IO_EVENT_LOOP_SHUTDOWN;
        }

        aws_raise_error(error_code);

        /* socket close will set the connection args to NULL etc...*/
        aws_socket_close(socket);
        socket->connection_result_fn(socket, error_code, socket->connect_accept_user_data);
    }

    struct aws_allocator *allocator = socket_args->allocator;
    aws_mem_release(allocator, socket_args);
}

/* initiate an outbound tcp connection (client mode). */
static inline int s_tcp_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *connect_loop,
    struct sockaddr *bind_addr,
    struct sockaddr *socket_addr,
    size_t sock_size) {
    struct iocp_socket *socket_impl = socket->impl;
    socket->remote_endpoint = *remote_endpoint;

    int reuse = 1;
    if (setsockopt((SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(int))) {
        int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
        AWS_LOGF_WARN(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: setsockopt() call for enabling SO_REUSEADDR failed with WSAError %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            wsa_err);
        return aws_raise_error(s_determine_socket_error(wsa_err));
    }

    struct socket_connect_args *connect_args = aws_mem_calloc(socket->allocator, 1, sizeof(struct socket_connect_args));
    if (!connect_args) {
        socket->state = ERRORED;
        return AWS_OP_ERR;
    }

    connect_args->timeout_task.fn = s_handle_socket_timeout;
    connect_args->timeout_task.arg = connect_args;

    LPFN_CONNECTEX connect_fn = NULL;
    if (aws_socket_assign_to_event_loop(socket, connect_loop)) {
        socket->state = ERRORED;
        aws_mem_release(socket->allocator, connect_args);
        return AWS_OP_ERR;
    }

    connect_args->allocator = socket->allocator;
    connect_args->socket = socket;
    socket->state = CONNECTING;
    connect_fn = (LPFN_CONNECTEX)aws_winsock_get_connectex_fn();
    socket_impl->read_io_data->in_use = true;
    aws_overlapped_init(&socket_impl->read_io_data->signal, s_socket_connection_completion, connect_args);
    int fake_buffer = 0;
    socket_impl->connect_args = connect_args;
    BOOL connect_res = false;
    bind((SOCKET)socket->io_handle.data.handle, bind_addr, (int)sock_size);
    /* socket may be killed by the connection_completion callback inside of connect_fn, so copy out info
     * we need (allocator, event loop, timeout, etc), socket isn't safe to touch below connect_fn() */
    struct aws_allocator *allocator = socket->allocator;
    uint32_t connect_timeout_ms = socket->options.connect_timeout_ms;
    connect_res = connect_fn(
        (SOCKET)socket->io_handle.data.handle,
        socket_addr,
        (int)sock_size,
        &fake_buffer,
        0,
        NULL,
        aws_overlapped_to_windows_overlapped(&socket_impl->read_io_data->signal));

    uint64_t time_to_run = 0;
    /* if the connect succeeded immediately, let the timeout task still run, but it can run immediately. This is cleaner
       because it can just deallocate the memory we just allocated. */
    aws_event_loop_current_clock_time(connect_loop, &time_to_run);

    /* with IO completion ports, the overlapped callback triggers even if the operation succedded immediately,
       so we can just act like it's pending and the code path is the same.*/
    if (!connect_res) {
        int error_code = WSAGetLastError();
        if (error_code != ERROR_IO_PENDING) {
            AWS_LOGF_DEBUG(
                AWS_LS_IO_TLS,
                "id=%p handle=%p: connection error %d",
                (void *)socket,
                (void *)socket->io_handle.data.handle,
                error_code);
            socket_impl->connect_args = NULL;
            socket_impl->read_io_data->in_use = false;
            aws_mem_release(allocator, connect_args);
            int aws_err = s_determine_socket_error(error_code);
            return aws_raise_error(aws_err);
        }

        time_to_run += aws_timestamp_convert(connect_timeout_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    } else {
        /*add 500 ms just in case we're under heavy load*/
        time_to_run += aws_timestamp_convert(500, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: connection pending, scheduling timeout task",
        (void *)socket,
        (void *)socket->io_handle.data.handle);
    aws_event_loop_schedule_task_future(connect_loop, &connect_args->timeout_task, time_to_run);

    return AWS_OP_SUCCESS;
}

/* This should be called IMMEDIATELY after failure.
 * Otherwise, WSAGetLastError() could get cleared accidentally by a logging call */
static inline int s_convert_pton_error(int pton_err) {
    if (pton_err == 0) {
        return AWS_IO_SOCKET_INVALID_ADDRESS;
    }

    return s_determine_socket_error(WSAGetLastError());
}

/* initiate TCP ipv4 outbound connection. */
static int s_ipv4_stream_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *connect_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data) {
    AWS_ASSERT(connect_loop);
    AWS_ASSERT(on_connection_result);

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p handle=%p: beginning connect.", (void *)socket, (void *)socket->io_handle.data.handle);

    socket->connection_result_fn = on_connection_result;
    socket->connect_accept_user_data = user_data;
    struct sockaddr_in addr_in;
    AWS_ZERO_STRUCT(addr_in);
    int err = inet_pton(AF_INET, remote_endpoint->address, &(addr_in.sin_addr));

    if (err != 1) {
        int aws_err = s_convert_pton_error(err); /* call before logging or WSAError may get cleared */
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to parse address %s:%u.",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            remote_endpoint->address,
            remote_endpoint->port);
        return aws_raise_error(aws_err);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: connecting to endpoint %s:%u.",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        remote_endpoint->address,
        remote_endpoint->port);

    addr_in.sin_port = htons((uint16_t)remote_endpoint->port);
    addr_in.sin_family = AF_INET;

    /* stupid as hell, we have to bind first*/
    struct sockaddr_in in_bind_addr;
    AWS_ZERO_STRUCT(in_bind_addr);
    in_bind_addr.sin_family = AF_INET;
    in_bind_addr.sin_addr.s_addr = INADDR_ANY;
    in_bind_addr.sin_port = 0;

    return s_tcp_connect(
        socket,
        remote_endpoint,
        connect_loop,
        (struct sockaddr *)&in_bind_addr,
        (struct sockaddr *)&addr_in,
        sizeof(addr_in));
}

/* initiate TCP ipv6 outbound connection. */
static int s_ipv6_stream_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *connect_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data) {
    AWS_ASSERT(connect_loop);
    AWS_ASSERT(on_connection_result);

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p handle=%p: beginning connect.", (void *)socket, (void *)socket->io_handle.data.handle);

    if (socket->state != INIT) {
        socket->state = ERRORED;
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    socket->connection_result_fn = on_connection_result;
    socket->connect_accept_user_data = user_data;
    struct sockaddr_in6 bind_addr;
    AWS_ZERO_STRUCT(bind_addr);
    bind_addr.sin6_family = AF_INET6;
    bind_addr.sin6_port = 0;

    struct sockaddr_in6 addr_in6;
    AWS_ZERO_STRUCT(addr_in6);
    int pton_err = inet_pton(AF_INET6, remote_endpoint->address, &(addr_in6.sin6_addr));
    if (pton_err != 1) {
        int aws_err = s_convert_pton_error(pton_err); /* call before logging or WSAError may get cleared */
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to parse address %s:%u.",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            remote_endpoint->address,
            remote_endpoint->port);
        return aws_raise_error(aws_err);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: connecting to endpoint %s:%u.",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        remote_endpoint->address,
        remote_endpoint->port);

    addr_in6.sin6_port = htons((uint16_t)remote_endpoint->port);
    addr_in6.sin6_family = AF_INET6;

    return s_tcp_connect(
        socket,
        remote_endpoint,
        connect_loop,
        (struct sockaddr *)&bind_addr,
        (struct sockaddr *)&addr_in6,
        sizeof(addr_in6));
}

/* simply moves the connection_success notification into the event-loop's thread. */
static void s_connection_success_task(struct aws_task *task, void *arg, enum aws_task_status task_status) {
    (void)task;
    (void)task_status;

    struct io_operation_data *io_data = arg;

    if (!io_data->socket) {
        aws_mem_release(io_data->allocator, io_data);
        return;
    }

    io_data->sequential_task_storage.fn = NULL;
    io_data->sequential_task_storage.arg = NULL;
    io_data->in_use = false;

    struct aws_socket *socket = io_data->socket;
    struct iocp_socket *socket_impl = socket->impl;
    socket_impl->vtable->connection_success(socket);
}

/* initiate the client end of a named pipe. */
static int s_local_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *connect_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data) {
    AWS_ASSERT(connect_loop);
    AWS_ASSERT(on_connection_result);

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p handle=%p: beginning connect.", (void *)socket, (void *)socket->io_handle.data.handle);

    socket->connection_result_fn = on_connection_result;
    socket->connect_accept_user_data = user_data;

    if (s_process_tcp_sock_options(socket)) {
        socket->state = ERRORED;
        return AWS_OP_ERR;
    }

    struct iocp_socket *socket_impl = socket->impl;
    socket->remote_endpoint = *remote_endpoint;

    socket->io_handle.data.handle = CreateFileA(
        remote_endpoint->address,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL);

    if (socket->io_handle.data.handle != INVALID_HANDLE_VALUE) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: Successfully connected to named pipe %s.",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            remote_endpoint->address);

        if (aws_socket_assign_to_event_loop(socket, connect_loop)) {
            goto error;
        }

        socket_impl->read_io_data->sequential_task_storage.fn = s_connection_success_task;
        socket_impl->read_io_data->sequential_task_storage.arg = socket_impl->read_io_data;
        socket_impl->read_io_data->in_use = true;
        aws_event_loop_schedule_task_now(connect_loop, &socket_impl->read_io_data->sequential_task_storage);
        return AWS_OP_SUCCESS;
    }

error:;
    int win_error = GetLastError(); /* logging may reset error, so cache it */
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: failed to connect to named pipe %s.",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        remote_endpoint->address);
    socket->state = ERRORED;
    int aws_error = s_determine_socket_error(win_error);
    aws_raise_error(aws_error);
    return AWS_OP_ERR;
}

/* connect generic udp outbound */
static inline int s_dgram_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *connect_loop,
    struct sockaddr *socket_addr,
    size_t sock_size) {
    struct iocp_socket *socket_impl = socket->impl;
    socket->remote_endpoint = *remote_endpoint;

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: connecting to to %s:%u",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        remote_endpoint->address,
        remote_endpoint->port);

    int reuse = 1;
    if (setsockopt((SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(int))) {
        int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
        AWS_LOGF_WARN(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: setsockopt() call for enabling SO_REUSEADDR failed with WSAError %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            wsa_err);
        aws_raise_error(s_determine_socket_error(wsa_err));
        goto error;
    }

    int connect_err = connect((SOCKET)socket->io_handle.data.handle, socket_addr, (int)sock_size);

    if (connect_err) {
        int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: Failed to connect to %s:%u with error %d.",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            remote_endpoint->address,
            remote_endpoint->port,
            wsa_err);
        aws_raise_error(s_determine_socket_error(wsa_err));
        goto error;
    }

    if (s_update_local_endpoint_ipv4_ipv6(socket)) {
        goto error;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: local endpoint %s:%u",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        socket->local_endpoint.address,
        socket->local_endpoint.port);

    if (s_process_tcp_sock_options(socket)) {
        goto error;
    }
    socket->state = CONNECTED_READ | CONNECTED_WRITE;

    if (connect_loop) {
        if (aws_socket_assign_to_event_loop(socket, connect_loop)) {
            goto error;
        }

        socket_impl->read_io_data->sequential_task_storage.fn = s_connection_success_task;
        socket_impl->read_io_data->sequential_task_storage.arg = socket_impl->read_io_data;
        socket_impl->read_io_data->in_use = true;
        aws_event_loop_schedule_task_now(connect_loop, &socket_impl->read_io_data->sequential_task_storage);
    }

    return AWS_OP_SUCCESS;

error:
    socket->state = ERRORED;
    return AWS_OP_ERR;
}

static int s_ipv4_dgram_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *connect_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data) {
    (void)user_data;

    /* we don't actually care if it's null in this case. */
    socket->connection_result_fn = on_connection_result;
    socket->connect_accept_user_data = user_data;
    struct sockaddr_in addr_in;
    AWS_ZERO_STRUCT(addr_in);
    int pton_err = inet_pton(AF_INET, remote_endpoint->address, &(addr_in.sin_addr));
    if (pton_err != 1) {
        int aws_err = s_convert_pton_error(pton_err); /* call right after failure, so that WSAError isn't cleared */
        socket->state = ERRORED;
        return aws_raise_error(aws_err);
    }

    addr_in.sin_port = htons((uint16_t)remote_endpoint->port);
    addr_in.sin_family = AF_INET;

    return s_dgram_connect(socket, remote_endpoint, connect_loop, (struct sockaddr *)&addr_in, sizeof(addr_in));
}

static int s_ipv6_dgram_connect(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *connect_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data) {
    (void)user_data;

    /* we don't actually care if it's null in this case. */
    socket->connection_result_fn = on_connection_result;
    socket->connect_accept_user_data = user_data;
    struct sockaddr_in6 addr_in6;
    AWS_ZERO_STRUCT(addr_in6);
    int pton_err = inet_pton(AF_INET6, remote_endpoint->address, &(addr_in6.sin6_addr));

    if (pton_err != 1) {
        int aws_err = s_convert_pton_error(pton_err); /* call right after failure, so that WSAError isn't cleared */
        socket->state = ERRORED;
        return aws_raise_error(aws_err);
    }

    addr_in6.sin6_port = htons((uint16_t)remote_endpoint->port);
    addr_in6.sin6_family = AF_INET6;

    return s_dgram_connect(socket, remote_endpoint, connect_loop, (struct sockaddr *)&addr_in6, sizeof(addr_in6));
}

static inline int s_tcp_bind(struct aws_socket *socket, struct sockaddr *sock_addr, size_t sock_size) {

    /* set this option to prevent duplicate bind calls. */
    int exclusive_use_val = 1;
    if (setsockopt(
            (SOCKET)socket->io_handle.data.handle,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (char *)&exclusive_use_val,
            sizeof(int))) {
        int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
        AWS_LOGF_WARN(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: setsockopt() call for enabling SO_EXCLUSIVEADDRUSE failed with WSAError %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            wsa_err);
        aws_raise_error(s_determine_socket_error(wsa_err));
        goto error;
    }

    if (bind((SOCKET)socket->io_handle.data.handle, sock_addr, (int)sock_size) != 0) {
        int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: error binding. error %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            wsa_err);
        aws_raise_error(s_determine_socket_error(wsa_err));
        goto error;
    }

    if (s_update_local_endpoint_ipv4_ipv6(socket)) {
        goto error;
    }

    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: binding to tcp %s:%u",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        socket->local_endpoint.address,
        socket->local_endpoint.port);

    socket->state = BOUND;
    return AWS_OP_SUCCESS;

error:
    socket->state = ERRORED;
    return AWS_OP_ERR;
}

static int s_ipv4_stream_bind(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint) {
    struct sockaddr_in addr_in;
    AWS_ZERO_STRUCT(addr_in);
    int pton_err = inet_pton(AF_INET, local_endpoint->address, &(addr_in.sin_addr));

    if (pton_err != 1) {
        int aws_err = s_convert_pton_error(pton_err); /* call right after failure, so that WSAError isn't cleared */
        socket->state = ERRORED;
        return aws_raise_error(aws_err);
    }

    addr_in.sin_port = htons((uint16_t)local_endpoint->port);
    addr_in.sin_family = AF_INET;

    return s_tcp_bind(socket, (struct sockaddr *)&addr_in, sizeof(addr_in));
}

static int s_ipv6_stream_bind(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint) {
    struct sockaddr_in6 addr_in6;
    AWS_ZERO_STRUCT(addr_in6);
    int pton_err = inet_pton(AF_INET6, local_endpoint->address, &(addr_in6.sin6_addr));

    if (pton_err != 1) {
        int aws_err = s_convert_pton_error(pton_err); /* call right after failure, so that WSAError isn't cleared */
        socket->state = ERRORED;
        return aws_raise_error(aws_err);
    }

    addr_in6.sin6_port = htons((uint16_t)local_endpoint->port);
    addr_in6.sin6_family = AF_INET6;

    return s_tcp_bind(socket, (struct sockaddr *)&addr_in6, sizeof(addr_in6));
}

static inline int s_udp_bind(struct aws_socket *socket, struct sockaddr *sock_addr, size_t sock_size) {

    if (bind((SOCKET)socket->io_handle.data.handle, sock_addr, (int)sock_size) != 0) {
        int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: error binding. error %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            wsa_err);
        aws_raise_error(s_determine_socket_error(wsa_err));
        goto error;
    }

    if (s_update_local_endpoint_ipv4_ipv6(socket)) {
        goto error;
    }

    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: binding to udp %s:%u",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        socket->local_endpoint.address,
        socket->local_endpoint.port);

    socket->state = CONNECTED_READ;
    return AWS_OP_SUCCESS;

error:
    socket->state = ERRORED;
    return AWS_OP_ERR;
}

static int s_ipv4_dgram_bind(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint) {
    struct sockaddr_in addr_in;
    AWS_ZERO_STRUCT(addr_in);
    int pton_err = inet_pton(AF_INET, local_endpoint->address, &(addr_in.sin_addr));

    if (pton_err != 1) {
        int aws_err = s_convert_pton_error(pton_err); /* call right after failure, so that WSAError isn't cleared */
        socket->state = ERRORED;
        return aws_raise_error(aws_err);
    }

    addr_in.sin_port = htons((uint16_t)local_endpoint->port);
    addr_in.sin_family = AF_INET;

    return s_udp_bind(socket, (struct sockaddr *)&addr_in, sizeof(addr_in));
}

static int s_ipv6_dgram_bind(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint) {
    struct sockaddr_in6 addr_in6;
    AWS_ZERO_STRUCT(addr_in6);
    int pton_err = inet_pton(AF_INET6, local_endpoint->address, &(addr_in6.sin6_addr));

    if (pton_err != 1) {
        int aws_err = s_convert_pton_error(pton_err); /* call right after failure, so that WSAError isn't cleared */
        socket->state = ERRORED;
        return aws_raise_error(aws_err);
    }

    addr_in6.sin6_port = htons((uint16_t)local_endpoint->port);
    addr_in6.sin6_family = AF_INET6;

    return s_udp_bind(socket, (struct sockaddr *)&addr_in6, sizeof(addr_in6));
}

static int s_local_bind(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint) {
    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: binding to named pipe %s",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        local_endpoint->address);

    socket->local_endpoint = *local_endpoint;
    socket->io_handle.data.handle = CreateNamedPipeA(
        local_endpoint->address,
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
        PIPE_UNLIMITED_INSTANCES,
        PIPE_BUFFER_SIZE,
        PIPE_BUFFER_SIZE,
        0,
        NULL);

    if (socket->io_handle.data.handle != INVALID_HANDLE_VALUE) {
        socket->state = BOUND;
        return AWS_OP_SUCCESS;
    } else {
        int error_code = GetLastError(); /* logging may reset error, so cache it */
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to open named pipe %s with error %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            local_endpoint->address,
            error_code);

        socket->state = ERRORED;
        int aws_error = s_determine_socket_error(error_code);
        return aws_raise_error(aws_error);
    }
}

static int s_tcp_listen(struct aws_socket *socket, int backlog_size) {
    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: starting listen with backlog %d",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        backlog_size);
    int error_code = listen((SOCKET)socket->io_handle.data.handle, backlog_size);

    if (!error_code) {
        socket->state = LISTENING;
        return AWS_OP_SUCCESS;
    }

    error_code = GetLastError(); /* logging may reset error, so cache it */
    AWS_LOGF_ERROR(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: listen failed with error code %d",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        error_code);
    int aws_error = s_determine_socket_error(error_code);
    return aws_raise_error(aws_error);
}

static int s_udp_listen(struct aws_socket *socket, int backlog_size) {
    (void)socket;
    (void)backlog_size;
    return aws_raise_error(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE);
}

static int s_local_listen(struct aws_socket *socket, int backlog_size) {
    (void)socket;
    (void)backlog_size;
    if (AWS_UNLIKELY(socket->state != BOUND)) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    socket->state = LISTENING;
    return AWS_OP_SUCCESS;
}

/* triggered by the event loop upon an incoming pipe connection. */
static void s_incoming_pipe_connection_event(
    struct aws_event_loop *event_loop,
    struct aws_overlapped *overlapped,
    int status_code,
    size_t num_bytes_transferred) {
    (void)event_loop;
    (void)num_bytes_transferred;

    struct io_operation_data *operation_data = AWS_CONTAINER_OF(overlapped, struct io_operation_data, signal);
    struct aws_socket *socket = overlapped->user_data;

    if (!operation_data->socket) {
        aws_mem_release(operation_data->allocator, operation_data);
        return;
    }

    if (status_code == IO_OPERATION_CANCELLED) {
        operation_data->in_use = false;
        return;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: named-pipe listening event received",
        (void *)socket,
        (void *)socket->io_handle.data.handle);
    struct iocp_socket *socket_impl = socket->impl;

    if (status_code) {
        if (status_code == IO_PIPE_BROKEN) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: named-pipe is closed",
                (void *)socket,
                (void *)socket->io_handle.data.handle);
            aws_raise_error(AWS_IO_SOCKET_CLOSED);
            socket->state = CLOSED;
        } else {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: named-pipe error %d",
                (void *)socket,
                (void *)socket->io_handle.data.handle,
                (int)GetLastError());
            aws_raise_error(s_determine_socket_error(status_code));
            socket->state = ERRORED;
        }

        socket_impl->vtable->connection_error(socket, aws_last_error());
        operation_data->in_use = false;
        return;
    }

    bool continue_accept_loop = !socket_impl->stop_accept;

    do {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: incoming connection",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        struct aws_socket *new_socket = aws_mem_acquire(socket->allocator, sizeof(struct aws_socket));

        if (!new_socket) {
            socket->state = ERRORED;
            operation_data->in_use = false;
            socket_impl->vtable->connection_error(socket, AWS_ERROR_OOM);
            return;
        }

        if (s_socket_init(new_socket, socket->allocator, &socket->options, false)) {
            aws_mem_release(socket->allocator, new_socket);
            socket->state = ERRORED;
            operation_data->in_use = false;
            socket_impl->vtable->connection_error(socket, aws_last_error());
            return;
        }

        new_socket->state = CONNECTED_WRITE | CONNECTED_READ;

        /* Named pipes don't work like traditional socket APIs. The original handle is used
           for the incoming connection. so we copy it over and do some trickery with the
           event loop registrations. */
        new_socket->io_handle = socket->io_handle;
        aws_event_loop_unsubscribe_from_io_events(event_loop, &new_socket->io_handle);
        new_socket->event_loop = NULL;

        socket->io_handle.data.handle = CreateNamedPipeA(
            socket->local_endpoint.address,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            NULL);

        if (socket->io_handle.data.handle == INVALID_HANDLE_VALUE) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: error rebinding named pipe with error %d",
                (void *)socket,
                (void *)socket->io_handle.data.handle,
                (int)GetLastError());
            socket->state = ERRORED;
            operation_data->in_use = false;
            socket_impl->vtable->connection_error(socket, aws_last_error());
            return;
        }

        aws_overlapped_init(&socket_impl->read_io_data->signal, s_incoming_pipe_connection_event, socket);
        socket->event_loop = NULL;
        if (aws_socket_assign_to_event_loop(socket, event_loop)) {
            socket->state = ERRORED;
            operation_data->in_use = false;
            aws_socket_clean_up(new_socket);
            socket_impl->vtable->connection_error(socket, aws_last_error());
            return;
        }

        socket->accept_result_fn(socket, AWS_ERROR_SUCCESS, new_socket, socket->connect_accept_user_data);

        if (!operation_data->socket) {
            socket->state = ERRORED;
            operation_data->in_use = false;
            aws_mem_release(operation_data->allocator, operation_data);
            return;
        }

        socket_impl->read_io_data->in_use = true;
        BOOL res = ConnectNamedPipe(
            socket->io_handle.data.handle, aws_overlapped_to_windows_overlapped(&socket_impl->read_io_data->signal));

        continue_accept_loop = false;

        if (!res) {
            int error_code = GetLastError();
            if (error_code != ERROR_IO_PENDING && error_code != ERROR_PIPE_CONNECTED) {
                AWS_LOGF_ERROR(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: named-pipe connect failed with error %d",
                    (void *)socket,
                    (void *)socket->io_handle.data.handle,
                    error_code);
                socket->state = ERRORED;
                socket_impl->read_io_data->in_use = false;
                int aws_err = s_determine_socket_error(error_code);
                socket_impl->vtable->connection_error(socket, aws_err);
                return;
            } else if (error_code == ERROR_PIPE_CONNECTED) {
                continue_accept_loop = true;
            } else {
                AWS_LOGF_TRACE(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: no pending connections exiting accept loop.",
                    (void *)socket,
                    (void *)socket->io_handle.data.handle);
            }
        }
    } while (continue_accept_loop && !socket_impl->stop_accept);
}

static void s_tcp_accept_event(
    struct aws_event_loop *event_loop,
    struct aws_overlapped *overlapped,
    int status_code,
    size_t num_bytes_transferred);

static int s_socket_setup_accept(struct aws_socket *socket, struct aws_event_loop *accept_loop) {
    struct iocp_socket *socket_impl = socket->impl;
    socket_impl->incoming_socket = aws_mem_acquire(socket->allocator, sizeof(struct aws_socket));

    if (!socket_impl->incoming_socket) {
        return AWS_OP_ERR;
    }

    int err = s_socket_init(socket_impl->incoming_socket, socket->allocator, &socket->options, true);

    if (err) {
        socket->state = ERRORED;
        aws_socket_clean_up(socket_impl->incoming_socket);
        aws_mem_release(socket->allocator, socket_impl->incoming_socket);
        socket_impl->incoming_socket = NULL;
        return AWS_OP_ERR;
    }

    socket_impl->incoming_socket->local_endpoint = socket->local_endpoint;
    socket_impl->incoming_socket->state = INIT;

    if (accept_loop && aws_socket_assign_to_event_loop(socket, accept_loop)) {
        socket->state = ERRORED;
        aws_socket_clean_up(socket_impl->incoming_socket);
        aws_mem_release(socket->allocator, socket_impl->incoming_socket);
        socket_impl->incoming_socket = NULL;
        return AWS_OP_ERR;
    }

    aws_overlapped_init(&socket_impl->read_io_data->signal, s_tcp_accept_event, socket);

    LPFN_ACCEPTEX accept_fn = (LPFN_ACCEPTEX)aws_winsock_get_acceptex_fn();
    socket_impl->read_io_data->in_use = true;

    while (true) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: performing non-blocking accept",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        BOOL res = accept_fn(
            (SOCKET)socket->io_handle.data.handle,
            (SOCKET)socket_impl->incoming_socket->io_handle.data.handle,
            socket_impl->accept_buffer,
            0,
            SOCK_STORAGE_SIZE,
            SOCK_STORAGE_SIZE,
            NULL,
            aws_overlapped_to_windows_overlapped(&socket_impl->read_io_data->signal));

        if (!res) {
            int win_err = WSAGetLastError();
            if (win_err == ERROR_IO_PENDING) {
                AWS_LOGF_TRACE(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: no pending incoming connections, exiting loop.",
                    (void *)socket,
                    (void *)socket->io_handle.data.handle);
                return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
            } else if (AWS_UNLIKELY(win_err == WSAECONNRESET)) {
                continue;
            }

            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: accept failed with error %d",
                (void *)socket,
                (void *)socket->io_handle.data.handle,
                (int)win_err);
            socket->state = ERRORED;
            socket_impl->read_io_data->in_use = false;
            aws_mem_release(socket->allocator, socket_impl->incoming_socket);
            socket_impl->incoming_socket = NULL;
            int aws_err = s_determine_socket_error(win_err);
            return aws_raise_error(aws_err);
        }

        return AWS_OP_SUCCESS;
    }
}

/* invoked by the event loop when a listening socket has incoming connections. This is only used for TCP.*/
static void s_tcp_accept_event(
    struct aws_event_loop *event_loop,
    struct aws_overlapped *overlapped,
    int status_code,
    size_t num_bytes_transferred) {

    (void)event_loop;
    (void)num_bytes_transferred;

    struct io_operation_data *operation_data = AWS_CONTAINER_OF(overlapped, struct io_operation_data, signal);
    struct aws_socket *socket = overlapped->user_data;

    if (!operation_data->socket) {
        aws_mem_release(operation_data->allocator, operation_data);
        return;
    }

    if (status_code == IO_OPERATION_CANCELLED || status_code == WSAECONNRESET) {
        operation_data->in_use = false;
        return;
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: accept event triggered.",
        (void *)socket,
        (void *)socket->io_handle.data.handle);
    struct iocp_socket *socket_impl = socket->impl;

    if (!status_code && !socket_impl->stop_accept) {
        int err = AWS_OP_SUCCESS;

        do {
            socket_impl->incoming_socket->state = CONNECTED_WRITE | CONNECTED_READ;

            uint32_t port = 0;

            struct sockaddr_storage *in_addr = (struct sockaddr_storage *)socket_impl->accept_buffer;

            if (in_addr->ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)in_addr;
                port = ntohs(s->sin_port);
                /* the kernel created these, a.) they won't fail, b.) if they do it's not fatal. log it later. */
                InetNtopA(
                    AF_INET,
                    &s->sin_addr,
                    socket_impl->incoming_socket->remote_endpoint.address,
                    sizeof(socket_impl->incoming_socket->remote_endpoint.address));
                socket_impl->incoming_socket->options.domain = AWS_SOCKET_IPV4;
            } else if (in_addr->ss_family == AF_INET6) {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)in_addr;
                port = ntohs(s->sin6_port);
                /* the kernel created these, a.) they won't fail, b.) if they do it's not fatal. log it later. */
                InetNtopA(
                    AF_INET6,
                    &s->sin6_addr,
                    socket_impl->incoming_socket->remote_endpoint.address,
                    sizeof(socket_impl->incoming_socket->remote_endpoint.address));
                socket_impl->incoming_socket->options.domain = AWS_SOCKET_IPV6;
            }

            socket_impl->incoming_socket->remote_endpoint.port = port;
            AWS_LOGF_INFO(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: incoming connection accepted from %s:%u.",
                (void *)socket,
                (void *)socket->io_handle.data.handle,
                socket_impl->incoming_socket->remote_endpoint.address,
                port);

            u_long non_blocking = 1;
            ioctlsocket((SOCKET)socket_impl->incoming_socket->io_handle.data.handle, FIONBIO, &non_blocking);
            aws_socket_set_options(socket_impl->incoming_socket, &socket->options);

            struct aws_socket *incoming_socket = socket_impl->incoming_socket;
            socket_impl->incoming_socket = NULL;
            socket->accept_result_fn(socket, AWS_ERROR_SUCCESS, incoming_socket, socket->connect_accept_user_data);
            if (!operation_data->socket) {
                aws_mem_release(operation_data->allocator, operation_data);
                return;
            }

            socket_impl->incoming_socket = NULL;
            err = s_socket_setup_accept(socket, NULL);

            if (err) {
                if (aws_last_error() != AWS_IO_READ_WOULD_BLOCK) {
                    socket->state = ERRORED;
                    socket_impl->vtable->connection_error(socket, aws_last_error());
                }
                return;
            }
        } while (!err && !socket_impl->stop_accept);
    } else if (status_code) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: error occurred %d.",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            status_code);
        socket->state = ERRORED;
        int aws_error = s_determine_socket_error(status_code);
        aws_raise_error(aws_error);
        socket_impl->vtable->connection_error(socket, aws_error);
        operation_data->in_use = false;
    }
}

static int s_tcp_start_accept(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    aws_socket_on_accept_result_fn *on_accept_result,
    void *user_data) {
    AWS_ASSERT(accept_loop);
    AWS_ASSERT(on_accept_result);

    if (AWS_UNLIKELY(socket->state != LISTENING)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: invalid state for start_accept operation. You must call listen first.",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    if (AWS_UNLIKELY(socket->event_loop && socket->event_loop != accept_loop)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: is already assigned to event-loop %p.",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            (void *)socket->event_loop);
        return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
    }

    struct iocp_socket *socket_impl = socket->impl;

    if (!socket_impl->read_io_data) {
        socket_impl->read_io_data = aws_mem_calloc(socket->allocator, 1, sizeof(struct io_operation_data));
        if (!socket_impl->read_io_data) {
            socket->state = ERRORED;
            return AWS_OP_ERR;
        }
        socket_impl->read_io_data->allocator = socket->allocator;
        socket_impl->read_io_data->in_use = false;
        socket_impl->read_io_data->socket = socket;
    }

    socket->accept_result_fn = on_accept_result;
    socket->connect_accept_user_data = user_data;
    socket_impl->stop_accept = false;

    struct aws_event_loop *el_to_use = !socket->event_loop ? accept_loop : NULL;
    int err = s_socket_setup_accept(socket, el_to_use);

    if (!err || aws_last_error() == AWS_IO_READ_WOULD_BLOCK) {
        return AWS_OP_SUCCESS;
    }

    socket->state = ERRORED;
    return AWS_OP_ERR;
}

struct stop_accept_args {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_var;
    struct aws_socket *socket;
    bool invoked;
    int ret_code;
};

static bool s_stop_accept_predicate(void *arg) {
    struct stop_accept_args *stop_accept_args = arg;
    return stop_accept_args->invoked;
}

static int s_stream_stop_accept(struct aws_socket *socket);

static void s_stop_accept_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;

    struct stop_accept_args *stop_accept_args = arg;
    aws_mutex_lock(&stop_accept_args->mutex);
    stop_accept_args->ret_code = AWS_OP_SUCCESS;

    if (aws_socket_stop_accept(stop_accept_args->socket)) {
        stop_accept_args->ret_code = aws_last_error();
    }
    stop_accept_args->invoked = true;
    aws_condition_variable_notify_one(&stop_accept_args->condition_var);
    aws_mutex_unlock(&stop_accept_args->mutex);
}

static int s_stream_stop_accept(struct aws_socket *socket) {
    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: shutting down accept.",
        (void *)socket,
        (void *)socket->io_handle.data.handle);
    AWS_ASSERT(socket->event_loop);
    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        struct stop_accept_args args = {
            .mutex = AWS_MUTEX_INIT,
            .condition_var = AWS_CONDITION_VARIABLE_INIT,
            .socket = socket,
            .ret_code = AWS_OP_SUCCESS,
        };

        struct aws_task stop_accept_task = {
            .fn = s_stop_accept_task,
            .arg = &args,
        };

        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: accept is shutting down, but it was called outside the "
            " event-loop thread. Blocking waiting on shutdown",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        aws_mutex_lock(&args.mutex);
        aws_event_loop_schedule_task_now(socket->event_loop, &stop_accept_task);
        aws_condition_variable_wait_pred(&args.condition_var, &args.mutex, s_stop_accept_predicate, &args);
        aws_mutex_unlock(&args.mutex);
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: accept shutdown completed",
            (void *)socket,
            (void *)socket->io_handle.data.handle);

        if (args.ret_code) {
            socket->state = ERRORED;
            return aws_raise_error(args.ret_code);
        }

        return AWS_OP_SUCCESS;
    }

    struct iocp_socket *socket_impl = socket->impl;
    socket_impl->stop_accept = true;
    CancelIo(socket->io_handle.data.handle);

    if (!socket_impl->read_io_data && socket_impl->incoming_socket) {
        aws_socket_clean_up(socket_impl->incoming_socket);
        aws_mem_release(socket->allocator, socket_impl->incoming_socket);
        socket_impl->incoming_socket = NULL;
    }

    return AWS_OP_SUCCESS;
}

static void s_named_pipe_is_ridiculous_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)task;
    struct io_operation_data *io_data = args;

    if (!io_data->socket) {
        aws_mem_release(io_data->allocator, io_data);
        return;
    }

    if (status == AWS_TASK_STATUS_RUN_READY) {
        io_data->sequential_task_storage.fn = NULL;
        io_data->sequential_task_storage.arg = NULL;
        s_incoming_pipe_connection_event(io_data->socket->event_loop, &io_data->signal, AWS_OP_SUCCESS, 0);
    } else {
        io_data->in_use = false;
    }
}

static int s_local_start_accept(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    aws_socket_on_accept_result_fn *on_accept_result,
    void *user_data) {
    AWS_ASSERT(accept_loop);
    AWS_ASSERT(on_accept_result);

    if (AWS_UNLIKELY(socket->state != LISTENING)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: invalid state for start_accept operation. You must call listen first.",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    if (AWS_UNLIKELY(socket->event_loop && socket->event_loop != accept_loop)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: is already assigned to event-loop %p.",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            (void *)socket->event_loop);
        return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
    }

    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: is starting to accept incoming connections",
        (void *)socket,
        (void *)socket->io_handle.data.handle);
    struct iocp_socket *socket_impl = socket->impl;

    if (!socket_impl->read_io_data) {
        socket_impl->read_io_data = aws_mem_calloc(socket->allocator, 1, sizeof(struct io_operation_data));
        if (!socket_impl->read_io_data) {
            socket->state = ERRORED;
            return AWS_OP_ERR;
        }
        socket_impl->read_io_data->allocator = socket->allocator;
        socket_impl->read_io_data->in_use = false;
        socket_impl->read_io_data->socket = socket;
    }

    socket->accept_result_fn = on_accept_result;
    socket->connect_accept_user_data = user_data;
    socket_impl->stop_accept = false;
    aws_overlapped_init(&socket_impl->read_io_data->signal, s_incoming_pipe_connection_event, socket);
    socket_impl->read_io_data->in_use = true;

    if (!socket->event_loop && aws_socket_assign_to_event_loop(socket, accept_loop)) {
        socket_impl->read_io_data->in_use = false;
        socket->state = ERRORED;
        return AWS_OP_ERR;
    }

    BOOL res = ConnectNamedPipe(
        socket->io_handle.data.handle, aws_overlapped_to_windows_overlapped(&socket_impl->read_io_data->signal));

    if (!res) {
        int error_code = GetLastError();
        if (error_code != ERROR_IO_PENDING && error_code != ERROR_PIPE_CONNECTED) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: ConnectNamedPipe() failed with error %d.",
                (void *)socket,
                (void *)socket->io_handle.data.handle,
                error_code);
            socket->state = ERRORED;
            socket_impl->read_io_data->in_use = false;
            int aws_err = s_determine_socket_error(error_code);
            return aws_raise_error(aws_err);
        } else if (error_code == ERROR_PIPE_CONNECTED) {
            AWS_LOGF_TRACE(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: Pipe connected immediately, scheduling task for setup.",
                (void *)socket,
                (void *)socket->io_handle.data.handle,
                error_code);
            /* There will be no IO-completion event in the case of ERROR_PIPE_CONNECTED,
            so schedule a task to finish the connection */
            socket_impl->read_io_data->sequential_task_storage.fn = s_named_pipe_is_ridiculous_task;
            socket_impl->read_io_data->sequential_task_storage.arg = socket_impl->read_io_data;
            aws_event_loop_schedule_task_now(socket->event_loop, &socket_impl->read_io_data->sequential_task_storage);
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_dgram_start_accept(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    aws_socket_on_accept_result_fn *on_accept_result,
    void *user_data) {
    (void)socket;
    (void)accept_loop;
    (void)on_accept_result;
    (void)user_data;
    return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
}

static int s_dgram_stop_accept(struct aws_socket *socket) {
    (void)socket;
    return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
}

int aws_socket_set_options(struct aws_socket *socket, const struct aws_socket_options *options) {
    if (socket->options.domain != options->domain || socket->options.type != options->type) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: setting socket options to: keep-alive %d, keep idle %d, keep-alive interval %d, max failed "
        "probe count %d",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        (int)options->keepalive,
        (int)options->keep_alive_timeout_sec,
        (int)options->keep_alive_interval_sec,
        (int)options->keep_alive_max_failed_probes);

    socket->options = *options;

    if (socket->options.domain != AWS_SOCKET_LOCAL && socket->options.type == AWS_SOCKET_STREAM) {
        if (socket->options.keepalive &&
            !(socket->options.keep_alive_interval_sec && socket->options.keep_alive_timeout_sec)) {
            int keep_alive = 1;
            if (setsockopt(
                    (SOCKET)socket->io_handle.data.handle,
                    SOL_SOCKET,
                    SO_KEEPALIVE,
                    (char *)&keep_alive,
                    sizeof(int))) {
                int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
                AWS_LOGF_WARN(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: setsockopt() call for enabling keep-alive failed with WSAError %d",
                    (void *)socket,
                    (void *)socket->io_handle.data.handle,
                    wsa_err);
            }
        } else if (socket->options.keepalive) {
            ULONG keep_alive_timeout = (ULONG)aws_timestamp_convert(
                socket->options.keep_alive_timeout_sec, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL);
            ULONG keep_alive_interval = (ULONG)aws_timestamp_convert(
                socket->options.keep_alive_interval_sec, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_MILLIS, NULL);
            struct tcp_keepalive keepalive_args = {
                .onoff = 1,
                .keepalivetime = keep_alive_timeout,
                .keepaliveinterval = keep_alive_interval,
            };
            DWORD bytes_returned = 0;
            if (WSAIoctl(
                    (SOCKET)socket->io_handle.data.handle,
                    SIO_KEEPALIVE_VALS,
                    &keepalive_args,
                    sizeof(keepalive_args),
                    NULL,
                    0,
                    &bytes_returned,
                    NULL,
                    NULL)) {
                int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
                AWS_LOGF_WARN(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: WSAIoctl() call for setting keep-alive values failed with WSAError %d",
                    (void *)socket,
                    (void *)socket->io_handle.data.handle,
                    wsa_err);
            }
        }
/* this is only available in Windows 10 1703 and later. It doesn't, matter if this runs on an older version
   the call will just fail, no harm done.*/
#ifdef TCP_KEEPCNT
        if (socket->options.keep_alive_max_failed_probes) {
            DWORD max_probes = socket->options.keep_alive_max_failed_probes;
            if (setsockopt(
                    (SOCKET)socket->io_handle.data.handle,
                    IPPROTO_TCP,
                    TCP_KEEPCNT,
                    (char *)&max_probes,
                    sizeof(max_probes))) {
                int wsa_err = WSAGetLastError(); /* logging may reset error, so cache it */
                AWS_LOGF_WARN(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: setsockopt() call for setting keep-alive probe count value failed with WSAError "
                    "%d. This likely"
                    " isn't a problem. It's more likely you're on an old version of windows. This feature was added in "
                    "Windows 10 1703",
                    (void *)socket,
                    (void *)socket->io_handle.data.handle,
                    wsa_err);
            }
        }
#endif
    }

    return AWS_OP_SUCCESS;
}

struct close_args {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_var;
    struct aws_socket *socket;
    bool invoked;
    int ret_code;
};

static bool s_close_predicate(void *arg) {
    struct close_args *close_args = arg;
    return close_args->invoked;
}

static int s_socket_close(struct aws_socket *socket);

static void s_close_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct close_args *close_args = arg;
    aws_mutex_lock(&close_args->mutex);
    close_args->ret_code = AWS_OP_SUCCESS;

    /* since the task is canceled the event-loop is gone and the iocp will not trigger, so go ahead
       and tell the socket cleanup stuff that the iocp handle is no longer pending operations. */
    if (status == AWS_TASK_STATUS_CANCELED) {
        struct iocp_socket *iocp_socket = close_args->socket->impl;
        iocp_socket->read_io_data->in_use = false;
    }

    if (aws_socket_close(close_args->socket)) {
        close_args->ret_code = aws_last_error();
    }
    close_args->invoked = true;
    aws_condition_variable_notify_one(&close_args->condition_var);
    aws_mutex_unlock(&close_args->mutex);
}

static int s_wait_on_close(struct aws_socket *socket) {
    AWS_ASSERT(socket->event_loop);

    /* don't freak out on me, this almost never happens, and never occurs inside a channel
    * it only gets hit from a listening socket shutting down or from a unit test.
       the only time we allow this kind of thing is when you're a listener.*/
    if (socket->state != LISTENING) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    void *handle_for_logging = socket->io_handle.data.handle; /* socket's handle gets reset before final log */
    (void)handle_for_logging;

    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: closing from a different thread than "
        "the socket is running from. Blocking until it closes down.",
        (void *)socket,
        handle_for_logging);

    struct close_args args = {
        .mutex = AWS_MUTEX_INIT,
        .condition_var = AWS_CONDITION_VARIABLE_INIT,
        .socket = socket,
        .ret_code = AWS_OP_SUCCESS,
    };

    struct aws_task close_task = {
        .fn = s_close_task,
        .arg = &args,
    };

    aws_mutex_lock(&args.mutex);
    aws_event_loop_schedule_task_now(socket->event_loop, &close_task);
    aws_condition_variable_wait_pred(&args.condition_var, &args.mutex, s_close_predicate, &args);
    aws_mutex_unlock(&args.mutex);
    AWS_LOGF_INFO(AWS_LS_IO_SOCKET, "id=%p handle=%p: close task completed.", (void *)socket, handle_for_logging);

    if (args.ret_code) {
        return aws_raise_error(args.ret_code);
    }

    return AWS_OP_SUCCESS;
}

static int s_socket_close(struct aws_socket *socket) {
    struct iocp_socket *socket_impl = socket->impl;
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p handle=%p: closing", (void *)socket, (void *)socket->io_handle.data.handle);

    if (socket->event_loop) {
        if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
            return s_wait_on_close(socket);
        }

        if (socket->state & LISTENING && !socket_impl->stop_accept) {
            aws_socket_stop_accept(socket);
        }
    }

    if (socket_impl->connect_args) {
        socket_impl->connect_args->socket = NULL;
        socket_impl->connect_args = NULL;
    }

    if (socket_impl->read_io_data && socket_impl->read_io_data->in_use) {
        socket_impl->read_io_data->socket = NULL;
        socket_impl->read_io_data = NULL;
    } else if (socket_impl->read_io_data) {
        aws_mem_release(socket->allocator, socket_impl->read_io_data);
        socket_impl->read_io_data = NULL;
    }

    if (socket->io_handle.data.handle != INVALID_HANDLE_VALUE) {
        shutdown((SOCKET)socket->io_handle.data.handle, SD_BOTH);
        closesocket((SOCKET)socket->io_handle.data.handle);
        socket->io_handle.data.handle = INVALID_HANDLE_VALUE;
    }

    socket->state = CLOSED;

    while (!aws_linked_list_empty(&socket_impl->pending_io_operations)) {
        struct aws_linked_list_node *node = aws_linked_list_front(&socket_impl->pending_io_operations);
        struct io_operation_data *op_data = AWS_CONTAINER_OF(node, struct io_operation_data, node);
        op_data->socket = NULL;
        aws_linked_list_pop_front(&socket_impl->pending_io_operations);
    }

    socket->event_loop = NULL;

    return AWS_OP_SUCCESS;
}

static int s_local_close(struct aws_socket *socket) {
    struct iocp_socket *socket_impl = socket->impl;
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p handle=%p: closing", (void *)socket, (void *)socket->io_handle.data.handle);

    if (socket->event_loop) {
        if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
            return s_wait_on_close(socket);
        }
    }

    if (socket_impl->connect_args) {
        socket_impl->connect_args->socket = NULL;
        socket_impl->connect_args = NULL;
    }

    if (socket_impl->read_io_data && socket_impl->read_io_data->in_use) {
        socket_impl->read_io_data->socket = NULL;
        socket_impl->read_io_data = NULL;
    } else if (socket_impl->read_io_data) {
        aws_mem_release(socket->allocator, socket_impl->read_io_data);
        socket_impl->read_io_data = NULL;
    }

    if (socket->io_handle.data.handle != INVALID_HANDLE_VALUE) {
        CloseHandle(socket->io_handle.data.handle);
        socket->io_handle.data.handle = INVALID_HANDLE_VALUE;
    }

    socket->state = CLOSED;

    while (!aws_linked_list_empty(&socket_impl->pending_io_operations)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&socket_impl->pending_io_operations);
        struct io_operation_data *op_data = AWS_CONTAINER_OF(node, struct io_operation_data, node);

        op_data->socket = NULL;
    }

    return AWS_OP_SUCCESS;
}

int aws_socket_half_close(struct aws_socket *socket, enum aws_channel_direction dir) {
    int how = dir == AWS_CHANNEL_DIR_READ ? 0 : 1;

    struct iocp_socket *socket_impl = socket->impl;
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: shutting down in direction %d",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        dir);
    if (shutdown((SOCKET)socket->io_handle.data.handle, how)) {
        int error = WSAGetLastError();
        int aws_error = s_determine_socket_error(error);
        aws_raise_error(aws_error);
        socket_impl->vtable->connection_error(socket, aws_error);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

struct aws_io_handle *aws_socket_get_io_handle(struct aws_socket *socket) {
    return &socket->io_handle;
}

int aws_socket_assign_to_event_loop(struct aws_socket *socket, struct aws_event_loop *event_loop) {
    if (socket->event_loop) {
        return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
    }

    socket->event_loop = event_loop;
    return aws_event_loop_connect_handle_to_io_completion_port(event_loop, &socket->io_handle);
}

struct aws_event_loop *aws_socket_get_event_loop(struct aws_socket *socket) {
    return socket->event_loop;
}

struct read_cb_args {
    struct aws_socket *socket;
    aws_socket_on_readable_fn *user_callback;
    void *user_data;
};

/* invoked by the event loop when the socket (TCP or Local) becomes readable. */
static void s_stream_readable_event(
    struct aws_event_loop *event_loop,
    struct aws_overlapped *overlapped,
    int status_code,
    size_t num_bytes_transferred) {
    (void)num_bytes_transferred;
    (void)event_loop;

    struct io_operation_data *operation_data = AWS_CONTAINER_OF(overlapped, struct io_operation_data, signal);
    struct aws_socket *socket = overlapped->user_data;

    if (!operation_data->socket) {
        aws_mem_release(operation_data->allocator, operation_data);
        return;
    }

    if (status_code == WSA_OPERATION_ABORTED || status_code == IO_OPERATION_CANCELLED) {
        return;
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: socket readable event triggered",
        (void *)socket,
        (void *)socket->io_handle.data.handle);
    struct iocp_socket *socket_impl = socket->impl;
    socket->state = socket->state & ~CONNECTED_WAITING_ON_READABLE;

    int err_code = AWS_OP_SUCCESS;
    if (status_code && status_code != ERROR_IO_PENDING) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: socket status error %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            status_code);
        err_code = s_determine_socket_error(status_code);
        if (err_code == AWS_IO_SOCKET_CLOSED) {
            socket->state = CLOSED;
        } else {
            socket->state = ERRORED;
        }
    }

    socket->readable_fn(socket, err_code, socket->readable_user_data);

    if (operation_data->socket && socket_impl->read_io_data) {
        /* recursion and what not.... what if someone calls read from the callback
           until it says, HEY I'm out of data, then they toggle this flag? So check that
           they didn't go back into the CONNECTED_WAITING_ON_READABLE before clearing this flag. */
        if (!(socket->state & CONNECTED_WAITING_ON_READABLE)) {
            socket_impl->read_io_data->in_use = false;
        }
    }

    if (!operation_data->socket) {
        aws_mem_release(operation_data->allocator, operation_data);
        return;
    }
}

/* Invoked by the event loop when a UDP socket goes readable. */
static void s_dgram_readable_event(
    struct aws_event_loop *event_loop,
    struct aws_overlapped *overlapped,
    int status_code,
    size_t num_bytes_transferred) {
    (void)num_bytes_transferred;
    (void)event_loop;

    struct io_operation_data *operation_data = AWS_CONTAINER_OF(overlapped, struct io_operation_data, signal);
    struct aws_socket *socket = overlapped->user_data;

    if (!operation_data->socket) {
        aws_mem_release(operation_data->allocator, operation_data);
        return;
    }

    if (status_code == WSA_OPERATION_ABORTED || status_code == IO_OPERATION_CANCELLED) {
        return;
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: socket readable event triggered",
        (void *)socket,
        (void *)socket->io_handle.data.handle);
    struct iocp_socket *socket_impl = socket->impl;
    socket->state = socket->state & ~CONNECTED_WAITING_ON_READABLE;

    int err_code = AWS_OP_SUCCESS;
    /* IO_STATUS_BUFFER_OVERFLOW we did a peek on a zero buffer size.... this is fine
        we just wanted to know we're readable. */
    if (status_code != ERROR_IO_PENDING && status_code != IO_STATUS_BUFFER_OVERFLOW) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: socket status error %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            status_code);
        err_code = s_determine_socket_error(status_code);
        if (err_code == AWS_IO_SOCKET_CLOSED) {
            socket->state = CLOSED;
        } else {
            socket->state = ERRORED;
        }
    }

    socket->readable_fn(socket, err_code, socket->readable_user_data);

    if (operation_data->socket && socket_impl->read_io_data) {
        /* recursion and what not.... what if someone calls read from the callback
        until it says, HEY I'm out of data, then they toggle this flag? So check that
        they didn't go back into the CONNECTED_WAITING_ON_READABLE before clearing this flag. */
        if (!(socket->state & CONNECTED_WAITING_ON_READABLE)) {
            socket_impl->read_io_data->in_use = false;
        }
    }

    if (!operation_data->socket) {
        aws_mem_release(operation_data->allocator, operation_data);
        return;
    }
}

static int s_stream_subscribe_to_read(
    struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable,
    void *user_data) {
    socket->readable_fn = on_readable;
    socket->readable_user_data = user_data;

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: subscribing to readable event",
        (void *)socket,
        (void *)socket->io_handle.data.handle);

    struct iocp_socket *iocp_socket = socket->impl;
    iocp_socket->read_io_data->in_use = true;
    aws_overlapped_init(&iocp_socket->read_io_data->signal, s_stream_readable_event, socket);

    int fake_buffer = 0;
    socket->state |= CONNECTED_WAITING_ON_READABLE;
    BOOL success = ReadFile(
        socket->io_handle.data.handle,
        &fake_buffer,
        0,
        NULL,
        aws_overlapped_to_windows_overlapped(&iocp_socket->read_io_data->signal));
    if (!success) {
        int win_err = GetLastError();
        if (win_err != ERROR_IO_PENDING) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: socket ReadFile() failed with error %d",
                (void *)socket,
                (void *)socket->io_handle.data.handle,
                win_err);
            iocp_socket->read_io_data->in_use = false;
            socket->state &= ~CONNECTED_WAITING_ON_READABLE;

            int aws_error = s_determine_socket_error(win_err);
            if (aws_error == AWS_IO_SOCKET_CLOSED) {
                socket->state = CLOSED;
            } else {
                socket->state = ERRORED;
            }
            return aws_raise_error(aws_error);
        }
    }
    return AWS_OP_SUCCESS;
}

static int s_dgram_subscribe_to_read(
    struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable,
    void *user_data) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: subscribing to readable event",
        (void *)socket,
        (void *)socket->io_handle.data.handle);
    socket->readable_fn = on_readable;
    socket->readable_user_data = user_data;

    struct iocp_socket *iocp_socket = socket->impl;
    iocp_socket->read_io_data->in_use = true;
    aws_overlapped_init(&iocp_socket->read_io_data->signal, s_dgram_readable_event, socket);

    socket->state |= CONNECTED_WAITING_ON_READABLE;
    /* the zero byte read trick with ReadFile doesn't actually work for UDP because it actually
       clears the buffer from the kernel, but if we use WSARecv, we can tell it we just want to peek
       which won't clear the kernel buffers. Giving a BS buffer with 0 len seems to do the trick. */
    WSABUF buf = {
        .len = 0,
        .buf = NULL,
    };
    DWORD flags = MSG_PEEK;
    int err = WSARecv(
        (SOCKET)socket->io_handle.data.handle,
        &buf,
        1,
        NULL,
        &flags,
        aws_overlapped_to_windows_overlapped(&iocp_socket->read_io_data->signal),
        NULL);

    if (err) {
        int wsa_err = WSAGetLastError();
        if (wsa_err != ERROR_IO_PENDING) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: socket WSARecv() failed with error %d",
                (void *)socket,
                (void *)socket->io_handle.data.handle,
                wsa_err);
            iocp_socket->read_io_data->in_use = false;
            int aws_error = s_determine_socket_error(wsa_err);
            if (aws_error == AWS_IO_SOCKET_CLOSED) {
                socket->state = CLOSED;
            } else {
                socket->state = ERRORED;
            }
            return aws_raise_error(aws_error);
        }
    }
    return AWS_OP_SUCCESS;
}

static int s_local_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: reading from named pipe",
        (void *)socket,
        (void *)socket->io_handle.data.handle);

    DWORD bytes_available = 0;
    BOOL peek_success = PeekNamedPipe(socket->io_handle.data.handle, NULL, 0, NULL, &bytes_available, NULL);

    if (!peek_success) {
        int error_code = GetLastError();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: PeekNamedPipe() failed with error %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            error_code);
        return aws_raise_error(s_determine_socket_error(error_code));
    }

    if (!bytes_available) {
        if (!(socket->state & CONNECTED_WAITING_ON_READABLE)) {
            struct iocp_socket *iocp_socket = socket->impl;
            socket->state |= CONNECTED_WAITING_ON_READABLE;
            iocp_socket->read_io_data->in_use = true;
            aws_overlapped_init(&iocp_socket->read_io_data->signal, s_stream_readable_event, socket);
            int fake_buffer = 0;
            BOOL success = ReadFile(
                socket->io_handle.data.handle,
                &fake_buffer,
                0,
                NULL,
                aws_overlapped_to_windows_overlapped(&iocp_socket->read_io_data->signal));
            if (!success) {
                int win_err = GetLastError();
                if (win_err != ERROR_IO_PENDING) {
                    AWS_LOGF_ERROR(
                        AWS_LS_IO_SOCKET,
                        "id=%p handle=%p: ReadFile() failed with error %d",
                        (void *)socket,
                        (void *)socket->io_handle.data.handle,
                        win_err);
                    iocp_socket->read_io_data->in_use = false;
                    int aws_error = s_determine_socket_error(win_err);
                    if (aws_error == AWS_IO_SOCKET_CLOSED) {
                        socket->state = CLOSED;
                    } else {
                        socket->state = ERRORED;
                    }
                    return aws_raise_error(aws_error);
                }
            }
        }

        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read would block, returning",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: %u bytes available for read.",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        bytes_available);
    DWORD bytes_read = 0;
    size_t read_capacity = buffer->capacity - buffer->len;
    DWORD bytes_to_read = (DWORD)(bytes_available > read_capacity ? read_capacity : bytes_available);
    BOOL read_success =
        ReadFile(socket->io_handle.data.handle, buffer->buffer + buffer->len, bytes_to_read, &bytes_read, NULL);

    if (!read_success) {
        int error_code = GetLastError();
        int aws_error = s_determine_socket_error(error_code);
        if (aws_error == AWS_IO_SOCKET_CLOSED) {
            socket->state = CLOSED;
        } else {
            socket->state = ERRORED;
        }
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: socket ReadFile() failed with error %d",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            error_code);
        return aws_raise_error(aws_error);
    }

    *amount_read = bytes_read;
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: successfully read %u bytes.",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        bytes_read);
    buffer->len += bytes_read;
    return AWS_OP_SUCCESS;
}

static int s_tcp_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: reading from socket",
        (void *)socket,
        (void *)socket->io_handle.data.handle);

    int read_val = recv(
        (SOCKET)socket->io_handle.data.handle,
        (char *)buffer->buffer + buffer->len,
        (int)(buffer->capacity - buffer->len),
        0);

    if (read_val > 0) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read %d bytes from socket",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            read_val);
        *amount_read = (size_t)read_val;
        buffer->len += *amount_read;
        return AWS_OP_SUCCESS;
    }

    if (read_val == 0) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: socket closed gracefully",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        socket->state = CLOSED;
        return aws_raise_error(AWS_IO_SOCKET_CLOSED);
    }

    int error = WSAGetLastError();

    if (error == WSAEWOULDBLOCK) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read would block, scheduling 0 byte read and returning",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        if (!(socket->state & CONNECTED_WAITING_ON_READABLE)) {
            struct iocp_socket *iocp_socket = socket->impl;
            socket->state |= CONNECTED_WAITING_ON_READABLE;
            iocp_socket->read_io_data->in_use = true;
            aws_overlapped_init(&iocp_socket->read_io_data->signal, s_stream_readable_event, socket);
            int fake_buffer = 0;
            BOOL success = ReadFile(
                socket->io_handle.data.handle,
                &fake_buffer,
                0,
                NULL,
                aws_overlapped_to_windows_overlapped(&iocp_socket->read_io_data->signal));
            if (!success) {
                int win_err = GetLastError();
                if (win_err != ERROR_IO_PENDING) {
                    AWS_LOGF_ERROR(
                        AWS_LS_IO_SOCKET,
                        "id=%p handle=%p: ReadFile() for 0 byte read failed with error %d",
                        (void *)socket,
                        (void *)socket->io_handle.data.handle,
                        win_err);
                    iocp_socket->read_io_data->in_use = false;
                    int aws_error = s_determine_socket_error(win_err);
                    if (aws_error == AWS_IO_SOCKET_CLOSED) {
                        socket->state = CLOSED;
                    } else {
                        socket->state = ERRORED;
                    }
                    return aws_raise_error(aws_error);
                }
            }
        }

        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    if (error == EPIPE) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET, "id=%p handle=%p: socket closed", (void *)socket, (void *)socket->io_handle.data.handle);
        socket->state = CLOSED;
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    AWS_LOGF_ERROR(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: recv() failed with error %d",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        error);
    return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
}

static int s_dgram_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: reading from socket",
        (void *)socket,
        (void *)socket->io_handle.data.handle);
    int read_val = recv(
        (SOCKET)socket->io_handle.data.handle,
        (char *)buffer->buffer + buffer->len,
        (int)(buffer->capacity - buffer->len),
        0);

    if (read_val > 0) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read %d bytes from socket",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            read_val);
        *amount_read = (size_t)read_val;
        buffer->len += *amount_read;
        return AWS_OP_SUCCESS;
    }

    if (read_val == 0) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: socket closed gracefully",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        socket->state = CLOSED;
        return aws_raise_error(AWS_IO_SOCKET_CLOSED);
    }

    int error = WSAGetLastError();

    if (error == WSAEWOULDBLOCK) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read would block, scheduling 0 byte read and returning",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        if (!(socket->state & CONNECTED_WAITING_ON_READABLE)) {
            struct iocp_socket *iocp_socket = socket->impl;
            socket->state |= CONNECTED_WAITING_ON_READABLE;
            iocp_socket->read_io_data->in_use = true;
            aws_overlapped_init(&iocp_socket->read_io_data->signal, s_stream_readable_event, socket);
            /* the zero byte read trick with ReadFile doesn't actually work for UDP because it actually
            clears the buffer from the kernel, but if we use WSARecv, we can tell it we just want to peek
            which won't clear the kernel buffers. Giving it a BS buffer with 0 len seems to do the trick. */
            WSABUF buf = {
                .len = 0,
                .buf = NULL,
            };

            DWORD flags = MSG_PEEK;
            int err = WSARecv(
                (SOCKET)socket->io_handle.data.handle,
                &buf,
                1,
                NULL,
                &flags,
                aws_overlapped_to_windows_overlapped(&iocp_socket->read_io_data->signal),
                NULL);
            if (err) {
                int wsa_err = WSAGetLastError();
                if (wsa_err != ERROR_IO_PENDING) {
                    AWS_LOGF_ERROR(
                        AWS_LS_IO_SOCKET,
                        "id=%p handle=%p: WSARecv() for 0 byte read failed with error %d",
                        (void *)socket,
                        (void *)socket->io_handle.data.handle,
                        wsa_err);
                    iocp_socket->read_io_data->in_use = false;
                    int aws_error = s_determine_socket_error(wsa_err);
                    if (aws_error == AWS_IO_SOCKET_CLOSED) {
                        socket->state = CLOSED;
                    } else {
                        socket->state = ERRORED;
                    }

                    return aws_raise_error(aws_error);
                }
            }
        }

        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    if (error == EPIPE) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET, "id=%p handle=%p: socket closed", (void *)socket, (void *)socket->io_handle.data.handle);
        socket->state = CLOSED;
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    AWS_LOGF_ERROR(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: recv() failed with error %d",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        error);
    return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
}

struct write_cb_args {
    struct io_operation_data io_data;
    size_t original_buffer_len;
    aws_socket_on_write_completed_fn *user_callback;
    void *user_data;
};

/* Invoked for TCP, UDP, and Local when a message has been completely written to the wire.*/
static void s_socket_written_event(
    struct aws_event_loop *event_loop,
    struct aws_overlapped *overlapped,
    int status_code,
    size_t num_bytes_transferred) {
    (void)event_loop;
    (void)num_bytes_transferred;

    struct io_operation_data *operation_data = AWS_CONTAINER_OF(overlapped, struct io_operation_data, signal);
    struct write_cb_args *write_cb_args = overlapped->user_data;
    struct aws_socket *socket = operation_data->socket;
    int aws_error_code = status_code ? s_determine_socket_error(status_code) : AWS_OP_SUCCESS;

    if (aws_error_code) {
        aws_raise_error(aws_error_code);
    }

    if (!socket) {
        void *user_data = write_cb_args->user_data;
        aws_socket_on_write_completed_fn *callback = write_cb_args->user_callback;
        callback(NULL, aws_error_code, num_bytes_transferred, user_data);
        aws_mem_release(operation_data->allocator, write_cb_args);
        return;
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: Write Completion callback triggered",
        (void *)socket,
        (void *)socket->io_handle.data.handle);

    if (status_code) {
        if (aws_error_code == AWS_IO_SOCKET_CLOSED) {
            socket->state = CLOSED;
        } else {
            socket->state = ERRORED;
        }
    } else {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: Write of size %llu completed",
            (void *)socket,
            (void *)socket->io_handle.data.handle,
            (unsigned long long)num_bytes_transferred);
        AWS_ASSERT(num_bytes_transferred == write_cb_args->original_buffer_len);
    }

    aws_linked_list_remove(&operation_data->node);

    void *user_data = write_cb_args->user_data;
    aws_socket_on_write_completed_fn *callback = write_cb_args->user_callback;
    callback(operation_data->socket, aws_error_code, num_bytes_transferred, user_data);

    aws_mem_release(operation_data->allocator, write_cb_args);
}

int aws_socket_write(
    struct aws_socket *socket,
    const struct aws_byte_cursor *cursor,
    aws_socket_on_write_completed_fn *written_fn,
    void *user_data) {
    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (!(socket->state & CONNECTED_WRITE)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot write to because it is not connected",
            (void *)socket,
            (void *)socket->io_handle.data.handle);
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    struct write_cb_args *write_cb_data = aws_mem_calloc(socket->allocator, 1, sizeof(struct write_cb_args));
    if (!write_cb_data) {
        socket->state = ERRORED;
        return AWS_OP_ERR;
    }

    write_cb_data->user_callback = written_fn;
    write_cb_data->user_data = user_data;
    write_cb_data->original_buffer_len = cursor->len;
    write_cb_data->io_data.allocator = socket->allocator;
    write_cb_data->io_data.in_use = true;
    write_cb_data->io_data.socket = socket;

    aws_overlapped_init(&write_cb_data->io_data.signal, s_socket_written_event, write_cb_data);
    struct iocp_socket *socket_impl = socket->impl;

    aws_linked_list_push_back(&socket_impl->pending_io_operations, &write_cb_data->io_data.node);
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: queueing write of %llu bytes",
        (void *)socket,
        (void *)socket->io_handle.data.handle,
        (unsigned long long)cursor->len);

    BOOL res = WriteFile(
        socket->io_handle.data.handle,
        cursor->ptr,
        (DWORD)cursor->len,
        NULL,
        aws_overlapped_to_windows_overlapped(&write_cb_data->io_data.signal));

    if (!res) {
        int error_code = GetLastError();
        if (error_code != ERROR_IO_PENDING) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: WriteFile() failed with error %d",
                (void *)socket,
                (void *)socket->io_handle.data.handle,
                error_code);

            aws_linked_list_remove(&write_cb_data->io_data.node);
            aws_mem_release(socket->allocator, write_cb_data);
            int aws_error = s_determine_socket_error(error_code);
            if (aws_error == AWS_IO_SOCKET_CLOSED) {
                socket->state = CLOSED;
            } else {
                socket->state = ERRORED;
            }
            return aws_raise_error(aws_error);
        }
    }

    return AWS_OP_SUCCESS;
}

int aws_socket_get_error(struct aws_socket *socket) {
    if (socket->options.domain != AWS_SOCKET_LOCAL) {
        int connect_result;
        socklen_t result_length = sizeof(connect_result);
        if (getsockopt(
                (SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_ERROR, (char *)&connect_result, &result_length) <
            0) {
            return s_determine_socket_error(WSAGetLastError());
        }

        if (connect_result) {
            return s_determine_socket_error(connect_result);
        }
    } else {
        return s_determine_socket_error(WSAGetLastError());
    }

    return AWS_OP_SUCCESS;
}

bool aws_socket_is_open(struct aws_socket *socket) {
    return socket->io_handle.data.handle != INVALID_HANDLE_VALUE;
}

void aws_socket_endpoint_init_local_address_for_test(struct aws_socket_endpoint *endpoint) {
    struct aws_uuid uuid;
    AWS_FATAL_ASSERT(aws_uuid_init(&uuid) == AWS_OP_SUCCESS);
    char uuid_str[AWS_UUID_STR_LEN] = {0};
    struct aws_byte_buf uuid_buf = aws_byte_buf_from_empty_array(uuid_str, sizeof(uuid_str));
    AWS_FATAL_ASSERT(aws_uuid_to_str(&uuid, &uuid_buf) == AWS_OP_SUCCESS);
    snprintf(endpoint->address, sizeof(endpoint->address), "\\\\.\\pipe\\testsock" PRInSTR, AWS_BYTE_BUF_PRI(uuid_buf));
}
