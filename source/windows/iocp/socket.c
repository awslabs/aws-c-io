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

/*keep these where they are.*/
#include <WS2tcpip.h>
#include <MSWSock.h>
#include <Mstcpip.h>

#include <aws/io/socket.h>

#include <aws/common/byte_buf.h>
#include <aws/common/clock.h>
#include <aws/common/task_scheduler.h>

#include <aws/io/event_loop.h>
#include <aws/io/pipe.h>

#include <assert.h>
#include <aws/io/io.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if _MSC_VER
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

#define PIPE_BUFFER_SIZE 512

struct socket_vtable {
    int(*connection_success)(struct aws_socket *socket);
    void(*connection_error)(struct aws_socket *socket, int error_code);
    int(*close)(struct aws_socket *socket);
    int(*connect)(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *connect_loop);
    int(*start_accept)(struct aws_socket *socket, struct aws_event_loop *accept_loop);
    int(*stop_accept)(struct aws_socket *socket);
    int(*bind)(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint);
    int(*listen)(struct aws_socket *socket, int backlog_size);
    int(*read)(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read);
    int(*subscribe_to_read)(struct aws_socket *socket,
        aws_socket_on_readable_fn *on_readable, void *user_data);
};

static int s_ipv4_stream_connection_success(struct aws_socket *socket);
static int s_ipv6_stream_connection_success(struct aws_socket *socket);
static void s_connection_error(struct aws_socket *socket, int error_code);
static int s_local_and_udp_connection_success(struct aws_socket *socket);
static int s_ipv4_stream_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *connect_loop);
static int s_ipv4_dgram_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *connect_loop);
static int s_ipv6_stream_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *connect_loop);
static int s_ipv6_dgram_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *connect_loop);
static int s_local_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *connect_loop);
static int s_tcp_start_accept(struct aws_socket *socket, struct aws_event_loop *accept_loop);
static int s_local_start_accept(struct aws_socket *socket, struct aws_event_loop *accept_loop);
static int s_stream_stop_accept(struct aws_socket *socket);
static int s_dgram_start_accept(struct aws_socket *socket, struct aws_event_loop *accept_loop);
static int s_dgram_stop_accept(struct aws_socket *socket);

static int s_tcp_listen(struct aws_socket *socket, int backlog_size);
static int s_udp_listen(struct aws_socket *socket, int backlog_size);
static int s_local_listen(struct aws_socket *socket, int backlog_size);
static int s_tcp_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read);
static int s_local_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read);
static int s_dgram_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read);
static int s_socket_close(struct aws_socket *socket);
static int s_local_close(struct aws_socket *socket);
static int s_ipv4_stream_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint);
static int s_ipv4_dgram_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint);
static int s_ipv6_stream_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint);
static int s_ipv6_dgram_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint);
static int s_local_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint);

static int s_stream_subscribe_to_read(struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable, void *user_data);
static int s_dgram_subscribe_to_read(struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable, void *user_data);

static int s_determine_socket_error(int error);

/* Why build this V-table instead of doing that beautiful posix code I just read?
   I'm glad you asked...... because winsock is nothing like posix and certainly not
   as well thought out. There were so many branches to handle three entirely different 
   APIs we decided it was less painful to just have a bunch of function pointers in a table
   than to want to gouge our eyes out while looking at a ridiculous number of branches. */
static struct socket_vtable vtables[3][2] = {
    [AWS_SOCKET_IPV4] = {
        [AWS_SOCKET_STREAM] = {
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
        [AWS_SOCKET_DGRAM] = {
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
    [AWS_SOCKET_IPV6] = {
        [AWS_SOCKET_STREAM] = {
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
    [AWS_SOCKET_DGRAM] = {
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
    [AWS_SOCKET_LOCAL] = {
        [AWS_SOCKET_STREAM] = {
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
        [AWS_SOCKET_DGRAM] = { 0 },
    },
};

enum socket_state {
    INIT = 0x01,
    CONNECTING = 0x02,
    CONNECTED_READ = 0x04,
    CONNECTED_WRITE = 0x08,
    BOUND = 0x10,
    LISTENING = 0x20,
    TIMEDOUT = 0x40,
    WAITING_ON_READABLE = 0x80,
};

enum pending_operations {
    PENDING_CONNECT = 0x01,
    PENDING_ACCEPT= 0x02,
    PENDING_READ = 0x04,
    PENDING_WRITE = 0x08,
};

static int convert_domain(enum aws_socket_domain domain) {
    switch (domain) {
    case AWS_SOCKET_IPV4:
        return AF_INET;
    case AWS_SOCKET_IPV6:
        return AF_INET6;
    case AWS_SOCKET_LOCAL:
        return AF_UNIX;
    default:
        assert(0);
        return AF_INET;
    }
}

static int convert_type(enum aws_socket_type type) {
    switch (type) {
    case AWS_SOCKET_STREAM:
        return SOCK_STREAM;
    case AWS_SOCKET_DGRAM:
        return SOCK_DGRAM;
    default:
        assert(0);
        return SOCK_STREAM;
    }
}

#define SOCK_STORAGE_SIZE (sizeof(struct sockaddr_storage) + 16)

struct iocp_socket {
    struct socket_vtable *vtable;
    struct aws_overlapped *read_signal;
    struct aws_socket *incoming_socket;
    uint8_t accept_buffer[SOCK_STORAGE_SIZE * 2];
    struct aws_task sequential_task_storage;
    volatile bool stop_accept;
    volatile uint8_t pending_operations;
};

static int create_socket(struct aws_socket *sock, struct aws_socket_options *options) {
    SOCKET handle = socket(convert_domain(options->domain), convert_type(options->type), 0);
    u_long non_blocking = 1;
    if (handle != INVALID_SOCKET && !ioctlsocket(handle, FIONBIO, &non_blocking)) {       
        sock->io_handle.data.handle = (HANDLE)handle;
        sock->io_handle.additional_data = NULL;
        return aws_socket_set_options(sock, options);
    }

    int error_code = WSAGetLastError();
    int aws_error = s_determine_socket_error(error_code);
    return aws_raise_error(aws_error);
}

static int s_socket_init(struct aws_socket *socket, struct aws_allocator *alloc, struct aws_socket_options *options) {
    assert(options->domain <= AWS_SOCKET_LOCAL);
    assert(options->type <= AWS_SOCKET_DGRAM);
    AWS_ZERO_STRUCT(*socket);

    struct iocp_socket *impl = aws_mem_acquire(alloc, sizeof(struct iocp_socket));
    if (!impl) {
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*impl);
    impl->vtable = &vtables[options->domain][options->type];
    if (!impl->vtable || !impl->vtable->read) {
        aws_mem_release(alloc, impl);
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
    }

    impl->read_signal = aws_mem_acquire(alloc, sizeof(struct aws_overlapped));

    if (!impl->read_signal) {
        aws_mem_release(alloc, impl);
        return AWS_OP_ERR;
    }

    aws_overlapped_reset(impl->read_signal);
    impl->read_signal->alloc = alloc;
    
    socket->allocator = alloc;
    socket->io_handle.data.handle = INVALID_HANDLE_VALUE;
    socket->state = INIT;
    socket->impl = impl;
    socket->options = *options;

    if (options->domain != AWS_SOCKET_LOCAL) {
        return create_socket(socket, options);
    }
    return AWS_OP_SUCCESS;
}

int aws_socket_init(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    struct aws_socket_options *options,
    struct aws_socket_creation_args *creation_args) {
    assert(options);
    assert(creation_args);
   
    aws_check_and_init_winsock();

    int err = s_socket_init(socket, alloc, options);

    if (!err) {
        socket->creation_args = *creation_args;
    }

    return err;
}

void aws_socket_clean_up(struct aws_socket *socket) {
    struct iocp_socket *socket_impl = socket->impl;
    socket_impl->vtable->close(socket);

    if (socket_impl->incoming_socket) {
       aws_socket_clean_up(socket_impl->incoming_socket);
       aws_mem_release(socket->allocator, socket_impl->incoming_socket);
    }

    /* if we still have pending operations, the event loop is still going to notify. 
       in that case, we'll have to leave the overlapped pointer dangling and let the 
       callbacks clean it up. */
    if (!socket_impl->pending_operations) {
        aws_mem_release(socket->allocator, socket_impl->read_signal);
    }

    aws_mem_release(socket->allocator, socket->impl);
    AWS_ZERO_STRUCT(*socket);
    socket->io_handle.data.handle = INVALID_HANDLE_VALUE;
}

int aws_socket_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *event_loop) {
    struct iocp_socket *socket_impl = socket->impl;
    return socket_impl->vtable->connect(socket, remote_endpoint, event_loop);
}

int aws_socket_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint) {
    struct iocp_socket *socket_impl = socket->impl;
    return socket_impl->vtable->bind(socket, local_endpoint);
}

int aws_socket_listen(struct aws_socket *socket, int backlog_size) {
    struct iocp_socket *socket_impl = socket->impl;
    return socket_impl->vtable->listen(socket, backlog_size);
}

int aws_socket_start_accept(struct aws_socket *socket, struct aws_event_loop *accept_loop) {
    struct iocp_socket *socket_impl = socket->impl;
    return socket_impl->vtable->start_accept(socket, accept_loop);
}

int aws_socket_stop_accept(struct aws_socket *socket) {
    struct iocp_socket *socket_impl = socket->impl;
    return socket_impl->vtable->stop_accept(socket);
}

int aws_socket_shutdown(struct aws_socket *socket) {
    struct iocp_socket *socket_impl = socket->impl;
    return socket_impl->vtable->close(socket);
}

int aws_socket_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read) {
    struct iocp_socket *socket_impl = socket->impl;
    return socket_impl->vtable->read(socket, buffer, amount_read);
}

int aws_socket_subscribe_to_readable_events(struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable, void *user_data) {
    struct iocp_socket *socket_impl = socket->impl;
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
        return AWS_IO_SOCKET_CLOSED;
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
        return AWS_IO_MAX_FDS_EXCEEDED;
    case WSAENAMETOOLONG:
    case WSA_INVALID_PARAMETER:
    case SOME_ERROR_CODE_THAT_MEANS_INVALID_PATH:
        return AWS_IO_FILE_INVALID_PATH;
    case WSAEAFNOSUPPORT:
        return AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY;
    case WSAEACCES:
        return AWS_IO_NO_PERMISSION;
    default:
        return AWS_IO_SOCKET_NOT_CONNECTED;
    }
}

static inline int s_process_tcp_sock_options(struct aws_socket *socket) {
    if (aws_socket_set_options(socket, &socket->options)) {
        aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);

        if (socket->creation_args.on_error) {
            socket->creation_args.on_error(socket, AWS_IO_SOCKET_INVALID_OPTIONS, socket->creation_args.user_data);
        }

        return AWS_OP_ERR;
    }
    return AWS_OP_SUCCESS;
}

/* called when an IPV4 tcp socket successfully has connected. */
static int s_ipv4_stream_connection_success(struct aws_socket *socket) {

    if (s_process_tcp_sock_options(socket)) {
        return AWS_OP_ERR;
    }

    int connect_result = 0;
    socklen_t result_length = sizeof(connect_result);
    struct iocp_socket *socket_impl = socket->impl;
    if (getsockopt((SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_ERROR, (char *)&connect_result, &result_length) < 0) {
        int error = s_determine_socket_error(WSAGetLastError());
        aws_raise_error(error);
        socket_impl->vtable->connection_error(socket, error);
        return AWS_OP_ERR;
    }

    if (connect_result) {
        int error = s_determine_socket_error(connect_result);
        aws_raise_error(error);
        socket_impl->vtable->connection_error(socket, error);
        return AWS_OP_ERR;
    }

    struct sockaddr_storage address;
    AWS_ZERO_STRUCT(address);
    socklen_t address_size = sizeof(address);
    if (!getsockname((SOCKET)socket->io_handle.data.handle, (struct sockaddr *)&address, &address_size)) {
        uint16_t port = 0;
        struct sockaddr_in *s = (struct sockaddr_in *)&address;
        port = ntohs(s->sin_port);
        InetNtopA(AF_INET, &s->sin_addr, socket->local_endpoint.address, sizeof(socket->local_endpoint.address));    
        sprintf_s(socket->local_endpoint.port, sizeof(socket->local_endpoint.port), "%d", port);
    }
    else {
        int error = s_determine_socket_error(WSAGetLastError());
        aws_raise_error(error);
        socket_impl->vtable->connection_error(socket, error);
        return AWS_OP_ERR;
    }   

    setsockopt((SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);
    socket->state = CONNECTED_WRITE | CONNECTED_READ;
  
    if (socket->creation_args.on_connection_established) {
        socket->creation_args.on_connection_established(socket, socket->creation_args.user_data);
    }

    return AWS_OP_SUCCESS;
}

/* called upon a successful TCP over IPv6 connection. */
static int s_ipv6_stream_connection_success(struct aws_socket *socket) {

    if (s_process_tcp_sock_options(socket)) {
        return AWS_OP_ERR;
    }

    int connect_result = 0;
    socklen_t result_length = sizeof(connect_result);
    struct iocp_socket *socket_impl = socket->impl;
    if (getsockopt((SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_ERROR, (char *)&connect_result, &result_length) < 0) {
        int error = s_determine_socket_error(WSAGetLastError());
        aws_raise_error(error);
        socket_impl->vtable->connection_error(socket, error);
        return AWS_OP_ERR;
    }

    if (connect_result) {
        int error = s_determine_socket_error(connect_result);
        aws_raise_error(error);
        socket_impl->vtable->connection_error(socket, error);
        return AWS_OP_ERR;
    }

    struct sockaddr_storage address;
    AWS_ZERO_STRUCT(address);
    socklen_t address_size = sizeof(address);
    if (!getsockname((SOCKET)socket->io_handle.data.handle, (struct sockaddr *)&address, &address_size)) {
        uint16_t port = 0;
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&address;
        port = ntohs(s->sin6_port);
        InetNtopA(AF_INET6, &s->sin6_addr, socket->local_endpoint.address, sizeof(socket->local_endpoint.address));
    }
    else {
        int error = s_determine_socket_error(WSAGetLastError());
        aws_raise_error(error);
        socket_impl->vtable->connection_error(socket, error);
        return AWS_OP_ERR;
    }

    setsockopt((SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);

    socket->state = CONNECTED_WRITE | CONNECTED_READ;

    if (socket->creation_args.on_connection_established) {
        socket->creation_args.on_connection_established(socket, socket->creation_args.user_data);
    }

    return AWS_OP_SUCCESS;
}

/* Outgoing UDP and Named pipe connections. */
static int s_local_and_udp_connection_success(struct aws_socket *socket) {
    socket->state = CONNECTED_WRITE | CONNECTED_READ;

    if (socket->creation_args.on_connection_established) {
        socket->creation_args.on_connection_established(socket, socket->creation_args.user_data);
    }

    return AWS_OP_SUCCESS;
}

static void s_connection_error(struct aws_socket *socket, int error) {
    socket->state = ERROR;
    struct iocp_socket *socket_impl = socket->impl;
    socket_impl->pending_operations = 0;
    if (socket->creation_args.on_error) {
        socket->creation_args.on_error(socket, error, socket->creation_args.user_data);
    }
}

struct socket_connect_args {
    struct aws_allocator *allocator;
    struct aws_socket *socket;
};

/* Named Pipes and TCP connection callbacks from the event loop. */
void s_socket_connection_completion(struct aws_event_loop *event_loop, struct aws_overlapped *overlapped, int status_code, size_t num_bytes_transferred) {
    (void)num_bytes_transferred;
    (void)event_loop;

    if (status_code == IO_OPERATION_CANCELLED) {
        aws_mem_release(overlapped->alloc, overlapped);
        return;
    }

    struct socket_connect_args *socket_args = (struct socket_connect_args *)overlapped->user_data;
    struct iocp_socket *socket_impl = socket_args->socket->impl;
    socket_impl->pending_operations = socket_impl->pending_operations & ~PENDING_CONNECT;

    if (socket_args) {
        if (socket_args->socket) {
            struct aws_socket *socket = socket_args->socket;
            socket->readable_fn = NULL;
            socket->readable_user_data = NULL;
            socket_args->socket = NULL;

            if (!status_code) {
                socket_impl->vtable->connection_success(socket);
            }
            else {
                int error = s_determine_socket_error(status_code);
                socket_impl->vtable->connection_error(socket, error);
            }
            return;
        }
    }
}

/* outgoing tcp connection. If this task runs before `s_socket_connection_completion()`, then the
   connection is considered timedout. */
static void s_handle_socket_timeout(struct aws_task *task, void *args, aws_task_status status) {
    struct socket_connect_args *socket_args = args;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        if (socket_args->socket) {
            socket_args->socket->state = TIMEDOUT;            
            socket_args->socket->event_loop = NULL;
            aws_socket_shutdown(socket_args->socket);

            if (socket_args->socket->creation_args.on_error) {
                aws_raise_error(AWS_IO_SOCKET_TIMEOUT);
                socket_args->socket->creation_args.on_error(
                    socket_args->socket, AWS_IO_SOCKET_TIMEOUT, socket_args->socket->creation_args.user_data);
            }
        }
    }

    struct aws_allocator *allocator = socket_args->allocator;
    aws_mem_release(allocator, socket_args);
    aws_mem_release(allocator, task);
}

/* initiate an outbound tcp connection (client mode). */
static inline int s_tcp_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *connect_loop, 
    struct sockaddr *bind_addr, struct sockaddr *socket_addr, size_t sock_size) {
    struct iocp_socket *socket_impl = socket->impl;
    memcpy(socket->remote_endpoint.port, remote_endpoint->port, sizeof(remote_endpoint->port));
    memcpy(socket->remote_endpoint.address, remote_endpoint->address, sizeof(socket->remote_endpoint.address));

    struct socket_connect_args *connect_args = aws_mem_acquire(socket->allocator, sizeof(struct socket_connect_args));

    if (!connect_args) {
        return AWS_OP_ERR;
    }

    struct aws_task *timeout_task = aws_mem_acquire(socket->allocator, sizeof(struct aws_task));

    if (!timeout_task) {
        aws_mem_release(socket->allocator, connect_args);
        return AWS_OP_ERR;
    }

    timeout_task->fn = s_handle_socket_timeout;
    timeout_task->arg = connect_args;

    LPFN_CONNECTEX connect_fn = NULL;
    if (aws_socket_assign_to_event_loop(socket, connect_loop)) {
        aws_mem_release(socket->allocator, connect_args);
        aws_mem_release(socket->allocator, timeout_task);
        return AWS_OP_ERR;
    }

    connect_args->allocator = socket->allocator;
    connect_args->socket = socket;
    socket->state = CONNECTING;
    connect_fn = (LPFN_CONNECTEX)aws_winsock_get_connectex_fn();
    aws_overlapped_init(socket_impl->read_signal, s_socket_connection_completion, connect_args);
    int fake_buffer = 0;

    BOOL connect_res = false;
    bind((SOCKET)socket->io_handle.data.handle, bind_addr, (int)sock_size);
    connect_res = connect_fn((SOCKET)socket->io_handle.data.handle, socket_addr, (int)sock_size,
        &fake_buffer, 0, NULL, &socket_impl->read_signal->overlapped);

    uint64_t time_to_run = 0;
    /* if the connect succedded immediately, let the timeout task still run, but it can run immediately. This is cleaner
       because it can just deallocate the memory we just allocated. */
    aws_event_loop_current_clock_time(socket->event_loop, &time_to_run);

    /* with IO completion ports, the overlapped callback triggers even if the operation succedded immediately,
       so we can just act like it's pending and the code path is the same.*/
    if (!connect_res) {
        int error_code = WSAGetLastError();
        if (error_code != ERROR_IO_PENDING) {
            aws_mem_release(socket->allocator, connect_args);
            aws_mem_release(socket->allocator, timeout_task);

            int aws_err = s_determine_socket_error(error_code);
            socket_impl->vtable->connection_error(socket, error_code);
            return aws_raise_error(aws_err);
        }
        time_to_run += aws_timestamp_convert(socket->options.connect_timeout, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    }
    
    socket_impl->pending_operations |= PENDING_CONNECT;
    aws_event_loop_schedule_task_future(socket->event_loop, timeout_task, time_to_run);  

    return AWS_OP_SUCCESS;
}

/* initiate TCP ipv4 outbound connection. */
static int s_ipv4_stream_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *connect_loop) {
    assert(connect_loop);
    struct sockaddr_in addr_in;
    inet_pton(AF_INET, remote_endpoint->address, &(addr_in.sin_addr));
    addr_in.sin_port = htons((uint16_t)atoi(remote_endpoint->port));
    addr_in.sin_family = AF_INET;

    /* stupid as hell, we have to bind first*/
    struct sockaddr_in in_bind_addr;
    AWS_ZERO_STRUCT(in_bind_addr);
    in_bind_addr.sin_family = AF_INET;
    in_bind_addr.sin_addr.s_addr = INADDR_ANY;
    in_bind_addr.sin_port = 0;

    return s_tcp_connect(socket, remote_endpoint, connect_loop, (struct sockaddr *)&in_bind_addr, (struct sockaddr *)&addr_in, sizeof(addr_in));   
}

/* initiate TCP ipv6 outbound connection. */
static int s_ipv6_stream_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *connect_loop) {
    struct sockaddr_in6 bind_addr;
    AWS_ZERO_STRUCT(bind_addr);
    bind_addr.sin6_family = AF_INET6;
    bind_addr.sin6_port = 0;

    struct sockaddr_in6 addr_in6;
    inet_pton(AF_INET6, remote_endpoint->address, &(addr_in6.sin6_addr));
    addr_in6.sin6_port = htons((uint16_t)atoi(remote_endpoint->port));
    addr_in6.sin6_family = AF_INET6;

    return s_tcp_connect(socket, remote_endpoint, connect_loop, (struct sockaddr *)&bind_addr, (struct sockaddr *)&addr_in6, sizeof(addr_in6));
}

/* simply moves the connection_success notification into the event-loop's thread. */
static void s_connection_success_task(struct aws_task *task, void *arg, enum aws_task_status task_status) {
    (void)task;
    if (task_status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_socket *socket = arg;
        struct iocp_socket *socket_impl = socket->impl;
        socket_impl->sequential_task_storage.fn = NULL;
        socket_impl->sequential_task_storage.arg = NULL;
        socket_impl->vtable->connection_success(socket);
    }
}

/* initiate the client end of a named pipe. */
static int s_local_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *connect_loop) {
    if (s_process_tcp_sock_options(socket)) {
        return AWS_OP_ERR;
    }

    struct iocp_socket *socket_impl = socket->impl;
    memcpy(socket->remote_endpoint.socket_name, remote_endpoint->socket_name, sizeof(remote_endpoint->socket_name));

    socket->io_handle.data.handle = CreateFileA(remote_endpoint->socket_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, 
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

    if (socket->io_handle.data.handle != INVALID_HANDLE_VALUE) {
        aws_socket_assign_to_event_loop(socket, connect_loop);

        socket_impl->sequential_task_storage.fn = s_connection_success_task;
        socket_impl->sequential_task_storage.arg = socket;
        aws_event_loop_schedule_task_now(connect_loop, &socket_impl->sequential_task_storage);
        return AWS_OP_SUCCESS;
    } else {
        int win_error = GetLastError();
        int aws_error = s_determine_socket_error(win_error);
        aws_raise_error(aws_error);
        socket_impl->vtable->connection_error(socket, aws_error);
        return AWS_OP_ERR;
    }
}

/* connect generic udp outbound */
static inline int s_dgram_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, 
    struct aws_event_loop *connect_loop, struct sockaddr *socket_addr, size_t sock_size) {
    struct iocp_socket *socket_impl = socket->impl;
    memcpy(socket->remote_endpoint.port, remote_endpoint->port, sizeof(remote_endpoint->port));
    memcpy(socket->remote_endpoint.address, remote_endpoint->address, sizeof(socket->remote_endpoint.address));
   
    int connect_err = connect((SOCKET)socket->io_handle.data.handle, socket_addr, (int)sock_size);

    if (connect_err) {
        int error_code = WSAGetLastError();
        int aws_error = s_determine_socket_error(error_code);
        aws_raise_error(aws_error);
        socket_impl->vtable->connection_error(socket, aws_error);
        return AWS_OP_ERR;
    }

    /* keep in mind, we already know the size, since we created it. */
    int fake_sock_size = (int)sock_size;
    int sock_name_err = getsockname((SOCKET)socket->io_handle.data.handle, socket_addr, &fake_sock_size);
    if (!sock_name_err) {
        uint16_t port = 0;        
        if (socket->options.domain == AWS_SOCKET_IPV4) {
            struct sockaddr_in *ipv4_addr = (struct sockaddr_in *)socket_addr;
            port = ntohs(ipv4_addr->sin_port);
            InetNtopA(AF_INET, &ipv4_addr->sin_addr, socket->local_endpoint.address, sizeof(socket->local_endpoint.address));
        }
        else {
            struct sockaddr_in6 *ipv6_addr = (struct sockaddr_in6 *)socket_addr;
            port = ntohs(ipv6_addr->sin6_port);
            InetNtopA(AF_INET, &ipv6_addr->sin6_addr, socket->local_endpoint.address, sizeof(socket->local_endpoint.address));
        }
    }

    if (sock_name_err || s_process_tcp_sock_options(socket)) {
        int error = s_determine_socket_error(WSAGetLastError());
        aws_raise_error(error);
        socket_impl->vtable->connection_error(socket, error);
        return AWS_OP_ERR;
    }

    if (connect_loop) {
        aws_socket_assign_to_event_loop(socket, connect_loop);
        socket_impl->sequential_task_storage.fn = s_connection_success_task;
        socket_impl->sequential_task_storage.arg = socket;
        aws_event_loop_schedule_task_now(connect_loop, &socket_impl->sequential_task_storage);
    }
    else {
        socket_impl->vtable->connection_success(socket);
    }

    return AWS_OP_SUCCESS;
}

static int s_ipv4_dgram_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *connect_loop) {
    struct sockaddr_in addr_in;
    inet_pton(AF_INET, remote_endpoint->address, &(addr_in.sin_addr));
    addr_in.sin_port = htons((uint16_t)atoi(remote_endpoint->port));
    addr_in.sin_family = AF_INET;

    return s_dgram_connect(socket, remote_endpoint, connect_loop, (struct sockaddr *)&addr_in, sizeof(addr_in));
}

static int s_ipv6_dgram_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *connect_loop) {
    struct sockaddr_in6 addr_in6;
    inet_pton(AF_INET6, remote_endpoint->address, &(addr_in6.sin6_addr));
    addr_in6.sin6_port = htons((uint16_t)atoi(remote_endpoint->port));
    addr_in6.sin6_family = AF_INET6;

    return s_dgram_connect(socket, remote_endpoint, connect_loop, (struct sockaddr *)&addr_in6, sizeof(addr_in6));
}

static inline int s_tcp_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint, struct sockaddr *sock_addr, size_t sock_size) {
    memcpy(socket->local_endpoint.port, local_endpoint->port, sizeof(local_endpoint->port));
    memcpy(socket->local_endpoint.address, local_endpoint->address, sizeof(local_endpoint->address));

    int error_code = bind((SOCKET)socket->io_handle.data.handle, sock_addr, (int)sock_size);

    if (!error_code) {
        socket->state = BOUND;
        return AWS_OP_SUCCESS;
    }

    socket->state = ERROR;
    int error = s_determine_socket_error(WSAGetLastError());
    return aws_raise_error(error);
}

static int s_ipv4_stream_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint) {
    struct sockaddr_in addr_in;
    inet_pton(AF_INET, local_endpoint->address, &(addr_in.sin_addr));
    addr_in.sin_port = htons((uint16_t)atoi(local_endpoint->port));
    addr_in.sin_family = AF_INET;

    return s_tcp_bind(socket, local_endpoint, (struct sockaddr *)&addr_in, sizeof(addr_in));
}

static int s_ipv6_stream_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint) {
    struct sockaddr_in6 addr_in6;
    inet_pton(AF_INET, local_endpoint->address, &(addr_in6.sin6_addr));
    addr_in6.sin6_port = htons((uint16_t)atoi(local_endpoint->port));
    addr_in6.sin6_family = AF_INET6;

    return s_tcp_bind(socket, local_endpoint, (struct sockaddr *)&addr_in6, sizeof(addr_in6));
}

static inline int s_udp_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint, struct sockaddr *sock_addr, size_t sock_size) {
    memcpy(socket->local_endpoint.port, local_endpoint->port, sizeof(local_endpoint->port));
    memcpy(socket->local_endpoint.address, local_endpoint->address, sizeof(local_endpoint->address));

    int error_code = bind((SOCKET)socket->io_handle.data.handle, sock_addr, (int)sock_size);

    if (!error_code) {
        socket->state |= CONNECTED_READ;
        return AWS_OP_SUCCESS;
    }

    socket->state = ERROR;
    int error = s_determine_socket_error(WSAGetLastError());
    return aws_raise_error(error);
}

static int s_ipv4_dgram_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint) {
    struct sockaddr_in addr_in;
    inet_pton(AF_INET, local_endpoint->address, &(addr_in.sin_addr));
    addr_in.sin_port = htons((uint16_t)atoi(local_endpoint->port));
    addr_in.sin_family = AF_INET;

    return s_udp_bind(socket, local_endpoint, (struct sockaddr *)&addr_in, sizeof(addr_in));
}

static int s_ipv6_dgram_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint) {
    struct sockaddr_in6 addr_in6;
    inet_pton(AF_INET, local_endpoint->address, &(addr_in6.sin6_addr));
    addr_in6.sin6_port = htons((uint16_t)atoi(local_endpoint->port));
    addr_in6.sin6_family = AF_INET6;

    return s_udp_bind(socket, local_endpoint, (struct sockaddr *)&addr_in6, sizeof(addr_in6));
}

static int s_local_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint) {
    memcpy(socket->local_endpoint.socket_name,  local_endpoint->socket_name, sizeof(socket->local_endpoint.socket_name));
    socket->io_handle.data.handle = CreateNamedPipeA(local_endpoint->socket_name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
        PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 0, NULL);

    if (socket->io_handle.data.handle != INVALID_HANDLE_VALUE) {
        socket->state = BOUND;
        return AWS_OP_SUCCESS;
    }
    else {
        int error_code = GetLastError();
        int aws_error = s_determine_socket_error(error_code);
        return aws_raise_error(aws_error);
    }
}

static int s_tcp_listen(struct aws_socket *socket, int backlog_size) {
    if (AWS_UNLIKELY(socket->state != BOUND)) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    int error_code = listen((SOCKET)socket->io_handle.data.handle, backlog_size);

    if (!error_code) {
        socket->state = LISTENING;
        return AWS_OP_SUCCESS;
    }

    error_code = GetLastError();
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

/* triggered by the event loop upon an incomming pipe connection. */
static void s_incoming_pipe_connection_event(struct aws_event_loop *event_loop, struct aws_overlapped *overlapped, 
    int status_code, size_t num_bytes_transferred) {
    (void)event_loop;
    (void)num_bytes_transferred;

    if (status_code == IO_PIPE_BROKEN) {
        aws_mem_release(overlapped->alloc, overlapped);
        return;
    }

    struct aws_socket *socket = (struct aws_socket *)overlapped->user_data;
    struct iocp_socket *socket_impl = socket->impl;

    if (!status_code && !socket_impl->stop_accept) {
        int err = AWS_OP_SUCCESS;
        bool continue_accept_loop = false;

        do {
            struct aws_socket *new_socket = aws_mem_acquire(socket->allocator, sizeof(struct aws_socket));

            if (!new_socket) {
                socket_impl->vtable->connection_error(socket, AWS_ERROR_OOM);
                return;
            }

            if (s_socket_init(new_socket, socket->allocator, &socket->options)) {
                aws_mem_release(socket->allocator, new_socket);
                socket_impl->vtable->connection_error(socket, aws_last_error());
                return;
            }

            new_socket->state = CONNECTED_WRITE | CONNECTED_READ;

            /* Named pipes don't work like traditional socket APIs. The original handle is used
               for the incoming connection. so we copy it over and do some trickery with the 
               event loop registrations. */
            new_socket->io_handle = socket->io_handle;
            struct iocp_socket *new_socket_impl = new_socket->impl;
            new_socket_impl->read_signal->alloc = socket->allocator;
            aws_event_loop_unsubscribe_from_io_events(event_loop, &new_socket->io_handle);
            new_socket->event_loop = NULL;

            socket_impl->pending_operations &= ~PENDING_ACCEPT;
            socket->io_handle.data.handle = CreateNamedPipeA(socket->local_endpoint.socket_name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES, PIPE_BUFFER_SIZE, PIPE_BUFFER_SIZE, 0, NULL);

            socket->creation_args.on_incoming_connection(socket, new_socket, socket->creation_args.user_data);

            if (socket->io_handle.data.handle == INVALID_HANDLE_VALUE) {
                aws_mem_release(socket->allocator, new_socket);
                socket_impl->vtable->connection_error(socket, aws_last_error());
                return;
            }

            aws_overlapped_reset(socket_impl->read_signal);
            aws_overlapped_init(socket_impl->read_signal, s_incoming_pipe_connection_event, socket);
            socket->event_loop = NULL;
            aws_socket_assign_to_event_loop(socket, event_loop);

            BOOL res = ConnectNamedPipe(socket->io_handle.data.handle, &socket_impl->read_signal->overlapped);

            continue_accept_loop = res;

            if (!res) {
                int error_code = GetLastError();
                if (error_code != ERROR_IO_PENDING) {
                    err = s_determine_socket_error(WSAGetLastError());
                    aws_raise_error(err);
                    socket_impl->vtable->connection_error(socket, err);
                    return;
                }
                continue_accept_loop = false;
                socket_impl->pending_operations |= PENDING_ACCEPT;
            }

        } while (continue_accept_loop && !socket_impl->stop_accept);
    }
}

/* invoked by the event loop when a listening socket has incoming connections. This is only used for TCP.*/
static void s_socket_accept_event(struct aws_event_loop *event_loop, struct aws_overlapped *overlapped, 
    int status_code, size_t num_bytes_transferred) {

    (void)event_loop;
    (void)num_bytes_transferred;

    if (status_code == IO_OPERATION_CANCELLED) {
        aws_mem_release(overlapped->alloc, overlapped);
        return;        
    }

    struct aws_socket *socket = (struct aws_socket *)overlapped->user_data;
    struct iocp_socket *socket_impl = socket->impl;

    if (!status_code && !socket_impl->stop_accept) {
        LPFN_ACCEPTEX accept_fn = (LPFN_ACCEPTEX)aws_winsock_get_acceptex_fn();
        BOOL accept_status = false;
        int err = AWS_OP_SUCCESS;

        do {
            AWS_ZERO_STRUCT(socket_impl->incoming_socket->creation_args);
            socket_impl->incoming_socket->state = CONNECTED_WRITE | CONNECTED_READ;

            uint16_t port = 0;

            struct sockaddr_storage *in_addr = (struct sockaddr_storage *)socket_impl->accept_buffer;

            if (in_addr->ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)in_addr;
                port = ntohs(s->sin_port);
                InetNtopA(
                    AF_INET,
                    &s->sin_addr,
                    socket_impl->incoming_socket->remote_endpoint.address,
                    sizeof(socket_impl->incoming_socket->remote_endpoint.address));
                socket_impl->incoming_socket->options.domain = AWS_SOCKET_IPV4;
            }
            else if (in_addr->ss_family == AF_INET6) {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)in_addr;
                port = ntohs(s->sin6_port);
                InetNtopA(
                    AF_INET6,
                    &s->sin6_addr,
                    socket_impl->incoming_socket->remote_endpoint.address,
                    sizeof(socket_impl->incoming_socket->remote_endpoint.address));
                socket_impl->incoming_socket->options.domain = AWS_SOCKET_IPV6;
            }

            sprintf_s(socket_impl->incoming_socket->remote_endpoint.port, 
                sizeof(socket_impl->incoming_socket->remote_endpoint.port), "%d", port);

            u_long non_blocking = 1;
            ioctlsocket((SOCKET)socket_impl->incoming_socket->io_handle.data.handle, FIONBIO, &non_blocking);
            aws_socket_set_options(socket_impl->incoming_socket, &socket->options);
            socket->creation_args.on_incoming_connection(socket, socket_impl->incoming_socket, 
                socket->creation_args.user_data);
            socket_impl->incoming_socket = NULL;

            aws_overlapped_reset(socket_impl->read_signal);
            aws_overlapped_init(socket_impl->read_signal, s_socket_accept_event, socket);

            socket_impl->incoming_socket = aws_mem_acquire(socket->allocator, sizeof(struct aws_socket));

            if (!socket_impl->incoming_socket) {
                socket_impl->vtable->connection_error(socket, AWS_ERROR_OOM);
                return;
            }
 
            err = s_socket_init(socket_impl->incoming_socket, socket->allocator, &socket->options);

            /* we need to start the accept process over again. */
            if (!err) {
                socket_impl->incoming_socket->state = INIT;
                memcpy(&socket_impl->incoming_socket->local_endpoint, &socket->local_endpoint,
                    sizeof(socket->local_endpoint));
                accept_status = accept_fn((SOCKET)socket->io_handle.data.handle, 
                    (SOCKET)socket_impl->incoming_socket->io_handle.data.handle, socket_impl->accept_buffer, 0,
                    SOCK_STORAGE_SIZE, SOCK_STORAGE_SIZE, NULL, &socket_impl->read_signal->overlapped);

                if (!accept_status) {
                    int win_err = WSAGetLastError();
                    if (win_err != ERROR_IO_PENDING) {
                        aws_socket_clean_up(socket_impl->incoming_socket);
                        aws_mem_release(socket->allocator, socket_impl->incoming_socket);
                        socket_impl->incoming_socket = NULL;
                        int aws_error = s_determine_socket_error(win_err);
                        aws_raise_error(aws_error);
                        socket_impl->vtable->connection_error(socket, aws_error);
                        return;
                    }
                }
            }
            else {
                aws_socket_clean_up(socket_impl->incoming_socket);
                aws_mem_release(socket->allocator, socket_impl->incoming_socket);
                socket_impl->vtable->connection_error(socket, err);
                return;
            }
        } while (!err && accept_status && !socket_impl->stop_accept);
    }
    else if (status_code) {
        int aws_error = s_determine_socket_error(status_code);
        aws_raise_error(aws_error);
        socket_impl->vtable->connection_error(socket, aws_error);
    }

    if (socket_impl->stop_accept) {
        socket_impl->pending_operations = socket_impl->pending_operations & ~PENDING_ACCEPT;
    }
}

static int s_tcp_start_accept(struct aws_socket *socket, struct aws_event_loop *accept_loop) {
    if (AWS_UNLIKELY(socket->state != LISTENING)) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    struct iocp_socket *socket_impl = socket->impl;
    socket_impl->incoming_socket = aws_mem_acquire(socket->allocator, sizeof(struct aws_socket));

    if (!socket_impl->incoming_socket) {
        return AWS_OP_ERR;
    }

    int err = s_socket_init(socket_impl->incoming_socket, socket->allocator, &socket->options);

    if (err) {
        aws_socket_clean_up(socket_impl->incoming_socket);
        aws_mem_release(socket->allocator, socket_impl->incoming_socket);
        socket_impl->incoming_socket = NULL;
        return AWS_OP_ERR;
    }

    memcpy(&socket_impl->incoming_socket->local_endpoint, &socket->local_endpoint, sizeof(socket->local_endpoint));

    aws_socket_assign_to_event_loop(socket, accept_loop);

    aws_overlapped_reset(socket_impl->read_signal);
    aws_overlapped_init(socket_impl->read_signal, s_socket_accept_event, socket);
    LPFN_ACCEPTEX accept_fn = (LPFN_ACCEPTEX)aws_winsock_get_acceptex_fn();
    BOOL res = accept_fn((SOCKET)socket->io_handle.data.handle, 
        (SOCKET)socket_impl->incoming_socket->io_handle.data.handle, socket_impl->accept_buffer, 0,
        SOCK_STORAGE_SIZE, SOCK_STORAGE_SIZE, NULL, &socket_impl->read_signal->overlapped);

    if (!res) {
        int win_err = WSAGetLastError();
        if (win_err != ERROR_IO_PENDING) {
            aws_mem_release(socket->allocator, socket_impl->incoming_socket);
            socket_impl->incoming_socket = NULL;
            int aws_err = s_determine_socket_error(win_err);
            return aws_raise_error(aws_err);
        }
        socket_impl->pending_operations |= PENDING_ACCEPT;
    }

    return AWS_OP_SUCCESS;
}

static int s_stream_stop_accept(struct aws_socket *socket) {
    struct iocp_socket *socket_impl = socket->impl;
    socket_impl->stop_accept = true;
    int ret_val = AWS_OP_SUCCESS;
    socket->event_loop = NULL;
    return ret_val;
}

static int s_local_start_accept(struct aws_socket *socket, struct aws_event_loop *accept_loop) {
    if (AWS_UNLIKELY(socket->state != LISTENING)) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    struct iocp_socket *socket_impl = socket->impl;
    aws_socket_assign_to_event_loop(socket, accept_loop);

    aws_overlapped_reset(socket_impl->read_signal);
    aws_overlapped_init(socket_impl->read_signal, s_incoming_pipe_connection_event, socket);
    BOOL res = ConnectNamedPipe(socket->io_handle.data.handle, &socket_impl->read_signal->overlapped);

    if (!res) {
        int error_code = GetLastError();
        if (error_code != ERROR_IO_PENDING) {
            int aws_err = s_determine_socket_error(error_code);
            return aws_raise_error(aws_err);
        }
        socket_impl->pending_operations |= PENDING_ACCEPT;
    }

    return AWS_OP_SUCCESS;
}

static int s_dgram_start_accept(struct aws_socket *socket, struct aws_event_loop *accept_loop) {
    (void)socket;
    (void)accept_loop;
    return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
}

static int s_dgram_stop_accept(struct aws_socket *socket) {
    (void)socket;
    return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
}

int aws_socket_set_options(struct aws_socket *socket, struct aws_socket_options *options) {
    socket->options = *options;

    int reuse = 1;
    setsockopt((SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(int));

    if (socket->options.domain != AWS_SOCKET_LOCAL && socket->options.type == AWS_SOCKET_STREAM) {
        if (socket->options.keepalive && !(socket->options.keep_alive_interval 
            && socket->options.keep_alive_timeout)) {
            int keep_alive = 1;
            setsockopt((SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_KEEPALIVE, 
                (char *)&keep_alive, sizeof(int));
        }
        else if (socket->options.keepalive) {
            struct tcp_keepalive keepalive_args = {
                .onoff = 1,
                .keepalivetime = socket->options.keep_alive_timeout,
                .keepaliveinterval = socket->options.keep_alive_interval,
            };
            DWORD bytes_returned = 0;
            WSAIoctl((SOCKET)socket->io_handle.data.handle, SIO_KEEPALIVE_VALS, 
                &keepalive_args, sizeof(keepalive_args),
                NULL, 0, &bytes_returned, NULL, NULL);
        }
    }

    if (socket->options.linger_time) {
        struct linger linger;
        linger.l_onoff = 1;
        linger.l_linger = (u_short)socket->options.linger_time;
        setsockopt((SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_LINGER, (char *)&linger, 
            sizeof(struct linger));
    }

    return AWS_OP_SUCCESS;
}

static int s_socket_close(struct aws_socket *socket) {
    if (socket->io_handle.data.handle != INVALID_HANDLE_VALUE) { 
        shutdown((SOCKET)socket->io_handle.data.handle, SD_BOTH);
        closesocket((SOCKET)socket->io_handle.data.handle);  
        socket->io_handle.data.handle = INVALID_HANDLE_VALUE;
    }

    return AWS_OP_SUCCESS;
}

static int s_local_close(struct aws_socket *socket) {
    if (socket->io_handle.data.handle != INVALID_HANDLE_VALUE) {
        aws_socket_stop_accept(socket);
        CloseHandle(socket->io_handle.data.handle);
        socket->io_handle.data.handle = INVALID_HANDLE_VALUE;
    }

    return AWS_OP_SUCCESS;
}


int aws_socket_half_close(struct aws_socket *socket, enum aws_channel_direction dir) {
    int how = dir == AWS_CHANNEL_DIR_READ ? 0 : 1;

    struct iocp_socket *socket_impl = socket->impl;
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
static void s_stream_readable_event(struct aws_event_loop *event_loop, struct aws_overlapped *overlapped, 
    int status_code, size_t num_bytes_transferred) {
    (void)num_bytes_transferred;
    (void)event_loop;

    if (status_code == WSA_OPERATION_ABORTED || status_code == IO_OPERATION_CANCELLED) {
        aws_mem_release(overlapped->alloc, overlapped);
        return;
    }

    struct aws_socket *socket = overlapped->user_data;
    struct iocp_socket *socket_impl = socket->impl;
    socket_impl->pending_operations = socket_impl->pending_operations & ~PENDING_READ;
    socket->state = socket->state & ~WAITING_ON_READABLE;

    int err_code = AWS_OP_SUCCESS;
    if (status_code != ERROR_IO_PENDING) {
        err_code = s_determine_socket_error(status_code);
    }

    socket->readable_fn(socket, err_code, socket->readable_user_data);
}

/* Invoked by the event loop when a UDP socket goes readable. */
static void s_dgram_readable_event(struct aws_event_loop *event_loop, struct aws_overlapped *overlapped, 
    int status_code, size_t num_bytes_transferred) {
    (void)num_bytes_transferred;
    (void)event_loop;

     if (status_code == WSA_OPERATION_ABORTED || status_code == IO_OPERATION_CANCELLED) {
        aws_mem_release(overlapped->alloc, overlapped);
        return;
     }

    struct aws_socket *socket = overlapped->user_data;
    struct iocp_socket *socket_impl = socket->impl;
    socket_impl->pending_operations = socket_impl->pending_operations & ~PENDING_READ;
    socket->state = socket->state & ~WAITING_ON_READABLE;

    int err_code = AWS_OP_SUCCESS;
    if (status_code !=  ERROR_IO_PENDING) {
        err_code = s_determine_socket_error(status_code);
    }

    socket->readable_fn(socket, err_code , socket->readable_user_data);
}


static int s_stream_subscribe_to_read(struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable, void *user_data) {
    assert(socket->event_loop);
    
    assert(!socket->readable_fn);

    socket->readable_fn = on_readable;
    socket->readable_user_data = user_data;

    struct iocp_socket *iocp_socket = socket->impl;
    aws_overlapped_reset(iocp_socket->read_signal);
    aws_overlapped_init(iocp_socket->read_signal, s_stream_readable_event, socket);

    int fake_buffer = 0;
    socket->state |= WAITING_ON_READABLE;
    iocp_socket->pending_operations |= PENDING_READ;
    int err = ReadFile(socket->io_handle.data.handle, &fake_buffer, 0, NULL, &iocp_socket->read_signal->overlapped);
    if (err) {
        int wsa_err = WSAGetLastError();
        if (wsa_err != ERROR_IO_PENDING) {
            int aws_error = s_determine_socket_error(wsa_err);
            return aws_raise_error(aws_error);
        }
    }
    return AWS_OP_SUCCESS;
}

static int s_dgram_subscribe_to_read(struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable, void *user_data) {
    assert(socket->event_loop);
    /* don't do duplicate registrations. */
    assert(!socket->readable_fn);

    socket->readable_fn = on_readable;
    socket->readable_user_data = user_data;

    struct iocp_socket *iocp_socket = socket->impl;
    aws_overlapped_reset(iocp_socket->read_signal);
    aws_overlapped_init(iocp_socket->read_signal, s_dgram_readable_event, socket);

    socket->state |= WAITING_ON_READABLE;
    iocp_socket->pending_operations |= PENDING_READ;
    /* the zero byte read trick with ReadFile doesn't actually work for UDP because it actually
       clears the buffer from the kernel, but if we use WSARecv, we can tell it we just want to peek
       which won't clear the kernel buffers. Giving a BS buffer with 0 len seems to do the trick. */
    WSABUF buf = {
        .len = 0,
        .buf = NULL,
    };
    DWORD flags = MSG_PEEK;
    int err = WSARecv((SOCKET)socket->io_handle.data.handle, &buf, 1, NULL, &flags, 
        &iocp_socket->read_signal->overlapped, NULL);

    if (err) {
        int wsa_err = WSAGetLastError();
        if (wsa_err != ERROR_IO_PENDING) {
            int aws_error = s_determine_socket_error(wsa_err);
            return aws_raise_error(aws_error);
        }
    }   
    return AWS_OP_SUCCESS;
}

static int s_local_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read) {
    assert(socket->readable_fn);
    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (!(socket->state & CONNECTED_READ)) {
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    DWORD bytes_available = 0;
    BOOL peek_success = PeekNamedPipe(socket->io_handle.data.handle, NULL, 0, NULL, &bytes_available, NULL);

    if (!peek_success) {
        int error_code = GetLastError();
        return aws_raise_error(s_determine_socket_error(error_code));
    }

    if (!bytes_available) {
        if (!(socket->state & WAITING_ON_READABLE)) {
            struct iocp_socket *iocp_socket = socket->impl;
            socket->state |= WAITING_ON_READABLE;
            aws_overlapped_reset(iocp_socket->read_signal);
            aws_overlapped_init(iocp_socket->read_signal, s_stream_readable_event, socket);
            int fake_buffer = 0;
            iocp_socket->pending_operations |= PENDING_READ;
            int err = ReadFile(socket->io_handle.data.handle, &fake_buffer, 0, NULL, &iocp_socket->read_signal->overlapped);
            if (err) {
                int wsa_err = GetLastError();
                if (wsa_err != ERROR_IO_PENDING) {
                    int aws_error = s_determine_socket_error(wsa_err);
                    return aws_raise_error(aws_error);
                }
            }
        }
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    DWORD bytes_read = 0;
    size_t read_capacity = buffer->capacity - buffer->len;
    DWORD bytes_to_read = (DWORD)(bytes_available > read_capacity ? read_capacity : bytes_available);
    BOOL read_success = ReadFile(socket->io_handle.data.handle, buffer->buffer + buffer->len, 
        bytes_to_read, &bytes_read, NULL);

    if (!read_success) {
        int error_code = GetLastError();
        return aws_raise_error(s_determine_socket_error(error_code));
    }

    *amount_read = bytes_read;
    buffer->len += bytes_read;
    return AWS_OP_SUCCESS;
}

static int s_tcp_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read) {
    assert(socket->readable_fn);

    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (!(socket->state & CONNECTED_READ)) {
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    int read_val = recv((SOCKET)socket->io_handle.data.handle, (char *)buffer->buffer + buffer->len, 
        (int)(buffer->capacity - buffer->len), 0);

    if (read_val > 0) {
        *amount_read = (size_t)read_val;
        buffer->len += *amount_read;
        return AWS_OP_SUCCESS;
    }

    int error = WSAGetLastError();

    if (error == WSAEWOULDBLOCK) {
        if (!(socket->state & WAITING_ON_READABLE)) {
            struct iocp_socket *iocp_socket = socket->impl;
            socket->state |= WAITING_ON_READABLE;
            aws_overlapped_reset(iocp_socket->read_signal);
            aws_overlapped_init(iocp_socket->read_signal, s_stream_readable_event, socket);
            int fake_buffer = 0;
            iocp_socket->pending_operations |= PENDING_READ;
            int err = ReadFile(socket->io_handle.data.handle, &fake_buffer, 0, NULL, 
                &iocp_socket->read_signal->overlapped);
            if (err) {
                int wsa_err = WSAGetLastError();
                if (wsa_err != ERROR_IO_PENDING) {
                    int aws_error = s_determine_socket_error(wsa_err);
                    return aws_raise_error(aws_error);
                }
            }
        }

        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    if (error == EPIPE) {
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
}

static int s_dgram_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read) {
    assert(socket->readable_fn);

    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (!(socket->state & CONNECTED_READ)) {
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    int read_val = recv((SOCKET)socket->io_handle.data.handle, (char *)buffer->buffer + buffer->len, 
        (int)(buffer->capacity - buffer->len), 0);

    if (read_val > 0) {
        *amount_read = (size_t)read_val;
        buffer->len += *amount_read;
        return AWS_OP_SUCCESS;
    }

    int error = WSAGetLastError();

    if (error == WSAEWOULDBLOCK) {
        if (!(socket->state & WAITING_ON_READABLE)) {
            struct iocp_socket *iocp_socket = socket->impl;
            socket->state |= WAITING_ON_READABLE;
            aws_overlapped_reset(iocp_socket->read_signal);
            aws_overlapped_init(iocp_socket->read_signal, s_stream_readable_event, socket);
            iocp_socket->pending_operations |= PENDING_READ;
            /* the zero byte read trick with ReadFile doesn't actually work for UDP because it actually
            clears the buffer from the kernel, but if we use WSARecv, we can tell it we just want to peek
            which won't clear the kernel buffers. Giving it a BS buffer with 0 len seems to do the trick. */
            WSABUF buf = {
                .len = 0,
                .buf = NULL,
            };

            DWORD flags = MSG_PEEK;
            int err = WSARecv((SOCKET)socket->io_handle.data.handle, &buf, 1, NULL, &flags, 
                &iocp_socket->read_signal->overlapped, NULL);
            if (err) {
                int wsa_err = WSAGetLastError();
                if (wsa_err != ERROR_IO_PENDING) {
                    int aws_error = s_determine_socket_error(wsa_err);
                    return aws_raise_error(aws_error);
                }
            }
        }

        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    if (error == EPIPE) {
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
}

struct write_cb_args {
    struct aws_overlapped write_overlap;
    struct aws_socket *socket;
    struct aws_byte_cursor cursor;
    aws_socket_on_data_written_fn *user_callback;
    void *user_data;
};

/* Invoked for TCP, UDP, and Local when a message has been completely written to the wire.*/
static void s_socket_written_event(struct aws_event_loop *event_loop, struct aws_overlapped *overlapped, 
    int status_code, size_t num_bytes_transferred) {
    (void)event_loop;

    struct write_cb_args *write_cb_args = overlapped->user_data;

    if (status_code == WSA_OPERATION_ABORTED || status_code == IO_OPERATION_CANCELLED) {
        aws_mem_release(overlapped->alloc, write_cb_args);
        aws_mem_release(overlapped->alloc, overlapped);
        return;
    }

    struct aws_socket *socket = write_cb_args->socket;
    struct iocp_socket *socket_impl = socket->impl;
    socket_impl->pending_operations &= ~PENDING_WRITE;

    int err_code = AWS_OP_SUCCESS;

    if (status_code) {
        err_code = s_determine_socket_error(WSAGetLastError());
    }
    else {
        assert(num_bytes_transferred == write_cb_args->cursor.len);
    }
    
    struct aws_byte_cursor cursor = write_cb_args->cursor;
    void *user_data = write_cb_args->user_data;
    aws_socket_on_data_written_fn *callback = write_cb_args->user_callback;
    aws_mem_release(write_cb_args->socket->allocator, write_cb_args);

    callback(socket, err_code, &cursor, user_data);
}

int aws_socket_write(struct aws_socket *socket, struct aws_byte_cursor *cursor,
    aws_socket_on_data_written_fn *written_fn, void *user_data) {
    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (!(socket->state & CONNECTED_WRITE)) {
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    struct write_cb_args *write_cb_data = aws_mem_acquire(socket->allocator, sizeof(struct write_cb_args));

    if (!write_cb_data) {
        return AWS_OP_ERR;
    }

    write_cb_data->socket = socket;
    write_cb_data->user_callback = written_fn;
    write_cb_data->user_data = user_data;
    write_cb_data->cursor = *cursor;

    aws_overlapped_init(&write_cb_data->write_overlap, s_socket_written_event, write_cb_data);
    write_cb_data->write_overlap.alloc = socket->allocator;

    struct iocp_socket *socket_impl = socket->impl;
    socket_impl->pending_operations |= PENDING_WRITE;

    BOOL res = WriteFile(socket->io_handle.data.handle, cursor->ptr, (DWORD)cursor->len, NULL, 
        &write_cb_data->write_overlap.overlapped);

    if (!res) {
        int error_code = GetLastError();
        if (error_code != ERROR_IO_PENDING) {
            socket_impl->pending_operations &= ~PENDING_WRITE;

            aws_mem_release(socket->allocator, write_cb_data);
            return aws_raise_error(s_determine_socket_error(error_code));
        }
    }    
    
    return AWS_OP_SUCCESS;  
}

int aws_socket_get_error(struct aws_socket *socket) {
    if (socket->options.domain != AWS_SOCKET_LOCAL) {
        int connect_result;
        socklen_t result_length = sizeof(connect_result);
        if (getsockopt((SOCKET)socket->io_handle.data.handle, SOL_SOCKET, SO_ERROR, 
            (char *)&connect_result, &result_length) < 0) {
            return AWS_OP_ERR;
        }


        if (connect_result) {
            return s_determine_socket_error(connect_result);
        }
    }
    else {
        return s_determine_socket_error(GetLastError());
    }

    return AWS_OP_SUCCESS;
}

bool aws_socket_is_open(struct aws_socket *socket) {
    return socket->io_handle.data.handle != INVALID_HANDLE_VALUE;
}
