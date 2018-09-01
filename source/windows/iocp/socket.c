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
#include <aws/io/socket.h>

#include <aws/common/byte_buf.h>
#include <aws/common/task_scheduler.h>
#include <aws/io/event_loop.h>
#include <aws/io/pipe.h>

#include <WS2tcpip.h>
#include <assert.h>
#include <aws/io/io.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum socket_state {
    INIT = 0x01,
    CONNECTING = 0x02,
    CONNECTED_READ = 0x04,
    CONNECTED_WRITE = 0x08,
    BOUND = 0x10,
    LISTENING = 0x20,
    TIMEDOUT = 0x40,
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

struct iocp_socket {
    struct aws_overlapped read_signal;
};

static int create_socket(struct aws_socket *sock, struct aws_socket_options *options) {
    struct iocp_socket *iocp_socket = sock->impl;
    SOCKET handle = socket(convert_domain(options->domain), convert_type(options->type), 0);
    u_long non_blocking = 1;
    if (handle != INVALID_SOCKET && !ioctlsocket(handle, FIONBIO, &non_blocking)) {       
        sock->io_handle.data.handle = handle;
        sock->io_handle.additional_data = NULL;
        return aws_socket_set_options(sock, options);
    }

    int error_code = WSAGetLastError();

    if (error_code == WSAENOBUFS) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    if (error_code == WSAEMFILE) {
        return aws_raise_error(AWS_IO_MAX_FDS_EXCEEDED);
    }

    if (error_code == WSAEAFNOSUPPORT) {
        return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
    }

    if (error_code == WSAEACCES) {
        return aws_raise_error(AWS_IO_NO_PERMISSION);
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
}

int aws_socket_init(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    struct aws_socket_options *options,
    struct aws_socket_creation_args *creation_args) {
    assert(options);
    assert(creation_args);

    socket->event_loop = NULL;

    socket->creation_args = *creation_args;
    socket->allocator = alloc;
    socket->io_handle.data.handle = INVALID_HANDLE_VALUE;
    socket->io_handle.additional_data = NULL;
    socket->state = INIT;

    return create_socket(socket, options);
}

void aws_socket_clean_up(struct aws_socket *socket) {
    aws_socket_shutdown(socket);
    AWS_ZERO_STRUCT(*socket);
    socket->io_handle.data.fd = -1;
}

static void on_connection_error(struct aws_socket *socket, int error);

static int on_connection_success(struct aws_socket *socket) {
    
    if (aws_socket_set_options(socket, &socket->options)) {
        aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);

        if (socket->creation_args.on_error && socket->options.type == AWS_SOCKET_STREAM) {
            socket->creation_args.on_error(socket, AWS_IO_SOCKET_INVALID_OPTIONS, socket->creation_args.user_data);
        }

        return AWS_OP_ERR;
    }

    int connect_result;
    socklen_t result_length = sizeof(connect_result);

    if (getsockopt(socket->io_handle.data.fd, SOL_SOCKET, SO_ERROR, &connect_result, &result_length) < 0) {
        on_connection_error(socket, WSAGetLastError());
        return AWS_OP_ERR;
    }

    if (connect_result) {
        on_connection_error(socket, connect_result);
        return AWS_OP_ERR;
    }

    struct sockaddr_storage address;
    AWS_ZERO_STRUCT(address);
    socklen_t address_size = sizeof(address);
    if (!getsockname(socket->io_handle.data.handle, (struct sockaddr *)&address, &address_size)) {
        uint16_t port = 0;

        if (address.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&address;
            port = ntohs(s->sin_port);
            InetNtopA(AF_INET, &s->sin_addr, socket->local_endpoint.address, sizeof(socket->local_endpoint.address));
        }
        else if (address.ss_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&address;
            port = ntohs(s->sin6_port);
            InetNtopA(AF_INET6, &s->sin6_addr, socket->local_endpoint.address, sizeof(socket->local_endpoint.address));
        }
        else if (address.ss_family == AF_UNIX) {
            struct sockaddr_in *s = (struct sockaddr_in *)&address;
            InetNtopA(
                AF_INET, &s->sin_addr, socket->local_endpoint.socket_name, sizeof(socket->local_endpoint.socket_name));
        }
        sprintf(socket->local_endpoint.port, "%d", port);
    }
    else {
        on_connection_error(socket, WSAGetLastError());
        return AWS_OP_ERR;
    }

    socket->state = CONNECTED_WRITE;
    if (socket->options.type == AWS_SOCKET_STREAM) {
        socket->state |= CONNECTED_READ;
    }

    if (socket->creation_args.on_connection_established && socket->options.type == AWS_SOCKET_STREAM) {
        socket->creation_args.on_connection_established(socket, socket->creation_args.user_data);
    }

    return AWS_OP_SUCCESS;
}

static int s_determine_socket_error(int error) {
    switch (error) {
    case WSAECONNREFUSED:
        return AWS_IO_SOCKET_CONNECTION_REFUSED;
    case WSAETIMEDOUT:
        return AWS_IO_SOCKET_TIMEOUT;
    case WSAENETUNREACH:
        return AWS_IO_SOCKET_NO_ROUTE_TO_HOST;
    case WSAENETDOWN:
        return AWS_IO_SOCKET_NETWORK_DOWN;
    case WSAECONNABORTED:
        return AWS_IO_SOCKET_CONNECT_ABORTED;
    case WSAENOBUFS:
        return AWS_ERROR_OOM;
    case WSAEMFILE:
        return AWS_IO_MAX_FDS_EXCEEDED;
    case WSAENAMETOOLONG:
    case WSA_INVALID_PARAMETER:
        return AWS_IO_FILE_INVALID_PATH;
    case 0:
        return AWS_IO_SOCKET_NOT_CONNECTED;
    default:
        return AWS_IO_SOCKET_NOT_CONNECTED;
    }
}

static void s_on_connection_error(struct aws_socket *socket, int error) {
    int error_code = s_determine_socket_error(error);

    aws_raise_error(error_code);
    socket->state = ERROR;
    if (socket->creation_args.on_error && socket->options.type == AWS_SOCKET_STREAM) {
        socket->creation_args.on_error(socket, error_code, socket->creation_args.user_data);
    }
}

struct socket_connect_args {
    struct aws_allocator *allocator;
    struct aws_socket *socket;
};

void s_socket_connection_completion(struct aws_event_loop *event_loop, struct aws_overlapped *overlapped, int status_code, size_t num_bytes_transferred) {
    struct socket_connect_args *socket_args = (struct socket_connect_args *)overlapped->user_data;

    if (socket_args->socket) {
        struct aws_socket *socket = overlapped->user_data;
        socket_args->socket = NULL;
        assert(socket->state == CONNECTING);
        
        if (!status_code) {
            socket->state = CONNECTED_READ | CONNECTED_WRITE;
            on_connection_success(socket);
        } else {
            s_on_connection_error(socket, WSAGetLastError());
        }
        return;        
    }
}

static void handle_socket_timeout(void *args, aws_task_status status) {
    struct socket_connect_args *socket_args = (struct socket_connect_args *)args;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        if (socket_args->socket) {
            socket_args->socket->state = TIMEDOUT;            
            socket_args->socket->event_loop = NULL;
            close(socket_args->socket->io_handle.data.handle);

            if (socket_args->socket->creation_args.on_error) {
                socket_args->socket->creation_args.on_error(
                    socket_args->socket, AWS_IO_SOCKET_TIMEOUT, socket_args->socket->creation_args.user_data);
            }
        }
    }

    aws_mem_release(socket_args->allocator, socket_args);
}

int aws_socket_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *connect_loop) {
    struct iocp_socket *iocp_socket = socket->impl;
    socket->state = CONNECTING;
    memcpy(socket->remote_endpoint.port, remote_endpoint->port, sizeof(remote_endpoint->port));
    memcpy(socket->remote_endpoint.socket_name, remote_endpoint->socket_name, sizeof(remote_endpoint->socket_name));
    memcpy(socket->remote_endpoint.address, remote_endpoint->address, sizeof(socket->remote_endpoint.address));

    if (socket->creation_args.on_connection_established) {
        socket->event_loop = connect_loop;
        aws_socket_assign_to_event_loop(socket, connect_loop);

        int error_code = -1;
        if (socket->options.domain == AWS_SOCKET_IPV4) {
            struct sockaddr_in addr_in;
            inet_pton(AF_INET, remote_endpoint->address, &(addr_in.sin_addr));
            addr_in.sin_port = htons((uint16_t)atoi(remote_endpoint->port));
            addr_in.sin_family = AF_INET;
            error_code = connect(socket->io_handle.data.handle, (struct sockaddr *)&addr_in, sizeof(addr_in));
        }
        else if (socket->options.domain == AWS_SOCKET_IPV6) {
            struct sockaddr_in6 addr_in;
            inet_pton(AF_INET6, remote_endpoint->address, &(addr_in.sin6_addr));
            addr_in.sin6_port = htons((uint16_t)atoi(remote_endpoint->port));
            addr_in.sin6_family = AF_INET6;
            error_code = connect(socket->io_handle.data.handle, (struct sockaddr *)&addr_in, sizeof(addr_in));
        }
       /* else if (socket->options.domain == AWS_SOCKET_LOCAL) {
            struct sockaddr_un addr;
            AWS_ZERO_STRUCT(addr);
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, remote_endpoint->socket_name, sizeof(addr.sun_path) - 1);
            error_code = connect(socket->io_handle.data.fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
        }*/
        else {
            assert(0);
            return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
        }

        if (!error_code) {
            socket->event_loop = NULL;
            on_connection_success(socket);
            return AWS_OP_SUCCESS;
        }

        error_code = WSAGetLastError();
        if (error_code == WSAEALREADY || error_code == WSAEWOULDBLOCK) {
            struct socket_connect_args *connect_args = aws_mem_acquire(socket->allocator, sizeof(struct socket_connect_args));

            if (!connect_args) {
                close(socket->io_handle.data.handle);
                return AWS_OP_ERR;
            }

            uint64_t time_to_run = 0;
            aws_event_loop_current_ticks(socket->event_loop, &time_to_run);
            time_to_run += (socket->options.connect_timeout * 1000000);

            aws_overlapped_init(&iocp_socket->read_signal, s_socket_connection_completion, socket);
            int fake_buffer = 0;
            ReadFile(socket->io_handle.data.handle, &fake_buffer, 0, NULL, &iocp_socket->read_signal.overlapped);

            struct aws_task task = { .fn = handle_socket_timeout,.arg = socket };
          
            return aws_event_loop_schedule_task(socket->event_loop, &task, time_to_run); 
        }

        socket->event_loop = NULL;
        on_connection_error(socket, error_code);
        return AWS_OP_ERR;
    }

    socket->event_loop = NULL;
    return aws_raise_error(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE);
}

int aws_socket_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint) {
    int error_code = -1;

    memcpy(socket->local_endpoint.port, local_endpoint->port, sizeof(local_endpoint->port));

    if (socket->options.domain == AWS_SOCKET_LOCAL) {
        memcpy(
            socket->local_endpoint.socket_name,
            local_endpoint->socket_name,
            sizeof(socket->local_endpoint.socket_name));
    }
    else {
        memcpy(socket->local_endpoint.address, local_endpoint->address, sizeof(socket->local_endpoint.address));
    }

    if (socket->options.domain == AWS_SOCKET_IPV4) {
        struct sockaddr_in addr_in;
        inet_pton(AF_INET, local_endpoint->address, &(addr_in.sin_addr));
        addr_in.sin_port = htons((uint16_t)atoi(local_endpoint->port));
        addr_in.sin_family = AF_INET;
        error_code = bind(socket->io_handle.data.fd, (struct sockaddr *)&addr_in, sizeof(addr_in));
    }
    else if (socket->options.domain == AWS_SOCKET_IPV6) {
        struct sockaddr_in6 addr_in;
        inet_pton(AF_INET6, local_endpoint->address, &(addr_in.sin6_addr));
        addr_in.sin6_port = htons((uint16_t)atoi(local_endpoint->port));
        addr_in.sin6_family = AF_INET6;
        error_code = bind(socket->io_handle.data.fd, (struct sockaddr *)&addr_in, sizeof(addr_in));
    }
    /*else if (socket->options.domain == AWS_SOCKET_LOCAL) {
        struct sockaddr_un name;
        AWS_ZERO_STRUCT(name);
        name.sun_family = AF_UNIX;
        strncpy(name.sun_path, local_endpoint->socket_name, sizeof(name.sun_path) - 1);
        error_code = bind(socket->io_handle.data.fd, (const struct sockaddr *)&name, sizeof(struct sockaddr_un));
    }*/

    if (!error_code) {
        if (socket->options.type == AWS_SOCKET_STREAM) {
            socket->state = BOUND;
        }
        else {
            socket->state = CONNECTED_READ;
        }

        return AWS_OP_SUCCESS;
    }

    socket->event_loop = NULL;
    socket->state = ERROR;
    error_code = errno;
    if (error_code == EACCES || error_code == EPERM) {
        return aws_raise_error(AWS_IO_NO_PERMISSION);
    }

    if (error_code == EADDRINUSE) {
        return aws_raise_error(AWS_IO_SOCKET_ADDRESS_IN_USE);
    }

    if (error_code == EINVAL || error_code == ENAMETOOLONG || error_code == ENOENT) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_ADDRESS);
    }

    if (error_code == ENOMEM) {
        return AWS_OP_ERR;
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
}

int aws_socket_listen(struct aws_socket *socket, int backlog_size) {
    if (socket->options.type != AWS_SOCKET_STREAM) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE);
    }

    if (AWS_UNLIKELY(socket->state != BOUND)) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    int error_code = listen(socket->io_handle.data.handle, backlog_size);

    if (!error_code) {
        socket->state = LISTENING;
        return AWS_OP_SUCCESS;
    }

    error_code = errno;
    socket->state = ERROR;

    if (error_code == EADDRINUSE) {
        return aws_raise_error(AWS_IO_SOCKET_ADDRESS_IN_USE);
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
}

static void s_socket_accept_event(struct aws_event_loop *event_loop, struct aws_overlapped *overlapped, int status_code, size_t num_bytes_transferred) {

    (void)event_loop;

    struct aws_socket *socket = (struct aws_socket *)overlapped->user_data;

    if (!status_code) {
        SOCKET in_sock = 0;
        while (in_sock != INVALID_SOCKET) {
            struct sockaddr_storage in_addr;
            socklen_t in_len = sizeof(struct sockaddr_storage);

            in_sock = accept(socket->io_handle.data.handle, (struct sockaddr *)&in_addr, &in_len);
            if (in_sock == -1) {
                int error = errno;

                if (error == EAGAIN || error == EWOULDBLOCK) {
                    break;
                }

                on_connection_error(socket, error);
                continue;
            }

            struct aws_socket *new_sock =
                (struct aws_socket *)aws_mem_acquire(socket->allocator, sizeof(struct aws_socket));

            if (!new_sock) {
                break;
            }

            new_sock->allocator = socket->allocator;
            new_sock->io_handle = (struct aws_io_handle) { .data = { .handle = in_sock }, .additional_data = NULL };
            AWS_ZERO_STRUCT(new_sock->creation_args);
            new_sock->event_loop = NULL;
            AWS_ZERO_STRUCT(new_sock->options);
            new_sock->options.type = AWS_SOCKET_STREAM;
            new_sock->state = CONNECTED_WRITE | CONNECTED_READ;
            memcpy(&new_sock->local_endpoint, &socket->local_endpoint, sizeof(socket->local_endpoint));
            AWS_ZERO_STRUCT(new_sock->remote_endpoint);

            uint16_t port = 0;

            if (in_addr.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&in_addr;
                port = ntohs(s->sin_port);
                InetNtopA(
                    AF_INET,
                    &s->sin_addr,
                    new_sock->remote_endpoint.address,
                    sizeof(new_sock->remote_endpoint.address));
                new_sock->options.domain = AWS_SOCKET_IPV4;
            }
            else if (in_addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&in_addr;
                port = ntohs(s->sin6_port);
                InetNtopA(
                    AF_INET6,
                    &s->sin6_addr,
                    new_sock->remote_endpoint.address,
                    sizeof(new_sock->remote_endpoint.address));
                new_sock->options.domain = AWS_SOCKET_IPV6;
            }
            else if (in_addr.ss_family == AF_UNIX) {
                memcpy(&new_sock->remote_endpoint, &socket->local_endpoint, sizeof(socket->local_endpoint));
                new_sock->options.domain = AWS_SOCKET_LOCAL;
            }

            sprintf(socket->remote_endpoint.port, "%d", port);

            u_long non_blocking = 1;
            ioctlsocket(in_sock, FIONBIO, &non_blocking);            
            aws_socket_set_options(new_sock, &socket->options);

            socket->creation_args.on_incoming_connection(socket, new_sock, socket->creation_args.user_data);
        }
        struct iocp_socket *iocp_socket = socket->impl;
        aws_overlapped_reset(&iocp_socket->read_signal);
        aws_overlapped_init(&iocp_socket->read_signal, s_socket_accept_event, socket);
        int fake_buffer = 0;
        ReadFile(socket->io_handle.data.handle, &fake_buffer, 0, NULL, &iocp_socket->read_signal);
    }
}

int aws_socket_start_accept(struct aws_socket *socket, struct aws_event_loop *accept_loop) {
    if (socket->options.type != AWS_SOCKET_STREAM) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE);
    }

    if (AWS_UNLIKELY(socket->state != LISTENING)) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    aws_socket_assign_to_event_loop(socket, accept_loop);
    struct iocp_socket *iocp_socket = socket->impl;
    aws_overlapped_reset(&iocp_socket->read_signal);
    aws_overlapped_init(&iocp_socket->read_signal, s_socket_accept_event, socket);
    int fake_buffer = 0;
    ReadFile(socket->io_handle.data.handle, &fake_buffer, 0, NULL, &iocp_socket->read_signal);
    return AWS_OP_SUCCESS;
}

int aws_socket_stop_accept(struct aws_socket *socket) {
    if (socket->options.type != AWS_SOCKET_STREAM) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE);
    }

    int ret_val = aws_event_loop_unsubscribe_from_io_events(socket->event_loop, &socket->io_handle);
    socket->event_loop = NULL;
    return ret_val;
}

int aws_socket_set_options(struct aws_socket *socket, struct aws_socket_options *options) {
    socket->options = *options;

    int reuse = 1;
    setsockopt(socket->io_handle.data.handle, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

    if (socket->options.send_timeout) {
        int send_timeout = (int)socket->options.send_timeout;
        setsockopt(socket->io_handle.data.handle, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(int));
    }

    if (socket->options.read_timeout) {
        int read_timeout = (int)socket->options.read_timeout;
        setsockopt(socket->io_handle.data.handle, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(int));
    }

    if (socket->options.keepalive) {
        int keep_alive = 1;
        setsockopt(socket->io_handle.data.handle, SOL_SOCKET, SO_KEEPALIVE, &keep_alive, sizeof(int));
    }

    if (socket->options.linger_time) {
        struct linger linger;
        linger.l_onoff = 1;
        linger.l_linger = (int)socket->options.linger_time;
        setsockopt(socket->io_handle.data.handle, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger));
    }

    return AWS_OP_SUCCESS;
}

int aws_socket_shutdown(struct aws_socket *socket) {
    if (socket->event_loop) {
        int err_code = aws_event_loop_unsubscribe_from_io_events(socket->event_loop, &socket->io_handle);

        if (err_code) {
            return AWS_OP_ERR;
        }
        socket->event_loop = NULL;
    }

    if (socket->io_handle.data.handle != INVALID_HANDLE_VALUE) {
        close(socket->io_handle.data.handle);
        socket->io_handle.data.handle = INVALID_HANDLE_VALUE;
    }

    return AWS_OP_SUCCESS;
}

int aws_socket_half_close(struct aws_socket *socket, enum aws_channel_direction dir) {
    int how = dir == AWS_CHANNEL_DIR_READ ? 0 : 1;

    if (shutdown(socket->io_handle.data.handle, how)) {
        on_connection_error(socket, errno);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

struct aws_io_handle *aws_socket_get_io_handle(struct aws_socket *socket) {
    return &socket->io_handle;
}

int aws_socket_assign_to_event_loop(struct aws_socket *socket, struct aws_io_event_loop *event_loop) {
    assert(!socket->event_loop);
    socket->event_loop = event_loop;
    return aws_event_loop_connect_handle_to_io_completion_port(event_loop, &socket->io_handle);
}

struct aws_io_event_loop *aws_socket_get_event_loop(struct aws_socket *socket) {
    return socket->event_loop;
}

int aws_socket_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read) {
    if (!(socket->state & CONNECTED_READ)) {
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    int read_val = read(socket->io_handle.data.handle, buffer->buffer + buffer->len, buffer->capacity - buffer->len);

    if (read_val > 0) {
        *amount_read = (size_t)read_val;
        buffer->len += *amount_read;
        return AWS_OP_SUCCESS;
    }

    int error = WSAGetLastError();

    if (error == WSAEWOULDBLOCK) {
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    if (error == EPIPE) {
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
}

struct read_cb_args {
    struct aws_socket *socket;
    aws_socket_on_readable_fn *user_callback;
    void *user_data;
};

static void s_socket_readable_event(struct aws_event_loop *event_loop, struct aws_overlapped *overlapped, int status_code, size_t num_bytes_transferred) {
    (void)num_bytes_transferred;
    
    struct read_cb_args *read_args = overlapped->user_data;

    int err_code = AWS_OP_SUCCESS;
    if (status_code) {
        err_code = s_determine_socket_error(WSAGetLastError());
    }

    read_args->user_callback(read_args->socket, err_code, read_args->user_data);
    aws_mem_release(read_args->socket->allocator, read_args);
}

int aws_socket_subscribe_to_readable_event(struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable, void *user_data) {
    assert(socket->event_loop);

    struct read_cb_args *read_args = aws_mem_acquire(socket->allocator, sizeof(struct read_cb_args));

    if (!read_args) {
        return AWS_OP_ERR;
    }

    read_args->socket = socket;
    read_args->user_callback = on_readable;
    read_args->user_data = user_data;

    struct iocp_socket *iocp_socket = socket->impl;
    aws_overlapped_reset(&iocp_socket->read_signal);
    aws_overlapped_init(&iocp_socket->read_signal, s_socket_readable_event, read_args);

    int fake_buffer = 0;
    ReadFile(socket->io_handle.data.handle, &fake_buffer, 0, NULL, &iocp_socket->read_signal);
    return AWS_OP_SUCCESS;
}

struct write_cb_args {
    struct aws_overlapped write_overlap;
    struct aws_socket *socket;
    struct aws_byte_cursor *cursor;
    aws_socket_on_data_written_fn *user_callback;
    void *user_data;
};

static void s_socket_written_event(struct aws_event_loop *event_loop, struct aws_overlapped *overlapped, int status_code, size_t num_bytes_transferred) {
    struct write_cb_args *write_cb_args = overlapped->user_data;

    int err_code = AWS_OP_SUCCESS;

    if (status_code) {
        err_code = s_determine_socket_error(WSAGetLastError());
    }
    else {
        assert(num_bytes_transferred == write_cb_args->cursor->len);
    }

    write_cb_args->user_callback(write_cb_args->socket, err_code, write_cb_args->cursor, write_cb_args->user_data);
    aws_mem_release(write_cb_args->socket->allocator, write_cb_args);
}

int aws_socket_write(struct aws_socket *socket, struct aws_byte_cursor *cursor,
    aws_socket_on_data_written_fn *written_fn, void *user_data) {
    assert(socket->event_loop);

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
    write_cb_data->cursor = cursor;
    aws_overlapped_init(&write_cb_data->write_overlap, s_socket_written_event, write_cb_data);
    WriteFile(socket->io_handle.data.handle, cursor->ptr, cursor->len, NULL, &write_cb_data->write_overlap);
    
    return AWS_OP_SUCCESS;  
}

int aws_socket_get_error(struct aws_socket *socket) {
    int connect_result;
    socklen_t result_length = sizeof(connect_result);

    if (getsockopt(socket->io_handle.data.fd, SOL_SOCKET, SO_ERROR, &connect_result, &result_length) < 0) {
        return AWS_OP_ERR;
    }

    if (connect_result) {
        return determine_socket_error(connect_result);
    }

    return AWS_OP_SUCCESS;
}

bool aws_socket_is_open(struct aws_socket *socket) {
    return socket->io_handle.data.handle != INVALID_HANDLE_VALUE;
}
