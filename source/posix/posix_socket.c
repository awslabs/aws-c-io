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
#include <aws/io/event_loop.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/byte_buf.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <stdlib.h>
#include <sys/un.h>
#include <zconf.h>
#include <signal.h>
#include <stdio.h>
#include <aws/io/io.h>

enum socket_state {
    INIT = 0x01,
    CONNECTING = 0x02,
    CONNECTED_READ = 0x04,
    CONNECTED_WRITE = 0x08,
    BOUND = 0x10,
    LISTENING = 0x20,
    TIMEDOUT = 0x40,
    ERROR = 0x80
};

static int convert_domain(enum aws_socket_domain domain) {
    switch(domain) {
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
    switch(type) {
        case AWS_SOCKET_STREAM:
            return SOCK_STREAM;
        case AWS_SOCKET_DGRAM:
            return SOCK_DGRAM;
        default:
            assert(0);
            return SOCK_STREAM;
    }
}

static int create_socket(struct aws_socket *sock, struct aws_socket_options *options) {

    int fd = socket(convert_domain(options->domain), convert_type(options->type),  0);
    int flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    flags |= O_CLOEXEC;
    fcntl(fd, F_SETFL, flags);

    if(fd != -1) {
        sock->io_handle.data.fd = fd;
        sock->io_handle.additional_data = NULL;
        return aws_socket_set_options(sock, options);
    }

    int error_code = errno;

    if(error_code == ENOBUFS || error_code == ENOMEM) {
        return AWS_OP_ERR;
    }

    if(error_code == EMFILE  || error_code == ENFILE ) {
        return aws_raise_error(AWS_IO_MAX_FDS_EXCEEDED);
    }

    if(error_code == EAFNOSUPPORT) {
        return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
    }

    if(error_code == EACCES) {
        return aws_raise_error(AWS_IO_NO_PERMISSION);
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
}

int aws_socket_init(struct aws_socket *socket, struct aws_allocator *alloc,
                             struct aws_socket_options *options, struct aws_event_loop *connection_loop,
                             struct aws_socket_creation_args *creation_args) {
    assert(options);
    assert(creation_args);

    if (options->type == AWS_SOCKET_STREAM && !connection_loop) {
        assert(0);
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
    }

    socket->connection_loop = NULL;

    if (options->type == AWS_SOCKET_STREAM) {
        socket->connection_loop = connection_loop;
    }

    socket->creation_args = *creation_args;
    socket->allocator = alloc;
    socket->io_handle.data.fd = -1;
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

    if (socket->connection_loop) {
        aws_event_loop_unsubscribe_from_io_events(socket->connection_loop, &socket->io_handle);
        socket->connection_loop = NULL;
    }

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
        on_connection_error(socket, errno);
        return AWS_OP_ERR;
    }

    if (connect_result) {
        on_connection_error(socket, connect_result);
        return AWS_OP_ERR;
    }
    else {
        struct sockaddr_storage address;
        AWS_ZERO_STRUCT(address);
        socklen_t address_size = sizeof(address);
        if (!getsockname(socket->io_handle.data.fd, (struct sockaddr *)&address, &address_size)) {
            uint16_t port = 0;

            if (address.ss_family == AF_INET)
            {
                struct sockaddr_in *s = (struct sockaddr_in *) &address;
                port = ntohs(s->sin_port);
                inet_ntop(AF_INET, &s->sin_addr, socket->local_endpoint.address, sizeof(socket->local_endpoint.address));
            }
            else if (address.ss_family == AF_INET6)
            {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *) &address;
                port = ntohs(s->sin6_port);
                inet_ntop(AF_INET6, &s->sin6_addr, socket->local_endpoint.address, sizeof(socket->local_endpoint.address));
            }
            else if (address.ss_family == AF_UNIX) {
                struct sockaddr_in *s = (struct sockaddr_in *) &address;
                inet_ntop(AF_INET, &s->sin_addr, socket->local_endpoint.socket_name, sizeof(socket->local_endpoint.socket_name));
            }
            sprintf(socket->local_endpoint.port, "%d", port);
        }
        else {
            on_connection_error(socket, errno);
            return AWS_OP_ERR;
        }
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

static int determine_socket_error(int error) {
    switch(error) {
        case ECONNREFUSED:
            return AWS_IO_SOCKET_CONNECTION_REFUSED;
        case ETIMEDOUT:
            return AWS_IO_SOCKET_TIMEOUT;
        case ENETUNREACH:
            return AWS_IO_SOCKET_NO_ROUTE_TO_HOST;
        case ENETDOWN:
            return AWS_IO_SOCKET_NETWORK_DOWN;
        case ECONNABORTED:
            return AWS_IO_SOCKET_CONNECT_ABORTED;
        case ENOBUFS:
        case ENOMEM:
            return AWS_ERROR_OOM;
        case EMFILE:
        case ENFILE:
            return AWS_IO_MAX_FDS_EXCEEDED;
        case ENOENT:
            return AWS_IO_FILE_NOT_FOUND;
        case 0:
            return AWS_IO_SOCKET_NOT_CONNECTED;
        default:
            return AWS_IO_SOCKET_NOT_CONNECTED;
    }

}

static void on_connection_error(struct aws_socket *socket, int error) {
    int error_code = determine_socket_error(error);

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

void socket_connect_event(struct aws_event_loop *event_loop, struct aws_io_handle *handle, int events, void *user_data) {
    struct socket_connect_args *socket_args = (struct socket_connect_args *)user_data;

    if (events & AWS_IO_EVENT_TYPE_READABLE || events & AWS_IO_EVENT_TYPE_WRITABLE) {
        if (socket_args->socket) {
            struct aws_socket *socket = socket_args->socket;
            socket_args->socket = NULL;
            on_connection_success(socket);
        }
        return;
    }

    on_connection_error(socket_args->socket, errno);
}

static void handle_socket_timeout (void *args, aws_task_status status) {
    struct socket_connect_args *socket_args = (struct socket_connect_args *)args;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        if (socket_args->socket) {
            socket_args->socket->state = TIMEDOUT;
            aws_event_loop_unsubscribe_from_io_events(socket_args->socket->connection_loop, &socket_args->socket->io_handle);
            socket_args->socket->connection_loop = NULL;
            close(socket_args->socket->io_handle.data.fd);

            if (socket_args->socket->creation_args.on_error) {
                socket_args->socket->creation_args.on_error(socket_args->socket, AWS_IO_SOCKET_TIMEOUT,
                                                            socket_args->socket->creation_args.user_data);
            }
        }
    }

    aws_mem_release(socket_args->allocator, socket_args);
}

int aws_socket_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint) {

    socket->state = CONNECTING;
    memcpy(socket->remote_endpoint.port, remote_endpoint->port, sizeof(remote_endpoint->port));
    memcpy(socket->remote_endpoint.socket_name, remote_endpoint->socket_name, sizeof(remote_endpoint->socket_name));
    memcpy(socket->remote_endpoint.address, remote_endpoint->address, sizeof(socket->remote_endpoint.address));

    if (socket->creation_args.on_connection_established) {
        int error_code = -1;
        if (socket->options.domain == AWS_SOCKET_IPV4) {
            struct sockaddr_in addr_in;
            inet_pton(AF_INET, remote_endpoint->address, &(addr_in.sin_addr));
            addr_in.sin_port = htons((uint16_t)atoi(remote_endpoint->port));
            addr_in.sin_family = AF_INET;
            error_code = connect(socket->io_handle.data.fd, (struct sockaddr *)&addr_in, sizeof(addr_in));
        }
        else if (socket->options.domain == AWS_SOCKET_IPV6) {
            struct sockaddr_in6 addr_in;
            inet_pton(AF_INET6, remote_endpoint->address, &(addr_in.sin6_addr));
            addr_in.sin6_port = htons((uint16_t)atoi(remote_endpoint->port));
            addr_in.sin6_family = AF_INET6;
            error_code = connect(socket->io_handle.data.fd, (struct sockaddr *)&addr_in, sizeof(addr_in));
        }
        else if (socket->options.domain == AWS_SOCKET_LOCAL) {
            struct sockaddr_un addr;
            AWS_ZERO_STRUCT(addr);
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, remote_endpoint->socket_name, sizeof(addr.sun_path) - 1);
            error_code = connect (socket->io_handle.data.fd, (const struct sockaddr *) &addr,
                           sizeof(struct sockaddr_un));
        }
        else {
            assert(0);
            return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
        }

        if(!error_code) {
            socket->connection_loop = NULL;
            on_connection_success(socket);
            return AWS_OP_SUCCESS;
        }

        error_code = errno;
        if(error_code == EINPROGRESS || error_code == EALREADY) {
            struct socket_connect_args *sock_args = (struct socket_connect_args *)aws_mem_acquire(socket->allocator,
                                                                                                    sizeof(struct socket_connect_args));

            if (!sock_args) {
                close(socket->io_handle.data.fd);
                return AWS_OP_ERR;
            }

            sock_args->socket = socket;
            sock_args->allocator = socket->allocator;

            uint64_t time_to_run = 0;
            aws_event_loop_current_ticks(socket->connection_loop, &time_to_run);
            time_to_run += (socket->options.connect_timeout * 1000000);

            struct aws_task task = {
                    .fn = handle_socket_timeout,
                    .arg = sock_args
            };

            if (!aws_event_loop_subscribe_to_io_events(socket->connection_loop, &socket->io_handle,
                                                         AWS_IO_EVENT_TYPE_READABLE | AWS_IO_EVENT_TYPE_WRITABLE,
                                                         socket_connect_event, sock_args)) {
                return aws_event_loop_schedule_task(socket->connection_loop, &task, time_to_run);
            }

            aws_mem_release(socket->allocator, sock_args);
            return AWS_OP_ERR;
        }

        socket->connection_loop = NULL;
        on_connection_error(socket, error_code);
        return AWS_OP_ERR;
    }

    socket->connection_loop = NULL;
    return aws_raise_error(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE);
}

int aws_socket_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint) {
    int error_code = -1;

    memcpy(socket->local_endpoint.port, local_endpoint->port, sizeof(local_endpoint->port));

    if (socket->options.domain == AWS_SOCKET_LOCAL) {
        memcpy(socket->local_endpoint.socket_name, local_endpoint->socket_name, sizeof(socket->local_endpoint.socket_name));
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
    else if (socket->options.domain == AWS_SOCKET_LOCAL) {
        struct sockaddr_un name;
        AWS_ZERO_STRUCT(name);
        name.sun_family = AF_UNIX;
        strncpy(name.sun_path, local_endpoint->socket_name , sizeof(name.sun_path) - 1);
        error_code = bind(socket->io_handle.data.fd, (const struct sockaddr *) &name, sizeof(struct sockaddr_un));
    }

    if(!error_code) {
        if (socket->options.type == AWS_SOCKET_STREAM) {
            socket->state = BOUND;
        }
        else {
            socket->state = CONNECTED_READ;
        }

        return AWS_OP_SUCCESS;
    }

    socket->connection_loop = NULL;
    socket->state = ERROR;
    error_code = errno;
    if(error_code == EACCES || error_code == EPERM) {
        return aws_raise_error(AWS_IO_NO_PERMISSION);
    }

    if(error_code == EADDRINUSE) {
        return aws_raise_error(AWS_IO_SOCKET_ADDRESS_IN_USE);
    }

    if(error_code == EINVAL || error_code == ENAMETOOLONG || error_code == ENOENT) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_ADDRESS);
    }

    if(error_code == ENOMEM) {
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

    int error_code = listen(socket->io_handle.data.fd, backlog_size);

    if(!error_code) {
        socket->state = LISTENING;
        return AWS_OP_SUCCESS;
     }

    error_code = errno;
    socket->state = ERROR;

     if(error_code == EADDRINUSE) {
         return aws_raise_error(AWS_IO_SOCKET_ADDRESS_IN_USE);
     }

     return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
}

static void socket_accept_event(struct aws_event_loop *event_loop, struct aws_io_handle *handle, int events, void *user_data) {
    struct aws_socket *socket = (struct aws_socket *) user_data;

    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        int in_fd = 0;
        while (in_fd != -1) {
            struct sockaddr_storage in_addr;
            socklen_t in_len = sizeof(struct sockaddr_storage);

            in_fd = accept(handle->data.fd, (struct sockaddr *) &in_addr, &in_len);
            if (in_fd == -1) {
                int error = errno;

                if (error == EAGAIN || error == EWOULDBLOCK) {
                    break;
                }

                on_connection_error(socket, error);
                continue;
            }

            struct aws_socket *new_sock = (struct aws_socket *)aws_mem_acquire(socket->allocator, sizeof (struct aws_socket));

            if (!new_sock) {
                break;
            }

            new_sock->allocator = socket->allocator;
            new_sock->io_handle = (struct aws_io_handle){.data = {.fd = in_fd}, .additional_data = NULL};
            AWS_ZERO_STRUCT(new_sock->creation_args);
            new_sock->connection_loop = NULL;
            AWS_ZERO_STRUCT(new_sock->options);
            new_sock->options.type = AWS_SOCKET_STREAM;
            new_sock->state = CONNECTED_WRITE | CONNECTED_READ;
            memcpy(&new_sock->local_endpoint, &socket->local_endpoint, sizeof(socket->local_endpoint));
            AWS_ZERO_STRUCT(new_sock->remote_endpoint);

            uint16_t port = 0;

            if (in_addr.ss_family == AF_INET)
            {
                struct sockaddr_in *s = (struct sockaddr_in *) &in_addr;
                port = ntohs(s->sin_port);
                inet_ntop(AF_INET, &s->sin_addr, new_sock->remote_endpoint.address, sizeof(new_sock->remote_endpoint.address));
                new_sock->options.domain = AWS_SOCKET_IPV4;
            }
            else if (in_addr.ss_family == AF_INET6)
            {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *) &in_addr;
                port = ntohs(s->sin6_port);
                inet_ntop(AF_INET6, &s->sin6_addr, new_sock->remote_endpoint.address, sizeof(new_sock->remote_endpoint.address));
                new_sock->options.domain = AWS_SOCKET_IPV6;
            }
            else if (in_addr.ss_family == AF_UNIX) {
                memcpy(&new_sock->remote_endpoint, &socket->local_endpoint, sizeof(socket->local_endpoint));
                new_sock->options.domain = AWS_SOCKET_LOCAL;
            }

            sprintf(socket->remote_endpoint.port, "%d", port);

            int flags = fcntl(in_fd, F_GETFL, 0);

            flags |= O_NONBLOCK | O_CLOEXEC;
            fcntl(in_fd, F_SETFL, flags);

            if (socket->creation_args.on_incoming_connection) {
                socket->creation_args.on_incoming_connection(socket, new_sock, socket->creation_args.user_data);
            }
        }
    }
}

int aws_socket_start_accept(struct aws_socket *socket) {
    if (socket->options.type != AWS_SOCKET_STREAM) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE);
    }

    if (AWS_UNLIKELY(socket->state != LISTENING)) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    return aws_event_loop_subscribe_to_io_events(socket->connection_loop, &socket->io_handle,
                                                 AWS_IO_EVENT_TYPE_READABLE, socket_accept_event, socket);
}

int aws_socket_stop_accept(struct aws_socket *socket) {
    if (socket->options.type != AWS_SOCKET_STREAM) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE);
    }

    int ret_val = aws_event_loop_unsubscribe_from_io_events(socket->connection_loop, &socket->io_handle);
    socket->connection_loop = NULL;
    return ret_val;
}

int aws_socket_set_options(struct aws_socket *socket, struct aws_socket_options *options) {
    socket->options = *options;

    int reuse = 1;
    setsockopt(socket->io_handle.data.fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

    if (socket->options.send_timeout) {
        int send_timeout = (int) socket->options.send_timeout;
        setsockopt(socket->io_handle.data.fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(int));
    }

    if (socket->options.read_timeout) {
        int read_timeout = (int) socket->options.read_timeout;
        setsockopt(socket->io_handle.data.fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(int));
    }

    if (socket->options.keepalive) {
        int keep_alive = 1;
        setsockopt(socket->io_handle.data.fd, SOL_SOCKET, SO_KEEPALIVE, &keep_alive, sizeof(int));
    }

    if (socket->options.linger_time) {
        struct linger linger;
        linger.l_onoff = 1;
        linger.l_linger = (int) socket->options.linger_time;
        setsockopt(socket->io_handle.data.fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger));
    }

    return AWS_OP_SUCCESS;
}

int aws_socket_shutdown(struct aws_socket *socket) {
    if (socket->connection_loop) {
        int err_code = aws_event_loop_unsubscribe_from_io_events(socket->connection_loop, &socket->io_handle);

        if (err_code) {
            return AWS_OP_ERR;
        }
        socket->connection_loop = NULL;
    }

    if (socket->io_handle.data.fd >= 0) {
        close(socket->io_handle.data.fd);
        socket->io_handle.data.fd = -1;
    }

    return AWS_OP_SUCCESS;
}

int aws_socket_half_close(struct aws_socket *socket, aws_channel_direction dir) {
    int how = dir == AWS_CHANNEL_DIR_READ ? 0 : 1;

    if (shutdown(socket->io_handle.data.fd, how)) {
        on_connection_error(socket, errno);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_socket_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read) {
    if (!(socket->state & CONNECTED_READ)) {
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    ssize_t read_val = read(socket->io_handle.data.fd, buffer->buffer + buffer->len, buffer->capacity - buffer->len);

    if (read_val > 0) {
        *amount_read = (size_t)read_val;
        buffer->len += *amount_read;
        return AWS_OP_SUCCESS;
    }

    int error = errno;

    if (error == EAGAIN) {
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    if (error == EPIPE) {
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
}

#if defined(__MACH__)
#define NO_SIGNAL SO_NOSIGPIPE
#else
#define NO_SIGNAL MSG_NOSIGNAL
#endif

int aws_socket_write(struct aws_socket *socket, const struct aws_byte_cursor *cursor, size_t *written) {
    if (!(socket->state & CONNECTED_WRITE)) {
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    ssize_t write_val = send(socket->io_handle.data.fd, cursor->ptr, cursor->len, NO_SIGNAL);

    if (write_val > 0) {
        *written = (size_t)write_val;
        return AWS_OP_SUCCESS;
    }

    int error = errno;
    if (error == EAGAIN) {
        return aws_raise_error(AWS_IO_WRITE_WOULD_BLOCK);
    }

    if (error == EPIPE) {
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
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
    return socket->io_handle.data.fd >= 0;
}
