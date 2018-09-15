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
#include <aws/common/clock.h>
#include <aws/common/task_scheduler.h>

#include <aws/io/event_loop.h>

#include <arpa/inet.h>
#include <assert.h>
#include <aws/io/io.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <unistd.h>
#include <zconf.h>


#if defined(__MACH__)
#    define NO_SIGNAL SO_NOSIGPIPE
#else
#    define NO_SIGNAL MSG_NOSIGNAL
#endif

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

static int s_convert_domain(enum aws_socket_domain domain) {
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

static int s_convert_type(enum aws_socket_type type) {
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

static int s_determine_socket_error(int error) {
    switch (error) {
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
        return AWS_IO_FILE_INVALID_PATH;
    case 0:
        return AWS_IO_SOCKET_NOT_CONNECTED;
    default:
        return AWS_IO_SOCKET_NOT_CONNECTED;
    }
}

static int s_create_socket(struct aws_socket *sock, struct aws_socket_options *options) {

    int fd = socket(s_convert_domain(options->domain), s_convert_type(options->type), 0);
    int flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    flags |= O_CLOEXEC;
    fcntl(fd, F_SETFL, flags);

    if (fd != -1) {
        sock->io_handle.data.fd = fd;
        sock->io_handle.additional_data = NULL;
        return aws_socket_set_options(sock, options);
    }

    int aws_error = s_determine_socket_error(errno);
    return aws_raise_error(aws_error);
}

struct posix_socket {
    struct aws_linked_list write_queue;
    bool write_in_progress;
};

static int s_socket_init(struct aws_socket *socket,
                  struct aws_allocator *alloc,
                  struct aws_socket_options *options,
                  struct aws_socket_creation_args *creation_args) {
    assert(options);
    AWS_ZERO_STRUCT(*socket);

    struct posix_socket *posix_socket = aws_mem_acquire(alloc, sizeof(struct posix_socket));
    if (!posix_socket) {
        return AWS_OP_ERR;
    }

    socket->allocator = alloc;
    socket->io_handle.data.fd = -1;
    socket->io_handle.additional_data = NULL;
    socket->state = INIT;

    if (creation_args) {
        socket->creation_args = *creation_args;

        int err = s_create_socket(socket, options);
        if (err) {
            aws_mem_release(alloc, posix_socket);
            return AWS_OP_ERR;
        }
    }

    aws_linked_list_init(&posix_socket->write_queue);
    posix_socket->write_in_progress = false;
    socket->impl = posix_socket;
    return AWS_OP_SUCCESS;
}

int aws_socket_init(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    struct aws_socket_options *options,
    struct aws_socket_creation_args *creation_args) {
    assert(options);
    assert(creation_args);
    return s_socket_init(socket, alloc, options, creation_args);
}

void aws_socket_clean_up(struct aws_socket *socket) {
    aws_socket_shutdown(socket);
    aws_mem_release(socket->allocator, socket->impl);
    AWS_ZERO_STRUCT(*socket);
    socket->io_handle.data.fd = -1;
}


static void s_on_connection_error(struct aws_socket *socket, int error);

static int s_on_connection_success(struct aws_socket *socket) {

    struct aws_event_loop *event_loop = socket->event_loop;
    aws_event_loop_unsubscribe_from_io_events(socket->event_loop, &socket->io_handle);
    socket->event_loop = NULL;
    if (aws_socket_set_options(socket, &socket->options)) {
        aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);

        return AWS_OP_ERR;
    }

    int connect_result;
    socklen_t result_length = sizeof(connect_result);

    if (getsockopt(socket->io_handle.data.fd, SOL_SOCKET, SO_ERROR, &connect_result, &result_length) < 0) {
        s_on_connection_error(socket, errno);
        return AWS_OP_ERR;
    }

    if (connect_result) {
        s_on_connection_error(socket, connect_result);
        return AWS_OP_ERR;
    }

    struct sockaddr_storage address;
    AWS_ZERO_STRUCT(address);
    socklen_t address_size = sizeof(address);
    if (!getsockname(socket->io_handle.data.fd, (struct sockaddr *)&address, &address_size)) {
        uint16_t port = 0;

        if (address.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&address;
            port = ntohs(s->sin_port);
            inet_ntop(AF_INET, &s->sin_addr, socket->local_endpoint.address, sizeof(socket->local_endpoint.address));
        } else if (address.ss_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&address;
            port = ntohs(s->sin6_port);
            inet_ntop(AF_INET6, &s->sin6_addr, socket->local_endpoint.address, sizeof(socket->local_endpoint.address));
        } else if (address.ss_family == AF_UNIX) {
            struct sockaddr_in *s = (struct sockaddr_in *)&address;
            inet_ntop(
                AF_INET, &s->sin_addr, socket->local_endpoint.socket_name, sizeof(socket->local_endpoint.socket_name));
        }
        sprintf(socket->local_endpoint.port, "%d", port);
    } else {
        s_on_connection_error(socket, errno);
        return AWS_OP_ERR;
    }

    socket->state = CONNECTED_WRITE | CONNECTED_READ;

    aws_socket_assign_to_event_loop(socket, event_loop);

    if (socket->creation_args.on_connection_established && socket->options.type == AWS_SOCKET_STREAM) {
        socket->creation_args.on_connection_established(socket, socket->creation_args.user_data);
    }

    return AWS_OP_SUCCESS;
}


static void s_on_connection_error(struct aws_socket *socket, int error) {
    socket->state = ERROR;
    if (socket->creation_args.on_error) {
        socket->creation_args.on_error(socket, error, socket->creation_args.user_data);
    }
}

struct socket_connect_args {
    struct aws_allocator *allocator;
    struct aws_socket *socket;
};

static void s_socket_connect_event(
        struct aws_event_loop *event_loop,
        struct aws_io_handle *handle,
        int events,
        void *user_data) {

    (void)event_loop;
    (void)handle;

    struct socket_connect_args *socket_args = (struct socket_connect_args *)user_data;

    if (events & AWS_IO_EVENT_TYPE_READABLE || events & AWS_IO_EVENT_TYPE_WRITABLE) {
        if (socket_args->socket) {
            struct aws_socket *socket = socket_args->socket;
            socket_args->socket = NULL;
            s_on_connection_success(socket);
        }
        return;
    }
    int aws_error = s_determine_socket_error(errno);
    aws_raise_error(aws_error);
    s_on_connection_error(socket_args->socket, aws_error);
}

static void s_handle_socket_timeout(struct aws_task *task, void *args, aws_task_status status) {
    struct socket_connect_args *socket_args = (struct socket_connect_args *)args;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        if (socket_args->socket) {
            socket_args->socket->state = TIMEDOUT;
            aws_event_loop_unsubscribe_from_io_events(
                socket_args->socket->event_loop, &socket_args->socket->io_handle);
            socket_args->socket->event_loop = NULL;

            aws_socket_shutdown(socket_args->socket);
            aws_raise_error(AWS_IO_SOCKET_TIMEOUT);

            if (socket_args->socket->creation_args.on_error) {
                socket_args->socket->creation_args.on_error(
                    socket_args->socket, AWS_IO_SOCKET_TIMEOUT, socket_args->socket->creation_args.user_data);
            }
        }
    }

    aws_mem_release(socket_args->allocator, task);
    aws_mem_release(socket_args->allocator, socket_args);
}

int aws_socket_connect(struct aws_socket *socket,
        struct aws_socket_endpoint *remote_endpoint, struct aws_event_loop *event_loop) {
    assert(event_loop);

    socket->state = CONNECTING;
    memcpy(socket->remote_endpoint.port, remote_endpoint->port, sizeof(remote_endpoint->port));
    memcpy(socket->remote_endpoint.socket_name, remote_endpoint->socket_name, sizeof(remote_endpoint->socket_name));
    memcpy(socket->remote_endpoint.address, remote_endpoint->address, sizeof(socket->remote_endpoint.address));

    struct socket_connect_args *sock_args = aws_mem_acquire(socket->allocator, sizeof(struct socket_connect_args));

    if (!sock_args) {
        return AWS_OP_ERR;
    }

    sock_args->socket = socket;
    sock_args->allocator = socket->allocator;

    struct aws_task *timeout_task = aws_mem_acquire(socket->allocator, sizeof(struct aws_task));

    if (!timeout_task) {
        aws_mem_release(socket->allocator, sock_args);
        return AWS_OP_ERR;
    }

    timeout_task->fn = s_handle_socket_timeout;
    timeout_task->arg = sock_args;

    if (aws_event_loop_subscribe_to_io_events(event_loop, &socket->io_handle,
            AWS_IO_EVENT_TYPE_READABLE | AWS_IO_EVENT_TYPE_WRITABLE, s_socket_connect_event, sock_args)) {
        goto err_clean_up;
    }
    socket->event_loop = event_loop;

    int error_code = -1;
    if (socket->options.domain == AWS_SOCKET_IPV4) {
        struct sockaddr_in addr_in;
        AWS_ZERO_STRUCT(addr_in);
        inet_pton(AF_INET, remote_endpoint->address, &(addr_in.sin_addr));
        addr_in.sin_port = htons((uint16_t)atoi(remote_endpoint->port));
        addr_in.sin_family = AF_INET;
        error_code = connect(socket->io_handle.data.fd, (struct sockaddr *)&addr_in, sizeof(addr_in));
    } else if (socket->options.domain == AWS_SOCKET_IPV6) {
        struct sockaddr_in6 addr_in;
        AWS_ZERO_STRUCT(addr_in);
        inet_pton(AF_INET6, remote_endpoint->address, &(addr_in.sin6_addr));
        addr_in.sin6_port = htons((uint16_t)atoi(remote_endpoint->port));
        addr_in.sin6_family = AF_INET6;
        error_code = connect(socket->io_handle.data.fd, (struct sockaddr *)&addr_in, sizeof(addr_in));
    } else if (socket->options.domain == AWS_SOCKET_LOCAL) {
        struct sockaddr_un addr;
        AWS_ZERO_STRUCT(addr);
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, remote_endpoint->socket_name, sizeof(addr.sun_path) - 1);
        error_code = connect(socket->io_handle.data.fd, (const struct sockaddr *)&addr, sizeof(struct sockaddr_un));
    } else {
        assert(0);
        aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
        goto err_clean_up;
    }

    /* if it happened synchronous, we'll still get the notification, so just go ahead and ignore that case
     * and force async flow. */
    uint64_t timeout = 0;
    aws_event_loop_current_clock_time(event_loop, &timeout);

    if (error_code) {
        error_code = errno;
        if (error_code == EINPROGRESS || error_code == EALREADY) {
            timeout += aws_timestamp_convert(socket->options.connect_timeout,
                    AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
        }
        else {
            aws_mem_release(socket->allocator, sock_args);
            int aws_error = s_determine_socket_error(error_code);
            aws_raise_error(aws_error);
            goto err_clean_up;
        }
    }
    aws_event_loop_schedule_task_future(event_loop, timeout_task, timeout);
    return AWS_OP_SUCCESS;

err_clean_up:
    aws_mem_release(socket->allocator, sock_args);
    aws_mem_release(socket->allocator, timeout_task);
    return AWS_OP_ERR;
}

int aws_socket_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint) {
    int error_code = -1;

    memcpy(socket->local_endpoint.port, local_endpoint->port, sizeof(local_endpoint->port));
    memcpy(socket->local_endpoint.socket_name, local_endpoint->socket_name, sizeof(local_endpoint->socket_name));
    memcpy(socket->local_endpoint.address, local_endpoint->address, sizeof(socket->local_endpoint.address));

    if (socket->options.domain == AWS_SOCKET_IPV4) {
        struct sockaddr_in addr_in;
        inet_pton(AF_INET, local_endpoint->address, &(addr_in.sin_addr));
        addr_in.sin_port = htons((uint16_t)atoi(local_endpoint->port));
        addr_in.sin_family = AF_INET;
        error_code = bind(socket->io_handle.data.fd, (struct sockaddr *)&addr_in, sizeof(addr_in));
    } else if (socket->options.domain == AWS_SOCKET_IPV6) {
        struct sockaddr_in6 addr_in;
        inet_pton(AF_INET6, local_endpoint->address, &(addr_in.sin6_addr));
        addr_in.sin6_port = htons((uint16_t)atoi(local_endpoint->port));
        addr_in.sin6_family = AF_INET6;
        error_code = bind(socket->io_handle.data.fd, (struct sockaddr *)&addr_in, sizeof(addr_in));
    } else if (socket->options.domain == AWS_SOCKET_LOCAL) {
        struct sockaddr_un name;
        AWS_ZERO_STRUCT(name);
        name.sun_family = AF_UNIX;
        strncpy(name.sun_path, local_endpoint->socket_name, sizeof(name.sun_path) - 1);
        error_code = bind(socket->io_handle.data.fd, (const struct sockaddr *)&name, sizeof(struct sockaddr_un));
    }

    if (!error_code) {
        if (socket->options.type == AWS_SOCKET_STREAM) {
            socket->state = BOUND;
        } else {
            socket->state = CONNECTED_READ;
        }

        return AWS_OP_SUCCESS;
    }

    socket->state = ERROR;
    error_code = errno;
    int aws_error = s_determine_socket_error(error_code);
    return aws_raise_error(aws_error);
}

int aws_socket_listen(struct aws_socket *socket, int backlog_size) {
    if (socket->state != BOUND) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    int error_code = listen(socket->io_handle.data.fd, backlog_size);

    if (!error_code) {
        socket->state = LISTENING;
        return AWS_OP_SUCCESS;
    }

    error_code = errno;
    socket->state = ERROR;

    return aws_raise_error(s_determine_socket_error(error_code));
}

static void socket_accept_event(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data) {

    (void)event_loop;

    struct aws_socket *socket = (struct aws_socket *)user_data;

    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        int in_fd = 0;
        while (in_fd != -1) {
            struct sockaddr_storage in_addr;
            socklen_t in_len = sizeof(struct sockaddr_storage);

            in_fd = accept(handle->data.fd, (struct sockaddr *)&in_addr, &in_len);
            if (in_fd == -1) {
                int error = errno;

                if (error == EAGAIN || error == EWOULDBLOCK) {
                    break;
                }

                s_on_connection_error(socket, error);
                continue;
            }

            struct aws_socket *new_sock =
                (struct aws_socket *)aws_mem_acquire(socket->allocator, sizeof(struct aws_socket));

            if (!new_sock) {
                break;
            }

            if (s_socket_init(new_sock, socket->allocator, &socket->options, NULL)) {
                aws_mem_release(socket->allocator, new_sock);
                break;
            }


            new_sock->io_handle = (struct aws_io_handle){.data = {.fd = in_fd}, .additional_data = NULL};
            memcpy(&new_sock->local_endpoint, &socket->local_endpoint, sizeof(socket->local_endpoint));
            aws_socket_set_options(new_sock, &socket->options);
            new_sock->state = CONNECTED_READ | CONNECTED_WRITE;
            uint16_t port = 0;

            if (in_addr.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&in_addr;
                port = ntohs(s->sin_port);
                inet_ntop(
                    AF_INET,
                    &s->sin_addr,
                    new_sock->remote_endpoint.address,
                    sizeof(new_sock->remote_endpoint.address));
                new_sock->options.domain = AWS_SOCKET_IPV4;
            } else if (in_addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&in_addr;
                port = ntohs(s->sin6_port);
                inet_ntop(
                    AF_INET6,
                    &s->sin6_addr,
                    new_sock->remote_endpoint.address,
                    sizeof(new_sock->remote_endpoint.address));
                new_sock->options.domain = AWS_SOCKET_IPV6;
            } else if (in_addr.ss_family == AF_UNIX) {
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

int aws_socket_start_accept(struct aws_socket *socket, struct aws_event_loop *accept_loop) {
    if (socket->state != LISTENING) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    socket->event_loop = accept_loop;
    return aws_event_loop_subscribe_to_io_events(
        socket->event_loop, &socket->io_handle, AWS_IO_EVENT_TYPE_READABLE, socket_accept_event, socket);
}

int aws_socket_stop_accept(struct aws_socket *socket) {
    if (socket->state != LISTENING) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    int ret_val = aws_event_loop_unsubscribe_from_io_events(socket->event_loop, &socket->io_handle);
    socket->event_loop = NULL;
    return ret_val;
}

int aws_socket_set_options(struct aws_socket *socket, struct aws_socket_options *options) {
    socket->options = *options;

    int option_value = 1;
    setsockopt(socket->io_handle.data.fd, SOL_SOCKET, NO_SIGNAL, &option_value, sizeof(option_value));

    int reuse = 1;
    setsockopt(socket->io_handle.data.fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));

    if (options->type == AWS_SOCKET_STREAM && options->domain != AWS_SOCKET_LOCAL) {
        if (socket->options.keepalive) {
            int keep_alive = 1;
            setsockopt(socket->io_handle.data.fd, SOL_SOCKET, SO_KEEPALIVE, &keep_alive, sizeof(int));
        }

        if (socket->options.keep_alive_interval && socket->options.keep_alive_timeout) {
            int ival_in_secs = (int) aws_timestamp_convert(socket->options.keep_alive_timeout,
                                                           AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_SECS, NULL);
            setsockopt(socket->io_handle.data.fd, IPPROTO_TCP, TCP_KEEPIDLE, &ival_in_secs, sizeof(ival_in_secs));

            ival_in_secs = (int) aws_timestamp_convert(socket->options.keep_alive_interval,
                                                       AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_SECS, NULL);
            setsockopt(socket->io_handle.data.fd, IPPROTO_TCP, TCP_KEEPINTVL, &ival_in_secs, sizeof(ival_in_secs));
        }
    }

    if (socket->options.linger_time) {
        struct linger linger;
        linger.l_onoff = 1;
        linger.l_linger = (int)socket->options.linger_time;
        setsockopt(socket->io_handle.data.fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger));
    }

    return AWS_OP_SUCCESS;
}

struct write_request {
    struct aws_task task_handle;
    struct aws_byte_cursor *original_cursor;
    struct aws_byte_cursor cursor_cpy;
    aws_socket_on_data_written_fn *written_fn;
    void *write_user_data;
    struct aws_linked_list_node node;
};

int aws_socket_shutdown(struct aws_socket *socket) {
    if (socket->event_loop) {
        int err_code = aws_event_loop_unsubscribe_from_io_events(socket->event_loop, &socket->io_handle);

        if (err_code) {
            return AWS_OP_ERR;
        }
    }

    if (socket->io_handle.data.fd >= 0) {
        close(socket->io_handle.data.fd);
        socket->io_handle.data.fd = -1;
    }

    struct posix_socket *socket_impl = socket->impl;

    while (!aws_linked_list_empty(&socket_impl->write_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&socket_impl->write_queue);
        struct write_request *write_request = AWS_CONTAINER_OF(node, struct write_request, node);

        write_request->written_fn(socket, AWS_IO_SOCKET_CLOSED,
                write_request->original_cursor, write_request->write_user_data);
        aws_mem_release(socket->allocator, write_request);
    }

    return AWS_OP_SUCCESS;
}

int aws_socket_half_close(struct aws_socket *socket, enum aws_channel_direction dir) {
    int how = dir == AWS_CHANNEL_DIR_READ ? 0 : 1;

    if (shutdown(socket->io_handle.data.fd, how)) {
        int aws_error = s_determine_socket_error(errno);
        return aws_raise_error(aws_error);
    }

    return AWS_OP_SUCCESS;
}

static int s_process_write_requests(struct aws_socket *socket) {
    struct posix_socket *socket_impl = socket->impl;
    socket_impl->write_in_progress = true;

    bool purge = false;
    int aws_error = AWS_OP_SUCCESS;

    while (!aws_linked_list_empty(&socket_impl->write_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_front(&socket_impl->write_queue);
        struct write_request *write_request = AWS_CONTAINER_OF(node, struct write_request, node);

        ssize_t written = send(socket->io_handle.data.fd,
                write_request->cursor_cpy.ptr, write_request->cursor_cpy.len, NO_SIGNAL);

        if (AWS_UNLIKELY(written < 0)) {
            int error = errno;
            if (error == EAGAIN) {
                break;
            }

            if (error == EPIPE) {
                aws_error = AWS_IO_SOCKET_CLOSED;
                purge = true;
                break;
            }

            purge = true;
            aws_error = s_determine_socket_error(error);
        }

        size_t remaining_to_write = write_request->cursor_cpy.len;
        aws_byte_cursor_advance(&write_request->cursor_cpy, (size_t)written);
        if ((size_t)written == remaining_to_write) {
            aws_linked_list_remove(node);
            write_request->written_fn(socket, AWS_OP_SUCCESS,
                    write_request->original_cursor, write_request->write_user_data);
            aws_mem_release(socket->allocator, write_request);
        }
    }

    if (purge) {
        aws_raise_error(aws_error);
        while (!aws_linked_list_empty(&socket_impl->write_queue)) {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&socket_impl->write_queue);
            struct write_request *write_request = AWS_CONTAINER_OF(node, struct write_request, node);

            write_request->written_fn(socket, aws_error, write_request->original_cursor, write_request->write_user_data);
            aws_mem_release(socket->allocator, write_request);
        }
        s_on_connection_error(socket, aws_error);
        socket_impl->write_in_progress = false;
        return AWS_OP_ERR;
    }

    socket_impl->write_in_progress = false;
    return AWS_OP_SUCCESS;
}

static void s_on_socket_io_event(struct aws_event_loop *event_loop,
                                 struct aws_io_handle *handle,
                                 int events,
                                 void *user_data) {
    (void)event_loop;
    (void)handle;
    struct aws_socket *socket = user_data;

    if (events & AWS_IO_EVENT_TYPE_REMOTE_HANG_UP || events & AWS_IO_EVENT_TYPE_CLOSED) {
        aws_raise_error(AWS_IO_SOCKET_CLOSED);
        if (socket->readable_fn) {
            socket->readable_fn(socket, AWS_IO_SOCKET_CLOSED, socket->readable_user_data);
        }
        return;
    }

    if (events & AWS_IO_EVENT_TYPE_ERROR) {
        int aws_error = s_determine_socket_error(errno);
        aws_raise_error(aws_error);
        if (socket->readable_fn) {
            socket->readable_fn(socket, aws_error, socket->readable_user_data);
        }
        return;
    }

    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        if (socket->readable_fn) {
            socket->readable_fn(socket, AWS_OP_SUCCESS, socket->readable_user_data);
        }
    }

    if (events & AWS_IO_EVENT_TYPE_WRITABLE) {
        s_process_write_requests(socket);
    }
}

int aws_socket_assign_to_event_loop(struct aws_socket *socket, struct aws_event_loop *event_loop) {
    if (!socket->event_loop) {
        socket->event_loop = event_loop;
        return aws_event_loop_subscribe_to_io_events(event_loop, &socket->io_handle,
                                                     AWS_IO_EVENT_TYPE_WRITABLE | AWS_IO_EVENT_TYPE_READABLE,
                                                     s_on_socket_io_event, socket);
    }
    return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
}

struct aws_event_loop *aws_socket_get_event_loop(struct aws_socket *socket) {
    return socket->event_loop;
}

int aws_socket_subscribe_to_readable_events(struct aws_socket *socket,
                                                       aws_socket_on_readable_fn *on_readable, void *user_data) {
    assert(!socket->readable_fn);
    socket->readable_fn = on_readable;
    socket->readable_user_data = user_data;
    return AWS_OP_SUCCESS;
}

int aws_socket_read(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read) {
    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

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
        return aws_raise_error(AWS_IO_SOCKET_CLOSED);
    }

    return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
}

static void s_write_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_socket *socket = arg;
        s_process_write_requests(socket);
    }
}

int aws_socket_write(struct aws_socket *socket, struct aws_byte_cursor *cursor,
                     aws_socket_on_data_written_fn *written_fn, void *user_data) {
    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (!(socket->state & CONNECTED_WRITE)) {
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    struct posix_socket *socket_impl = socket->impl;
    struct write_request *write_request = aws_mem_acquire(socket->allocator, sizeof(struct write_request));

    if (!write_request) {
        return AWS_OP_ERR;
    }

    write_request->original_cursor = cursor;
    write_request->written_fn = written_fn;
    write_request->write_user_data = user_data;
    write_request->cursor_cpy = *cursor;
    aws_linked_list_push_back(&socket_impl->write_queue, &write_request->node);

    /* avoid reentrancy when a user calls write after receiving their completion callback. */
    if (!socket_impl->write_in_progress) {
        return s_process_write_requests(socket);
    }

    write_request->task_handle.fn = s_write_task;
    write_request->task_handle.arg = socket;
    return AWS_OP_SUCCESS;
}

int aws_socket_get_error(struct aws_socket *socket) {
    int connect_result;
    socklen_t result_length = sizeof(connect_result);

    if (getsockopt(socket->io_handle.data.fd, SOL_SOCKET, SO_ERROR, &connect_result, &result_length) < 0) {
        return AWS_OP_ERR;
    }

    if (connect_result) {
        return s_determine_socket_error(connect_result);
    }

    return AWS_OP_SUCCESS;
}

bool aws_socket_is_open(struct aws_socket *socket) {
    return socket->io_handle.data.fd >= 0;
}
