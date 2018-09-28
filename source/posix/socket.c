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
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>

#include <aws/io/event_loop.h>

#include <arpa/inet.h>
#include <assert.h>
#include <aws/io/io.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <zconf.h>

#if defined(__MACH__)
#    define NO_SIGNAL SO_NOSIGPIPE
#    define TCP_KEEPIDLE TCP_KEEPALIVE
#else
#    define NO_SIGNAL MSG_NOSIGNAL
#endif

/* other than CONNECTED_READ | CONNECTED_WRITE
 * a socket is only in one of these states at a time. */
enum socket_state {
    INIT = 0x01,
    CONNECTING = 0x02,
    CONNECTED_READ = 0x04,
    CONNECTED_WRITE = 0x08,
    BOUND = 0x10,
    LISTENING = 0x20,
    TIMEDOUT = 0x40,
    ERROR = 0x80,
    CLOSED,
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
        case EADDRNOTAVAIL:
            return AWS_IO_SOCKET_INVALID_ADDRESS;
        case ENETDOWN:
            return AWS_IO_SOCKET_NETWORK_DOWN;
        case ECONNABORTED:
            return AWS_IO_SOCKET_CONNECT_ABORTED;
        case EADDRINUSE:
            return AWS_IO_SOCKET_ADDRESS_IN_USE;
        case ENOBUFS:
        case ENOMEM:
            return AWS_ERROR_OOM;
        case EAGAIN:
            return AWS_IO_READ_WOULD_BLOCK;
        case EMFILE:
        case ENFILE:
            return AWS_IO_MAX_FDS_EXCEEDED;
        case ENOENT:
        case EINVAL:
            return AWS_IO_FILE_INVALID_PATH;
        case EAFNOSUPPORT:
            return AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY;
        case EACCES:
            return AWS_IO_NO_PERMISSION;
        default:
            return AWS_IO_SOCKET_NOT_CONNECTED;
    }
}

static int s_create_socket(struct aws_socket *sock, struct aws_socket_options *options) {

    int fd = socket(s_convert_domain(options->domain), s_convert_type(options->type), 0);

    if (fd != -1) {
        int flags = fcntl(fd, F_GETFL, 0);
        flags |= O_NONBLOCK | O_CLOEXEC;
        int success = fcntl(fd, F_SETFL, flags);
        (void)success;
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
    bool currently_subscribed;
    bool continue_accept;
    bool currently_in_event;
    bool clean_yourself_up;
};

static int s_socket_init(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    struct aws_socket_options *options,
    bool create_the_socket) {
    assert(options);
    AWS_ZERO_STRUCT(*socket);

    struct posix_socket *posix_socket = aws_mem_acquire(alloc, sizeof(struct posix_socket));
    if (!posix_socket) {
        return AWS_OP_ERR;
    }

    socket->allocator = alloc;
    socket->io_handle.data.fd = -1;
    socket->state = INIT;
    socket->options = *options;

    if (create_the_socket) {
        int err = s_create_socket(socket, options);
        if (err) {
            aws_mem_release(alloc, posix_socket);
            return AWS_OP_ERR;
        }
    }

    aws_linked_list_init(&posix_socket->write_queue);
    posix_socket->write_in_progress = false;
    posix_socket->currently_subscribed = false;
    posix_socket->continue_accept = false;
    posix_socket->currently_in_event = false;
    posix_socket->clean_yourself_up = false;
    socket->impl = posix_socket;
    return AWS_OP_SUCCESS;
}

int aws_socket_init(struct aws_socket *socket, struct aws_allocator *alloc, struct aws_socket_options *options) {
    assert(options);
    return s_socket_init(socket, alloc, options, true);
}

void aws_socket_clean_up(struct aws_socket *socket) {
    if (aws_socket_is_open(socket)) {
        aws_socket_close(socket);
    }
    struct posix_socket *socket_impl = socket->impl;

    if (!socket_impl->currently_in_event) {
        aws_mem_release(socket->allocator, socket->impl);
    } else {
        socket_impl->clean_yourself_up = true;
    }

    AWS_ZERO_STRUCT(*socket);
    socket->io_handle.data.fd = -1;
}

static void s_on_connection_error(struct aws_socket *socket, int error);

static int s_on_connection_success(struct aws_socket *socket) {

    struct aws_event_loop *event_loop = socket->event_loop;
    struct posix_socket *socket_impl = socket->impl;

    if (socket_impl->currently_subscribed) {
        aws_event_loop_unsubscribe_from_io_events(socket->event_loop, &socket->io_handle);
        socket_impl->currently_subscribed = false;
    }

    socket->event_loop = NULL;
    if (aws_socket_set_options(socket, &socket->options)) {
        aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);

        return AWS_OP_ERR;
    }

    int connect_result;
    socklen_t result_length = sizeof(connect_result);

    if (getsockopt(socket->io_handle.data.fd, SOL_SOCKET, SO_ERROR, &connect_result, &result_length) < 0) {
        int aws_error = s_determine_socket_error(errno);
        aws_raise_error(aws_error);
        s_on_connection_error(socket, aws_error);
        return AWS_OP_ERR;
    }

    if (connect_result) {
        int aws_error = s_determine_socket_error(connect_result);
        aws_raise_error(aws_error);
        s_on_connection_error(socket, aws_error);
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
            /* this comes straight from the kernal. a.) they won't fail. b.) even if they do, it's not fatal
             * once we add logging, we can log this if it fails. */
            inet_ntop(AF_INET, &s->sin_addr, socket->local_endpoint.address, sizeof(socket->local_endpoint.address));
        } else if (address.ss_family == AF_INET6) {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&address;
            port = ntohs(s->sin6_port);
            /* this comes straight from the kernal. a.) they won't fail. b.) even if they do, it's not fatal
             * once we add logging, we can log this if it fails. */
            inet_ntop(AF_INET6, &s->sin6_addr, socket->local_endpoint.address, sizeof(socket->local_endpoint.address));
        }

        socket->local_endpoint.port = port;
    } else {
        int aws_error = s_determine_socket_error(connect_result);
        aws_raise_error(aws_error);
        s_on_connection_error(socket, aws_error);
        return AWS_OP_ERR;
    }

    socket->state = CONNECTED_WRITE | CONNECTED_READ;

    aws_socket_assign_to_event_loop(socket, event_loop);

    socket->connection_result_fn(socket, AWS_ERROR_SUCCESS, socket->connect_accept_user_data);

    return AWS_OP_SUCCESS;
}

static void s_on_connection_error(struct aws_socket *socket, int error) {
    socket->state = ERROR;

    if (socket->connection_result_fn) {
        socket->connection_result_fn(socket, error, socket->connect_accept_user_data);
    } else if (socket->accept_result_fn) {
        socket->accept_result_fn(socket, error, NULL, socket->connect_accept_user_data);
    }
}

struct posix_socket_connect_args {
    struct aws_task task;
    struct aws_allocator *allocator;
    struct aws_socket *socket;
};

/* the next two callbacks compete based on which one runs first. if s_socket_connect_event
 * comes back first, then we set socket_args->socket = NULL and continue on with the connection.
 * if s_handle_socket_timeout() runs first, is sees socket_args->socket is NULL and just cleans up its memory.
 * s_handle_socket_timeout() will always run so the memory for socket_connect_args is always cleaned up there. */
static void s_socket_connect_event(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data) {

    (void)event_loop;
    (void)handle;

    struct posix_socket_connect_args *socket_args = (struct posix_socket_connect_args *)user_data;

    if (!(events & AWS_IO_EVENT_TYPE_ERROR || events & AWS_IO_EVENT_TYPE_CLOSED) &&
        (events & AWS_IO_EVENT_TYPE_READABLE || events & AWS_IO_EVENT_TYPE_WRITABLE)) {
        struct aws_socket *socket = socket_args->socket;
        socket_args->socket = NULL;
        s_on_connection_success(socket);
        return;
    }

    int aws_error = aws_socket_get_error(socket_args->socket);
    /* we'll get another notification. */
    if (aws_error == AWS_IO_READ_WOULD_BLOCK) {
        return;
    }

    aws_raise_error(aws_error);
    s_on_connection_error(socket_args->socket, aws_error);
    socket_args->socket = NULL;
}

static void s_handle_socket_timeout(struct aws_task *task, void *args, aws_task_status status) {
    (void)task;
    struct posix_socket_connect_args *socket_args = args;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        if (socket_args->socket) {
            socket_args->socket->state = TIMEDOUT;
            aws_event_loop_unsubscribe_from_io_events(socket_args->socket->event_loop, &socket_args->socket->io_handle);
            socket_args->socket->event_loop = NULL;
            struct posix_socket *socket_impl = socket_args->socket->impl;
            socket_impl->currently_subscribed = false;
            aws_socket_close(socket_args->socket);
            aws_raise_error(AWS_IO_SOCKET_TIMEOUT);

            s_on_connection_error(socket_args->socket, AWS_IO_SOCKET_TIMEOUT);
            socket_args->socket = NULL;
        }
    }

    aws_mem_release(socket_args->allocator, socket_args);
}

/* this is used simply for moving a connect_success callback when the connect finished immediately
 * (like for unix domain sockets) into the event loop's thread. Also note, in that case there was no
 * timeout task scheduled, so in this case the socket_args are cleaned up. */
static void s_run_connect_success(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    struct posix_socket_connect_args *socket_args = arg;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        s_on_connection_success(socket_args->socket);
    }

    aws_mem_release(socket_args->allocator, socket_args);
}

static inline int s_convert_pton_error(int pton_code) {
    if (pton_code == 0) {
        return AWS_IO_SOCKET_INVALID_ADDRESS;
    }

    return s_determine_socket_error(errno);
}

struct socket_address {
    union sock_addr_types {
        struct sockaddr_in addr_in;
        struct sockaddr_in6 addr_in6;
        struct sockaddr_un un_addr;

    } sock_addr_types;
};

int aws_socket_connect(
    struct aws_socket *socket,
    struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *event_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    void *user_data) {
    assert(event_loop);

    if (socket->state != INIT) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
    }

    if (socket->options.type != AWS_SOCKET_DGRAM) {
        assert(on_connection_result);
    }

    struct socket_address address;
    AWS_ZERO_STRUCT(address);
    socklen_t sock_size = 0;
    int pton_err = 1;
    if (socket->options.domain == AWS_SOCKET_IPV4) {
        pton_err = inet_pton(AF_INET, remote_endpoint->address, &address.sock_addr_types.addr_in.sin_addr);
        address.sock_addr_types.addr_in.sin_port = htons(remote_endpoint->port);
        address.sock_addr_types.addr_in.sin_family = AF_INET;
        sock_size = sizeof(address.sock_addr_types.addr_in);
    } else if (socket->options.domain == AWS_SOCKET_IPV6) {
        pton_err = inet_pton(AF_INET6, remote_endpoint->address, &address.sock_addr_types.addr_in6.sin6_addr);
        address.sock_addr_types.addr_in6.sin6_port = htons(remote_endpoint->port);
        address.sock_addr_types.addr_in6.sin6_family = AF_INET6;
        sock_size = sizeof(address.sock_addr_types.addr_in6);
    } else if (socket->options.domain == AWS_SOCKET_LOCAL) {
        address.sock_addr_types.un_addr.sun_family = AF_UNIX;
        assert(sizeof(remote_endpoint->address) <= sizeof(address.sock_addr_types.un_addr.sun_path));
        strncpy(
            address.sock_addr_types.un_addr.sun_path,
            remote_endpoint->address,
            sizeof(address.sock_addr_types.un_addr.sun_path) - 1);
        sock_size = sizeof(address.sock_addr_types.un_addr);
    } else {
        assert(0);
        return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
    }

    if (pton_err != 1) {
        return aws_raise_error(s_convert_pton_error(pton_err));
    }

    socket->state = CONNECTING;
    socket->remote_endpoint = *remote_endpoint;
    socket->connect_accept_user_data = user_data;
    socket->connection_result_fn = on_connection_result;

    struct posix_socket_connect_args *sock_args =
        aws_mem_acquire(socket->allocator, sizeof(struct posix_socket_connect_args));

    if (!sock_args) {
        return AWS_OP_ERR;
    }

    sock_args->socket = socket;
    sock_args->allocator = socket->allocator;

    sock_args->task.fn = s_handle_socket_timeout;
    sock_args->task.arg = sock_args;

    int error_code = connect(socket->io_handle.data.fd, (struct sockaddr *)&address.sock_addr_types, sock_size);
    socket->event_loop = event_loop;

    if (!error_code) {
        sock_args->task.fn = s_run_connect_success;
        /* the subscription for IO will happen once we setup the connection in the task. Since we already
         * know the connection succeeded, we don't need to register for events yet. */
        aws_event_loop_schedule_task_now(event_loop, &sock_args->task);
    }

    if (error_code) {
        error_code = errno;
        if (error_code == EINPROGRESS || error_code == EALREADY) {
            /* This event is for when the connection finishes. (the fd will flip writable). */
            if (aws_event_loop_subscribe_to_io_events(
                    event_loop, &socket->io_handle, AWS_IO_EVENT_TYPE_WRITABLE, s_socket_connect_event, sock_args)) {
                goto err_clean_up;
            }
            struct posix_socket *socket_impl = socket->impl;
            socket_impl->currently_subscribed = true;

            uint64_t timeout = 0;
            aws_event_loop_current_clock_time(event_loop, &timeout);

            timeout += aws_timestamp_convert(
                socket->options.connect_timeout_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
            /* schedule a task to run at the connect timeout interval, if this task runs before the connect
             * happens, we consider that a timeout. */
            aws_event_loop_schedule_task_future(event_loop, &sock_args->task, timeout);
        } else {
            int aws_error = s_determine_socket_error(error_code);
            aws_raise_error(aws_error);
            goto err_clean_up;
        }
    }
    return AWS_OP_SUCCESS;

err_clean_up:
    aws_mem_release(socket->allocator, sock_args);
    return AWS_OP_ERR;
}

int aws_socket_bind(struct aws_socket *socket, struct aws_socket_endpoint *local_endpoint) {
    if (socket->state != INIT) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    int error_code = -1;

    socket->local_endpoint = *local_endpoint;

    struct socket_address address;
    AWS_ZERO_STRUCT(address);
    socklen_t sock_size = 0;
    int pton_err = 1;
    if (socket->options.domain == AWS_SOCKET_IPV4) {
        pton_err = inet_pton(AF_INET, local_endpoint->address, &address.sock_addr_types.addr_in.sin_addr);
        address.sock_addr_types.addr_in.sin_port = htons(local_endpoint->port);
        address.sock_addr_types.addr_in.sin_family = AF_INET;
        sock_size = sizeof(address.sock_addr_types.addr_in);
    } else if (socket->options.domain == AWS_SOCKET_IPV6) {
        pton_err = inet_pton(AF_INET6, local_endpoint->address, &address.sock_addr_types.addr_in6.sin6_addr);
        address.sock_addr_types.addr_in6.sin6_port = htons(local_endpoint->port);
        address.sock_addr_types.addr_in6.sin6_family = AF_INET6;
        sock_size = sizeof(address.sock_addr_types.addr_in6);
    } else if (socket->options.domain == AWS_SOCKET_LOCAL) {
        address.sock_addr_types.un_addr.sun_family = AF_UNIX;
        assert(sizeof(local_endpoint->address) <= sizeof(address.sock_addr_types.un_addr.sun_path));
        strncpy(
            address.sock_addr_types.un_addr.sun_path,
            local_endpoint->address,
            sizeof(address.sock_addr_types.un_addr.sun_path) - 1);
        sock_size = sizeof(address.sock_addr_types.un_addr);
    } else {
        assert(0);
        return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
    }

    if (pton_err != 1) {
        return aws_raise_error(s_convert_pton_error(pton_err));
    }

    error_code = bind(socket->io_handle.data.fd, (struct sockaddr *)&address.sock_addr_types, sock_size);

    if (!error_code) {
        if (socket->options.type == AWS_SOCKET_STREAM) {
            socket->state = BOUND;
        } else {
            /* e.g. UDP is now readable */
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

/* this is called by the event loop handler that was installed in start_accept(). It runs once the FD goes readable,
 * accepts as many as it can and then returns control to the event loop. */
static void socket_accept_event(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data) {

    (void)event_loop;

    struct aws_socket *socket = user_data;
    struct posix_socket *socket_impl = socket->impl;

    if (socket_impl->continue_accept && events & AWS_IO_EVENT_TYPE_READABLE) {
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

                int aws_error = aws_socket_get_error(socket);
                aws_raise_error(aws_error);
                s_on_connection_error(socket, aws_error);
                continue;
            }

            struct aws_socket *new_sock = aws_mem_acquire(socket->allocator, sizeof(struct aws_socket));

            if (!new_sock) {
                break;
            }

            if (s_socket_init(new_sock, socket->allocator, &socket->options, false)) {
                aws_mem_release(socket->allocator, new_sock);
                break;
            }

            new_sock->io_handle = (struct aws_io_handle){.data = {.fd = in_fd}, .additional_data = NULL};
            memcpy(&new_sock->local_endpoint, &socket->local_endpoint, sizeof(socket->local_endpoint));
            aws_socket_set_options(new_sock, &socket->options);
            new_sock->state = CONNECTED_READ | CONNECTED_WRITE;
            uint16_t port = 0;

            /* get the info on the incoming socket's address */
            if (in_addr.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&in_addr;
                port = ntohs(s->sin_port);
                /* this came from the kernel, a.) it won't fail. b.) even if it does
                 * its not fatal. come back and add logging later. */
                inet_ntop(
                    AF_INET,
                    &s->sin_addr,
                    new_sock->remote_endpoint.address,
                    sizeof(new_sock->remote_endpoint.address));
                new_sock->options.domain = AWS_SOCKET_IPV4;
            } else if (in_addr.ss_family == AF_INET6) {
                /* this came from the kernel, a.) it won't fail. b.) even if it does
                 * its not fatal. come back and add logging later. */
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&in_addr;
                port = ntohs(s->sin6_port);
                inet_ntop(
                    AF_INET6,
                    &s->sin6_addr,
                    new_sock->remote_endpoint.address,
                    sizeof(new_sock->remote_endpoint.address));
                new_sock->options.domain = AWS_SOCKET_IPV6;
            } else if (in_addr.ss_family == AF_UNIX) {
                new_sock->remote_endpoint = socket->local_endpoint;
                new_sock->options.domain = AWS_SOCKET_LOCAL;
            }

            new_sock->remote_endpoint.port = port;

            int flags = fcntl(in_fd, F_GETFL, 0);

            flags |= O_NONBLOCK | O_CLOEXEC;
            fcntl(in_fd, F_SETFL, flags);

            socket->accept_result_fn(socket, AWS_ERROR_SUCCESS, new_sock, socket->connect_accept_user_data);
        }
    }
}

int aws_socket_start_accept(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    aws_socket_on_accept_result_fn *on_accept_result,
    void *user_data) {
    assert(on_accept_result);
    assert(accept_loop);

    if (socket->state != LISTENING) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    socket->accept_result_fn = on_accept_result;
    socket->connect_accept_user_data = user_data;
    socket->event_loop = accept_loop;
    struct posix_socket *socket_impl = socket->impl;
    socket_impl->continue_accept = true;
    socket_impl->currently_subscribed = true;

    if (aws_event_loop_subscribe_to_io_events(
            socket->event_loop, &socket->io_handle, AWS_IO_EVENT_TYPE_READABLE, socket_accept_event, socket)) {
        socket_impl->continue_accept = false;
        socket_impl->currently_subscribed = false;

        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

struct stop_accept_args {
    struct aws_task task;
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    struct aws_socket *socket;
    int ret_code;
    bool invoked;
};

static bool s_stop_accept_pred(void *arg) {
    struct stop_accept_args *stop_accept_args = arg;
    return stop_accept_args->invoked;
}

static void s_stop_accept_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;

    struct stop_accept_args *stop_accept_args = arg;
    aws_mutex_lock(&stop_accept_args->mutex);
    stop_accept_args->ret_code = aws_socket_stop_accept(stop_accept_args->socket);
    stop_accept_args->invoked = true;
    aws_condition_variable_notify_one(&stop_accept_args->condition_variable);
    aws_mutex_unlock(&stop_accept_args->mutex);
}

int aws_socket_stop_accept(struct aws_socket *socket) {
    if (socket->state != LISTENING) {
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        struct stop_accept_args args = {.mutex = AWS_MUTEX_INIT,
                                        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
                                        .invoked = false,
                                        .socket = socket,
                                        .ret_code = AWS_OP_SUCCESS,
                                        .task = {.fn = s_stop_accept_task}};
        /* Look.... I know what I'm doing.... trust me, I'm an engineer.
         * We wait on the completion before 'args' goes out of scope.
         * NOLINTNEXTLINE */
        args.task.arg = &args;
        aws_mutex_lock(&args.mutex);
        aws_event_loop_schedule_task_now(socket->event_loop, &args.task);
        aws_condition_variable_wait_pred(&args.condition_variable, &args.mutex, s_stop_accept_pred, &args);
        return args.ret_code;
    }

    int ret_val = AWS_OP_SUCCESS;
    struct posix_socket *socket_impl = socket->impl;
    if (socket_impl->currently_subscribed) {
        ret_val = aws_event_loop_unsubscribe_from_io_events(socket->event_loop, &socket->io_handle);
        socket_impl->currently_subscribed = false;
        socket->event_loop = NULL;
    }

    return ret_val;
}

int aws_socket_set_options(struct aws_socket *socket, struct aws_socket_options *options) {
    if (socket->options.domain != options->domain || socket->options.type != options->type) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
    }

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

        if (socket->options.keep_alive_interval_sec && socket->options.keep_alive_timeout_sec) {
            int ival_in_secs = socket->options.keep_alive_interval_sec;
            setsockopt(socket->io_handle.data.fd, IPPROTO_TCP, TCP_KEEPIDLE, &ival_in_secs, sizeof(ival_in_secs));

            ival_in_secs = socket->options.keep_alive_timeout_sec;
            setsockopt(socket->io_handle.data.fd, IPPROTO_TCP, TCP_KEEPINTVL, &ival_in_secs, sizeof(ival_in_secs));
        }
    }

    return AWS_OP_SUCCESS;
}

struct write_request {
    struct aws_byte_cursor *original_cursor;
    struct aws_byte_cursor cursor_cpy;
    aws_socket_on_write_completed_fn *written_fn;
    void *write_user_data;
    struct aws_linked_list_node node;
};

struct posix_socket_shutdown_args {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    struct aws_socket *socket;
    bool invoked;
    int ret_code;
};

static bool s_shutdown_predicate(void *arg) {
    struct posix_socket_shutdown_args *shutdown_args = arg;
    return shutdown_args->invoked;
}

static void s_shutdown_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct posix_socket_shutdown_args *shutdown_args = arg;
        aws_mutex_lock(&shutdown_args->mutex);
        shutdown_args->ret_code = aws_socket_close(shutdown_args->socket);
        shutdown_args->invoked = true;
        aws_condition_variable_notify_one(&shutdown_args->condition_variable);
        aws_mutex_unlock(&shutdown_args->mutex);
    }
}

int aws_socket_close(struct aws_socket *socket) {
    struct posix_socket *socket_impl = socket->impl;

    if (socket->event_loop) {
        /* don't freak out on me, this almost never happens, and never occurs inside a channel
         * it only gets hit from a listening socket shutting down or from a unit test. */
        if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
            /* the only time we allow this kind of thing is when you're a listener.*/
            if (socket->state != LISTENING) {
                return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
            }

            struct posix_socket_shutdown_args args = {
                .mutex = AWS_MUTEX_INIT,
                .condition_variable = AWS_CONDITION_VARIABLE_INIT,
                .socket = socket,
                .ret_code = AWS_OP_SUCCESS,
            };

            struct aws_task shutdown_task = {
                .fn = s_shutdown_task,
                .arg = &args,
            };

            aws_mutex_lock(&args.mutex);
            aws_event_loop_schedule_task_now(socket->event_loop, &shutdown_task);
            aws_condition_variable_wait_pred(&args.condition_variable, &args.mutex, s_shutdown_predicate, &args);
            return args.ret_code;
        } else if (socket_impl->currently_subscribed) {
            int err_code = aws_event_loop_unsubscribe_from_io_events(socket->event_loop, &socket->io_handle);

            if (err_code) {
                return AWS_OP_ERR;
            }
            socket_impl->currently_subscribed = false;
            socket->event_loop = NULL;
        }
    }

    if (aws_socket_is_open(socket)) {
        close(socket->io_handle.data.fd);
        socket->io_handle.data.fd = -1;
        socket->state = CLOSED;

        /* after shutdown, just go ahead and clear out the pending writes queue
         * and tell the user they were cancelled. */
        while (!aws_linked_list_empty(&socket_impl->write_queue)) {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&socket_impl->write_queue);
            struct write_request *write_request = AWS_CONTAINER_OF(node, struct write_request, node);

            write_request->written_fn(
                socket, AWS_IO_SOCKET_CLOSED, write_request->original_cursor, write_request->write_user_data);
            aws_mem_release(socket->allocator, write_request);
        }
    }

    return AWS_OP_SUCCESS;
}

int aws_socket_shutdown_dir(struct aws_socket *socket, enum aws_channel_direction dir) {
    int how = dir == AWS_CHANNEL_DIR_READ ? 0 : 1;

    if (shutdown(socket->io_handle.data.fd, how)) {
        int aws_error = s_determine_socket_error(errno);
        return aws_raise_error(aws_error);
    }

    return AWS_OP_SUCCESS;
}

/* this gets called in two scenarios.
 * 1st scenario, someone called write and we want to at least try and make a write call if we can or return an
 * error if something bad has happened to the socket.
 * 2nd scenario, the event loop notified us that the socket went writable. */
static int s_process_write_requests(struct aws_socket *socket, bool spawned_from_event) {
    struct posix_socket *socket_impl = socket->impl;
    struct aws_allocator *allocator = socket->allocator;

    /* there's a potential deadlock where we notify the user that we wrote some data, the user
     * says, "cool, now I can write more and then immediately calls aws_socket_write(). We need to make sure
     * that we don't allow reentrancy in that case. */
    socket_impl->write_in_progress = true;

    if (!spawned_from_event) {
        socket_impl->currently_in_event = true;
    }

    bool purge = false;
    int aws_error = AWS_OP_SUCCESS;

    /* if a close call happens in the middle, this queue will have been cleaned out from under us. */
    while (!aws_linked_list_empty(&socket_impl->write_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_front(&socket_impl->write_queue);
        struct write_request *write_request = AWS_CONTAINER_OF(node, struct write_request, node);

        ssize_t written =
            send(socket->io_handle.data.fd, write_request->cursor_cpy.ptr, write_request->cursor_cpy.len, NO_SIGNAL);

        if (written < 0) {
            int error = errno;
            if (error == EAGAIN) {
                break;
            }

            if (error == EPIPE) {
                aws_error = AWS_IO_SOCKET_CLOSED;
                aws_raise_error(aws_error);
                purge = true;
                break;
            }

            purge = true;
            aws_error = s_determine_socket_error(error);
            aws_raise_error(aws_error);
            break;
        }

        size_t remaining_to_write = write_request->cursor_cpy.len;
        aws_byte_cursor_advance(&write_request->cursor_cpy, (size_t)written);
        if ((size_t)written == remaining_to_write) {
            aws_linked_list_remove(node);
            write_request->written_fn(
                socket, AWS_OP_SUCCESS, write_request->original_cursor, write_request->write_user_data);
            aws_mem_release(allocator, write_request);
        }
    }

    if (purge) {
        aws_raise_error(aws_error);
        while (!aws_linked_list_empty(&socket_impl->write_queue)) {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&socket_impl->write_queue);
            struct write_request *write_request = AWS_CONTAINER_OF(node, struct write_request, node);

            write_request->written_fn(
                socket, aws_error, write_request->original_cursor, write_request->write_user_data);
            aws_mem_release(socket->allocator, write_request);
        }
    }

    socket_impl->write_in_progress = false;

    if (!spawned_from_event) {
        socket_impl->currently_in_event = false;
    }

    if (socket_impl->clean_yourself_up) {
        aws_mem_release(allocator, socket_impl);
    }

    if (!aws_error) {
        return AWS_OP_SUCCESS;
    }

    return AWS_OP_ERR;
}

static void s_on_socket_io_event(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data) {
    (void)event_loop;
    (void)handle;
    /* this is to handle a race condition when an error kicks off a cleanup, or the user decides
     * to close the socket based on something they read (SSL validation failed for example).
     * if clean_up happens when currently_in_event is true, socket_impl is kept dangling but currently
     * subscribed is set to false. */
    struct aws_socket *socket = user_data;
    struct posix_socket *socket_impl = socket->impl;
    struct aws_allocator *allocator = socket->allocator;

    socket_impl->currently_in_event = true;

    if (events & AWS_IO_EVENT_TYPE_REMOTE_HANG_UP || events & AWS_IO_EVENT_TYPE_CLOSED) {
        aws_raise_error(AWS_IO_SOCKET_CLOSED);
        if (socket->readable_fn) {
            socket->readable_fn(socket, AWS_IO_SOCKET_CLOSED, socket->readable_user_data);
        }
        goto end_check;
    }

    if (socket_impl->currently_subscribed && events & AWS_IO_EVENT_TYPE_ERROR) {
        int aws_error = aws_socket_get_error(socket);
        aws_raise_error(aws_error);
        if (socket->readable_fn) {
            socket->readable_fn(socket, aws_error, socket->readable_user_data);
        }
        goto end_check;
    }

    if (socket_impl->currently_subscribed && events & AWS_IO_EVENT_TYPE_READABLE) {
        if (socket->readable_fn) {
            socket->readable_fn(socket, AWS_OP_SUCCESS, socket->readable_user_data);
        }
    }
    /* if socket closed in between these branches, the currently_subscribed will be false and socket_impl will not
     * have been cleaned up, so this next branch is safe. */
    if (socket_impl->currently_subscribed && events & AWS_IO_EVENT_TYPE_WRITABLE) {
        s_process_write_requests(socket, true);
    }

end_check:
    socket_impl->currently_in_event = false;

    if (socket_impl->clean_yourself_up) {
        aws_mem_release(allocator, socket_impl);
    }
}

int aws_socket_assign_to_event_loop(struct aws_socket *socket, struct aws_event_loop *event_loop) {
    if (!socket->event_loop) {
        socket->event_loop = event_loop;
        struct posix_socket *socket_impl = socket->impl;
        socket_impl->currently_subscribed = true;
        if (aws_event_loop_subscribe_to_io_events(
                event_loop,
                &socket->io_handle,
                AWS_IO_EVENT_TYPE_WRITABLE | AWS_IO_EVENT_TYPE_READABLE,
                s_on_socket_io_event,
                socket)) {
            socket_impl->currently_subscribed = false;
            return AWS_OP_ERR;
        }

        return AWS_OP_SUCCESS;
    }

    return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
}

struct aws_event_loop *aws_socket_get_event_loop(struct aws_socket *socket) {
    return socket->event_loop;
}

int aws_socket_subscribe_to_readable_events(
    struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable,
    void *user_data) {
    if (!(socket->state & CONNECTED_READ)) {
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    if (socket->readable_fn) {
        return aws_raise_error(AWS_ERROR_IO_ALREADY_SUBSCRIBED);
    }

    assert(on_readable);
    socket->readable_user_data = user_data;
    socket->readable_fn = on_readable;

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

    /* read_val of 0 means EOF which we'll treat as AWS_IO_SOCKET_CLOSED */
    if (read_val == 0) {
        if (buffer->capacity - buffer->len > 0) {
            return aws_raise_error(AWS_IO_SOCKET_CLOSED);
        } else {
            return AWS_OP_SUCCESS;
        }
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

int aws_socket_write(
    struct aws_socket *socket,
    struct aws_byte_cursor *cursor,
    aws_socket_on_write_completed_fn *written_fn,
    void *user_data) {
    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (!(socket->state & CONNECTED_WRITE)) {
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    assert(written_fn);
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
        return s_process_write_requests(socket, false);
    }

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
