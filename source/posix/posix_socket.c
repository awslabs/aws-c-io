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
#include <stdio.h>
#include <sys/un.h>


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
        case AWS_IO_SOCKET_STREAM:
            return SOCK_STREAM;
        case AWS_IO_SOCKET_DGRAM:
            return SOCK_DGRAM;
        default:
            assert(0);
            return SOCK_STREAM;
    }
}

static int create_socket(struct aws_socket *sock) {

    int fd = socket(convert_domain(sock->options.domain), convert_type(sock->options.type),  0);
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK | SOCK_CLOEXEC);

    if(fd != -1) {
        sock->io_handle.handle = fd;
        sock->io_handle.private_event_loop_data = NULL;
        return AWS_OP_SUCCESS;
    }

    int error_code = errno;

    if(error_code == ENOBUFS || error_code == ENOMEM) {
        return aws_raise_error(AWS_ERROR_OOM);
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


int aws_socket_outgoing_init(struct aws_socket *socket, struct aws_allocator *alloc,
                             struct aws_socket_options *options,
                             struct aws_event_loop *connection_loop,
                             struct aws_socket_creation_args *creation_args) {
    socket->allocator = alloc;
    socket->options = *options;
    socket->io_handle = {0};
    socket->creation_args = *creation_args;
    socket->connection_loop = connection_loop;

    return create_socket(socket);
}

int aws_socket_incoming_init(struct aws_socket *socket, struct aws_allocator *alloc,
                             struct aws_socket_options *options, struct aws_event_loop *connection_loop,
                             struct aws_socket_creation_args *creation_args) {
    socket->allocator = alloc;
    socket->options = *options;
    socket->io_handle = {0};
    socket->creation_args = *creation_args;
    socket->connection_loop = connection_loop;

    return create_socket(socket);
}

static void on_connection_success(struct aws_socket *socket) {

    if (socket->creation_args.on_connection_established) {
        socket->creation_args.on_connection_established(socket, socket->creation_args.ctx);
    }
}

static void on_connection_error(struct aws_socket *socket, int error) {
    int error_code = 0;
    switch(error) {
        case ECONNREFUSED:
            error_code = AWS_IO_SOCKET_CONNECTION_REFUSED;
            break;
        case ETIMEDOUT:
            error_code = AWS_IO_SOCKET_TIMEOUT;
            break;
        case ENETUNREACH:
            error_code = AWS_IO_SOCKET_NO_ROUTE_TO_HOST;
            break;
        case ENETDOWN:
            error_code = AWS_IO_SOCKET_NETWORK_DOWN;
            break;
        case 0:
            error_code = AWS_IO_SOCKET_NOT_CONNECTED;
            break;
        default:
            error_code = AWS_IO_SOCKET_NOT_CONNECTED;
    }

    aws_raise_error(error_code);

    if (socket->creation_args.on_closed) {
        socket->creation_args.on_closed(socket, error_code, socket->creation_args.ctx);
    }
}

void socket_connect_event(struct aws_event_loop *event_loop, struct aws_io_handle *handle, int events, void *ctx) {

    struct aws_socket *socket = (struct aws_socket *) ctx;
    aws_event_loop_unsubscribe_from_io_events(event_loop, handle);

    int connect_result;
    socklen_t result_length = sizeof(connect_result);

    if (getsockopt(socket->io_handle.handle, SOL_SOCKET, SO_ERROR, &connect_result, &result_length) < 0) {
        on_connection_error(socket, errno);
    }
    else {
        struct sockaddr_storage address = {0};
        socklen_t address_size = sizeof(address);
        if (!getsockname(socket->io_handle.handle, (struct sockaddr *)&address, &address_size)) {
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
            on_connection_success(socket);
        }
        else {
            on_connection_error(socket, errno);
        }
    }
}

int aws_socket_connect(struct aws_socket *socket, struct aws_socket_endpoint *remote_endpoint) {
    if (socket->options.type != AWS_IO_SOCKET_STREAM) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE);
    }

    memcpy(socket->remote_endpoint.port, remote_endpoint->port, sizeof(remote_endpoint->port));
    memcpy(socket->remote_endpoint.socket_name, remote_endpoint->socket_name, sizeof(remote_endpoint->socket_name));
    memcpy(socket->remote_endpoint.address, remote_endpoint->address, sizeof(socket->remote_endpoint.address));

    if (socket->creation_args.on_incoming_connection) {
        int error_code = -1;
        if (socket->options.domain == AWS_SOCKET_IPV4) {
            struct sockaddr_in addr_in;
            inet_pton(AF_INET, remote_endpoint->address, &(addr_in.sin_addr));
            addr_in.sin_port = htons((uint16_t)atoi(remote_endpoint->port));
            addr_in.sin_family = AF_INET;
            error_code = connect(socket->io_handle.handle, (struct sockaddr *)&addr_in, sizeof(addr_in));
        }
        else if (socket->options.domain == AWS_SOCKET_IPV6) {
            struct sockaddr_in6 addr_in;
            inet_pton(AF_INET6, remote_endpoint->address, &(addr_in.sin6_addr));
            addr_in.sin6_port = htons((uint16_t)atoi(remote_endpoint->port));
            addr_in.sin6_family = AF_INET6;
            error_code = connect(socket->io_handle.handle, (struct sockaddr *)&addr_in, sizeof(addr_in));
        }
        else if (socket->options.domain == AWS_SOCKET_LOCAL) {
            struct sockaddr_un addr = {0};
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, remote_endpoint->socket_name, sizeof(addr.sun_path) - 1);
            error_code = connect (socket->io_handle.handle, (const struct sockaddr *) &addr,
                           sizeof(struct sockaddr_un));
        }
        else {
            assert(0);
            return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
        }

        if(!error_code) {

            on_connection_success(socket);
            return AWS_OP_SUCCESS;
        }

        error_code = errno;
        if(error_code == EINPROGRESS || error_code == EALREADY) {
            return aws_event_loop_subscribe_to_io_events(socket->connection_loop, &socket->io_handle,
                                                         AWS_IO_EVENT_TYPE_READABLE | AWS_IO_EVENT_TYPE_WRITABLE,
                                                         socket_connect_event, socket);
        }

        on_connection_error(socket, error_code);
        return AWS_OP_SUCCESS;
    }

    return aws_raise_error(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE);
}

int aws_socket_bind(struct aws_socket *socket, struct aws_endpoint *local_endpoint) {

}
