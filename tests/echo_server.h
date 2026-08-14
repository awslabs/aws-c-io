/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef ECHO_SERVER_H
#define ECHO_SERVER_H

#include <aws/io/io.h>

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/io/socket.h>

struct aws_event_loop_group;
struct aws_server_bootstrap;

struct aws_echo_server;

struct aws_echo_server_options {
    struct aws_event_loop_group *elg;
    struct aws_server_bootstrap *listener_bootstrap;

    const char *host_name;
    uint16_t port;

    struct aws_socket_options socket_options;

    void (*on_setup)(struct aws_echo_server *server, int error_code, void *user_data);
    void *on_setup_user_data;

    void (*on_destroy)(struct aws_echo_server *server, void *user_data);
    void *on_destroy_user_data;
};

struct aws_echo_server_test_context {
    struct aws_allocator *allocator;

    struct aws_event_loop_group *elg;
    struct aws_server_bootstrap *server_bootstrap;

    struct aws_mutex lock;
    struct aws_condition_variable signal;
    struct {
        bool server_setup;
        int setup_error_code;
        bool server_shutdown;
    } sync;

    struct aws_echo_server *server;
};

AWS_EXTERN_C_BEGIN

AWS_IO_API struct aws_echo_server *aws_echo_server_new(
    struct aws_allocator *allocator,
    struct aws_echo_server_options *options);
AWS_IO_API struct aws_echo_server *aws_echo_server_acquire(struct aws_echo_server *server);
AWS_IO_API void aws_echo_server_release(struct aws_echo_server *server);

AWS_IO_API int aws_echo_server_begin_accept(struct aws_echo_server *server);

AWS_IO_API uint16_t aws_echo_server_get_listener_port(struct aws_echo_server *server);

AWS_IO_API void aws_echo_server_test_context_init(
    struct aws_echo_server_test_context *context,
    struct aws_allocator *allocator);
AWS_IO_API void aws_echo_server_test_context_clean_up(struct aws_echo_server_test_context *context);

AWS_IO_API void aws_echo_server_test_context_wait_on_server_setup(struct aws_echo_server_test_context *context);

AWS_EXTERN_C_END

#endif /* ECHO_SERVER_H */
