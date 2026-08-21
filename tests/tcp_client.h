/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <aws/io/io.h>

#include <aws/common/byte_buf.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/io/socket.h>

struct aws_client_bootstrap;
struct aws_l4_proxy_config;

struct aws_tcp_client;

typedef void (*aws_tcp_client_on_connection_result_callback)(int error_code, void *user_data);
typedef void (*aws_tcp_client_on_disconnection_callback)(int error_code, void *user_data);
typedef void (*aws_tcp_client_on_data_callback)(struct aws_byte_cursor data, void *user_data);
typedef void (*aws_tcp_client_on_destroyed_callback)(void *user_data);

struct aws_tcp_client_options {
    struct aws_byte_cursor remote_host_name;
    uint16_t remote_port;

    struct aws_l4_proxy_config *proxy_config;

    struct aws_client_bootstrap *bootstrap;
    struct aws_socket_options socket_options;

    aws_tcp_client_on_connection_result_callback on_connection_result_callback;
    aws_tcp_client_on_disconnection_callback on_disconnection_callback;
    aws_tcp_client_on_data_callback on_data_callback;
    aws_tcp_client_on_destroyed_callback on_destroyed_callback;

    void *user_data;
};

struct aws_tcp_client_test_context_options {
    struct aws_byte_cursor remote_host_name;
    uint16_t remote_port;

    struct aws_l4_proxy_config *proxy_config;

    struct aws_event_loop_group *elg;
};

struct aws_tcp_client_test_context {
    struct aws_allocator *allocator;

    struct aws_event_loop_group *elg;
    struct aws_client_bootstrap *bootstrap;
    struct aws_host_resolver *resolver;

    struct aws_mutex lock;
    struct aws_condition_variable signal;
    struct {
        bool connection_attempt_completed;
        int connection_error_code;
        bool disconnection_completed;
        int disconnection_error_code;
        bool destruction_completed;
        struct aws_byte_buf sent_data;
        struct aws_byte_buf received_data;
    } sync;

    struct aws_tcp_client *client;
};

AWS_EXTERN_C_BEGIN

AWS_IO_API struct aws_tcp_client *aws_tcp_client_new(
    struct aws_allocator *allocator,
    struct aws_tcp_client_options *options);
AWS_IO_API struct aws_tcp_client *aws_tcp_client_acquire(struct aws_tcp_client *client);
AWS_IO_API struct aws_tcp_client *aws_tcp_client_release(struct aws_tcp_client *client);

AWS_IO_API void aws_tcp_client_connect(struct aws_tcp_client *client);
AWS_IO_API void aws_tcp_client_disconnect(struct aws_tcp_client *client);
AWS_IO_API void aws_tcp_client_send(struct aws_tcp_client *client, struct aws_byte_cursor data);

AWS_IO_API void aws_tcp_client_test_context_init(
    struct aws_tcp_client_test_context *context,
    struct aws_allocator *allocator,
    struct aws_tcp_client_test_context_options *options);
AWS_IO_API void aws_tcp_client_test_context_clean_up(struct aws_tcp_client_test_context *context);

AWS_IO_API int aws_tcp_client_test_context_wait_on_connection_result(struct aws_tcp_client_test_context *context);
AWS_IO_API int aws_tcp_client_test_context_wait_on_disconnection_result(struct aws_tcp_client_test_context *context);

AWS_IO_API void aws_tcp_client_test_context_send_data(struct aws_tcp_client_test_context *context, struct aws_byte_cursor data);
AWS_IO_API void aws_tcp_client_test_context_wait_on_received_bytes(struct aws_tcp_client_test_context *context, size_t received_bytes);
AWS_IO_API void aws_tcp_client_test_context_get_sent_bytes(struct aws_tcp_client_test_context *context, struct aws_byte_buf *bytes);
AWS_IO_API void aws_tcp_client_test_context_get_received_bytes(struct aws_tcp_client_test_context *context, struct aws_byte_buf *bytes);

AWS_EXTERN_C_END

#endif /* TCP_CLIENT_H */
