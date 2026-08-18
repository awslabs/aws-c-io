/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "./echo_server.h"
#include "./socks5_server.h"
#include "./tcp_client.h"

#include <aws/testing/aws_test_harness.h>

#include <aws/io/event_loop.h>
#include <aws/io/socks5.h>

#include "aws/io/l4_proxy.h"

static int s_aws_socks5_server_create_destroy_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_server_test_context context;
    aws_socks5_server_test_context_init(&context, allocator, NULL);

    aws_socks5_server_test_context_wait_on_server_setup(&context);

    aws_socks5_server_test_context_clean_up(&context);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_server_create_destroy, s_aws_socks5_server_create_destroy_fn)

static int s_aws_echo_server_create_destroy_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_echo_server_test_context context;
    aws_echo_server_test_context_init(&context, allocator, NULL);

    aws_echo_server_test_context_wait_on_server_setup(&context);

    aws_echo_server_test_context_clean_up(&context);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_echo_server_create_destroy, s_aws_echo_server_create_destroy_fn)

struct aws_socks5_tcp_test_context {
    struct aws_allocator *allocator;

    struct aws_event_loop_group *elg;
    struct aws_l4_proxy_config *proxy_config;

    struct aws_echo_server_test_context echo_server_context;
    struct aws_socks5_server_test_context socks5_server_context;
    struct aws_tcp_client_test_context tcp_client_context;
};

typedef void (*socks5_server_options_override_fn)(struct aws_socks5_server_test_context_options *socks5_server_options);
typedef void (*tcp_client_options_override_fn)(struct aws_tcp_client_test_context_options *tcp_client_options);

static void s_aws_socks5_tcp_test_context_init(struct aws_socks5_tcp_test_context *context, struct aws_allocator *allocator, socks5_server_options_override_fn *socks5_override_fn, struct aws_socks5_proxy_negotiation_strategy *strategy) {
    AWS_ZERO_STRUCT(*context);

    context->allocator = allocator;

    struct aws_event_loop_group_options elg_options = {};
    context->elg = aws_event_loop_group_new(allocator, &elg_options);

    aws_echo_server_test_context_init(&context->echo_server_context, allocator, context->elg);
    aws_echo_server_test_context_wait_on_server_setup(&context->echo_server_context);

    uint16_t echo_server_port = aws_echo_server_get_listener_port(context->echo_server_context.server);

    struct aws_socks5_server_test_context_options socks5_test_context_options ={
        .elg = context->elg,
    };

    if (socks5_override_fn) {
        (*socks5_override_fn)(&socks5_test_context_options);
    }

    aws_socks5_server_test_context_init(&context->socks5_server_context, allocator, &socks5_test_context_options);
    aws_socks5_server_test_context_wait_on_server_setup(&context->socks5_server_context);

    struct aws_socks5_proxy_options proxy_options = {
        .proxy_host = aws_byte_cursor_from_c_str("127.0.0.1"),
        .proxy_port = aws_socks5_server_get_listener_port(context->socks5_server_context.server),
        .negotiation_strategy = strategy,
        .negotiation_timeout_ms = 10000,
    };

    context->proxy_config = aws_l4_proxy_config_new_socks5(allocator, &proxy_options);

    struct aws_tcp_client_test_context_options tcp_client_test_context_options = {
        .remote_host_name = aws_byte_cursor_from_c_str("127.0.0.1"),
        .remote_port = echo_server_port,
        .proxy_config = context->proxy_config,
        .elg = context->elg,
    };

    aws_tcp_client_test_context_init(&context->tcp_client_context, allocator, &tcp_client_test_context_options);
}

static void s_aws_socks5_tcp_test_context_clean_up(struct aws_socks5_tcp_test_context *context) {
    aws_tcp_client_test_context_clean_up(&context->tcp_client_context);
    aws_echo_server_test_context_clean_up(&context->echo_server_context);
    aws_socks5_server_test_context_clean_up(&context->socks5_server_context);
    aws_l4_proxy_config_release(context->proxy_config);
    aws_event_loop_group_release(context->elg);

}