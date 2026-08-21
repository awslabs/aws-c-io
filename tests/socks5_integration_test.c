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

static struct aws_socks5_proxy_negotiation_strategy *s_build_no_auth_strategy(struct aws_allocator *allocator) {
    return aws_socks5_proxy_negotiation_strategy_new_no_auth(allocator);
}

static const char s_good_username[] = "hello";
static const char s_good_password[] = "world";

static struct aws_socks5_proxy_negotiation_strategy *s_build_basic_auth_strategy_good(struct aws_allocator *allocator) {
    struct aws_socks5_proxy_negotiation_basic_auth_options good_options = {
        .username = aws_byte_cursor_from_array(s_good_username, AWS_ARRAY_SIZE(s_good_username)),
        .password = aws_byte_cursor_from_array(s_good_password, AWS_ARRAY_SIZE(s_good_password)),
    };

    return aws_socks5_proxy_negotiation_strategy_new_basic_auth(allocator, &good_options);
}

static struct aws_socks5_proxy_negotiation_strategy *s_build_basic_auth_strategy_bad(struct aws_allocator *allocator) {
    struct aws_socks5_proxy_negotiation_basic_auth_options bad_options = {
        .username = aws_byte_cursor_from_c_str("not"),
        .password = aws_byte_cursor_from_c_str("correct"),
    };

    return aws_socks5_proxy_negotiation_strategy_new_basic_auth(allocator, &bad_options);
}

static struct aws_byte_cursor s_good_username_cursor = {
    .ptr = (uint8_t *)s_good_username,
    .len = AWS_ARRAY_SIZE(s_good_username),
};

static struct aws_byte_cursor s_good_password_cursor = {
    .ptr = (uint8_t *)s_good_password,
    .len = AWS_ARRAY_SIZE(s_good_password),
};

static struct aws_socks5_server_auth_options s_good_basic_auth_options = {
    .allow_no_auth = false,
    .allow_basic_auth = true,
    .basic_username = &s_good_username_cursor,
    .basic_password = &s_good_password_cursor,
};

static int s_aws_socks5_full_test_context_create_destroy_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, NULL, NULL);

    aws_tcp_client_connect(context.tcp_client_context.client);
    aws_tcp_client_test_context_wait_on_connection_result(&context.tcp_client_context);

    struct aws_byte_buf to_send;
    aws_byte_buf_init(&to_send, allocator, 256);
    for (size_t i = 0; i < 256; ++i) {
        to_send.buffer[i] = i;
    }
    to_send.len = 256;

    struct aws_byte_cursor to_send_cursor = aws_byte_cursor_from_buf(&to_send);

    aws_tcp_client_test_context_send_data(&context.tcp_client_context, to_send_cursor);

    aws_tcp_client_test_context_wait_on_received_bytes(&context.tcp_client_context, 256);

    struct aws_byte_buf sent_data;
    aws_byte_buf_init(&to_send, allocator, 256);
    aws_tcp_client_test_context_get_sent_bytes(&context.tcp_client_context, &sent_data);

    struct aws_byte_buf received_data;
    aws_byte_buf_init(&to_send, allocator, 256);
    aws_tcp_client_test_context_get_received_bytes(&context.tcp_client_context, &received_data);

    ASSERT_BIN_ARRAYS_EQUALS(sent_data.buffer, sent_data.len, received_data.buffer, received_data.len);

    s_aws_socks5_tcp_test_context_clean_up(&context);

    aws_byte_buf_clean_up(&to_send);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_full_test_context_create_destroy, s_aws_socks5_full_test_context_create_destroy_fn)