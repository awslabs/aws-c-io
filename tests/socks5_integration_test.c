/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/echo_server.h>
#include <aws/testing/socks5_server.h>
#include <aws/testing/tcp_client.h>

#include <aws/testing/aws_test_harness.h>

#include "aws/io/l4_proxy.h"
#include <aws/common/clock.h>
#include <aws/io/event_loop.h>
#include <aws/io/socks5.h>

#include "aws/io/private/l4_proxy_impl.h"

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

typedef void(socks5_server_options_override_fn)(struct aws_socks5_server_test_context_options *socks5_server_options);
typedef void(tcp_client_options_override_fn)(struct aws_tcp_client_test_context_options *tcp_client_options);

struct aws_socks5_tcp_test_context_options {
    socks5_server_options_override_fn *socks5_server_options_override;
    struct aws_socks5_proxy_negotiation_strategy *strategy;
    tcp_client_options_override_fn *tcp_client_options_override;
};

static void s_aws_socks5_tcp_test_context_init(
    struct aws_socks5_tcp_test_context *context,
    struct aws_allocator *allocator,
    struct aws_socks5_tcp_test_context_options *context_options) {
    AWS_ZERO_STRUCT(*context);

    context->allocator = allocator;

    struct aws_event_loop_group_options elg_options = {};
    context->elg = aws_event_loop_group_new(allocator, &elg_options);

    aws_echo_server_test_context_init(&context->echo_server_context, allocator, context->elg);
    aws_echo_server_test_context_wait_on_server_setup(&context->echo_server_context);

    uint32_t echo_server_port = aws_echo_server_get_listener_port(context->echo_server_context.server);

    struct aws_socks5_server_test_context_options socks5_test_context_options = {
        .elg = context->elg,
    };

    if (context_options->socks5_server_options_override) {
        (*context_options->socks5_server_options_override)(&socks5_test_context_options);
    }

    aws_socks5_server_test_context_init(&context->socks5_server_context, allocator, &socks5_test_context_options);
    aws_socks5_server_test_context_wait_on_server_setup(&context->socks5_server_context);

    struct aws_socks5_proxy_options proxy_options = {
        .proxy_host = aws_byte_cursor_from_c_str("127.0.0.1"),
        .proxy_port = aws_socks5_server_get_listener_port(context->socks5_server_context.server),
        .negotiation_strategy = context_options->strategy,
        .negotiation_timeout_ms = 10000,
    };

    context->proxy_config = aws_l4_proxy_config_new_socks5(allocator, &proxy_options);

    struct aws_tcp_client_test_context_options tcp_client_test_context_options = {
        .remote_host_name = aws_byte_cursor_from_c_str("127.0.0.1"),
        .remote_port = echo_server_port,
        .proxy_config = context->proxy_config,
        .elg = context->elg,
    };

    if (context_options->tcp_client_options_override) {
        (*context_options->tcp_client_options_override)(&tcp_client_test_context_options);
    }

    aws_tcp_client_test_context_init(&context->tcp_client_context, allocator, &tcp_client_test_context_options);
}

static void s_aws_socks5_tcp_test_context_clean_up(struct aws_socks5_tcp_test_context *context) {
    aws_tcp_client_test_context_clean_up(&context->tcp_client_context);
    aws_echo_server_test_context_clean_up(&context->echo_server_context);
    aws_socks5_server_test_context_clean_up(&context->socks5_server_context);
    aws_l4_proxy_config_release(context->proxy_config);
    aws_event_loop_group_release(context->elg);
}

static int s_aws_socks5_connect_success_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_socks5_tcp_test_context_options context_options = {};

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, &context_options);

    aws_tcp_client_connect(context.tcp_client_context.client);
    aws_tcp_client_test_context_wait_on_connection_result(&context.tcp_client_context);

    s_aws_socks5_tcp_test_context_clean_up(&context);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_connect_success, s_aws_socks5_connect_success_fn)

static int s_aws_socks5_do_send_success_test(
    struct aws_tcp_client_test_context *client_context,
    size_t total_bytes,
    size_t chunk_size,
    uint64_t chunk_delay_millis) {
    struct aws_allocator *allocator = client_context->allocator;

    struct aws_byte_buf to_send;
    aws_byte_buf_init(&to_send, allocator, total_bytes);
    for (size_t i = 0; i < total_bytes; ++i) {
        to_send.buffer[i] = i % 256;
    }
    to_send.len = total_bytes;

    struct aws_byte_cursor to_send_cursor = aws_byte_cursor_from_buf(&to_send);

    while (to_send_cursor.len > 0) {
        size_t advance_size = aws_min_size(chunk_size, to_send_cursor.len);
        struct aws_byte_cursor chunk_cursor = aws_byte_cursor_advance(&to_send_cursor, advance_size);
        if (chunk_cursor.len > 0) {
            aws_tcp_client_test_context_send_data(client_context, chunk_cursor);
        }

        if (chunk_delay_millis > 0) {
            aws_thread_current_sleep(
                aws_timestamp_convert(chunk_delay_millis, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL));
        }
    }

    aws_tcp_client_test_context_wait_on_received_bytes(client_context, total_bytes);

    struct aws_byte_buf sent_data;
    aws_byte_buf_init(&sent_data, allocator, total_bytes);
    aws_tcp_client_test_context_get_sent_bytes(client_context, &sent_data);

    struct aws_byte_buf received_data;
    aws_byte_buf_init(&received_data, allocator, total_bytes);
    aws_tcp_client_test_context_get_received_bytes(client_context, &received_data);

    ASSERT_BIN_ARRAYS_EQUALS(sent_data.buffer, sent_data.len, received_data.buffer, received_data.len);

    aws_byte_buf_clean_up(&to_send);
    aws_byte_buf_clean_up(&sent_data);
    aws_byte_buf_clean_up(&received_data);

    return AWS_OP_SUCCESS;
}

static int s_aws_socks5_do_echo_success_test(
    struct aws_socks5_tcp_test_context *context,
    size_t total_bytes,
    size_t chunk_size,
    uint64_t chunk_delay_millis) {

    aws_tcp_client_connect(context->tcp_client_context.client);
    aws_tcp_client_test_context_wait_on_connection_result(&context->tcp_client_context);

    ASSERT_SUCCESS(
        s_aws_socks5_do_send_success_test(&context->tcp_client_context, total_bytes, chunk_size, chunk_delay_millis));

    s_aws_socks5_tcp_test_context_clean_up(context);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

static int s_aws_socks5_do_no_auth_echo_success_test(
    struct aws_allocator *allocator,
    size_t total_bytes,
    size_t chunk_size,
    uint64_t chunk_delay_millis) {
    aws_io_library_init(allocator);

    struct aws_socks5_tcp_test_context_options context_options = {};

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, &context_options);

    return s_aws_socks5_do_echo_success_test(&context, total_bytes, chunk_size, chunk_delay_millis);
}

static int s_aws_socks5_echo_success_256_256_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_no_auth_echo_success_test(allocator, 256, 256, 0));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_success_256_256, s_aws_socks5_echo_success_256_256_fn)

static int s_aws_socks5_echo_success_1024_256_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_no_auth_echo_success_test(allocator, 1024, 256, 0));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_success_1024_256, s_aws_socks5_echo_success_1024_256_fn)

static int s_aws_socks5_echo_success_5000_256_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_no_auth_echo_success_test(allocator, 5000, 256, 0));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_success_5000_256, s_aws_socks5_echo_success_5000_256_fn)

static int s_aws_socks5_echo_success_65536_16384_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_no_auth_echo_success_test(allocator, 65536, 16384, 0));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_success_65536_16384, s_aws_socks5_echo_success_65536_16384_fn)

static const char s_good_username[] = "hello";
static const char s_good_password[] = "world";

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

static struct aws_socks5_proxy_negotiation_strategy *s_build_basic_auth_strategy_good(struct aws_allocator *allocator) {
    struct aws_socks5_proxy_negotiation_basic_auth_options good_options = {
        .username = s_good_username_cursor,
        .password = s_good_password_cursor,
    };

    return aws_socks5_proxy_negotiation_strategy_new_basic_auth(allocator, &good_options);
}

static void aws_socks5_server_apply_basic_auth_override_fn(
    struct aws_socks5_server_test_context_options *socks5_server_options) {
    socks5_server_options->override_auth_options = &s_good_basic_auth_options;
}

static int s_aws_socks5_do_basic_auth_echo_success_test(
    struct aws_allocator *allocator,
    size_t total_bytes,
    size_t chunk_size,
    uint64_t chunk_delay_millis) {
    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *basic_auth_strategy = s_build_basic_auth_strategy_good(allocator);

    struct aws_socks5_tcp_test_context_options context_options = {
        .socks5_server_options_override = aws_socks5_server_apply_basic_auth_override_fn,
        .strategy = basic_auth_strategy,
    };

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, &context_options);

    aws_socks5_proxy_negotiation_strategy_release(basic_auth_strategy);

    return s_aws_socks5_do_echo_success_test(&context, total_bytes, chunk_size, chunk_delay_millis);
}

static int s_aws_socks5_echo_success_basic_auth_256_256_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_basic_auth_echo_success_test(allocator, 256, 256, 0));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_success_basic_auth_256_256, s_aws_socks5_echo_success_basic_auth_256_256_fn)

static int s_aws_socks5_echo_success_basic_auth_65536_16384_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_no_auth_echo_success_test(allocator, 65536, 16384, 0));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_success_basic_auth_65536_16384, s_aws_socks5_echo_success_basic_auth_65536_16384_fn)

static int s_aws_socks5_do_windowed_echo_success_test(
    struct aws_socks5_tcp_test_context *context,
    size_t total_bytes,
    size_t chunk_size,
    uint64_t chunk_delay_millis,
    size_t iterations) {

    aws_tcp_client_connect(context->tcp_client_context.client);
    aws_tcp_client_test_context_wait_on_connection_result(&context->tcp_client_context);

    for (size_t i = 0; i < iterations; ++i) {
        ASSERT_SUCCESS(s_aws_socks5_do_send_success_test(
            &context->tcp_client_context, total_bytes, chunk_size, chunk_delay_millis));

        aws_tcp_client_test_context_reset_data(&context->tcp_client_context);
    }

    s_aws_socks5_tcp_test_context_clean_up(context);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

static void aws_socks5_client_apply_large_window_override_fn(
    struct aws_tcp_client_test_context_options *tcp_client_options) {
    tcp_client_options->window_size = 65536;
}

static int s_aws_socks5_do_no_auth_large_window_echo_success_test(
    struct aws_allocator *allocator,
    size_t total_bytes,
    size_t chunk_size,
    uint64_t chunk_delay_millis,
    uint64_t iterations) {

    aws_io_library_init(allocator);

    struct aws_socks5_tcp_test_context_options context_options = {
        .tcp_client_options_override = aws_socks5_client_apply_large_window_override_fn,
    };

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, &context_options);

    return s_aws_socks5_do_windowed_echo_success_test(
        &context, total_bytes, chunk_size, chunk_delay_millis, iterations);
}

static int s_aws_socks5_echo_success_large_window_5000_256_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_no_auth_large_window_echo_success_test(allocator, 5000, 256, 0, 100));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_success_large_window_5000_256, s_aws_socks5_echo_success_large_window_5000_256_fn)

static int s_aws_socks5_echo_success_large_window_500000_80000_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_no_auth_large_window_echo_success_test(allocator, 500000, 80000, 0, 100));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_success_large_window_500000_80000, s_aws_socks5_echo_success_large_window_500000_80000_fn)

static void aws_socks5_client_apply_small_window_override_fn(
    struct aws_tcp_client_test_context_options *tcp_client_options) {
    tcp_client_options->window_size = 2000;
}

static int s_aws_socks5_do_no_auth_small_window_echo_success_test(
    struct aws_allocator *allocator,
    size_t total_bytes,
    size_t chunk_size,
    uint64_t chunk_delay_millis,
    uint64_t iterations) {

    aws_io_library_init(allocator);

    struct aws_socks5_tcp_test_context_options context_options = {
        .tcp_client_options_override = aws_socks5_client_apply_small_window_override_fn,
    };

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, &context_options);

    return s_aws_socks5_do_windowed_echo_success_test(
        &context, total_bytes, chunk_size, chunk_delay_millis, iterations);
}

static int s_aws_socks5_echo_success_small_window_5000_256_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_no_auth_small_window_echo_success_test(allocator, 5000, 256, 0, 100));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_success_small_window_5000_256, s_aws_socks5_echo_success_small_window_5000_256_fn)

static int s_aws_socks5_echo_success_small_window_500000_80000_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_no_auth_small_window_echo_success_test(allocator, 500000, 80000, 0, 100));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_success_small_window_500000_80000, s_aws_socks5_echo_success_small_window_500000_80000_fn)

static int s_aws_socks5_do_basic_auth_large_window_echo_success_test(
    struct aws_allocator *allocator,
    size_t total_bytes,
    size_t chunk_size,
    uint64_t chunk_delay_millis,
    uint64_t iterations) {

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *basic_auth_strategy = s_build_basic_auth_strategy_good(allocator);

    struct aws_socks5_tcp_test_context_options context_options = {
        .tcp_client_options_override = aws_socks5_client_apply_large_window_override_fn,
        .socks5_server_options_override = aws_socks5_server_apply_basic_auth_override_fn,
        .strategy = basic_auth_strategy,
    };

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, &context_options);

    aws_socks5_proxy_negotiation_strategy_release(basic_auth_strategy);

    return s_aws_socks5_do_windowed_echo_success_test(
        &context, total_bytes, chunk_size, chunk_delay_millis, iterations);
}

static int s_aws_socks5_echo_success_basic_auth_large_window_5000_256_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_basic_auth_large_window_echo_success_test(allocator, 5000, 256, 0, 100));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    aws_socks5_echo_success_basic_auth_large_window_5000_256,
    s_aws_socks5_echo_success_basic_auth_large_window_5000_256_fn)

static int s_aws_socks5_echo_success_basic_auth_large_window_500000_80000_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_basic_auth_large_window_echo_success_test(allocator, 500000, 80000, 0, 100));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    aws_socks5_echo_success_basic_auth_large_window_500000_80000,
    s_aws_socks5_echo_success_basic_auth_large_window_500000_80000_fn)

static int s_aws_socks5_do_basic_auth_small_window_echo_success_test(
    struct aws_allocator *allocator,
    size_t total_bytes,
    size_t chunk_size,
    uint64_t chunk_delay_millis,
    uint64_t iterations) {

    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *basic_auth_strategy = s_build_basic_auth_strategy_good(allocator);

    struct aws_socks5_tcp_test_context_options context_options = {
        .tcp_client_options_override = aws_socks5_client_apply_small_window_override_fn,
        .socks5_server_options_override = aws_socks5_server_apply_basic_auth_override_fn,
        .strategy = basic_auth_strategy,
    };

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, &context_options);

    aws_socks5_proxy_negotiation_strategy_release(basic_auth_strategy);

    return s_aws_socks5_do_windowed_echo_success_test(
        &context, total_bytes, chunk_size, chunk_delay_millis, iterations);
}

static int s_aws_socks5_echo_success_basic_auth_small_window_5000_256_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_basic_auth_small_window_echo_success_test(allocator, 5000, 256, 0, 100));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    aws_socks5_echo_success_basic_auth_small_window_5000_256,
    s_aws_socks5_echo_success_basic_auth_small_window_5000_256_fn)

static int s_aws_socks5_echo_success_basic_auth_small_window_500000_80000_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_basic_auth_small_window_echo_success_test(allocator, 500000, 80000, 0, 100));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    aws_socks5_echo_success_basic_auth_small_window_500000_80000,
    s_aws_socks5_echo_success_basic_auth_small_window_500000_80000_fn)

static int s_aws_socks5_do_connection_failure_test(
    struct aws_socks5_tcp_test_context *context,
    int expected_connect_error_code,
    int expected_shutdown_error_code) {
    aws_tcp_client_connect(context->tcp_client_context.client);

    int error_code = aws_tcp_client_test_context_wait_on_connection_result(&context->tcp_client_context);
    ASSERT_INT_EQUALS(expected_connect_error_code, error_code);

    if (expected_shutdown_error_code != AWS_ERROR_SUCCESS) {
        error_code = aws_tcp_client_test_context_wait_on_disconnection_result(&context->tcp_client_context);
        ASSERT_INT_EQUALS(expected_shutdown_error_code, error_code);
    }

    s_aws_socks5_tcp_test_context_clean_up(context);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

static void aws_socks5_client_apply_too_small_window_override_fn(
    struct aws_tcp_client_test_context_options *tcp_client_options) {
    tcp_client_options->window_size = 512;
}

static int s_aws_socks5_do_window_too_small_failure_test(struct aws_allocator *allocator) {
    aws_io_library_init(allocator);

    struct aws_socks5_tcp_test_context_options context_options = {
        .tcp_client_options_override = aws_socks5_client_apply_too_small_window_override_fn,
    };

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, &context_options);

    return s_aws_socks5_do_connection_failure_test(&context, AWS_ERROR_SUCCESS, AWS_ERROR_INVALID_STATE);
}

static int s_aws_socks5_echo_connect_failure_window_too_small_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_window_too_small_failure_test(allocator));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_connect_failure_window_too_small, s_aws_socks5_echo_connect_failure_window_too_small_fn)

static struct aws_socks5_server_auth_options s_no_auth_method_options = {
    .allow_basic_auth = false,
    .allow_no_auth = false,
};

static void aws_socks5_server_apply_no_auth_methods_override_fn(
    struct aws_socks5_server_test_context_options *socks5_server_options) {
    socks5_server_options->override_auth_options = &s_no_auth_method_options;
}

static int s_aws_socks5_do_no_auth_methods_failure_test(struct aws_allocator *allocator) {
    aws_io_library_init(allocator);

    struct aws_socks5_tcp_test_context_options context_options = {
        .socks5_server_options_override = aws_socks5_server_apply_no_auth_methods_override_fn,
    };

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, &context_options);

    return s_aws_socks5_do_connection_failure_test(&context, AWS_IO_SOCKS5_NO_ACCEPTABLE_METHODS, AWS_ERROR_SUCCESS);
}

static int s_aws_socks5_echo_connect_failure_no_auth_methods_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_no_auth_methods_failure_test(allocator));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_connect_failure_no_auth_methods, s_aws_socks5_echo_connect_failure_no_auth_methods_fn)

static void aws_socks5_server_apply_version_mismatch_override_fn(
    struct aws_socks5_server_test_context_options *socks5_server_options) {
    socks5_server_options->fault_mode = AWS_SOCKS5_SFM_BAD_VERSION;
}

static int s_aws_socks5_do_version_mismatch_failure_test(struct aws_allocator *allocator) {
    aws_io_library_init(allocator);

    struct aws_socks5_tcp_test_context_options context_options = {
        .socks5_server_options_override = aws_socks5_server_apply_version_mismatch_override_fn,
    };

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, &context_options);

    return s_aws_socks5_do_connection_failure_test(
        &context, AWS_IO_SOCKS5_PROTOCOL_VERSION_MISMATCH, AWS_ERROR_SUCCESS);
}

static int s_aws_socks5_echo_connect_failure_version_mismatch_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_version_mismatch_failure_test(allocator));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_connect_failure_version_mismatch, s_aws_socks5_echo_connect_failure_version_mismatch_fn)

static int s_aws_socks5_do_wrong_credentials_failure_test(struct aws_allocator *allocator) {
    aws_io_library_init(allocator);

    struct aws_socks5_proxy_negotiation_strategy *basic_auth_strategy = s_build_basic_auth_strategy_bad(allocator);

    struct aws_socks5_tcp_test_context_options context_options = {
        .socks5_server_options_override = aws_socks5_server_apply_basic_auth_override_fn,
        .strategy = basic_auth_strategy,
    };

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, &context_options);

    aws_socks5_proxy_negotiation_strategy_release(basic_auth_strategy);

    return s_aws_socks5_do_connection_failure_test(&context, AWS_IO_SOCKS5_SUBNEGOTIATION_REJECTED, AWS_ERROR_SUCCESS);
}

static int s_aws_socks5_echo_connect_failure_wrong_basic_auth_credentials_fn(
    struct aws_allocator *allocator,
    void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_wrong_credentials_failure_test(allocator));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    aws_socks5_echo_connect_failure_wrong_basic_auth_credentials,
    s_aws_socks5_echo_connect_failure_wrong_basic_auth_credentials_fn)

static void aws_socks5_server_apply_remote_refused_override_fn(
    struct aws_socks5_server_test_context_options *socks5_server_options) {
    socks5_server_options->fault_mode = AWS_SOCKS5_SFM_REMOTE_UNAVAILABLE;
}

static int s_aws_socks5_do_remote_refused_failure_test(struct aws_allocator *allocator) {
    aws_io_library_init(allocator);

    struct aws_socks5_tcp_test_context_options context_options = {
        .socks5_server_options_override = aws_socks5_server_apply_remote_refused_override_fn,
    };

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, &context_options);

    return s_aws_socks5_do_connection_failure_test(&context, AWS_IO_SOCKS5_CONNECT_REQUEST_FAILED, AWS_ERROR_SUCCESS);
}

static int s_aws_socks5_echo_connect_failure_remote_refused_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_remote_refused_failure_test(allocator));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_socks5_echo_connect_failure_remote_refused, s_aws_socks5_echo_connect_failure_remote_refused_fn)

static void aws_socks5_server_apply_negotiation_timeout_override_fn(
    struct aws_socks5_server_test_context_options *socks5_server_options) {
    socks5_server_options->fault_mode = AWS_SOCKS5_SFM_REMOTE_TIMEOUT;
}

static void s_apply_negotiation_timeout_override_fn(struct aws_tcp_client_test_context_options *tcp_client_options) {
    tcp_client_options->proxy_config->negotiation_timeout_ms = 1000;
}

static int s_aws_socks5_do_negotiation_timeout_failure_test(struct aws_allocator *allocator) {
    aws_io_library_init(allocator);

    struct aws_socks5_tcp_test_context_options context_options = {
        .socks5_server_options_override = aws_socks5_server_apply_negotiation_timeout_override_fn,
        .tcp_client_options_override = s_apply_negotiation_timeout_override_fn,
    };

    struct aws_socks5_tcp_test_context context;
    s_aws_socks5_tcp_test_context_init(&context, allocator, &context_options);

    return s_aws_socks5_do_connection_failure_test(&context, AWS_IO_SOCKS5_NEGOTIATION_TIMEOUT, AWS_ERROR_SUCCESS);
}

static int s_aws_socks5_echo_connect_failure_negotiation_timeout_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    ASSERT_SUCCESS(s_aws_socks5_do_negotiation_timeout_failure_test(allocator));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    aws_socks5_echo_connect_failure_negotiation_timeout,
    s_aws_socks5_echo_connect_failure_negotiation_timeout_fn)
