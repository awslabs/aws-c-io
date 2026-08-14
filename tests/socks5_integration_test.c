/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "./echo_server.h"
#include "./socks5_server.h"

#include <aws/testing/aws_test_harness.h>

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
    aws_echo_server_test_context_init(&context, allocator);

    aws_echo_server_test_context_wait_on_server_setup(&context);

    aws_echo_server_test_context_clean_up(&context);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(aws_echo_server_create_destroy, s_aws_echo_server_create_destroy_fn)
