/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/io/io.h>

/* Initialize this library and its dependencies.
 * This will fail if:
 * - the error info list is out of sync with the error enums.
 * - there is a memory leak */
static int s_test_io_library_init(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    aws_io_library_init(allocator);
    aws_io_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(io_library_init, s_test_io_library_init)

/* Ensure the library can go through the init/cleanup cycle multiple times */
static int s_test_io_library_init_cleanup_init_cleanup(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    aws_io_library_init(allocator);
    aws_io_library_clean_up();

    aws_io_library_init(allocator);
    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(io_library_init_cleanup_init_cleanup, s_test_io_library_init_cleanup_init_cleanup)

/* Make sure that new error codes are being added to the end instead of in the middle. */
static int s_test_io_library_error_order(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    aws_io_library_init(allocator);
    // Checking against expected int values of the error codes.
    // The checked error codes are the first, somewhere in the middle, and last as of this commit.
    ASSERT_TRUE(1024 == AWS_IO_CHANNEL_ERROR_ERROR_CANT_ACCEPT_INPUT);
    ASSERT_TRUE(1067 == AWS_IO_TLS_NEGOTIATION_TIMEOUT);
    ASSERT_TRUE(1194 == AWS_IO_TLS_HOST_NAME_MISMATCH);
    aws_io_library_clean_up();
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(io_library_error_order, s_test_io_library_error_order)