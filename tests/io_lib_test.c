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
