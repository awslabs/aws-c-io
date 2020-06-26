/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/io/io.h>

static int s_io_load_error_strings_test(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    /* Load aws-c-io's actual error info.
     * This will fail if the error info list is out of sync with the error enums. */
    aws_io_library_init(allocator);
    aws_io_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(io_load_error_strings_test, s_io_load_error_strings_test)
