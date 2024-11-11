/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/io.h>
#include <aws/io/retry_strategy.h>
#include <aws/testing/aws_test_harness.h>

static int s_test_no_retries_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_retry_strategy *retry_strategy = aws_retry_strategy_new_no_retry(allocator, NULL);
    ASSERT_NOT_NULL(retry_strategy);

    ASSERT_ERROR(
        AWS_IO_RETRY_PERMISSION_DENIED, aws_retry_strategy_acquire_retry_token(retry_strategy, NULL, NULL, NULL, 0));

    aws_retry_strategy_release(retry_strategy);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_no_retries, s_test_no_retries_fn)
