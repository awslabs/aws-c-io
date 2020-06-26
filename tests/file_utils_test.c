/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/file_utils.h>

#include <aws/testing/aws_test_harness.h>

#include <aws/common/string.h>

static int s_test_home_directory_not_null(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *home_directory = aws_get_home_directory(allocator);
    ASSERT_TRUE(home_directory != NULL);

    aws_string_destroy(home_directory);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_home_directory_not_null, s_test_home_directory_not_null);
