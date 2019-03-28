/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
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