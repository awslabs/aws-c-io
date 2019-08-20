/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/testing/aws_test_harness.h>

#include <aws/io/io.h>

static int s_io_load_error_strings_test(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    /* Load aws-c-io's actual error info.
     * This will fail if the error info list is out of sync with the error enums. */
    aws_io_library_init();
    aws_io_library_clean_up();
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(io_load_error_strings_test, s_io_load_error_strings_test)
