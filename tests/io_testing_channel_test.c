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
#include <aws/testing/io_testing_channel.h>

static int s_test_io_testing_channel(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct testing_channel testing_channel;
    ASSERT_SUCCESS(testing_channel_init(&testing_channel, allocator));
    ASSERT_SUCCESS(testing_channel_clean_up(&testing_channel));
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(io_testing_channel, s_test_io_testing_channel)
