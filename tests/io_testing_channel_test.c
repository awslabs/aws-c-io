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
    AWS_UNUSED_PARAM(ctx);

    struct testing_channel testing_channel;
    ASSERT_SUCCESS(testing_channel_init(&testing_channel, allocator));

    /* Install downstream handler, so the 2 handlers can pass messages to each other */
    ASSERT_SUCCESS(testing_channel_install_downstream_handler(&testing_channel, 16 * 1024));

    /* Push read message and assert that downstream handler receives it */
    struct aws_io_message *read_msg =
        aws_channel_acquire_message_from_pool(testing_channel.channel, AWS_IO_MESSAGE_APPLICATION_DATA, 64);
    ASSERT_NOT_NULL(read_msg);
    ASSERT_SUCCESS(testing_channel_push_read_message(&testing_channel, read_msg));

    struct aws_linked_list *read_queue = testing_channel_get_read_message_queue(&testing_channel);
    ASSERT_NOT_NULL(read_queue);
    ASSERT_FALSE(aws_linked_list_empty(read_queue));
    ASSERT_PTR_EQUALS(&read_msg->queueing_handle, aws_linked_list_front(read_queue));

    /* Push write message and assert that upstream handler receives it */
    struct aws_io_message *write_msg =
        aws_channel_acquire_message_from_pool(testing_channel.channel, AWS_IO_MESSAGE_APPLICATION_DATA, 64);
    ASSERT_NOT_NULL(write_msg);
    ASSERT_SUCCESS(testing_channel_push_write_message(&testing_channel, write_msg));

    struct aws_linked_list *write_queue = testing_channel_get_written_message_queue(&testing_channel);
    ASSERT_NOT_NULL(write_queue);
    ASSERT_FALSE(aws_linked_list_empty(write_queue));
    ASSERT_PTR_EQUALS(&write_msg->queueing_handle, aws_linked_list_front(write_queue));

    /* Test window updates */
    ASSERT_SUCCESS(testing_channel_increment_read_window(&testing_channel, 12345));
    ASSERT_UINT_EQUALS(12345, testing_channel_last_window_update(&testing_channel));

    /* Clean up */
    ASSERT_SUCCESS(testing_channel_clean_up(&testing_channel));
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(io_testing_channel, s_test_io_testing_channel)
