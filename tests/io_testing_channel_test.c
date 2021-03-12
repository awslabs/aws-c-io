/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/testing/io_testing_channel.h>

static int s_test_io_testing_channel(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_testing_channel_options test_channel_options = {.clock_fn = aws_high_res_clock_get_ticks};

    struct testing_channel testing_channel;
    ASSERT_SUCCESS(testing_channel_init(&testing_channel, allocator, &test_channel_options));

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

    testing_channel_drain_queued_tasks(&testing_channel);
    /* Test window updates */
    ASSERT_SUCCESS(testing_channel_increment_read_window(&testing_channel, 12345));
    testing_channel_drain_queued_tasks(&testing_channel);
    ASSERT_UINT_EQUALS(12345, testing_channel_last_window_update(&testing_channel));

    /* Clean up */
    ASSERT_SUCCESS(testing_channel_clean_up(&testing_channel));
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(io_testing_channel, s_test_io_testing_channel)
