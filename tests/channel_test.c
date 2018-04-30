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
#include <aws/io/channel.h>
#include <aws/common/condition_variable.h>

#include <read_write_test_handler.c>

struct channel_setup_test_args {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    int error_code;
};

static void channel_setup_test_on_setup_completed(struct aws_channel *channel, int error_code, void *ctx) {
    struct channel_setup_test_args *setup_test_args = (struct channel_setup_test_args *)ctx;

    aws_mutex_lock(&setup_test_args->mutex);
    setup_test_args->error_code |= error_code;
    aws_condition_variable_notify_one(&setup_test_args->condition_variable);
    aws_mutex_unlock(&setup_test_args->mutex);

}

static int test_channel_setup (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel channel_1;
    struct aws_channel channel_2;

    struct channel_setup_test_args test_args = {
            .error_code = 0,
            .mutex = AWS_MUTEX_INIT,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_channel_init(&channel_1, allocator, event_loop, channel_setup_test_on_setup_completed, &test_args));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    ASSERT_SUCCESS(aws_channel_init(&channel_2, allocator, event_loop, channel_setup_test_on_setup_completed, &test_args));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    /* the msg pool should have been setup and the same msg pool should be used*/
    ASSERT_INT_EQUALS(channel_1.msg_pool, channel_2.msg_pool);
    ASSERT_INT_EQUALS(0, test_args.error_code);

    aws_channel_clean_up(&channel_1);
    aws_channel_clean_up(&channel_2);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_setup, test_channel_setup)

static int test_channel_single_slot_cleans_up (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel channel;

    struct channel_setup_test_args test_args = {
            .error_code = 0,
            .mutex = AWS_MUTEX_INIT,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_channel_init(&channel, allocator, event_loop, channel_setup_test_on_setup_completed, &test_args));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    struct aws_channel_slot *slot;
    slot = aws_channel_slot_new(&channel);
    ASSERT_NOT_NULL(slot);

    aws_channel_clean_up(&channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_single_slot_cleans_up, test_channel_single_slot_cleans_up)

static int test_channel_slots_clean_up (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel channel;

    struct channel_setup_test_args test_args = {
            .error_code = 0,
            .mutex = AWS_MUTEX_INIT,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_channel_init(&channel, allocator, event_loop, channel_setup_test_on_setup_completed, &test_args));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    struct aws_channel_slot *slot_1, *slot_2, *slot_3, *slot_4, *slot_5;
    slot_1 = aws_channel_slot_new(&channel);
    slot_2 = aws_channel_slot_new(&channel);
    slot_3 = aws_channel_slot_new(&channel);
    slot_4 = aws_channel_slot_new(&channel);
    slot_5 = aws_channel_slot_new(&channel);

    ASSERT_NOT_NULL(slot_1);
    ASSERT_NOT_NULL(slot_2);
    ASSERT_NOT_NULL(slot_3);
    ASSERT_NOT_NULL(slot_4);
    ASSERT_NOT_NULL(slot_5);

    ASSERT_INT_EQUALS(channel.first, slot_1);

    ASSERT_SUCCESS(aws_channel_slot_insert_right(slot_1, slot_2));
    ASSERT_SUCCESS(aws_channel_slot_insert_right(slot_2, slot_3));
    ASSERT_SUCCESS(aws_channel_slot_insert_left(slot_3, slot_4));
    ASSERT_SUCCESS(aws_channel_slot_remove(slot_2));

    ASSERT_INT_EQUALS(slot_1, slot_4->adj_left);
    ASSERT_INT_EQUALS(slot_1->adj_right, slot_4);
    ASSERT_INT_EQUALS(slot_4->adj_left, slot_1);
    ASSERT_NULL(slot_1->adj_left);

    ASSERT_INT_EQUALS(slot_4, slot_3->adj_left);
    ASSERT_INT_EQUALS(slot_4->adj_right, slot_3);
    ASSERT_INT_EQUALS(slot_3->adj_left, slot_4);
    ASSERT_NULL(slot_3->adj_right);

    ASSERT_SUCCESS(aws_channel_slot_replace(slot_4, slot_5));
    ASSERT_INT_EQUALS(slot_1, slot_5->adj_left);
    ASSERT_INT_EQUALS(slot_1->adj_right, slot_5);
    ASSERT_INT_EQUALS(slot_5->adj_left, slot_1);

    ASSERT_INT_EQUALS(slot_5, slot_3->adj_left);
    ASSERT_INT_EQUALS(slot_5->adj_right, slot_3);
    ASSERT_INT_EQUALS(slot_3->adj_left, slot_5);

    aws_channel_clean_up(&channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_slots_clean_up, test_channel_slots_clean_up)

static void rw_test_on_shutdown_completed(struct aws_channel *channel, void *ctx) {

}

static int test_channel_message_passing (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel channel;

    struct channel_setup_test_args test_args = {
            .error_code = 0,
            .mutex = AWS_MUTEX_INIT,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_channel_init(&channel, allocator, event_loop, channel_setup_test_on_setup_completed, &test_args));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    struct aws_channel_slot *slot_1, *slot_2, *slot_3;
    slot_1 = aws_channel_slot_new(&channel);
    slot_2 = aws_channel_slot_new(&channel);
    slot_3 = aws_channel_slot_new(&channel);

    ASSERT_NOT_NULL(slot_1);
    ASSERT_NOT_NULL(slot_2);
    ASSERT_NOT_NULL(slot_3);

    ASSERT_SUCCESS(aws_channel_slot_insert_right(slot_1, slot_2));
    ASSERT_SUCCESS(aws_channel_slot_insert_right(slot_2, slot_3));

    struct aws_byte_buf handler_1_read_buf = aws_byte_buf_from_literal("handler 1 read, ");
    struct aws_byte_buf handler_1_write_buf = aws_byte_buf_from_literal("handler 1 written, ");

    struct aws_channel_handler *handler_1 = rw_test_handler_new(allocator, handler_1_read_buf, handler_1_write_buf);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot_1, handler_1));

    struct aws_byte_buf handler_2_read_buf = aws_byte_buf_from_literal("handler 2 read, ");
    struct aws_byte_buf handler_2_write_buf = aws_byte_buf_from_literal("handler 2 written, ");

    struct aws_channel_handler *handler_2 = rw_test_handler_new(allocator, handler_2_read_buf, handler_2_write_buf);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot_2, handler_2));

    struct aws_byte_buf handler_3_read_buf = aws_byte_buf_from_literal("handler 3 read, ");
    struct aws_byte_buf handler_3_write_buf = aws_byte_buf_from_literal("handler 3 written, ");

    struct aws_channel_handler *handler_3 = rw_test_handler_new(allocator, handler_3_read_buf, handler_3_write_buf);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot_3, handler_3));

    rw_handler_trigger_read(handler_1, slot_1);
    struct aws_byte_buf final_message = rw_handler_get_final_message(handler_1);

    struct aws_byte_buf expected = aws_byte_buf_from_literal("handler 1 read, handler 2 read, handler 3 read, "
                                                                     "handler 3 written, handler 2 written, handler 1 written, ");
    ASSERT_BIN_ARRAYS_EQUALS(expected.buffer, expected.len, final_message.buffer, final_message.len);

    aws_channel_shutdown(&channel, AWS_CHANNEL_DIR_READ, rw_test_on_shutdown_completed, NULL);
    aws_channel_shutdown(&channel, AWS_CHANNEL_DIR_WRITE, rw_test_on_shutdown_completed, NULL);

    ASSERT_TRUE(rw_handler_shutdown_notify_called(handler_1));
    ASSERT_TRUE(rw_handler_shutdown_notify_called(handler_2));
    ASSERT_TRUE(rw_handler_shutdown_notify_called(handler_3));
    ASSERT_TRUE(rw_handler_window_update_called(handler_1));
    ASSERT_TRUE(rw_handler_window_update_called(handler_2));

    aws_channel_clean_up(&channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_message_passing, test_channel_message_passing)


