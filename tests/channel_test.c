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

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/io/channel.h>
#include <aws/testing/aws_test_harness.h>

#include <read_write_test_handler.c>

struct channel_setup_test_args {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    bool shutdown_completed;
    int error_code;
};

static void s_channel_setup_test_on_setup_completed(struct aws_channel *channel, int error_code, void *user_data) {
    struct channel_setup_test_args *setup_test_args = (struct channel_setup_test_args *)user_data;

    aws_mutex_lock(&setup_test_args->mutex);
    setup_test_args->error_code |= error_code;
    aws_condition_variable_notify_one(&setup_test_args->condition_variable);
    aws_mutex_unlock(&setup_test_args->mutex);
}

static int s_test_channel_setup(struct aws_allocator *allocator, void *user_data) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel channel_1;
    struct aws_channel channel_2;

    struct channel_setup_test_args test_args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
    };

    struct aws_channel_creation_callbacks callbacks = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = NULL,
        .shutdown_user_data = NULL,
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_channel_init(&channel_1, allocator, event_loop, &callbacks));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    ASSERT_SUCCESS(aws_channel_init(&channel_2, allocator, event_loop, &callbacks));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    /* the msg pool should have been setup and the same msg pool should be used*/
    ASSERT_PTR_EQUALS(channel_1.msg_pool, channel_2.msg_pool);

    ASSERT_INT_EQUALS(0, test_args.error_code);

    aws_channel_clean_up(&channel_1);
    aws_channel_clean_up(&channel_2);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_setup, s_test_channel_setup)

static int s_test_channel_single_slot_cleans_up(struct aws_allocator *allocator, void *user_data) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel channel;

    struct channel_setup_test_args test_args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
    };

    struct aws_channel_creation_callbacks callbacks = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = NULL,
        .shutdown_user_data = NULL,
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_channel_init(&channel, allocator, event_loop, &callbacks));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    struct aws_channel_slot *slot;
    slot = aws_channel_slot_new(&channel);
    ASSERT_NOT_NULL(slot);

    aws_channel_clean_up(&channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_single_slot_cleans_up, s_test_channel_single_slot_cleans_up)

static int s_test_channel_slots_clean_up(struct aws_allocator *allocator, void *user_data) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel channel;

    struct channel_setup_test_args test_args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
    };

    struct aws_channel_creation_callbacks callbacks = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = NULL,
        .shutdown_user_data = NULL,
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_channel_init(&channel, allocator, event_loop, &callbacks));
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

    ASSERT_PTR_EQUALS(channel.first, slot_1);

    ASSERT_SUCCESS(aws_channel_slot_insert_right(slot_1, slot_2));
    ASSERT_SUCCESS(aws_channel_slot_insert_right(slot_2, slot_3));
    ASSERT_SUCCESS(aws_channel_slot_insert_left(slot_3, slot_4));
    ASSERT_SUCCESS(aws_channel_slot_remove(slot_2));

    ASSERT_PTR_EQUALS(slot_1, slot_4->adj_left);
    ASSERT_PTR_EQUALS(slot_1->adj_right, slot_4);
    ASSERT_PTR_EQUALS(slot_4->adj_left, slot_1);
    ASSERT_NULL(slot_1->adj_left);

    ASSERT_PTR_EQUALS(slot_4, slot_3->adj_left);
    ASSERT_PTR_EQUALS(slot_4->adj_right, slot_3);
    ASSERT_PTR_EQUALS(slot_3->adj_left, slot_4);
    ASSERT_NULL(slot_3->adj_right);

    ASSERT_SUCCESS(aws_channel_slot_replace(slot_4, slot_5));
    ASSERT_PTR_EQUALS(slot_1, slot_5->adj_left);
    ASSERT_PTR_EQUALS(slot_1->adj_right, slot_5);
    ASSERT_PTR_EQUALS(slot_5->adj_left, slot_1);

    ASSERT_PTR_EQUALS(slot_5, slot_3->adj_left);
    ASSERT_PTR_EQUALS(slot_5->adj_right, slot_3);
    ASSERT_PTR_EQUALS(slot_3->adj_left, slot_5);

    aws_channel_clean_up(&channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_slots_clean_up, s_test_channel_slots_clean_up)

struct channel_rw_test_args {
    struct aws_byte_buf read_tag;
    struct aws_byte_buf write_tag;
    struct aws_byte_buf latest_message;
    bool shutdown_completed;
    bool write_on_read;
    struct aws_condition_variable *condition_variable;
};

static bool s_rw_test_shutdown_predicate(void *arg) {
    struct channel_rw_test_args *rw_test_args = (struct channel_rw_test_args *)arg;
    return rw_test_args->shutdown_completed;
}

static void s_rw_test_on_shutdown_completed(struct aws_channel *channel, void *user_data) {
    struct channel_rw_test_args *rw_test_args = (struct channel_rw_test_args *)user_data;

    rw_test_args->shutdown_completed = true;

    if (rw_test_args->condition_variable) {
        aws_condition_variable_notify_one(rw_test_args->condition_variable);
    }
}

static struct aws_byte_buf s_channel_rw_test_on_write(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *data_read,
    void *user_data);

static struct aws_byte_buf s_channel_rw_test_on_read(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *data_read,
    void *user_data) {

    struct channel_rw_test_args *rw_test_args = (struct channel_rw_test_args *)user_data;

    if (data_read) {
        memcpy(rw_test_args->latest_message.buffer, data_read->buffer, data_read->len);
        memcpy(
            rw_test_args->latest_message.buffer + data_read->len,
            rw_test_args->read_tag.buffer,
            rw_test_args->read_tag.len);
        rw_test_args->latest_message.len = data_read->len + rw_test_args->read_tag.len;
    } else {
        return rw_test_args->read_tag;
    }

    if (rw_test_args->write_on_read) {
        struct aws_byte_buf write_data =
            s_channel_rw_test_on_write(handler, slot, &rw_test_args->latest_message, user_data);
        s_rw_handler_write(handler, slot, &write_data);
    }

    return rw_test_args->latest_message;
}

static struct aws_byte_buf s_channel_rw_test_on_write(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *data_read,
    void *user_data) {

    struct channel_rw_test_args *rw_test_args = (struct channel_rw_test_args *)user_data;

    memcpy(rw_test_args->latest_message.buffer, data_read->buffer, data_read->len);
    memcpy(
        rw_test_args->latest_message.buffer + data_read->len,
        rw_test_args->write_tag.buffer,
        rw_test_args->write_tag.len);
    rw_test_args->latest_message.len = data_read->len + rw_test_args->write_tag.len;

    return rw_test_args->latest_message;
}

static int s_test_channel_message_passing(struct aws_allocator *allocator, void *user_data) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel channel;

    struct channel_setup_test_args test_args = {
        .error_code = 0, .mutex = AWS_MUTEX_INIT, .condition_variable = AWS_CONDITION_VARIABLE_INIT};

    uint8_t handler_1_latest_message[128] = {0};
    uint8_t handler_2_latest_message[128] = {0};
    uint8_t handler_3_latest_message[128] = {0};

    struct aws_condition_variable shutdown_condition = AWS_CONDITION_VARIABLE_INIT;
    struct aws_mutex shutdown_mutex = AWS_MUTEX_INIT;

    struct channel_rw_test_args handler_1_args = {
        .shutdown_completed = false,
        .latest_message = aws_byte_buf_from_array(handler_1_latest_message, sizeof(handler_1_latest_message)),

        .read_tag = aws_byte_buf_from_c_str("handler 1 read, "),
        .write_tag = aws_byte_buf_from_c_str("handler 1 written, "),

        .write_on_read = false,
        .condition_variable = &shutdown_condition,
    };

    struct channel_rw_test_args handler_3_args = {
        .shutdown_completed = false,
        .latest_message = aws_byte_buf_from_array(handler_3_latest_message, sizeof(handler_1_latest_message)),
        .read_tag = aws_byte_buf_from_c_str("handler 3 read, "),
        .write_tag = aws_byte_buf_from_c_str("handler 3 written, "),

        .write_on_read = true,
        .condition_variable = NULL,
    };

    struct aws_channel_creation_callbacks callbacks = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = s_rw_test_on_shutdown_completed,
        .shutdown_user_data = &handler_1_args,
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_channel_init(&channel, allocator, event_loop, &callbacks));
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

    struct aws_channel_handler *handler_1 = rw_test_handler_new(
        allocator, s_channel_rw_test_on_read, s_channel_rw_test_on_write, false, 10000, &handler_1_args);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot_1, handler_1));

    struct channel_rw_test_args handler_2_args = {
        .shutdown_completed = false,
        .latest_message = aws_byte_buf_from_array(handler_2_latest_message, sizeof(handler_1_latest_message)),
        .read_tag = aws_byte_buf_from_c_str("handler 2 read, "),
        .write_tag = aws_byte_buf_from_c_str("handler 2 written, "),

        .write_on_read = false,
        .condition_variable = NULL,
    };

    struct aws_channel_handler *handler_2 = rw_test_handler_new(
        allocator, s_channel_rw_test_on_read, s_channel_rw_test_on_write, false, 10000, &handler_2_args);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot_2, handler_2));

    struct aws_channel_handler *handler_3 = rw_test_handler_new(
        allocator, s_channel_rw_test_on_read, s_channel_rw_test_on_write, false, 10000, &handler_3_args);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot_3, handler_3));

    s_rw_handler_trigger_read(handler_1, slot_1);
    struct aws_byte_buf final_message = handler_1_args.latest_message;

    struct aws_byte_buf expected = aws_byte_buf_from_c_str("handler 1 read, handler 2 read, handler 3 read, "

                                                           "handler 3 written, handler 2 written, handler 1 written, ");
    ASSERT_BIN_ARRAYS_EQUALS(expected.buffer, expected.len, final_message.buffer, final_message.len);

    aws_channel_shutdown(&channel, AWS_OP_SUCCESS);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &shutdown_condition, &shutdown_mutex, s_rw_test_shutdown_predicate, &handler_1_args));

    ASSERT_TRUE(handler_1_args.shutdown_completed);

    ASSERT_TRUE(s_rw_handler_shutdown_called(handler_1));
    ASSERT_TRUE(s_rw_handler_shutdown_called(handler_2));
    ASSERT_TRUE(s_rw_handler_shutdown_called(handler_3));
    ASSERT_TRUE(s_rw_handler_increment_read_window_called(handler_1));
    ASSERT_TRUE(s_rw_handler_increment_read_window_called(handler_2));

    aws_channel_clean_up(&channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_message_passing, s_test_channel_message_passing)
