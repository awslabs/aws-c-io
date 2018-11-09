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

#include <aws/common/atomics.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>

#include <aws/io/channel.h>
#include <aws/io/event_loop.h>
#include <aws/testing/aws_test_harness.h>

#include "read_write_test_handler.h"

struct channel_setup_test_args {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    bool shutdown_completed;
    int error_code;
    enum aws_task_status task_status;
};

static void s_channel_setup_test_on_setup_completed(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    struct channel_setup_test_args *setup_test_args = (struct channel_setup_test_args *)user_data;

    aws_mutex_lock(&setup_test_args->mutex);
    setup_test_args->error_code |= error_code;
    aws_condition_variable_notify_one(&setup_test_args->condition_variable);
    aws_mutex_unlock(&setup_test_args->mutex);
}

static int s_test_channel_setup(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation faÍiled with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel *channel_1;
    struct aws_channel *channel_2;

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
    channel_1 = aws_channel_new(allocator, event_loop, &callbacks);
    ASSERT_NOT_NULL(channel_1);
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    channel_2 = aws_channel_new(allocator, event_loop, &callbacks);
    ASSERT_NOT_NULL(channel_2);
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    ASSERT_INT_EQUALS(0, test_args.error_code);

    aws_channel_destroy(channel_1);
    aws_channel_destroy(channel_2);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_setup, s_test_channel_setup)

static int s_test_channel_single_slot_cleans_up(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel *channel;

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
    channel = aws_channel_new(allocator, event_loop, &callbacks);
    ASSERT_NOT_NULL(channel);
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    struct aws_channel_slot *slot;
    slot = aws_channel_slot_new(channel);
    ASSERT_NOT_NULL(slot);

    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_single_slot_cleans_up, s_test_channel_single_slot_cleans_up)

static int s_test_channel_slots_clean_up(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel *channel;

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
    channel = aws_channel_new(allocator, event_loop, &callbacks);
    ASSERT_NOT_NULL(channel);
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    struct aws_channel_slot *slot_1, *slot_2, *slot_3, *slot_4, *slot_5;
    slot_1 = aws_channel_slot_new(channel);
    slot_2 = aws_channel_slot_new(channel);
    slot_3 = aws_channel_slot_new(channel);
    slot_4 = aws_channel_slot_new(channel);
    slot_5 = aws_channel_slot_new(channel);

    ASSERT_NOT_NULL(slot_1);
    ASSERT_NOT_NULL(slot_2);
    ASSERT_NOT_NULL(slot_3);
    ASSERT_NOT_NULL(slot_4);
    ASSERT_NOT_NULL(slot_5);

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

    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_slots_clean_up, s_test_channel_slots_clean_up)

static void s_wait_a_bit_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct aws_condition_variable *cv = arg;
    aws_condition_variable_notify_one(cv);
}

static int s_wait_a_bit(struct aws_event_loop *loop) {
    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable cv = AWS_CONDITION_VARIABLE_INIT;
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));

    struct aws_task task;
    aws_task_init(&task, s_wait_a_bit_task, &cv);

    uint64_t run_at_ns;
    ASSERT_SUCCESS(aws_event_loop_current_clock_time(loop, &run_at_ns));
    run_at_ns += aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
    aws_event_loop_schedule_task_future(loop, &task, run_at_ns);

    return aws_condition_variable_wait(&cv, &mutex);
}

static int s_test_channel_refcount(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);
    ASSERT_NOT_NULL(event_loop);
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    /* Create channel */
    struct channel_setup_test_args test_args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
    };

    struct aws_channel_creation_callbacks callbacks = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = s_channel_setup_test_on_setup_completed,
        .shutdown_user_data = &test_args,
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    struct aws_channel *channel = aws_channel_new(allocator, event_loop, &callbacks);
    ASSERT_NOT_NULL(channel);

    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    /* Add handler to channel */
    struct aws_channel_slot *slot = aws_channel_slot_new(channel);
    ASSERT_NOT_NULL(slot);

    struct aws_channel_handler *handler = rw_handler_new(allocator, NULL, NULL, false, 10000, NULL);

    struct aws_atomic_var destroy_called = AWS_ATOMIC_INIT_INT(0);
    struct aws_mutex destroy_mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable destroy_condition_variable = AWS_CONDITION_VARIABLE_INIT;
    ASSERT_SUCCESS(aws_mutex_lock(&destroy_mutex));
    rw_handler_enable_wait_on_destroy(handler, &destroy_called, &destroy_condition_variable);

    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, handler));

    /* Shut down channel */
    ASSERT_SUCCESS(aws_channel_shutdown(channel, 0));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    /* Acquire 2 holds on channel and try to destroy it. The holds should prevent memory from being freed yet */
    aws_channel_acquire_hold(channel);
    aws_channel_acquire_hold(channel);
    aws_channel_destroy(channel);
    ASSERT_SUCCESS(s_wait_a_bit(event_loop));
    ASSERT_FALSE(aws_atomic_load_int(&destroy_called));

    /* Release hold 1/2. Handler shouldn't get destroyed. */
    aws_channel_release_hold(channel);
    ASSERT_SUCCESS(s_wait_a_bit(event_loop));
    ASSERT_FALSE(aws_atomic_load_int(&destroy_called));

    /* Release hold 2/2. The handler and channel should be destroyed. */
    aws_channel_release_hold(channel);
    ASSERT_SUCCESS(aws_condition_variable_wait(&destroy_condition_variable, &destroy_mutex));
    ASSERT_TRUE(aws_atomic_load_int(&destroy_called));

    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(channel_refcount_delays_clean_up, s_test_channel_refcount)

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

static void s_rw_test_on_shutdown_completed(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    (void)error_code;
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
        rw_handler_write(handler, slot, &write_data);
    }

    return rw_test_args->latest_message;
}

static struct aws_byte_buf s_channel_rw_test_on_write(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *data_read,
    void *user_data) {

    (void)handler;
    (void)slot;
    struct channel_rw_test_args *rw_test_args = (struct channel_rw_test_args *)user_data;

    memcpy(rw_test_args->latest_message.buffer, data_read->buffer, data_read->len);
    memcpy(
        rw_test_args->latest_message.buffer + data_read->len,
        rw_test_args->write_tag.buffer,
        rw_test_args->write_tag.len);
    rw_test_args->latest_message.len = data_read->len + rw_test_args->write_tag.len;

    return rw_test_args->latest_message;
}

static int s_test_channel_message_passing(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel *channel;

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
    channel = aws_channel_new(allocator, event_loop, &callbacks);
    ASSERT_NOT_NULL(channel);
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    struct aws_channel_slot *slot_1, *slot_2, *slot_3;
    slot_1 = aws_channel_slot_new(channel);
    slot_2 = aws_channel_slot_new(channel);
    slot_3 = aws_channel_slot_new(channel);

    ASSERT_NOT_NULL(slot_1);
    ASSERT_NOT_NULL(slot_2);
    ASSERT_NOT_NULL(slot_3);

    ASSERT_SUCCESS(aws_channel_slot_insert_right(slot_1, slot_2));
    ASSERT_SUCCESS(aws_channel_slot_insert_right(slot_2, slot_3));

    struct aws_channel_handler *handler_1 =
        rw_handler_new(allocator, s_channel_rw_test_on_read, s_channel_rw_test_on_write, false, 10000, &handler_1_args);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot_1, handler_1));

    struct channel_rw_test_args handler_2_args = {
        .shutdown_completed = false,
        .latest_message = aws_byte_buf_from_array(handler_2_latest_message, sizeof(handler_1_latest_message)),
        .read_tag = aws_byte_buf_from_c_str("handler 2 read, "),
        .write_tag = aws_byte_buf_from_c_str("handler 2 written, "),

        .write_on_read = false,
        .condition_variable = NULL,
    };

    struct aws_channel_handler *handler_2 =
        rw_handler_new(allocator, s_channel_rw_test_on_read, s_channel_rw_test_on_write, false, 10000, &handler_2_args);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot_2, handler_2));

    struct aws_channel_handler *handler_3 =
        rw_handler_new(allocator, s_channel_rw_test_on_read, s_channel_rw_test_on_write, false, 10000, &handler_3_args);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot_3, handler_3));

    rw_handler_trigger_read(handler_1, slot_1);
    struct aws_byte_buf final_message = handler_1_args.latest_message;

    struct aws_byte_buf expected = aws_byte_buf_from_c_str("handler 1 read, handler 2 read, handler 3 read, "

                                                           "handler 3 written, handler 2 written, handler 1 written, ");
    ASSERT_BIN_ARRAYS_EQUALS(expected.buffer, expected.len, final_message.buffer, final_message.len);

    aws_channel_shutdown(channel, AWS_OP_SUCCESS);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &shutdown_condition, &shutdown_mutex, s_rw_test_shutdown_predicate, &handler_1_args));

    ASSERT_TRUE(handler_1_args.shutdown_completed);

    ASSERT_TRUE(rw_handler_shutdown_called(handler_1));
    ASSERT_TRUE(rw_handler_shutdown_called(handler_2));
    ASSERT_TRUE(rw_handler_shutdown_called(handler_3));
    ASSERT_TRUE(rw_handler_increment_read_window_called(handler_1));
    ASSERT_TRUE(rw_handler_increment_read_window_called(handler_2));

    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_message_passing, s_test_channel_message_passing)

static void s_channel_post_shutdown_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct channel_setup_test_args *test_args = arg;
    test_args->task_status = status;
}

static void s_channel_test_shutdown(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    (void)error_code;

    struct channel_setup_test_args *test_args = user_data;
    aws_mutex_lock(&test_args->mutex);
    test_args->shutdown_completed = true;
    aws_mutex_unlock(&test_args->mutex);
    aws_condition_variable_notify_one(&test_args->condition_variable);
}

enum tasks_run_id {
    TASK_NOW_OFF_THREAD,
    TASK_NOW_ON_THREAD,
    TASK_FUTURE_OFF_THREAD,
    TASK_FUTURE_ON_THREAD,
    TASK_COUNT,
};

struct tasks_run_data {
    struct aws_mutex mutex;
    struct aws_condition_variable condvar;
    bool did_task_run[TASK_COUNT];
    bool did_task_fail[TASK_COUNT];
    struct aws_channel_task tasks[TASK_COUNT];
};

static struct tasks_run_data s_tasks_run_data;

static void s_tasks_run_fn(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    intptr_t id = (intptr_t)arg;

    aws_mutex_lock(&s_tasks_run_data.mutex);
    s_tasks_run_data.did_task_run[id] = true;
    s_tasks_run_data.did_task_fail[id] = (status == AWS_TASK_STATUS_CANCELED);
    aws_condition_variable_notify_one(&s_tasks_run_data.condvar);
    aws_mutex_unlock(&s_tasks_run_data.mutex);
}

static void s_schedule_on_thread_tasks_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct aws_channel *channel = arg;
    aws_channel_schedule_task_now(channel, &s_tasks_run_data.tasks[TASK_NOW_ON_THREAD]);
    aws_channel_schedule_task_future(channel, &s_tasks_run_data.tasks[TASK_FUTURE_ON_THREAD], 1);
}

static bool s_tasks_run_done_pred(void *user_data) {
    (void)user_data;
    for (int i = 0; i < TASK_COUNT; ++i) {
        if (!s_tasks_run_data.did_task_run[i]) {
            return false;
        }
    }
    return true;
}

static int s_test_channel_tasks_run(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop);
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel *channel = NULL;

    struct channel_setup_test_args test_args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .shutdown_completed = false,
        .task_status = 100,
    };

    struct aws_channel_creation_callbacks callbacks = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = s_channel_test_shutdown,
        .shutdown_user_data = &test_args,
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    channel = aws_channel_new(allocator, event_loop, &callbacks);
    ASSERT_NOT_NULL(channel);
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));
    ASSERT_INT_EQUALS(0, test_args.error_code);
    /* Channel is set up now*/

    /* Set up tasks */
    AWS_ZERO_STRUCT(s_tasks_run_data);
    ASSERT_SUCCESS(aws_mutex_init(&s_tasks_run_data.mutex));
    ASSERT_SUCCESS(aws_condition_variable_init(&s_tasks_run_data.condvar));
    for (int i = 0; i < TASK_COUNT; ++i) {
        aws_channel_task_init(&s_tasks_run_data.tasks[i], s_tasks_run_fn, (void *)(intptr_t)i);
    }

    /* Schedule channel-tasks from outside the channel's thread */
    ASSERT_SUCCESS(aws_mutex_lock(&s_tasks_run_data.mutex));
    aws_channel_schedule_task_now(channel, &s_tasks_run_data.tasks[TASK_NOW_OFF_THREAD]);
    aws_channel_schedule_task_future(channel, &s_tasks_run_data.tasks[TASK_FUTURE_OFF_THREAD], 1);

    /* Schedule task that schedules channel-tasks from on then channel's thread */
    struct aws_task scheduler_task;
    aws_task_init(&scheduler_task, s_schedule_on_thread_tasks_fn, channel);
    aws_event_loop_schedule_task_now(event_loop, &scheduler_task);

    /* Wait for all the tasks to finish */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &s_tasks_run_data.condvar, &s_tasks_run_data.mutex, s_tasks_run_done_pred, NULL));

    /* Check that none failed */
    bool all_succeeded = true;
    for (int i = 0; i < TASK_COUNT; ++i) {
        if (s_tasks_run_data.did_task_fail[i]) {
            all_succeeded = false;
        }
    }
    ASSERT_TRUE(all_succeeded);

    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_tasks_run, s_test_channel_tasks_run);

static int s_test_channel_rejects_post_shutdown_tasks(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel *channel = NULL;

    struct channel_setup_test_args test_args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .shutdown_completed = false,
        .task_status = 100,
    };

    struct aws_channel_creation_callbacks callbacks = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = s_channel_test_shutdown,
        .shutdown_user_data = &test_args,
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    channel = aws_channel_new(allocator, event_loop, &callbacks);
    ASSERT_NOT_NULL(channel);
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));
    ASSERT_INT_EQUALS(0, test_args.error_code);

    ASSERT_SUCCESS(aws_channel_shutdown(channel, AWS_ERROR_SUCCESS));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    struct aws_channel_task task;
    aws_channel_task_init(&task, s_channel_post_shutdown_task, &test_args);
    aws_channel_schedule_task_now(channel, &task);
    ASSERT_INT_EQUALS(AWS_TASK_STATUS_CANCELED, test_args.task_status);

    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_rejects_post_shutdown_tasks, s_test_channel_rejects_post_shutdown_tasks)

static int s_test_channel_cancels_pending_tasks(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel *channel = NULL;

    struct channel_setup_test_args test_args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .shutdown_completed = false,
        .task_status = 100,
    };

    struct aws_channel_creation_callbacks callbacks = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = s_channel_test_shutdown,
        .shutdown_user_data = &test_args,
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    channel = aws_channel_new(allocator, event_loop, &callbacks);
    ASSERT_NOT_NULL(channel);
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));
    ASSERT_INT_EQUALS(0, test_args.error_code);

    struct aws_channel_task task;
    aws_channel_task_init(&task, s_channel_post_shutdown_task, &test_args);
    /* schedule WAY in the future. */
    aws_channel_schedule_task_future(channel, &task, UINT64_MAX - 1);
    /* make sure it hasn't been invoked yet. */
    ASSERT_INT_EQUALS(100, test_args.task_status);

    ASSERT_SUCCESS(aws_channel_shutdown(channel, AWS_ERROR_SUCCESS));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    ASSERT_INT_EQUALS(AWS_TASK_STATUS_CANCELED, test_args.task_status);

    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_cancels_pending_tasks, s_test_channel_cancels_pending_tasks)
