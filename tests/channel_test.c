/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/atomics.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/string.h>

#include <aws/io/channel.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/testing/aws_test_harness.h>

#include "mock_dns_resolver.h"
#include "read_write_test_handler.h"

struct channel_setup_test_args {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    bool setup_completed;    /* protected by mutex */
    bool shutdown_completed; /* protected by mutex */
    int error_code;          /* protected by mutex */
    enum aws_task_status task_status;
};

static void s_channel_setup_test_on_setup_completed(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    struct channel_setup_test_args *setup_test_args = (struct channel_setup_test_args *)user_data;

    aws_mutex_lock(&setup_test_args->mutex);
    setup_test_args->error_code |= error_code;
    setup_test_args->setup_completed = true;
    aws_mutex_unlock(&setup_test_args->mutex);
    aws_condition_variable_notify_one(&setup_test_args->condition_variable);
}

static bool s_channel_setup_test_setup_completed_predicate(void *arg) {
    struct channel_setup_test_args *setup_test_args = (struct channel_setup_test_args *)arg;
    return setup_test_args->setup_completed;
}

/* Create a new channel and wait until its setup completes */
static int s_channel_setup_create_and_wait(
    struct aws_allocator *allocator,
    struct aws_channel_options *args,
    struct channel_setup_test_args *test_args,
    struct aws_channel **returned_channel) {
    ASSERT_NULL(*returned_channel);
    *returned_channel = aws_channel_new(allocator, args);
    ASSERT_NOT_NULL(*returned_channel);
    ASSERT_SUCCESS(aws_mutex_lock(&test_args->mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &test_args->condition_variable, &test_args->mutex, s_channel_setup_test_setup_completed_predicate, test_args));
    ASSERT_INT_EQUALS(0, test_args->error_code);
    ASSERT_SUCCESS(aws_mutex_unlock(&test_args->mutex));
    return AWS_OP_SUCCESS;
}

static int s_test_channel_setup(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel *channel_1 = NULL;
    struct aws_channel *channel_2 = NULL;

    struct channel_setup_test_args test_args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .setup_completed = false,
        .shutdown_completed = false,
    };

    struct aws_channel_options args = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = NULL,
        .shutdown_user_data = NULL,
        .event_loop = event_loop,
    };

    ASSERT_SUCCESS(s_channel_setup_create_and_wait(allocator, &args, &test_args, &channel_1));
    ASSERT_SUCCESS(s_channel_setup_create_and_wait(allocator, &args, &test_args, &channel_2));

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

    struct aws_channel *channel = NULL;

    struct channel_setup_test_args test_args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .setup_completed = false,
        .shutdown_completed = false,
    };

    struct aws_channel_options args = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = NULL,
        .shutdown_user_data = NULL,
        .event_loop = event_loop,
    };

    ASSERT_SUCCESS(s_channel_setup_create_and_wait(allocator, &args, &test_args, &channel));

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

    struct aws_channel *channel = NULL;

    struct channel_setup_test_args test_args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .setup_completed = false,
        .shutdown_completed = false,
    };

    struct aws_channel_options args = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = NULL,
        .shutdown_user_data = NULL,
        .event_loop = event_loop,
    };

    ASSERT_SUCCESS(s_channel_setup_create_and_wait(allocator, &args, &test_args, &channel));

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
    struct aws_atomic_var *task_executed = arg;
    aws_atomic_store_int(task_executed, true);
}

static int s_wait_a_bit(struct aws_event_loop *loop) {
    struct aws_task task;
    struct aws_atomic_var task_executed = AWS_ATOMIC_INIT_INT(false);
    aws_task_init(&task, s_wait_a_bit_task, &task_executed, "wait_a_bit");

    uint64_t run_at_ns;
    ASSERT_SUCCESS(aws_event_loop_current_clock_time(loop, &run_at_ns));
    run_at_ns += aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
    aws_event_loop_schedule_task_future(loop, &task, run_at_ns);

    while (!aws_atomic_load_int(&task_executed)) {
        ; /* block until signaled */
    }
    return AWS_OP_SUCCESS;
}

static bool s_atomic_var_is_set_predicate(void *arg) {
    struct aws_atomic_var *var = arg;
    return aws_atomic_load_int(var);
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
        .setup_completed = false,
        .shutdown_completed = false,
    };

    struct aws_channel_options args = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = NULL,
        .shutdown_user_data = NULL,
        .event_loop = event_loop,
    };

    struct aws_channel *channel = NULL;
    ASSERT_SUCCESS(s_channel_setup_create_and_wait(allocator, &args, &test_args, &channel));

    /* Add handler to channel */
    struct aws_channel_slot *slot = aws_channel_slot_new(channel);
    ASSERT_NOT_NULL(slot);

    struct aws_channel_handler *handler = rw_handler_new(allocator, NULL, NULL, false, 10000, NULL);

    struct aws_atomic_var destroy_called = AWS_ATOMIC_INIT_INT(0);
    struct aws_mutex destroy_mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable destroy_condition_variable = AWS_CONDITION_VARIABLE_INIT;
    rw_handler_enable_wait_on_destroy(handler, &destroy_called, &destroy_condition_variable);

    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, handler));

    /* Shut down channel */
    ASSERT_SUCCESS(aws_channel_shutdown(channel, 0));

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
    ASSERT_SUCCESS(aws_mutex_lock(&destroy_mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &destroy_condition_variable, &destroy_mutex, s_atomic_var_is_set_predicate, &destroy_called));
    ASSERT_SUCCESS(aws_mutex_unlock(&destroy_mutex));
    ASSERT_TRUE(aws_atomic_load_int(&destroy_called));

    while (!aws_atomic_load_int(&destroy_called)) {
        ; /* block until signaled */
    }

    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(channel_refcount_delays_clean_up, s_test_channel_refcount)

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

static bool s_channel_test_shutdown_predicate(void *arg) {
    struct channel_setup_test_args *test_args = (struct channel_setup_test_args *)arg;
    return test_args->shutdown_completed;
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

static int s_test_channel_tasks_run_aux(
    struct aws_allocator *allocator,
    aws_task_fn *on_thread_invoker_fn,
    void (*submit_now_fn)(struct aws_channel *, struct aws_channel_task *)) {
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop);
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel *channel = NULL;

    struct channel_setup_test_args test_args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .setup_completed = false,
        .shutdown_completed = false,
        .task_status = 100,
    };

    struct aws_channel_options args = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = s_channel_test_shutdown,
        .shutdown_user_data = &test_args,
        .event_loop = event_loop,
    };

    ASSERT_SUCCESS(s_channel_setup_create_and_wait(allocator, &args, &test_args, &channel));

    /* Set up tasks */
    AWS_ZERO_STRUCT(s_tasks_run_data);
    ASSERT_SUCCESS(aws_mutex_init(&s_tasks_run_data.mutex));
    ASSERT_SUCCESS(aws_condition_variable_init(&s_tasks_run_data.condvar));
    for (int i = 0; i < TASK_COUNT; ++i) {
        aws_channel_task_init(&s_tasks_run_data.tasks[i], s_tasks_run_fn, (void *)(intptr_t)i, "test_channel_task");
    }

    /* Schedule channel-tasks from outside the channel's thread */
    ASSERT_SUCCESS(aws_mutex_lock(&s_tasks_run_data.mutex));
    submit_now_fn(channel, &s_tasks_run_data.tasks[TASK_NOW_OFF_THREAD]);
    aws_channel_schedule_task_future(channel, &s_tasks_run_data.tasks[TASK_FUTURE_OFF_THREAD], 1);

    /* Schedule task that schedules channel-tasks from on then channel's thread */
    struct aws_task scheduler_task;
    aws_task_init(&scheduler_task, on_thread_invoker_fn, channel, "schedule_on_thread_tasks");
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
    ASSERT_SUCCESS(aws_mutex_unlock(&s_tasks_run_data.mutex));

    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

static int s_test_channel_tasks_run(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(
        s_test_channel_tasks_run_aux(allocator, s_schedule_on_thread_tasks_fn, aws_channel_schedule_task_now));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_tasks_run, s_test_channel_tasks_run);

static void s_serialized_tasks_run_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct aws_channel *channel = arg;
    aws_channel_schedule_task_now_serialized(channel, &s_tasks_run_data.tasks[TASK_NOW_ON_THREAD]);
    aws_channel_schedule_task_future(channel, &s_tasks_run_data.tasks[TASK_FUTURE_ON_THREAD], 1);
}

static int s_channel_tasks_serialized_run(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    ASSERT_SUCCESS(
        s_test_channel_tasks_run_aux(allocator, s_serialized_tasks_run_fn, aws_channel_schedule_task_now_serialized));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_tasks_serialized_run, s_channel_tasks_serialized_run);

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
        .setup_completed = false,
        .shutdown_completed = false,
        .task_status = 100,
    };

    struct aws_channel_options args = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = s_channel_test_shutdown,
        .shutdown_user_data = &test_args,
        .event_loop = event_loop,
    };

    ASSERT_SUCCESS(s_channel_setup_create_and_wait(allocator, &args, &test_args, &channel));

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_channel_shutdown(channel, AWS_ERROR_SUCCESS));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &test_args.condition_variable, &test_args.mutex, s_channel_test_shutdown_predicate, &test_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&test_args.mutex));

    struct aws_channel_task task;
    aws_channel_task_init(&task, s_channel_post_shutdown_task, &test_args, "channel_post_shutdown");
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
        .setup_completed = false,
        .shutdown_completed = false,
        .task_status = 100,
    };

    struct aws_channel_options args = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = s_channel_test_shutdown,
        .shutdown_user_data = &test_args,
        .event_loop = event_loop,
    };

    ASSERT_SUCCESS(s_channel_setup_create_and_wait(allocator, &args, &test_args, &channel));

    struct aws_channel_task task;
    aws_channel_task_init(&task, s_channel_post_shutdown_task, &test_args, "channel_post_shutdown_cancellation");
    /* schedule WAY in the future. */
    aws_channel_schedule_task_future(channel, &task, UINT64_MAX - 1);
    /* make sure it hasn't been invoked yet. */
    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_INT_EQUALS(100, test_args.task_status);

    ASSERT_SUCCESS(aws_channel_shutdown(channel, AWS_ERROR_SUCCESS));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &test_args.condition_variable, &test_args.mutex, s_channel_test_shutdown_predicate, &test_args));

    ASSERT_INT_EQUALS(AWS_TASK_STATUS_CANCELED, test_args.task_status);
    ASSERT_SUCCESS(aws_mutex_unlock(&test_args.mutex));

    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_cancels_pending_tasks, s_test_channel_cancels_pending_tasks)

static int s_test_channel_duplicate_shutdown(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel *channel = NULL;

    struct channel_setup_test_args test_args = {
        .error_code = 0,
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .setup_completed = false,
        .shutdown_completed = false,
    };

    struct aws_channel_options args = {
        .on_setup_completed = s_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = s_channel_test_shutdown,
        .shutdown_user_data = &test_args,
        .event_loop = event_loop,
    };

    ASSERT_SUCCESS(s_channel_setup_create_and_wait(allocator, &args, &test_args, &channel));

    ASSERT_SUCCESS(aws_channel_shutdown(channel, AWS_ERROR_SUCCESS));
    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &test_args.condition_variable, &test_args.mutex, s_channel_test_shutdown_predicate, &test_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&test_args.mutex));

    /* make sure this doesn't explode! */
    ASSERT_SUCCESS(aws_channel_shutdown(channel, AWS_ERROR_SUCCESS));
    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(channel_duplicate_shutdown, s_test_channel_duplicate_shutdown)

struct channel_connect_test_args {
    struct aws_mutex *mutex;
    struct aws_condition_variable cv;
    int error_code;
    struct aws_channel *channel;
    bool setup;
    bool shutdown;
};

static void s_test_channel_connect_some_hosts_timeout_setup(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;

    struct channel_connect_test_args *test_args = user_data;
    aws_mutex_lock(test_args->mutex);
    test_args->setup = true;
    test_args->channel = channel;
    test_args->error_code = error_code;
    aws_condition_variable_notify_one(&test_args->cv);
    aws_mutex_unlock(test_args->mutex);
}

static void s_test_channel_connect_some_hosts_timeout_shutdown(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    (void)channel;

    struct channel_connect_test_args *test_args = user_data;
    aws_mutex_lock(test_args->mutex);
    test_args->channel = NULL;
    test_args->shutdown = true;
    test_args->error_code = error_code;
    aws_condition_variable_notify_one(&test_args->cv);
    aws_mutex_unlock(test_args->mutex);
}

static bool s_setup_complete_pred(void *user_data) {
    struct channel_connect_test_args *test_args = user_data;
    return test_args->setup;
}

static bool s_shutdown_complete_pred(void *user_data) {
    struct channel_connect_test_args *test_args = user_data;
    return test_args->shutdown;
}

static int s_test_channel_connect_some_hosts_timeout(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    struct aws_mutex mutex = AWS_MUTEX_INIT;

    struct channel_connect_test_args callback_data = {
        .mutex = &mutex,
        .cv = AWS_CONDITION_VARIABLE_INIT,
        .error_code = 0,
        .channel = NULL,
        .setup = false,
        .shutdown = false,
    };

    struct aws_event_loop_group *event_loop_group = aws_event_loop_group_new_default(allocator, 1, NULL);

    /* resolve our s3 test bucket and an EC2 host with an ACL that blackholes the connection */
    const struct aws_string *addr1_ipv4 = NULL;
    const struct aws_string *addr2_ipv4 = NULL;

    struct aws_string *bh_host = aws_string_new_from_c_str(allocator, "ec2-54-158-231-48.compute-1.amazonaws.com");
    struct aws_string *s3_host = aws_string_new_from_c_str(allocator, "aws-crt-test-stuff.s3.amazonaws.com");

    struct aws_host_address *resolved_s3_address = NULL;
    struct aws_host_address *resolved_bh_address = NULL;

    /* resolve s3 test bucket */
    struct aws_array_list s3_addresses;
    aws_array_list_init_dynamic(&s3_addresses, allocator, 4, sizeof(struct aws_host_address));
    aws_default_dns_resolve(allocator, s3_host, &s3_addresses, NULL);
    const size_t s3_address_count = aws_array_list_length(&s3_addresses);
    ASSERT_TRUE(s3_address_count >= 1);
    /* find the first A record, ignore AAAA records */
    for (size_t addr_idx = 0; addr_idx < s3_address_count; ++addr_idx) {
        aws_array_list_get_at_ptr(&s3_addresses, (void *)&resolved_s3_address, addr_idx);
        if (resolved_s3_address->record_type == AWS_ADDRESS_RECORD_TYPE_A) {
            break;
        }
    }
    ASSERT_NOT_NULL(resolved_s3_address);
    ASSERT_INT_EQUALS(AWS_ADDRESS_RECORD_TYPE_A, resolved_s3_address->record_type, "Did not find an A record");
    addr1_ipv4 = aws_string_new_from_string(allocator, resolved_s3_address->address);

    /* resolve black hole */
    struct aws_array_list bh_addresses;
    aws_array_list_init_dynamic(&bh_addresses, allocator, 4, sizeof(struct aws_host_address));
    aws_default_dns_resolve(allocator, bh_host, &bh_addresses, NULL);
    const size_t bh_address_count = aws_array_list_length(&bh_addresses);
    ASSERT_TRUE(bh_address_count >= 1);
    /* find the first A record, ignore AAAA records */
    for (size_t addr_idx = 0; addr_idx < bh_address_count; ++addr_idx) {
        aws_array_list_get_at_ptr(&bh_addresses, (void *)&resolved_bh_address, addr_idx);
        if (resolved_bh_address->record_type == AWS_ADDRESS_RECORD_TYPE_A) {
            break;
        }
    }
    ASSERT_NOT_NULL(resolved_bh_address);
    ASSERT_INT_EQUALS(AWS_ADDRESS_RECORD_TYPE_A, resolved_bh_address->record_type, "Did not find an A record");
    addr2_ipv4 = aws_string_new_from_string(allocator, resolved_bh_address->address);

    /* create a resolver with 2 addresses: 1 which will always succeed, and 1 which will always timeout */
    struct mock_dns_resolver mock_dns_resolver;
    ASSERT_SUCCESS(mock_dns_resolver_init(&mock_dns_resolver, 2, allocator));

    struct aws_host_resolution_config mock_resolver_config = {
        .max_ttl = 1,
        .impl = mock_dns_resolve,
        .impl_data = &mock_dns_resolver,
    };

    struct aws_host_address host_address_1 = {
        .address = addr1_ipv4,
        .allocator = allocator,
        .expiry = 0,
        /* connections should always succeed, if not, things are worse than this unit test failing */
        .host = s3_host,
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_A,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_host_address host_address_2 = {
        .address = addr2_ipv4,
        .allocator = allocator,
        .expiry = 0,
        /* same black-holed host from the timeout test, connections are a guaranteed timeout */
        .host = bh_host,
        .connection_failure_count = 0,
        .record_type = AWS_ADDRESS_RECORD_TYPE_AAAA,
        .use_count = 0,
        .weight = 0,
    };

    struct aws_array_list address_list;
    ASSERT_SUCCESS(aws_array_list_init_dynamic(&address_list, allocator, 2, sizeof(struct aws_host_address)));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list, &host_address_2));
    ASSERT_SUCCESS(aws_array_list_push_back(&address_list, &host_address_1));
    ASSERT_SUCCESS(mock_dns_resolver_append_address_list(&mock_dns_resolver, &address_list));

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = event_loop_group,
        .max_entries = 8,
    };
    struct aws_host_resolver *resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = event_loop_group,
        .host_resolver = resolver,
        .host_resolution_config = &mock_resolver_config,
    };

    struct aws_client_bootstrap *bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    ASSERT_NOT_NULL(bootstrap);

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 10000;
    options.type = AWS_SOCKET_STREAM;

    struct aws_socket_channel_bootstrap_options channel_options;
    AWS_ZERO_STRUCT(channel_options);
    channel_options.bootstrap = bootstrap;
    channel_options.host_name = aws_string_c_str(s3_host);
    channel_options.port = 80;
    channel_options.socket_options = &options;
    channel_options.setup_callback = s_test_channel_connect_some_hosts_timeout_setup;
    channel_options.shutdown_callback = s_test_channel_connect_some_hosts_timeout_shutdown;
    channel_options.user_data = &callback_data;

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&channel_options));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&callback_data.cv, &mutex, s_setup_complete_pred, &callback_data));

    ASSERT_INT_EQUALS(0, callback_data.error_code, aws_error_str(callback_data.error_code));
    ASSERT_NOT_NULL(callback_data.channel);
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    /* this should cause a disconnect and tear down */
    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_channel_shutdown(callback_data.channel, AWS_OP_SUCCESS));
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&callback_data.cv, &mutex, s_shutdown_complete_pred, &callback_data));

    ASSERT_INT_EQUALS(0, callback_data.error_code, aws_error_str(callback_data.error_code));
    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));

    /* clean up */
    aws_client_bootstrap_release(bootstrap);
    aws_host_resolver_release(resolver);
    mock_dns_resolver_clean_up(&mock_dns_resolver);
    aws_event_loop_group_release(event_loop_group);

    for (size_t addr_idx = 0; addr_idx < s3_address_count; ++addr_idx) {
        aws_array_list_get_at_ptr(&s3_addresses, (void *)&resolved_s3_address, addr_idx);
        aws_host_address_clean_up(resolved_s3_address);
    }
    aws_array_list_clean_up(&s3_addresses);
    for (size_t addr_idx = 0; addr_idx < bh_address_count; ++addr_idx) {
        aws_array_list_get_at_ptr(&bh_addresses, (void *)&resolved_bh_address, addr_idx);
        aws_host_address_clean_up(resolved_bh_address);
    }
    aws_array_list_clean_up(&bh_addresses);

    aws_io_library_clean_up();

    return 0;
}

AWS_TEST_CASE(channel_connect_some_hosts_timeout, s_test_channel_connect_some_hosts_timeout);
