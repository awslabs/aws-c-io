#ifndef AWS_TESTING_IO_TESTING_CHANNEL_H
#define AWS_TESTING_IO_TESTING_CHANNEL_H
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
#include <aws/common/task_scheduler.h>
#include <aws/io/channel.h>
#include <aws/io/event_loop.h>
#include <aws/io/logging.h>
#include <aws/testing/aws_test_harness.h>

struct testing_loop {
    struct aws_task_scheduler scheduler;
    bool mock_on_callers_thread;
};

static int s_testing_loop_run(struct aws_event_loop *event_loop) {
    (void)event_loop;
    return AWS_OP_SUCCESS;
}

static int s_testing_loop_stop(struct aws_event_loop *event_loop) {
    (void)event_loop;
    return AWS_OP_SUCCESS;
}

static int s_testing_loop_wait_for_stop_completion(struct aws_event_loop *event_loop) {
    (void)event_loop;
    return AWS_OP_SUCCESS;
}

static void s_testing_loop_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task) {
    struct testing_loop *testing_loop = event_loop->impl_data;
    aws_task_scheduler_schedule_now(&testing_loop->scheduler, task);
}

static void s_testing_loop_schedule_task_future(
    struct aws_event_loop *event_loop,
    struct aws_task *task,
    uint64_t run_at_nanos) {

    struct testing_loop *testing_loop = event_loop->impl_data;
    aws_task_scheduler_schedule_future(&testing_loop->scheduler, task, run_at_nanos);
}

static bool s_testing_loop_is_on_callers_thread(struct aws_event_loop *event_loop) {
    struct testing_loop *testing_loop = event_loop->impl_data;
    return testing_loop->mock_on_callers_thread;
}

static void s_testing_loop_destroy(struct aws_event_loop *event_loop) {
    struct testing_loop *testing_loop = event_loop->impl_data;
    aws_task_scheduler_clean_up(&testing_loop->scheduler);
    aws_mem_release(event_loop->alloc, testing_loop);
    aws_event_loop_clean_up_base(event_loop);
    aws_mem_release(event_loop->alloc, event_loop);
}

static struct aws_event_loop_vtable s_testing_loop_vtable = {
    .destroy = s_testing_loop_destroy,
    .is_on_callers_thread = s_testing_loop_is_on_callers_thread,
    .run = s_testing_loop_run,
    .schedule_task_now = s_testing_loop_schedule_task_now,
    .schedule_task_future = s_testing_loop_schedule_task_future,
    .stop = s_testing_loop_stop,
    .wait_for_stop_completion = s_testing_loop_wait_for_stop_completion,
};

static struct aws_event_loop *s_testing_loop_new(struct aws_allocator *allocator, aws_io_clock_fn clock) {
    struct aws_event_loop *event_loop = aws_mem_acquire(allocator, sizeof(struct aws_event_loop));
    aws_event_loop_init_base(event_loop, allocator, clock);

    struct testing_loop *testing_loop = aws_mem_acquire(allocator, sizeof(struct testing_loop));
    aws_task_scheduler_init(&testing_loop->scheduler, allocator);
    testing_loop->mock_on_callers_thread = true;
    event_loop->impl_data = testing_loop;
    event_loop->vtable = &s_testing_loop_vtable;

    return event_loop;
}

struct testing_channel_handler {
    struct aws_linked_list messages;
    size_t latest_window_update;
};

static int s_testing_channel_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)handler;
    (void)slot;
    (void)message;
    /*this should never happen, this is a mocked out handler for testing out the next downstream handler*/
    AWS_ASSERT(0);
    return AWS_OP_ERR;
}

static int s_testing_channel_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)slot;

    struct testing_channel_handler *testing_handler = handler->impl;
    aws_linked_list_push_back(&testing_handler->messages, &message->queueing_handle);
    return AWS_OP_SUCCESS;
}

static int s_testing_channel_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {
    (void)slot;

    struct testing_channel_handler *testing_handler = handler->impl;
    testing_handler->latest_window_update = size;
    return AWS_OP_SUCCESS;
}

static int s_testing_channel_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    (void)handler;
    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
}

static size_t s_testing_channel_handler_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;
    return 16 * 1024;
}

static size_t s_testing_channel_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;
    return 0;
}

static void s_testing_channel_handler_destroy(struct aws_channel_handler *handler) {
    struct testing_channel_handler *testing_handler = handler->impl;

    while (!aws_linked_list_empty(&testing_handler->messages)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&testing_handler->messages);
        struct aws_io_message *msg = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);
        aws_mem_release(msg->allocator, msg);
    }

    aws_mem_release(handler->alloc, testing_handler);
    aws_mem_release(handler->alloc, handler);
}

static struct aws_channel_handler_vtable s_testing_channel_handler_vtable = {
    .process_read_message = s_testing_channel_handler_process_read_message,
    .process_write_message = s_testing_channel_handler_process_write_message,
    .increment_read_window = s_testing_channel_handler_increment_read_window,
    .shutdown = s_testing_channel_handler_shutdown,
    .initial_window_size = s_testing_channel_handler_initial_window_size,
    .message_overhead = s_testing_channel_handler_message_overhead,
    .destroy = s_testing_channel_handler_destroy,
};

static struct aws_channel_handler *s_new_testing_channel_handler(struct aws_allocator *allocator) {
    struct aws_channel_handler *handler = aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));
    struct testing_channel_handler *testing_handler =
        aws_mem_acquire(allocator, sizeof(struct testing_channel_handler));
    aws_linked_list_init(&testing_handler->messages);
    testing_handler->latest_window_update = 0;
    handler->impl = testing_handler;
    handler->vtable = &s_testing_channel_handler_vtable;
    handler->alloc = allocator;

    return handler;
}

struct testing_channel {
    struct aws_event_loop *loop;
    struct testing_loop *loop_impl;
    struct aws_channel *channel;
    struct testing_channel_handler *handler_impl;
    struct aws_channel_slot *handler_slot;

    bool channel_setup_completed;
    bool channel_shutdown_completed;
};

static void s_testing_channel_on_setup_completed(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    (void)error_code;
    struct testing_channel *testing = user_data;
    testing->channel_setup_completed = true;
}

static void s_testing_channel_on_shutdown_completed(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    (void)error_code;
    struct testing_channel *testing = user_data;
    testing->channel_shutdown_completed = true;
}

/** API for testing, use this for testing purely your channel handlers and nothing else. Because of that, the s_
 * convention isn't used on the functions (since they're intended for you to call). */

/** when you want to test the read path of your handler, call this with the message you want it to read. */
AWS_STATIC_IMPL int testing_channel_push_read_message(struct testing_channel *testing, struct aws_io_message *message) {
    return aws_channel_slot_send_message(testing->handler_slot, message, AWS_CHANNEL_DIR_READ);
}

/** when you want to test the write output of your handler, call this, get the queue and iterate the messages. */
AWS_STATIC_IMPL struct aws_linked_list *testing_channel_get_written_message_queue(struct testing_channel *testing) {
    return &testing->handler_impl->messages;
}

/** When you want to see what the latest window update issues from your channel handler was, call this. */
AWS_STATIC_IMPL size_t testing_channel_last_window_update(struct testing_channel *testing) {
    return testing->handler_impl->latest_window_update;
}

/** Executes all currently scheduled tasks whose time has come.
 * Use testing_channel_drain_queued_tasks() to repeatedly run tasks until only future-tasks remain.
 */
AWS_STATIC_IMPL void testing_channel_run_currently_queued_tasks(struct testing_channel *testing) {
    AWS_ASSERT(aws_channel_thread_is_callers_thread(testing->channel));

    uint64_t now = 0;
    aws_event_loop_current_clock_time(testing->loop, &now);
    aws_task_scheduler_run_all(&testing->loop_impl->scheduler, now);
}

/** Repeatedly executes scheduled tasks until only those in the future remain.
 * This covers the common case where there's a chain reaction of now-tasks scheduling further now-tasks.
 */
AWS_STATIC_IMPL void testing_channel_drain_queued_tasks(struct testing_channel *testing) {
    AWS_ASSERT(aws_channel_thread_is_callers_thread(testing->channel));

    uint64_t now = 0;
    uint64_t next_task_time = 0;
    size_t count = 0;

    while (true) {
        aws_event_loop_current_clock_time(testing->loop, &now);
        if (aws_task_scheduler_has_tasks(&testing->loop_impl->scheduler, &next_task_time) && (next_task_time <= now)) {
            aws_task_scheduler_run_all(&testing->loop_impl->scheduler, now);
        } else {
            break;
        }

        /* NOTE: This will loop infinitely if there's a task the perpetually re-schedules another task.
         * Consider capping the number of loops if we want to support that behavior. */
        if ((++count % 1000) == 0) {
            AWS_LOGF_WARN(
                AWS_LS_IO_CHANNEL,
                "id=%p: testing_channel_drain_queued_tasks() has looped %zu times.",
                (void *)testing->channel,
                count);
        }
    }
}
/** When you want to force the  "not on channel thread path" for your handler, set 'on_users_thread' to false.
 * when you want to undo that, set it back to true. If you set it to false, you'll need to call
 * 'testing_channel_execute_queued_tasks()' to invoke the tasks that ended up being scheduled. */
AWS_STATIC_IMPL void testing_channel_set_is_on_users_thread(struct testing_channel *testing, bool on_users_thread) {
    testing->loop_impl->mock_on_callers_thread = on_users_thread;
}

AWS_STATIC_IMPL int testing_channel_init(struct testing_channel *testing, struct aws_allocator *allocator) {
    AWS_ZERO_STRUCT(*testing);

    testing->loop = s_testing_loop_new(allocator, aws_high_res_clock_get_ticks);
    testing->loop_impl = testing->loop->impl_data;

    struct aws_channel_creation_callbacks callbacks = {
        .on_setup_completed = s_testing_channel_on_setup_completed,
        .on_shutdown_completed = s_testing_channel_on_shutdown_completed,
        .setup_user_data = testing,
        .shutdown_user_data = testing,
    };

    testing->channel = aws_channel_new(allocator, testing->loop, &callbacks);

    /* Wait for channel to finish setup */
    testing_channel_drain_queued_tasks(testing);
    ASSERT_TRUE(testing->channel_setup_completed);

    testing->handler_slot = aws_channel_slot_new(testing->channel);
    struct aws_channel_handler *handler = s_new_testing_channel_handler(allocator);
    testing->handler_impl = handler->impl;
    ASSERT_SUCCESS(aws_channel_slot_set_handler(testing->handler_slot, handler));

    return AWS_OP_SUCCESS;
}

AWS_STATIC_IMPL int testing_channel_clean_up(struct testing_channel *testing) {
    aws_channel_shutdown(testing->channel, AWS_ERROR_SUCCESS);

    /* Wait for channel to finish shutdown */
    testing_channel_drain_queued_tasks(testing);
    ASSERT_TRUE(testing->channel_shutdown_completed);

    aws_channel_destroy(testing->channel);

    /* event_loop can't be destroyed from its own thread */
    testing_channel_set_is_on_users_thread(testing, false);
    aws_event_loop_destroy(testing->loop);

    ASSERT_TRUE(testing->channel_shutdown_completed);

    return AWS_OP_SUCCESS;
}

#endif /* AWS_TESTING_IO_TESTING_CHANNEL_H */
