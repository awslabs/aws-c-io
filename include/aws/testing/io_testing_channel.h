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
#include <aws/common/task_scheduler.h>
#include <aws/io/channel.h>
#include <aws/io/event_loop.h>

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
    return aws_task_scheduler_schedule_now(&testing_loop->scheduler, task);
}

static void s_testing_loop_schedule_task_future(
    struct aws_event_loop *event_loop,
    struct aws_task *task,
    uint64_t run_at) {

    struct testing_loop *testing_loop = event_loop->impl_data;
    return aws_task_scheduler_schedule_future(&testing_loop->scheduler, task, run_at);
}

static int s_testing_loop_subscribe_to_io_events(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    aws_event_loop_on_event on_event,
    void *user_data) {
    (void)event_loop;
    (void)handle;
    (void)events;
    (void)on_event;
    (void)user_data;
    return AWS_OP_SUCCESS;
}

static int s_testing_loop_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    (void)event_loop;
    (void)handle;
    return AWS_OP_SUCCESS;
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
}

static struct aws_event_loop_vtable s_testing_loop_vtable = {
    .destroy = s_testing_loop_destroy,
    .is_on_callers_thread = s_testing_loop_is_on_callers_thread,
    .run = s_testing_loop_run,
    .schedule_task_now = s_testing_loop_schedule_task_now,
    .schedule_task_future = s_testing_loop_schedule_task_future,
    .stop = s_testing_loop_stop,
    .subscribe_to_io_events = s_testing_loop_subscribe_to_io_events,
    .unsubscribe_from_io_events = s_testing_loop_unsubscribe_from_io_events,
    .wait_for_stop_completion = s_testing_loop_wait_for_stop_completion,
};

static struct aws_event_loop *s_testing_loop_new(struct aws_allocator *allocator, aws_io_clock_fn clock) {
    struct aws_event_loop *event_loop = aws_mem_acquire(allocator, sizeof(struct aws_event_loop));
    aws_event_loop_init_base(event_loop, allocator, clock);

    struct testing_loop *testing_loop = aws_mem_acquire(allocator, sizeof(struct testing_loop));
    aws_task_scheduler_init(&testing_loop->scheduler, allocator);
    testing_loop->mock_on_callers_thread = true;
    event_loop->impl_data = testing_loop;
    event_loop->vtable = s_testing_loop_vtable;

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
    assert(0);
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
    if (dir == AWS_CHANNEL_DIR_READ) {
        return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
    }

    return AWS_OP_SUCCESS;
}

static size_t s_testing_channel_handler_initial_window_size(struct aws_channel_handler *handler) {
    return 16 * 1024;
}

static void s_testing_channel_handler_destroy(struct aws_channel_handler *handler) {
    struct testing_channel_handler *testing_handler = handler->impl;
    aws_mem_release(handler->alloc, testing_handler);
    aws_mem_release(handler->alloc, handler);
}

static struct aws_channel_handler_vtable s_testing_channel_handler_vtable = {
    .process_read_message = s_testing_channel_handler_process_read_message,
    .process_write_message = s_testing_channel_handler_process_write_message,
    .increment_read_window = s_testing_channel_handler_increment_read_window,
    .shutdown = s_testing_channel_handler_shutdown,
    .initial_window_size = s_testing_channel_handler_initial_window_size,
    .destroy = s_testing_channel_handler_destroy,
};

static struct aws_channel_handler *s_new_testing_channel_handler(struct aws_allocator *allocator) {
    struct aws_channel_handler *handler = aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));
    struct testing_channel_handler *testing_handler =
        aws_mem_acquire(allocator, sizeof(struct testing_channel_handler));
    aws_linked_list_init(&testing_handler->messages);
    testing_handler->latest_window_update = 0;
    handler->impl = testing_handler;
    handler->vtable = s_testing_channel_handler_vtable;
    handler->alloc = allocator;

    return handler;
}

static void s_testing_channel_on_setup_completed(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    (void)error_code;
    (void)user_data;
}

static void s_testing_channel_on_shutdown_completed(struct aws_channel *channel, void *user_data) {
    (void)channel;
    (void)user_data;
}

/** API for testing, use this for testing purely your channel handlers and nothing else. Because of that, the s_
 * convention isn't used on the functions (since they're intended for you to call). */
static struct aws_channel *new_testing_channel(struct aws_allocator *allocator) {
    struct aws_channel *channel = aws_mem_acquire(allocator, sizeof(struct aws_channel));
    struct aws_event_loop *test_event_loop = s_testing_loop_new(allocator, aws_high_res_clock_get_ticks);

    struct aws_channel_creation_callbacks callbacks = {
        .on_setup_completed = s_testing_channel_on_setup_completed,
        .on_shutdown_completed = s_testing_channel_on_shutdown_completed,
        .setup_user_data = NULL,
        .shutdown_user_data = NULL,

    };

    aws_channel_init(channel, allocator, test_event_loop, &callbacks);
    struct testing_loop *testing_loop = test_event_loop->impl_data;
    /* run the task scheduler, so the callbacks get invoked (all on this thread). */
    uint64_t now = 0;
    aws_event_loop_current_clock_time(&test_event_loop, &now);
    aws_task_scheduler_run_all(&testing_loop->scheduler, now);

    struct aws_channel_slot *slot = aws_channel_slot_new(channel);
    struct aws_channel_handler *handler = s_new_testing_channel_handler(allocator);
    aws_channel_slot_set_handler(slot, handler);

    return channel;
}

/** when you want to test the read path of your handler, call this with the message you want it to read. */
static int testing_channel_push_read_message(struct aws_channel *test_channel, struct aws_io_message *message) {
    struct aws_channel_slot *first_slot = test_channel->first;
    return aws_channel_slot_send_message(first_slot, message, AWS_CHANNEL_DIR_READ);
}

/** when you want to test the write output of your handler, call this, get the queue and iterate the messages. */
static struct aws_linked_list *testing_channel_get_written_message_queue(struct aws_channel *test_channel) {
    struct aws_channel_slot *first_slot = test_channel->first;
    struct testing_channel_handler *testing_handler = first_slot->handler->impl;
    return &testing_handler->messages;
}

/** When you want to see what the latest window update issues from your channel handler was, call this. */
static size_t testing_channel_last_window_update(struct aws_channel *test_channel) {
    struct aws_channel_slot *first_slot = test_channel->first;
    struct testing_channel_handler *testing_handler = first_slot->handler->impl;
    return testing_handler->latest_window_update;
}

/** When you want to execute any tasks that were scheduled, call this, it will execute the tasks on the current thread.
 */
static void testing_channel_execute_queued_tasks(struct aws_channel *test_channel) {
    struct testing_loop *testing_loop = test_channel->loop->impl_data;
    uint64_t now = 0;
    aws_event_loop_current_clock_time(test_channel->loop, &now);
    aws_task_scheduler_run_all(&testing_loop->scheduler, now);
}

/** When you want to force the  "not on channel thread path" for your handler, set 'on_users_thread' to false.
 * when you want to undo that, set it back to true. If you set it to false, you'll need to call
 * 'testing_channel_execute_queued_tasks()' to invoke the tasks that ended up being scheduled. */
static void testing_channel_set_is_on_users_thread(struct aws_channel *test_channel, bool on_users_thread) {
    struct testing_loop *testing_loop = test_channel->loop->impl_data;
    testing_loop->mock_on_callers_thread = on_users_thread;
}

#endif /* AWS_TESTING_IO_TESTING_CHANNEL_H */
