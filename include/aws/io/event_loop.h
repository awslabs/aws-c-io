#ifndef AWS_IO_EVENT_LOOP_H
#define AWS_IO_EVENT_LOOP_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/io.h>

AWS_PUSH_SANE_WARNING_LEVEL

struct aws_event_loop;
struct aws_event_loop_group;
struct aws_task;

typedef void(aws_elg_shutdown_completion_callback)(void *);

struct aws_event_loop_group_shutdown_options {
    aws_elg_shutdown_completion_callback *shutdown_callback_fn;
    void *shutdown_callback_user_data;
};

struct aws_event_loop_group_pin_options {
    uint16_t cpu_group;
};

struct aws_event_loop_group_options {
    uint16_t loop_count;
    aws_io_clock_fn *clock_override;
    struct aws_shutdown_callback_options *shutdown_options;
    struct aws_event_loop_group_pin_options *pin_options;
};

AWS_EXTERN_C_BEGIN

/**
 * The event loop will schedule the task and run it on the event loop thread as soon as possible.
 * Note that cancelled tasks may execute outside the event loop thread.
 * This function may be called from outside or inside the event loop thread.
 *
 * The task should not be cleaned up or modified until its function is executed.
 */
AWS_IO_API
void aws_event_loop_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task);

/**
 * The event loop will schedule the task and run it at the specified time.
 * Use aws_event_loop_current_clock_time() to query the current time in nanoseconds.
 * Note that cancelled tasks may execute outside the event loop thread.
 * This function may be called from outside or inside the event loop thread.
 *
 * The task should not be cleaned up or modified until its function is executed.
 */
AWS_IO_API
void aws_event_loop_schedule_task_future(
    struct aws_event_loop *event_loop,
    struct aws_task *task,
    uint64_t run_at_nanos);

/**
 * Cancels task.
 * This function must be called from the event loop's thread, and is only guaranteed
 * to work properly on tasks scheduled from within the event loop's thread.
 * The task will be executed with the AWS_TASK_STATUS_CANCELED status inside this call.
 */
AWS_IO_API
void aws_event_loop_cancel_task(struct aws_event_loop *event_loop, struct aws_task *task);

/**
 * Returns true if the event loop's thread is the same thread that called this function, otherwise false.
 */
AWS_IO_API
bool aws_event_loop_thread_is_callers_thread(struct aws_event_loop *event_loop);

/**
 * Gets the current timestamp for the event loop's clock, in nanoseconds. This function is thread-safe.
 */
AWS_IO_API
int aws_event_loop_current_clock_time(struct aws_event_loop *event_loop, uint64_t *time_nanos);

/**
 */
AWS_IO_API
struct aws_event_loop_group *aws_event_loop_group_new(
    struct aws_allocator *allocator,
    const struct aws_event_loop_group_options *options);

/**
 * Increments the reference count on the event loop group, allowing the caller to take a reference to it.
 *
 * Returns the same event loop group passed in.
 */
AWS_IO_API
struct aws_event_loop_group *aws_event_loop_group_acquire(struct aws_event_loop_group *el_group);

/**
 * Decrements an event loop group's ref count.  When the ref count drops to zero, the event loop group will be
 * destroyed.
 */
AWS_IO_API
void aws_event_loop_group_release(struct aws_event_loop_group *el_group);

AWS_IO_API
struct aws_event_loop *aws_event_loop_group_get_loop_at(struct aws_event_loop_group *el_group, size_t index);

AWS_IO_API
size_t aws_event_loop_group_get_loop_count(struct aws_event_loop_group *el_group);

/**
 * Fetches the next loop for use. The purpose is to enable load balancing across loops. You should not depend on how
 * this load balancing is done as it is subject to change in the future. Currently it uses the "best-of-two" algorithm
 * based on the load factor of each loop.
 */
AWS_IO_API
struct aws_event_loop *aws_event_loop_group_get_next_loop(struct aws_event_loop_group *el_group);

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_IO_EVENT_LOOP_H */
