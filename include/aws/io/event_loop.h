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
struct aws_shutdown_callback_options;
struct aws_task;

/**
 * Event Loop Type.  If set to `AWS_ELT_PLATFORM_DEFAULT`, the event loop will automatically use the platform’s default
 * event loop type.
 *
 * Default Event Loop Type
 * Linux       | AWS_ELT_EPOLL
 * Windows	   | AWS_ELT_IOCP
 * BSD Variants| AWS_ELT_KQUEUE
 * MacOS	   | AWS_ELT_KQUEUE
 * iOS         | AWS_ELT_DISPATCH_QUEUE
 */
enum aws_event_loop_type {
    AWS_ELT_PLATFORM_DEFAULT = 0,
    AWS_ELT_EPOLL,
    AWS_ELT_IOCP,
    AWS_ELT_KQUEUE,
    AWS_ELT_DISPATCH_QUEUE,
};

/**
 * Configuration to pin an event loop group to a particular CPU group
 */
struct aws_event_loop_group_pin_options {

    /**
     * CPU group id that threads in this event loop group should be bound to
     */
    uint16_t cpu_group;
};

/**
 * Event loop group configuration options
 */
struct aws_event_loop_group_options {

    /**
     * How many event loops that event loop group should contain.  For most group types, this implies
     * the creation and management of an analagous amount of managed threads
     */
    uint16_t loop_count;

    /**
     * Event loop type. If the event loop type is set to AWS_ELT_PLATFORM_DEFAULT, the
     * creation function will automatically use the platform’s default event loop type.
     */
    enum aws_event_loop_type type;

    /**
     * Optional callback to invoke when the event loop group finishes destruction.
     */
    struct aws_shutdown_callback_options *shutdown_options;

    /**
     * Optional configuration to control how the event loop group's threads bind to CPU groups
     */
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
 * Creation function for event loop groups.
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

/**
 * Returns the event loop at a particular index.  If the index is out of bounds, null is returned.
 */
AWS_IO_API
struct aws_event_loop *aws_event_loop_group_get_loop_at(struct aws_event_loop_group *el_group, size_t index);

/**
 * Gets the number of event loops managed by an event loop group.
 */
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
