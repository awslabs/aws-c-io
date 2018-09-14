#ifndef AWS_IO_EVENT_LOOP_H
#define AWS_IO_EVENT_LOOP_H

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

#include <aws/common/hash_table.h>
#include <aws/io/io.h>

enum aws_io_event_type {
    AWS_IO_EVENT_TYPE_READABLE = 1,
    AWS_IO_EVENT_TYPE_WRITABLE = 2,
    AWS_IO_EVENT_TYPE_REMOTE_HANG_UP = 4,
    AWS_IO_EVENT_TYPE_CLOSED = 8,
    AWS_IO_EVENT_TYPE_ERROR = 16,
};

struct aws_event_loop;
struct aws_task;

#if AWS_USE_IO_COMPLETION_PORTS
struct aws_overlapped;

typedef void(aws_event_loop_on_completion_fn)(
    struct aws_event_loop *event_loop,
    struct aws_overlapped *overlapped,
    int status_code,
    size_t num_bytes_transferred);

/**
 * Use aws_overlapped when a handle connected to the event loop needs an OVERLAPPED struct.
 * OVERLAPPED structs are needed to make OS-level async I/O calls.
 * When the I/O completes, the assigned aws_event_loop_on_completion_fn is called from the event_loop's thread.
 * While the I/O is pending, it is not safe to modify or delete aws_overlapped.
 * Call aws_overlapped_init() before first use. If the aws_overlapped will be used multiple times, call
 * aws_overlapped_reset() or aws_overlapped_init() between uses.
 */
struct aws_overlapped {
    OVERLAPPED overlapped;
    aws_event_loop_on_completion_fn *on_completion;
    void *user_data;
    struct aws_allocator *alloc;
};

#else /* !AWS_USE_IO_COMPLETION_PORTS */

typedef void(aws_event_loop_on_event_fn)(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data);

#endif /* AWS_USE_IO_COMPLETION_PORTS */

struct aws_event_loop_vtable {
    void (*destroy)(struct aws_event_loop *event_loop);
    int (*run)(struct aws_event_loop *event_loop);
    int (*stop)(struct aws_event_loop *event_loop);
    int (*wait_for_stop_completion)(struct aws_event_loop *event_loop);
    void (*schedule_task_now)(struct aws_event_loop *event_loop, struct aws_task *task);
    void (*schedule_task_future)(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos);
#if AWS_USE_IO_COMPLETION_PORTS
    int (*connect_to_io_completion_port)(struct aws_event_loop *event_loop, struct aws_io_handle *handle);
#else
    int (*subscribe_to_io_events)(
        struct aws_event_loop *event_loop,
        struct aws_io_handle *handle,
        int events,
        aws_event_loop_on_event_fn *on_event,
        void *user_data);
#endif
    int (*unsubscribe_from_io_events)(struct aws_event_loop *event_loop, struct aws_io_handle *handle);
    bool (*is_on_callers_thread)(struct aws_event_loop *event_loop);
};

struct aws_event_loop {
    struct aws_event_loop_vtable vtable;
    struct aws_allocator *alloc;
    aws_io_clock_fn *clock;
    struct aws_hash_table local_data;
    void *impl_data;
};

struct aws_event_loop_local_object;
typedef void(aws_event_loop_on_local_object_removed_fn)(struct aws_event_loop_local_object *);

struct aws_event_loop_local_object {
    const void *key;
    void *object;
    aws_event_loop_on_local_object_removed_fn *on_object_removed;
};

typedef struct aws_event_loop *(
    aws_new_event_loop_fn)(struct aws_allocator *alloc, aws_io_clock_fn *clock, void *new_loop_user_data);

struct aws_event_loop_group {
    struct aws_allocator *allocator;
    struct aws_array_list event_loops;
    volatile uint32_t current_index;
};

#ifdef __cplusplus
extern "C" {
#endif

#ifdef AWS_USE_IO_COMPLETION_PORTS
/**
 * Prepares aws_overlapped for use, and sets a function to call when the overlapped operation completes.
 */
AWS_IO_API
void aws_overlapped_init(
    struct aws_overlapped *overlapped,
    aws_event_loop_on_completion_fn *on_completion,
    void *user_data);

/**
 * Prepares aws_overlapped for re-use without changing the assigned aws_event_loop_on_completion_fn.
 * Call aws_overlapped_init(), instead of aws_overlapped_reset(), to change the aws_event_loop_on_completion_fn.
 */
AWS_IO_API
void aws_overlapped_reset(struct aws_overlapped *overlapped);
#endif /* AWS_USE_IO_COMPLETION_PORTS */

/**
 * Initializes an event loop group, with clock, number of loops to manage, and the function to call for creating a new
 * event loop.
 */
AWS_IO_API
int aws_event_loop_group_init(
    struct aws_event_loop_group *el_group,
    struct aws_allocator *alloc,
    aws_io_clock_fn *clock,
    uint16_t el_count,
    aws_new_event_loop_fn *new_loop_fn,
    void *new_loop_user_data);

/**
 * Initializes an event loop group with platform defaults. loop count will be the number of available processors on the
 * machine.
 */
AWS_IO_API
int aws_event_loop_group_default_init(struct aws_event_loop_group *el_group, struct aws_allocator *alloc);

/**
 * Destroys each event loop in the event loop group and then cleans up resources.
 */
AWS_IO_API
void aws_event_loop_group_clean_up(struct aws_event_loop_group *el_group);

/**
 * Fetches the next loop for use. The purpose is to enable load balancing across loops. You should not depend on how
 * this load balancing is done as it is subject to change in the future. Currently it just returns them round-robin
 * style.
 */
AWS_IO_API
struct aws_event_loop *aws_event_loop_get_next_loop(struct aws_event_loop_group *el_group);

/**
 * Creates an instance of the default event loop implementation for the current architecture and operating system.
 */
AWS_IO_API
struct aws_event_loop *aws_event_loop_new_default(struct aws_allocator *alloc, aws_io_clock_fn *clock);

/**
 * Invokes the destroy() fn for the event loop implementation.
 * If the event loop is still in a running state, this function will block waiting on the event loop to shutdown.
 * If you do not want this function to block, call aws_event_loop_stop() manually first.
 */
AWS_IO_API
void aws_event_loop_destroy(struct aws_event_loop *event_loop);

/**
 * Initializes common event-loop data structures.
 * This is only called from the *new() function of event loop implementations.
 */
AWS_IO_API
int aws_event_loop_init_base(struct aws_event_loop *event_loop, struct aws_allocator *alloc, aws_io_clock_fn *clock);

/**
 * Common cleanup code for all implementations.
 * This is only called from the *destroy() function of event loop implementations.
 */
AWS_IO_API
void aws_event_loop_clean_up_base(struct aws_event_loop *event_loop);

/**
 * Fetches an object from the event-loop's data store. Key will be taken as the memory address of the memory pointed to
 * by key. This function is not thread safe and should be called inside the event-loop's thread.
 */
AWS_IO_API
int aws_event_loop_fetch_local_object(
    struct aws_event_loop *event_loop,
    void *key,
    struct aws_event_loop_local_object *obj);

/**
 * Puts an item object the event-loop's data store. Key will be taken as the memory address of the memory pointed to by
 * key. The lifetime of item must live until remove or a put item overrides it. This function is not thread safe and
 * should be called inside the event-loop's thread.
 */
AWS_IO_API
int aws_event_loop_put_local_object(struct aws_event_loop *event_loop, struct aws_event_loop_local_object *obj);

/**
 * Removes an object from the event-loop's data store. Key will be taken as the memory address of the memory pointed to
 * by key. If removed_item is not null, the removed item will be moved to it if it exists. Otherwise, the default
 * deallocation strategy will be used. This function is not thread safe and should be called inside the event-loop's
 * thread.
 */
AWS_IO_API
int aws_event_loop_remove_local_object(
    struct aws_event_loop *event_loop,
    void *key,
    struct aws_event_loop_local_object *removed_obj);

/**
 * Triggers the running of the event loop. This function must not block. The event loop is not active until this
 * function is invoked. This function can be called again on an event loop after calling aws_event_loop_stop() and
 * aws_event_loop_wait_for_stop_completion().
 */
AWS_IO_API
int aws_event_loop_run(struct aws_event_loop *event_loop);

/**
 * Triggers the event loop to stop, but does not wait for the loop to stop completely.
 * This function may be called from outside or inside the event loop thread. It is safe to call multiple times.
 * This function is called from destroy().
 *
 * If you do not call destroy(), an event loop can be run again by calling stop(), wait_for_stop_completion(), run().
 */
AWS_IO_API
int aws_event_loop_stop(struct aws_event_loop *event_loop);

/**
 * Blocks until the event loop stops completely.
 * If you want to call aws_event_loop_run() again, you must call this after aws_event_loop_stop().
 * It is not safe to call this function from inside the event loop thread.
 */
AWS_IO_API
int aws_event_loop_wait_for_stop_completion(struct aws_event_loop *event_loop);

/**
 * The event loop will schedule the task and run it on the event loop thread as soon as possible.
 * Note that cancelled tasks will execute outside the event loop thread.
 * This function may be called from outside or inside the event loop thread.
 *
 * The task should not be cleaned up or modified until its function is executed.
 */
AWS_IO_API
void aws_event_loop_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task);

/**
 * The event loop will schedule the task and run it at the specified time.
 * Use aws_event_loop_current_clock_time() to query the current time in nanoseconds.
 * Note that cancelled tasks will execute outside the event loop thread.
 * This function may be called from outside or inside the event loop thread.
 *
 * The task should not be cleaned up or modified until its function is executed.
 */
AWS_IO_API
void aws_event_loop_schedule_task_future(
    struct aws_event_loop *event_loop,
    struct aws_task *task,
    uint64_t run_at_nanos);

#if AWS_USE_IO_COMPLETION_PORTS

/**
 * Associates an aws_io_handle with the event loop's I/O Completion Port.
 *
 * The handle must use aws_overlapped for all async operations requiring an OVERLAPPED struct.
 * When the operation completes, the aws_overlapped's completion function will run on the event loop thread.
 * Note that completion functions will not be invoked while the event loop is stopped. Users should wait for all async
 * operations on connected handles to complete before cleaning up or destroying the event loop.
 *
 * A handle may only be connected to one event loop in its lifetime.
 */
AWS_IO_API
int aws_event_loop_connect_handle_to_io_completion_port(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle);

#else /* !AWS_USE_IO_COMPLETION_PORTS */

/**
 * Subscribes on_event to events on the event-loop for handle. events is a bitwise concatenation of the events that were
 * received. The definition for these values can be found in aws_io_event_type. Currently, only
 * AWS_IO_EVENT_TYPE_READABLE and AWS_IO_EVENT_TYPE_WRITABLE are honored. You always are registered for error conditions
 * and closure. This function may be called from outside or inside the event loop thread.
 */
AWS_IO_API
int aws_event_loop_subscribe_to_io_events(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    aws_event_loop_on_event_fn *on_event,
    void *user_data);

#endif /* AWS_USE_IO_COMPLETION_PORTS */

/**
* Unsubscribes handle from event-loop notifications. You may still receive events for up to one event-loop tick.
* This function may be called from outside or inside the event loop thread.
*/
AWS_IO_API
int aws_event_loop_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle);

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

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_EVENT_LOOP_H */
