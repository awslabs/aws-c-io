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
#include <aws/common/clock.h>
#include <aws/io/io.h>
#include <stdbool.h>

enum aws_io_event_type {
    AWS_IO_EVENT_TYPE_READABLE = 1,
    AWS_IO_EVENT_TYPE_WRITABLE = 2,
    AWS_IO_EVENT_TYPE_REMOTE_HANG_UP = 4,
    AWS_IO_EVENT_TYPE_CLOSED = 8,
    AWS_IO_EVENT_TYPE_ERROR = 16
};

struct aws_event_loop;
struct aws_task;

typedef void (*aws_event_loop_stopped_promise) (struct aws_event_loop *, void *);
typedef void (*aws_event_loop_on_event)(struct aws_event_loop *, struct aws_io_handle *handle, int events, void *);

struct aws_event_loop_vtable {
    void (*destroy)(struct aws_event_loop *);
    int (*run) (struct aws_event_loop *);
    int (*stop) (struct aws_event_loop *, aws_event_loop_stopped_promise promise, void *);
    int (*schedule_task) (struct aws_event_loop *, struct aws_task *task, uint64_t run_at);
    int (*subscribe_to_io_events) (struct aws_event_loop *, struct aws_io_handle *handle, int events,
                                   aws_event_loop_on_event on_event, void *ctx);
    int (*unsubscribe_from_io_events) (struct aws_event_loop *, struct aws_io_handle *handle);
    bool (*is_on_callers_thread) (struct aws_event_loop *);
};

struct aws_event_loop {
    struct aws_event_loop_vtable vtable;
    struct aws_allocator *alloc;
    aws_io_clock clock;
    struct aws_common_hash_table local_data;
    void *impl_data;
};

struct aws_event_loop_local_object;
typedef void(*aws_event_loop_on_local_data_eviction)(struct aws_event_loop_local_object *);

struct aws_event_loop_local_object {
    const void *key;
    void *object;
    aws_event_loop_on_local_data_eviction on_data_eviction;
};

#ifdef __cplusplus
extern "C" {
#endif

AWS_IO_API int aws_event_loop_base_init(struct aws_event_loop *event_loop, struct aws_allocator *alloc, aws_io_clock clock);

AWS_IO_API struct aws_event_loop *aws_event_loop_default_new(struct aws_allocator *, aws_io_clock clock);

AWS_IO_API void aws_event_loop_base_clean_up(struct aws_event_loop *);

AWS_IO_API void aws_event_loop_destroy(struct aws_event_loop *);

AWS_IO_API int aws_event_loop_fetch_local_item ( struct aws_event_loop *, void *key, struct aws_event_loop_local_object *item);

AWS_IO_API int aws_event_loop_put_local_item ( struct aws_event_loop *, struct aws_event_loop_local_object *item);

AWS_IO_API int aws_event_loop_remove_local_item ( struct aws_event_loop *, void *key, struct aws_event_loop_local_object *removed_item);

/**
 * Triggers the running of the event loop. This function must not block. The event loop is not active until this function
 * is invoked.
 */
AWS_IO_API int aws_event_loop_run(struct aws_event_loop *event_loop);

/**
 * Stops the event loop. If block is specified this function must block until the loop has stopped.
 * This function is called from destroy(), so, in that context, when the function returns,
 * the memory for the loop will be freed.
 */
AWS_IO_API int aws_event_loop_stop(struct aws_event_loop *event_loop, void (*stopped_promise) (struct aws_event_loop *, void *), void *promise_ctx);

/**
 * The event loop is responsible for queuing and executing scheduled tasks. If this function is invoked outside
 * of the event-loop's thread it is responsible for pushing the task into the correct thread before mutating state.
 * For example on edge triggered epoll, if this function is called outside of the event loop thread,
 * the task is written to a pipe. Epoll will notice the change on the pipe and then the loop will queue the task and execute it.
 */
AWS_IO_API int aws_event_loop_schedule_task(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at);

AWS_IO_API int aws_event_loop_subscribe_to_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle, int events,
                    aws_event_loop_on_event on_event, void *ctx);

AWS_IO_API int aws_event_loop_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle);

AWS_IO_API bool aws_event_loop_is_on_callers_thread (struct aws_event_loop *event_loop);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_EVENT_LOOP_H */
