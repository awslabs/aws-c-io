/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/event_loop.h>
#include <aws/io/private/event_loop_impl.h>

#include <aws/common/atomics.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/uuid.h>

#include <aws/io/logging.h>

#include <unistd.h>

#include "aws_apple_network_framework.h"
#include <Block.h>
#include <dispatch/dispatch.h>
#include <dispatch/queue.h>

static void s_destroy(struct aws_event_loop *event_loop);
static int s_run(struct aws_event_loop *event_loop);
static int s_stop(struct aws_event_loop *event_loop);
static int s_wait_for_stop_completion(struct aws_event_loop *event_loop);
static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task);
static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos);
static void s_cancel_task(struct aws_event_loop *event_loop, struct aws_task *task);
static int s_connect_to_dispatch_queue(struct aws_event_loop *event_loop, struct aws_io_handle *handle);
static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle);
static void s_free_io_event_resources(void *user_data) {
    (void)user_data;
}
static bool s_is_on_callers_thread(struct aws_event_loop *event_loop);

static struct aws_event_loop_vtable s_vtable = {
    .destroy = s_destroy,
    .run = s_run,
    .stop = s_stop,
    .wait_for_stop_completion = s_wait_for_stop_completion,
    .schedule_task_now = s_schedule_task_now,
    .schedule_task_future = s_schedule_task_future,
    .cancel_task = s_cancel_task,
    .connect_to_io_completion_port = s_connect_to_dispatch_queue,
    .unsubscribe_from_io_events = s_unsubscribe_from_io_events,
    .free_io_event_resources = s_free_io_event_resources,
    .is_on_callers_thread = s_is_on_callers_thread,
};

/* Internal ref-counted dispatch loop context to processing Apple Dispatch Queue Resources */
struct dispatch_loop_context {
    struct aws_mutex lock;
    struct dispatch_loop *io_dispatch_loop;
    struct dispatch_scheduling_state scheduling_state;
    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;
};

struct scheduled_service_entry {
    struct aws_allocator *allocator;
    uint64_t timestamp;
    struct aws_linked_list_node node;
    struct dispatch_loop_context *dispatch_queue_context;
};

static struct scheduled_service_entry *s_scheduled_service_entry_new(
    struct dispatch_loop_context *context,
    uint64_t timestamp) {
    struct scheduled_service_entry *entry =
        aws_mem_calloc(context->allocator, 1, sizeof(struct scheduled_service_entry));

    entry->allocator = context->allocator;
    entry->timestamp = timestamp;
    entry->dispatch_queue_context = context;
    aws_ref_count_acquire(&context->ref_count);

    return entry;
}

static void s_scheduled_service_entry_destroy(struct scheduled_service_entry *entry) {
    if (aws_linked_list_node_is_in_list(&entry->node)) {
        aws_linked_list_remove(&entry->node);
    }
    struct dispatch_loop_context *dispatch_queue_context = entry->dispatch_queue_context;
    aws_ref_count_release(&dispatch_queue_context->ref_count);

    aws_mem_release(entry->allocator, entry);
}

// checks to see if another scheduled iteration already exists that will either
// handle our needs or reschedule at the end to do so
static bool s_should_schedule_iteration(
    struct aws_linked_list *scheduled_iterations,
    uint64_t proposed_iteration_time) {
    if (aws_linked_list_empty(scheduled_iterations)) {
        return true;
    }

    struct aws_linked_list_node *head_node = aws_linked_list_front(scheduled_iterations);
    struct scheduled_service_entry *entry = AWS_CONTAINER_OF(head_node, struct scheduled_service_entry, node);

    // is the next scheduled iteration later than what we require?
    return entry->timestamp > proposed_iteration_time;
}

/* On dispatch event loop context ref-count reaches 0 */
static void s_dispatch_loop_context_destroy(void *context) {
    struct dispatch_loop_context *dispatch_loop_context = context;
    aws_mutex_clean_up(&dispatch_loop_context->lock);
    aws_mem_release(dispatch_loop_context->allocator, dispatch_loop_context);
}

/* On dispatch event loop ref-count reaches 0 */
static void s_dispatch_event_loop_destroy(void *context) {
    // release dispatch loop
    struct aws_event_loop *event_loop = context;
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    // Null out the dispatch queue loop context
    aws_mutex_lock(&dispatch_loop->synced_task_data.context->lock);
    dispatch_loop->synced_task_data.context->io_dispatch_loop = NULL;
    aws_mutex_unlock(&dispatch_loop->synced_task_data.context->lock);
    aws_ref_count_release(&dispatch_loop->synced_task_data.context->ref_count);

    aws_string_destroy(dispatch_loop->dispatch_queue_id);
    aws_mem_release(dispatch_loop->allocator, dispatch_loop);
    aws_event_loop_clean_up_base(event_loop);
    aws_mem_release(event_loop->alloc, event_loop);

    AWS_LOGF_DEBUG(AWS_LS_IO_EVENT_LOOP, "id=%p: Destroyed Dispatch Queue Event Loop.", (void *)event_loop);
}

/** Return a aws_string* with unique dispatch queue id string. The id is In format of
 * "com.amazonaws.commonruntime.eventloop.<UUID>"*/
static struct aws_string *s_get_unique_dispatch_queue_id(struct aws_allocator *alloc) {
    struct aws_uuid uuid;
    AWS_FATAL_ASSERT(aws_uuid_init(&uuid) == AWS_OP_SUCCESS);
    char uuid_str[AWS_UUID_STR_LEN] = {0};
    struct aws_byte_buf uuid_buf = aws_byte_buf_from_array(uuid_str, sizeof(uuid_str));
    uuid_buf.len = 0;
    aws_uuid_to_str(&uuid, &uuid_buf);
    struct aws_byte_cursor uuid_cursor = aws_byte_cursor_from_buf(&uuid_buf);

    struct aws_byte_buf dispatch_queue_id_buf;
    aws_byte_buf_init_copy_from_cursor(
        &dispatch_queue_id_buf, alloc, aws_byte_cursor_from_c_str("com.amazonaws.commonruntime.eventloop."));

    aws_byte_buf_append_dynamic(&dispatch_queue_id_buf, &uuid_cursor);

    struct aws_string *result = aws_string_new_from_buf(alloc, &dispatch_queue_id_buf);
    aws_byte_buf_clean_up(&dispatch_queue_id_buf);
    return result;
}

#if defined(aws_event_loop_new_with_dispatch_queue)
/* Setup a dispatch_queue with a scheduler. */
struct aws_event_loop *aws_event_loop_new_with_dispatch_queue(
    struct aws_allocator *alloc,
    const struct aws_event_loop_options *options) {
    AWS_PRECONDITION(options);
    AWS_PRECONDITION(options->clock);

    struct aws_event_loop *loop = aws_mem_calloc(alloc, 1, sizeof(struct aws_event_loop));
    struct dispatch_loop *dispatch_loop = NULL;

    AWS_LOGF_DEBUG(AWS_LS_IO_EVENT_LOOP, "id=%p: Initializing dispatch_queue event-loop", (void *)loop);
    if (aws_event_loop_init_base(loop, alloc, options->clock)) {
        goto clean_up;
    }

    dispatch_loop = aws_mem_calloc(alloc, 1, sizeof(struct dispatch_loop));

    dispatch_loop->dispatch_queue_id = s_get_unique_dispatch_queue_id(alloc);

    dispatch_loop->dispatch_queue =
        dispatch_queue_create((char *)dispatch_loop->dispatch_queue_id->bytes, DISPATCH_QUEUE_SERIAL);
    if (!dispatch_loop->dispatch_queue) {
        AWS_LOGF_FATAL(AWS_LS_IO_EVENT_LOOP, "id=%p: Failed to create dispatch queue.", (void *)loop);
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto clean_up;
    }

    int err = aws_task_scheduler_init(&dispatch_loop->scheduler, alloc);
    if (err) {
        AWS_LOGF_ERROR(AWS_LS_IO_EVENT_LOOP, "id=%p: Initializing task scheduler failed", (void *)loop);
        goto clean_up;
    }

    dispatch_loop->allocator = alloc;
    dispatch_loop->base_loop = loop;

    aws_linked_list_init(&dispatch_loop->local_cross_thread_tasks);
    aws_linked_list_init(&dispatch_loop->synced_task_data.cross_thread_tasks);

    aws_mutex_init(&dispatch_loop->synced_thread_data.thread_data_lock);
    dispatch_loop->synced_thread_data.is_executing = false;

    struct dispatch_loop_context *context = aws_mem_calloc(alloc, 1, sizeof(struct dispatch_loop_context));
    aws_ref_count_init(&context->ref_count, context, s_dispatch_loop_context_destroy);
    context->scheduling_state.will_schedule = false;
    aws_linked_list_init(&context->scheduling_state.scheduled_services);
    aws_mutex_init(&context->lock);
    context->io_dispatch_loop = dispatch_loop;
    context->allocator = alloc;
    dispatch_loop->synced_task_data.context = context;

    loop->impl_data = dispatch_loop;
    loop->vtable = &s_vtable;

    return loop;

clean_up:
    if (dispatch_loop) {
        if (dispatch_loop->dispatch_queue) {
            dispatch_release(dispatch_loop->dispatch_queue);
        }
        s_dispatch_event_loop_destroy(loop);
    }

    aws_mem_release(alloc, loop);

    return NULL;
}

#endif // AWS_ENABLE_DISPATCH_QUEUE

static void s_dispatch_queue_destroy_task(void *context) {
    struct dispatch_loop *dispatch_loop = context;

    aws_mutex_lock(&dispatch_loop->synced_thread_data.thread_data_lock);
    dispatch_loop->synced_thread_data.current_thread_id = aws_thread_current_thread_id();
    dispatch_loop->synced_thread_data.is_executing = true;
    aws_mutex_unlock(&dispatch_loop->synced_thread_data.thread_data_lock);

    aws_task_scheduler_clean_up(&dispatch_loop->scheduler);
    aws_mutex_lock(&dispatch_loop->synced_task_data.context->lock);

    while (!aws_linked_list_empty(&dispatch_loop->synced_task_data.cross_thread_tasks)) {
        struct aws_linked_list_node *node =
            aws_linked_list_pop_front(&dispatch_loop->synced_task_data.cross_thread_tasks);

        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
        task->fn(task, task->arg, AWS_TASK_STATUS_CANCELED);
    }

    while (!aws_linked_list_empty(&dispatch_loop->local_cross_thread_tasks)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&dispatch_loop->local_cross_thread_tasks);
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
        task->fn(task, task->arg, AWS_TASK_STATUS_CANCELED);
    }

    dispatch_loop->synced_task_data.suspended = true;
    aws_mutex_unlock(&dispatch_loop->synced_task_data.context->lock);

    aws_mutex_lock(&dispatch_loop->synced_thread_data.thread_data_lock);
    dispatch_loop->synced_thread_data.is_executing = false;
    aws_mutex_unlock(&dispatch_loop->synced_thread_data.thread_data_lock);

    s_dispatch_event_loop_destroy(dispatch_loop->base_loop);
}

static void s_destroy(struct aws_event_loop *event_loop) {
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Destroying Dispatch Queue Event Loop", (void *)event_loop);
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;
    /* Avoid double release on dispatch_loop */
    if (!dispatch_loop) {
        return;
    }

    /* make sure the loop is running so we can schedule a last task. */
    s_run(event_loop);

    /* cancel outstanding tasks */
    dispatch_async_and_wait_f(dispatch_loop->dispatch_queue, dispatch_loop, s_dispatch_queue_destroy_task);

    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Releasing Dispatch Queue.", (void *)event_loop);
}

static int s_wait_for_stop_completion(struct aws_event_loop *event_loop) {
    (void)event_loop;

    return AWS_OP_SUCCESS;
}

static int s_run(struct aws_event_loop *event_loop) {
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    aws_mutex_lock(&dispatch_loop->synced_task_data.context->lock);
    if (dispatch_loop->synced_task_data.suspended) {
        AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Starting event-loop thread.", (void *)event_loop);
        dispatch_resume(dispatch_loop->dispatch_queue);
        dispatch_loop->synced_task_data.suspended = false;
    }
    aws_mutex_unlock(&dispatch_loop->synced_task_data.context->lock);

    return AWS_OP_SUCCESS;
}

static int s_stop(struct aws_event_loop *event_loop) {
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    aws_mutex_lock(&dispatch_loop->synced_task_data.context->lock);
    if (!dispatch_loop->synced_task_data.suspended) {
        dispatch_loop->synced_task_data.suspended = true;
        AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Stopping event-loop thread.", (void *)event_loop);
        /* Suspend will increase the dispatch reference count. It is required to call resume before
         * releasing the dispatch queue. */
        dispatch_suspend(dispatch_loop->dispatch_queue);
    }
    aws_mutex_unlock(&dispatch_loop->synced_task_data.context->lock);

    return AWS_OP_SUCCESS;
}

static void s_try_schedule_new_iteration(struct dispatch_loop_context *loop, uint64_t timestamp);

// returns true if we should execute an iteration, false otherwise
static bool begin_iteration(struct scheduled_service_entry *entry) {
    bool should_execute_iteration = false;
    struct dispatch_loop_context *contxt = entry->dispatch_queue_context;
    aws_mutex_lock(&contxt->lock);

    struct dispatch_loop *dispatch_loop = entry->dispatch_queue_context->io_dispatch_loop;
    if (!dispatch_loop) {
        aws_mutex_unlock(&contxt->lock);
        return should_execute_iteration;
    }

    // swap the cross-thread tasks into task-local data
    AWS_FATAL_ASSERT(aws_linked_list_empty(&dispatch_loop->local_cross_thread_tasks));
    aws_linked_list_swap_contents(
        &dispatch_loop->synced_task_data.cross_thread_tasks, &dispatch_loop->local_cross_thread_tasks);

    // mark us as running an iteration and remove from the pending list
    dispatch_loop->synced_task_data.context->scheduling_state.will_schedule = true;
    aws_linked_list_remove(&entry->node);
    aws_mutex_unlock(&contxt->lock);

    should_execute_iteration = true;
    return should_execute_iteration;
}

// conditionally schedule another iteration as needed
static void end_iteration(struct scheduled_service_entry *entry) {

    struct dispatch_loop_context *contxt = entry->dispatch_queue_context;
    aws_mutex_lock(&contxt->lock);
    struct dispatch_loop *dispatch_loop = entry->dispatch_queue_context->io_dispatch_loop;
    if (!dispatch_loop) {
        aws_mutex_unlock(&contxt->lock);
        return;
    }

    dispatch_loop->synced_task_data.context->scheduling_state.will_schedule = false;

    // if there are any cross-thread tasks, reschedule an iteration for now
    if (!aws_linked_list_empty(&dispatch_loop->synced_task_data.cross_thread_tasks)) {
        // added during service which means nothing was scheduled because will_schedule was true
        s_try_schedule_new_iteration(contxt, 0);
    } else {
        // no cross thread tasks, so check internal time-based scheduler
        uint64_t next_task_time = 0;
        /* we already know it has tasks, we just scheduled one. We just want the next run time. */
        bool has_task = aws_task_scheduler_has_tasks(&dispatch_loop->scheduler, &next_task_time);

        if (has_task) {
            // only schedule an iteration if there isn't an existing dispatched iteration for the next task time or
            // earlier
            if (s_should_schedule_iteration(
                    &dispatch_loop->synced_task_data.context->scheduling_state.scheduled_services, next_task_time)) {
                s_try_schedule_new_iteration(contxt, next_task_time);
            }
        }
    }

    aws_mutex_unlock(&contxt->lock);
    s_scheduled_service_entry_destroy(entry);
}

// Iteration function that scheduled and executed by the Dispatch Queue API
static void s_run_iteration(void *context) {
    struct scheduled_service_entry *entry = context;

    struct dispatch_loop_context *dispatch_queue_context = entry->dispatch_queue_context;
    aws_mutex_lock(&dispatch_queue_context->lock);
    struct dispatch_loop *dispatch_loop = entry->dispatch_queue_context->io_dispatch_loop;
    aws_mutex_unlock(&dispatch_queue_context->lock);
    if (!dispatch_loop) {
        s_scheduled_service_entry_destroy(entry);
        return;
    }

    if (!begin_iteration(entry)) {
        s_scheduled_service_entry_destroy(entry);
        return;
    }

    aws_event_loop_register_tick_start(dispatch_loop->base_loop);
    // run the full iteration here: local cross-thread tasks

    while (!aws_linked_list_empty(&dispatch_loop->local_cross_thread_tasks)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&dispatch_loop->local_cross_thread_tasks);
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);

        /* Timestamp 0 is used to denote "now" tasks */
        if (task->timestamp == 0) {
            aws_task_scheduler_schedule_now(&dispatch_loop->scheduler, task);
        } else {
            aws_task_scheduler_schedule_future(&dispatch_loop->scheduler, task, task->timestamp);
        }
    }

    aws_mutex_lock(&dispatch_loop->synced_thread_data.thread_data_lock);
    dispatch_loop->synced_thread_data.current_thread_id = aws_thread_current_thread_id();
    dispatch_loop->synced_thread_data.is_executing = true;
    aws_mutex_unlock(&dispatch_loop->synced_thread_data.thread_data_lock);

    // run all scheduled tasks
    uint64_t now_ns = 0;
    aws_event_loop_current_clock_time(dispatch_loop->base_loop, &now_ns);
    aws_task_scheduler_run_all(&dispatch_loop->scheduler, now_ns);
    aws_event_loop_register_tick_end(dispatch_loop->base_loop);

    aws_mutex_lock(&dispatch_loop->synced_thread_data.thread_data_lock);
    dispatch_loop->synced_thread_data.is_executing = false;
    aws_mutex_unlock(&dispatch_loop->synced_thread_data.thread_data_lock);

    end_iteration(entry);
}

/**
 * Checks if a new iteration task needs to be scheduled, given a target timestamp. If so, submits an iteration task to
 * dispatch queue and registers the pending execution in the event loop's list of scheduled iterations.
 *
 * If timestamp==0, the function will always schedule a new iteration as long as the event loop is not suspended.
 *
 * The function should be wrapped with dispatch_loop->synced_task_data->lock
 */
static void s_try_schedule_new_iteration(struct dispatch_loop_context *dispatch_loop_context, uint64_t timestamp) {
    struct dispatch_loop *dispatch_loop = dispatch_loop_context->io_dispatch_loop;
    if (!dispatch_loop || dispatch_loop->synced_task_data.suspended)
        return;
    if (!s_should_schedule_iteration(
            &dispatch_loop->synced_task_data.context->scheduling_state.scheduled_services, timestamp)) {
        return;
    }
    struct scheduled_service_entry *entry = s_scheduled_service_entry_new(dispatch_loop_context, timestamp);
    aws_linked_list_push_front(
        &dispatch_loop->synced_task_data.context->scheduling_state.scheduled_services, &entry->node);
    dispatch_async_f(dispatch_loop->dispatch_queue, entry, s_run_iteration);
}

static void s_schedule_task_common(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    aws_mutex_lock(&dispatch_loop->synced_task_data.context->lock);
    bool should_schedule = false;

    bool was_empty = aws_linked_list_empty(&dispatch_loop->synced_task_data.cross_thread_tasks);
    task->timestamp = run_at_nanos;

    // As we dont have control to dispatch queue thread, all tasks are treated as cross thread tasks
    aws_linked_list_push_back(&dispatch_loop->synced_task_data.cross_thread_tasks, &task->node);

    /**
     * To avoid explicit scheduling event loop iterations, the actual "iteration scheduling" should happened at the end
     * of each iteration run. (The scheduling will happened in function `void end_iteration(struct
     * scheduled_service_entry *entry)`). Therefore, as long as there is an executing iteration, we can guaranteed that
     * the tasks will be scheduled.
     *
     * `was_empty` is used for a quick validation. If the `cross_thread_tasks` is not empty, we must have a running
     * iteration that is processing the `cross_thread_tasks`.
     */

    if (was_empty && !dispatch_loop->synced_task_data.context->scheduling_state.will_schedule) {
        /** If there is no currently running iteration, then we check if we have already scheduled an iteration
         * scheduled before this task's run time. */
        should_schedule = s_should_schedule_iteration(
            &dispatch_loop->synced_task_data.context->scheduling_state.scheduled_services, run_at_nanos);
    }

    // If there is no scheduled iteration, start one right now to process the `cross_thread_task`.
    if (should_schedule) {
        s_try_schedule_new_iteration(dispatch_loop->synced_task_data.context, 0);
    }

    aws_mutex_unlock(&dispatch_loop->synced_task_data.context->lock);
}

static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task) {
    s_schedule_task_common(event_loop, task, 0 /* zero denotes "now" task */);
}

static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    s_schedule_task_common(event_loop, task, run_at_nanos);
}

static void s_cancel_task(struct aws_event_loop *event_loop, struct aws_task *task) {
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: cancelling task %p", (void *)event_loop, (void *)task);
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;
    aws_task_scheduler_cancel_task(&dispatch_loop->scheduler, task);
}

static int s_connect_to_dispatch_queue(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    (void)event_loop;
    (void)handle;
    AWS_PRECONDITION(handle->set_queue && handle->clear_queue);

    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: subscribing to events on handle %p",
        (void *)event_loop,
        (void *)handle->data.handle);
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;
    handle->set_queue(handle, dispatch_loop->dispatch_queue);
    return AWS_OP_SUCCESS;
}

static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: un-subscribing from events on handle %p",
        (void *)event_loop,
        (void *)handle->data.handle);
    handle->clear_queue(handle);
    return AWS_OP_SUCCESS;
}

// The dispatch queue will assign the task block to threads, we will threat all
// tasks as cross thread tasks. Ignore the caller thread verification for apple
// dispatch queue.
static bool s_is_on_callers_thread(struct aws_event_loop *event_loop) {
    struct dispatch_loop *dispatch_queue = event_loop->impl_data;
    aws_mutex_lock(&dispatch_queue->synced_thread_data.thread_data_lock);
    bool result = dispatch_queue->synced_thread_data.is_executing &&
                  aws_thread_thread_id_equal(
                      dispatch_queue->synced_thread_data.current_thread_id, aws_thread_current_thread_id());
    aws_mutex_unlock(&dispatch_queue->synced_thread_data.thread_data_lock);
    return result;
}
