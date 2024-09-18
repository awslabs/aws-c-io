/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/event_loop.h>

#include <aws/common/atomics.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>

#include <aws/io/logging.h>

#include <unistd.h>

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
    .register_style.connect_to_completion_port = s_connect_to_dispatch_queue,
    .event_loop_style = AWS_EVENT_LOOP_STYLE_COMPLETION_PORT_BASED,
    .unsubscribe_from_io_events = s_unsubscribe_from_io_events,
    .free_io_event_resources = s_free_io_event_resources,
    .is_on_callers_thread = s_is_on_callers_thread,
};

struct dispatch_scheduling_state {
    // Let's us skip processing an iteration task if one is already in the middle
    // of executing
    bool is_executing_iteration;

    // List<scheduled_service_entry> in sorted order by timestamp
    //
    // When we go to schedule a new iteration, we check here first to see
    // if our scheduling attempt is redundant
    struct aws_linked_list scheduled_services;
};

struct scheduled_service_entry {
    struct aws_allocator *allocator;
    uint64_t timestamp;
    struct aws_linked_list_node node;
    struct aws_event_loop *loop; // might eventually need to be ref-counted for cleanup?
};

struct dispatch_loop {
    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;
    dispatch_queue_t dispatch_queue;
    struct aws_task_scheduler scheduler;
    struct aws_linked_list local_cross_thread_tasks;

    struct {
        struct dispatch_scheduling_state scheduling_state;
        struct aws_linked_list cross_thread_tasks;
        struct aws_mutex lock;
        bool suspended;
    } synced_data;

    bool wakeup_schedule_needed;
};

struct scheduled_service_entry *scheduled_service_entry_new(struct aws_event_loop *loop, uint64_t timestamp) {
    struct scheduled_service_entry *entry = aws_mem_calloc(loop->alloc, 1, sizeof(struct scheduled_service_entry));

    entry->allocator = loop->alloc;
    entry->timestamp = timestamp;
    entry->loop = loop;
    struct dispatch_loop *dispatch_loop = loop->impl_data;
    aws_ref_count_acquire(&dispatch_loop->ref_count);

    return entry;
}

// may only be called when the dispatch event loop synced data lock is held
void scheduled_service_entry_destroy(struct scheduled_service_entry *entry) {
    if (aws_linked_list_node_is_in_list(&entry->node)) {
        aws_linked_list_remove(&entry->node);
    }
    struct dispatch_loop *dispatch_loop = entry->loop->impl_data;
    aws_ref_count_release(&dispatch_loop->ref_count);

    aws_mem_release(entry->allocator, entry);
}

// checks to see if another scheduled iteration already exists that will either
// handle our needs or reschedule at the end to do so
bool should_schedule_iteration(struct aws_linked_list *scheduled_iterations, uint64_t proposed_iteration_time) {
    if (aws_linked_list_empty(scheduled_iterations)) {
        return true;
    }

    struct aws_linked_list_node *head_node = aws_linked_list_front(scheduled_iterations);
    struct scheduled_service_entry *entry = AWS_CONTAINER_OF(head_node, struct scheduled_service_entry, node);

    // is the next scheduled iteration later than what we require?
    return entry->timestamp > proposed_iteration_time;
}

static void s_dispatch_event_loop_destroy(void *context) {
    // release dispatch loop

    struct aws_event_loop *event_loop = context;
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    AWS_LOGF_DEBUG(AWS_LS_IO_EVENT_LOOP, "id=%p: Destroy Dispatch Queue Event Loop.", (void *)event_loop);

    aws_mutex_clean_up(&dispatch_loop->synced_data.lock);
    aws_mem_release(dispatch_loop->allocator, dispatch_loop);
    aws_event_loop_clean_up_base(event_loop);
    aws_mem_release(event_loop->alloc, event_loop);

    aws_thread_decrement_unjoined_count();
}

/* Setup a dispatch_queue with a scheduler. */
struct aws_event_loop *aws_event_loop_new_dispatch_queue_with_options(
    struct aws_allocator *alloc,
    const struct aws_event_loop_options *options) {
    AWS_PRECONDITION(options);
    AWS_PRECONDITION(options->clock);

    struct aws_event_loop *loop = aws_mem_calloc(alloc, 1, sizeof(struct aws_event_loop));

    AWS_LOGF_DEBUG(AWS_LS_IO_EVENT_LOOP, "id=%p: Initializing dispatch_queue event-loop", (void *)loop);
    if (aws_event_loop_init_base(loop, alloc, options->clock)) {
        goto clean_up_loop;
    }

    struct dispatch_loop *dispatch_loop = aws_mem_calloc(alloc, 1, sizeof(struct dispatch_loop));
    aws_ref_count_init(&dispatch_loop->ref_count, loop, s_dispatch_event_loop_destroy);

    dispatch_loop->dispatch_queue =
        dispatch_queue_create("com.amazonaws.commonruntime.eventloop", DISPATCH_QUEUE_SERIAL);
    if (!dispatch_loop->dispatch_queue) {
        AWS_LOGF_FATAL(AWS_LS_IO_EVENT_LOOP, "id=%p: Failed to create dispatch queue.", (void *)loop);
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto clean_up_dispatch;
    }

    dispatch_loop->synced_data.scheduling_state.is_executing_iteration = false;
    dispatch_loop->allocator = alloc;

    int err = aws_task_scheduler_init(&dispatch_loop->scheduler, alloc);
    if (err) {
        AWS_LOGF_ERROR(AWS_LS_IO_EVENT_LOOP, "id=%p: Initializing task scheduler failed", (void *)loop);
        goto clean_up_dispatch;
    }

    aws_linked_list_init(&dispatch_loop->local_cross_thread_tasks);
    aws_linked_list_init(&dispatch_loop->synced_data.scheduling_state.scheduled_services);
    aws_linked_list_init(&dispatch_loop->synced_data.cross_thread_tasks);

    dispatch_loop->wakeup_schedule_needed = true;
    aws_mutex_init(&dispatch_loop->synced_data.lock);

    loop->impl_data = dispatch_loop;
    loop->vtable = &s_vtable;

    // manually increament the thread count, so the library will wait for dispatch queue releasing
    aws_thread_increment_unjoined_count();

    return loop;

clean_up_dispatch:
    if (dispatch_loop->dispatch_queue) {
        dispatch_release(dispatch_loop->dispatch_queue);
    }

    aws_mem_release(alloc, dispatch_loop);
    aws_event_loop_clean_up_base(loop);

clean_up_loop:
    aws_mem_release(alloc, loop);

    return NULL;
}

static void s_destroy(struct aws_event_loop *event_loop) {
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Destroying Dispatch Queue Event Loop", (void *)event_loop);

    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    /* make sure the loop is running so we can schedule a last task. */
    s_run(event_loop);

    /* cancel outstanding tasks */
    dispatch_async_and_wait(dispatch_loop->dispatch_queue, ^{
      aws_task_scheduler_clean_up(&dispatch_loop->scheduler);

      aws_mutex_lock(&dispatch_loop->synced_data.lock);
      while (!aws_linked_list_empty(&dispatch_loop->synced_data.cross_thread_tasks)) {
          struct aws_linked_list_node *node = aws_linked_list_pop_front(&dispatch_loop->synced_data.cross_thread_tasks);
          struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
          task->fn(task, task->arg, AWS_TASK_STATUS_CANCELED);
      }

      while (!aws_linked_list_empty(&dispatch_loop->local_cross_thread_tasks)) {
          struct aws_linked_list_node *node = aws_linked_list_pop_front(&dispatch_loop->local_cross_thread_tasks);
          struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
          task->fn(task, task->arg, AWS_TASK_STATUS_CANCELED);
      }

      while (!aws_linked_list_empty(&dispatch_loop->synced_data.scheduling_state.scheduled_services)) {
          struct aws_linked_list_node *node =
              aws_linked_list_pop_front(&dispatch_loop->synced_data.scheduling_state.scheduled_services);
          struct scheduled_service_entry *entry = AWS_CONTAINER_OF(node, struct scheduled_service_entry, node);
          scheduled_service_entry_destroy(entry);
      }

      dispatch_loop->synced_data.suspended = true;
      aws_mutex_unlock(&dispatch_loop->synced_data.lock);
    });

    /* we don't want it stopped while shutting down. dispatch_release will fail on a suspended loop. */
    dispatch_release(dispatch_loop->dispatch_queue);

    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Releasing Dispatch Queue.", (void *)event_loop);
    aws_ref_count_release(&dispatch_loop->ref_count);
}

static int s_wait_for_stop_completion(struct aws_event_loop *event_loop) {
    (void)event_loop;

    return AWS_OP_SUCCESS;
}

static int s_run(struct aws_event_loop *event_loop) {
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    aws_mutex_lock(&dispatch_loop->synced_data.lock);
    if (dispatch_loop->synced_data.suspended) {
        AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Starting event-loop thread.", (void *)event_loop);
        dispatch_resume(dispatch_loop->dispatch_queue);
        dispatch_loop->synced_data.suspended = false;
    }
    aws_mutex_unlock(&dispatch_loop->synced_data.lock);

    return AWS_OP_SUCCESS;
}

static int s_stop(struct aws_event_loop *event_loop) {
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    aws_mutex_lock(&dispatch_loop->synced_data.lock);
    if (!dispatch_loop->synced_data.suspended) {
        dispatch_loop->synced_data.suspended = true;
        AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Stopping event-loop thread.", (void *)event_loop);
        // Suspend will increase the dispatch reference count. It is required to call resume before
        // releasing the dispatch queue.
        dispatch_suspend(dispatch_loop->dispatch_queue);
    }
    aws_mutex_unlock(&dispatch_loop->synced_data.lock);

    return AWS_OP_SUCCESS;
}

void try_schedule_new_iteration(struct aws_event_loop *loop, uint64_t timestamp);

// returns true if we should execute an iteration, false otherwise
bool begin_iteration(struct scheduled_service_entry *entry) {
    bool should_execute_iteration = false;
    struct dispatch_loop *dispatch_loop = entry->loop->impl_data;

    aws_mutex_lock(&dispatch_loop->synced_data.lock);

    // someone else is already going, do nothing
    if (dispatch_loop->synced_data.scheduling_state.is_executing_iteration) {
        goto done;
    }

    // swap the cross-thread tasks into task-local data
    AWS_FATAL_ASSERT(aws_linked_list_empty(&dispatch_loop->local_cross_thread_tasks));
    aws_linked_list_swap_contents(
        &dispatch_loop->synced_data.cross_thread_tasks, &dispatch_loop->local_cross_thread_tasks);

    // mark us as running an iteration and remove from the pending list
    dispatch_loop->synced_data.scheduling_state.is_executing_iteration = true;
    aws_linked_list_remove(&entry->node);

    should_execute_iteration = true;

done:

    aws_mutex_unlock(&dispatch_loop->synced_data.lock);

    return should_execute_iteration;
}

// conditionally schedule another iteration as needed
void end_iteration(struct scheduled_service_entry *entry) {
    struct dispatch_loop *loop = entry->loop->impl_data;

    aws_mutex_lock(&loop->synced_data.lock);

    loop->synced_data.scheduling_state.is_executing_iteration = false;

    // if there are any cross-thread tasks, reschedule an iteration for now
    if (!aws_linked_list_empty(&loop->synced_data.cross_thread_tasks)) {
        // added during service which means nothing was scheduled because is_executing_iteration was true
        try_schedule_new_iteration(entry->loop, 0);
    } else {
        // no cross thread tasks, so check internal time-based scheduler
        uint64_t next_task_time = 0;
        /* we already know it has tasks, we just scheduled one. We just want the next run time. */
        bool has_task = aws_task_scheduler_has_tasks(&loop->scheduler, &next_task_time);

        if (has_task) {
            // only schedule an iteration if there isn't an existing dispatched iteration for the next task time or
            // earlier
            if (should_schedule_iteration(&loop->synced_data.scheduling_state.scheduled_services, next_task_time)) {
                try_schedule_new_iteration(entry->loop, next_task_time);
            }
        }
    }

    aws_mutex_unlock(&loop->synced_data.lock);
    scheduled_service_entry_destroy(entry);
}

// this function is what gets scheduled and executed by the Dispatch Queue API
void run_iteration(void *context) {
    struct scheduled_service_entry *entry = context;
    struct aws_event_loop *event_loop = entry->loop;
    if (event_loop == NULL)
        return;
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    if (!begin_iteration(entry)) {
        return;
    }

    aws_event_loop_register_tick_start(event_loop);
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

    // run all scheduled tasks
    uint64_t now_ns = 0;
    aws_event_loop_current_clock_time(event_loop, &now_ns);
    aws_task_scheduler_run_all(&dispatch_loop->scheduler, now_ns);
    aws_event_loop_register_tick_end(event_loop);

    end_iteration(entry);
}

// Checks if a new iteration task needs to be scheduled, given a target timestamp
// If so, submits an iteration task to dispatch queue and registers the pending
// execution in the event loop's list of scheduled iterations.
// The function should be wrapped with dispatch_loop->synced_data->lock
void try_schedule_new_iteration(struct aws_event_loop *loop, uint64_t timestamp) {
    struct dispatch_loop *dispatch_loop = loop->impl_data;
    if (dispatch_loop->synced_data.suspended)
        return;
    if (!should_schedule_iteration(&dispatch_loop->synced_data.scheduling_state.scheduled_services, timestamp)) {
        return;
    }
    struct scheduled_service_entry *entry = scheduled_service_entry_new(loop, timestamp);
    aws_linked_list_push_front(&dispatch_loop->synced_data.scheduling_state.scheduled_services, &entry->node);
    dispatch_async_f(dispatch_loop->dispatch_queue, entry, run_iteration);
}

static void s_schedule_task_common(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    aws_mutex_lock(&dispatch_loop->synced_data.lock);
    bool should_schedule = false;

    bool is_empty = aws_linked_list_empty(&dispatch_loop->synced_data.cross_thread_tasks);
    task->timestamp = run_at_nanos;

    // We dont have control to dispatch queue thread, threat all tasks are threated as cross thread tasks
    aws_linked_list_push_back(&dispatch_loop->synced_data.cross_thread_tasks, &task->node);
    if (is_empty) {
        if (!dispatch_loop->synced_data.scheduling_state.is_executing_iteration) {
            if (should_schedule_iteration(
                    &dispatch_loop->synced_data.scheduling_state.scheduled_services, run_at_nanos)) {
                should_schedule = true;
            }
        }
    }

    aws_mutex_unlock(&dispatch_loop->synced_data.lock);

    if (should_schedule) {
        try_schedule_new_iteration(event_loop, 0);
    }
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
    (void)event_loop;
    return true;
}
