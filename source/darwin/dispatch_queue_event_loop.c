/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/event_loop.h>
#include <aws/io/private/event_loop_impl.h>

#include <aws/common/clock.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/uuid.h>

#include <aws/io/logging.h>

#include <unistd.h>

#include "./dispatch_queue_event_loop_private.h" // private header
#include <dispatch/dispatch.h>
#include <dispatch/queue.h>

// Maximum amount of time we schedule event loop service tasks out into the future.  This bounds the maximum
// amount of time we have to wait for those scheduled tasks to resolve during shutdown, which in turn bounds
// how long shutdown can take.
//
// Start with a second for now.
#define AWS_DISPATCH_QUEUE_MAX_FUTURE_SERVICE_INTERVAL (AWS_TIMESTAMP_NANOS)

static void s_start_destroy(struct aws_event_loop *event_loop);
static void s_complete_destroy(struct aws_event_loop *event_loop);
static int s_run(struct aws_event_loop *event_loop);
static int s_stop(struct aws_event_loop *event_loop);
static int s_wait_for_stop_completion(struct aws_event_loop *event_loop);
static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task);
static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos);
static void s_cancel_task(struct aws_event_loop *event_loop, struct aws_task *task);
static int s_connect_to_io_completion_port(struct aws_event_loop *event_loop, struct aws_io_handle *handle);
static int s_subscribe_to_io_events(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    aws_event_loop_on_event_fn *on_event,
    void *user_data) {
    (void)event_loop;
    (void)handle;
    (void)events;
    (void)on_event;
    (void)user_data;
    AWS_LOGF_ERROR(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: subscribe_to_io_events() is not supported using Dispatch Queue Event Loops",
        (void *)event_loop);
    return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
}
static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    (void)handle;
    AWS_LOGF_ERROR(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: unsubscribe_from_io_events() is not supported using Dispatch Queue Event Loops",
        (void *)event_loop);
    return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
}
static void s_free_io_event_resources(void *user_data) {
    /* No io event resources to free */
    (void)user_data;
}
static void *s_get_base_event_loop_group(struct aws_event_loop *event_loop);
static bool s_is_on_callers_thread(struct aws_event_loop *event_loop);

static struct aws_event_loop_vtable s_vtable = {
    .start_destroy = s_start_destroy,
    .complete_destroy = s_complete_destroy,
    .run = s_run,
    .stop = s_stop,
    .wait_for_stop_completion = s_wait_for_stop_completion,
    .schedule_task_now = s_schedule_task_now,
    .schedule_task_future = s_schedule_task_future,
    .cancel_task = s_cancel_task,
    .connect_to_io_completion_port = s_connect_to_io_completion_port,
    .subscribe_to_io_events = s_subscribe_to_io_events,
    .unsubscribe_from_io_events = s_unsubscribe_from_io_events,
    .free_io_event_resources = s_free_io_event_resources,
    .get_base_event_loop_group = s_get_base_event_loop_group,
    .is_on_callers_thread = s_is_on_callers_thread,
};

/**
 * DISPATCH QUEUE
 *
 * Event loop is responsible for processing events and tasks by launching an execution loop on a single thread. Each
 * iteration of this loop performs three primary jobs:
 * 1. Process I/O events.
 * 2. Process cross-thread tasks.
 * 3. Execute all runnable tasks.
 *
 * Apple Dispatch queues can be given a concurrent or serial attribute on creation. We use Serial Dispatch Queues that
 * are FIFO queues to which the application can submit tasks in the form of block objects. The block objects will be
 * executed on a system defined thread pool. Instead of executing the loop on a single thread, we recurrently run
 * iterations of the execution loop as dispatch queue block objects. aws-c-io library uses a serial dispatch
 * queue to insure the tasks scheduled on the event loop task scheduler are executed in the correct order.
 *
 * Data Structures ******
 * `scheduled_iteration_entry `: Each entry maps to an execution block submitted to Apple's dispatch queue. Since Apple
 * ensures the dispatch queue remains active until all scheduled blocks have been executed, it is necessary to keep the
 * aws_dispatch_loop alive accordingly. This is achieved by holding a reference to aws_dispatch_loop within each entry.
 * An entry is created upon block submission and is destroyed once the block has been executed, preventing premature
 * deallocation of the dispatch loop.
 *
 * `dispatch_loop`: Implementation of the event loop for dispatch queue.
 *
 * Functions ************
 * `s_run_iteration`: This function represents the block scheduled in `scheduled_iteration_entry`'s
 */

/* Help functions to lock status */

/* The synced_data_lock is held when any member of `aws_dispatch_loop`'s `synced_data` is accessed or modified */
static int s_lock_synced_data(struct aws_dispatch_loop *dispatch_loop) {
    return aws_mutex_lock(&dispatch_loop->synced_data.synced_data_lock);
}

static int s_unlock_synced_data(struct aws_dispatch_loop *dispatch_loop) {
    return aws_mutex_unlock(&dispatch_loop->synced_data.synced_data_lock);
}

static struct aws_dispatch_loop *s_dispatch_loop_acquire(struct aws_dispatch_loop *dispatch_loop) {
    if (dispatch_loop) {
        aws_ref_count_acquire(&dispatch_loop->ref_count);
    }

    return dispatch_loop;
}

static void s_dispatch_loop_release(struct aws_dispatch_loop *dispatch_loop) {
    if (dispatch_loop) {
        aws_ref_count_release(&dispatch_loop->ref_count);
    }
}

/*
 * The data structure used to track the dispatch queue execution iteration (block). Each entry is associated with
 * a block scheduled on Apple Dispatch Queue that runs a service iteration.
 */
struct scheduled_iteration_entry {
    struct aws_allocator *allocator;
    uint64_t timestamp;
    struct aws_linked_list_node scheduled_entry_node;
    struct aws_dispatch_loop *dispatch_loop;
};

/*
 * Allocates and returns a new memory alocated `scheduled_iteration_entry` struct
 * All scheduled_iteration_entry structs must have `s_scheduled_iteration_entry_destroy()` called on them.
 */
static struct scheduled_iteration_entry *s_scheduled_iteration_entry_new(
    struct aws_dispatch_loop *dispatch_loop,
    uint64_t timestamp) {
    struct scheduled_iteration_entry *entry =
        aws_mem_calloc(dispatch_loop->allocator, 1, sizeof(struct scheduled_iteration_entry));

    entry->allocator = dispatch_loop->allocator;
    entry->timestamp = timestamp;
    entry->dispatch_loop = s_dispatch_loop_acquire(dispatch_loop);

    return entry;
}

/*
 * Cleans up the memory allocated for a `scheduled_iteration_entry`.
 */
static void s_scheduled_iteration_entry_destroy(struct scheduled_iteration_entry *entry) {
    if (!entry) {
        return;
    }

    s_dispatch_loop_release(entry->dispatch_loop);
    aws_mem_release(entry->allocator, entry);
}

/* Manually called to destroy an aws_event_loop */
static void s_dispatch_event_loop_final_destroy(struct aws_event_loop *event_loop) {
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;

    if (aws_task_scheduler_is_valid(&dispatch_loop->scheduler)) {
        aws_task_scheduler_clean_up(&dispatch_loop->scheduler);
    }

    aws_mutex_clean_up(&dispatch_loop->synced_data.synced_data_lock);
    aws_condition_variable_clean_up(&dispatch_loop->synced_data.signal);
    // We don't need to clean up the dispatch_loop->synced_data.scheduled_iterations, as all scheduling entries should
    // have cleaned up before destroy call.
    aws_mem_release(dispatch_loop->allocator, dispatch_loop);
    aws_event_loop_clean_up_base(event_loop);
    aws_mem_release(event_loop->alloc, event_loop);

    aws_thread_decrement_unjoined_count();

    AWS_LOGF_DEBUG(AWS_LS_IO_EVENT_LOOP, "id=%p: Destroyed Dispatch Queue Event Loop.", (void *)event_loop);
}

static const char AWS_LITERAL_APPLE_DISPATCH_QUEUE_ID_PREFIX[] = "com.amazonaws.commonruntime.eventloop.";
static const size_t AWS_IO_APPLE_DISPATCH_QUEUE_ID_PREFIX_LENGTH =
    AWS_ARRAY_SIZE(AWS_LITERAL_APPLE_DISPATCH_QUEUE_ID_PREFIX) - 1; // remove string terminator
static const size_t AWS_IO_APPLE_DISPATCH_QUEUE_ID_LENGTH =
    AWS_IO_APPLE_DISPATCH_QUEUE_ID_PREFIX_LENGTH + AWS_UUID_STR_LEN;
/**
 * Generates a unique identifier for a dispatch queue in the format "com.amazonaws.commonruntime.eventloop.<UUID>".
 * This identifier will be stored in the provided `result` buffer.
 */
static void s_get_unique_dispatch_queue_id(char result[AWS_IO_APPLE_DISPATCH_QUEUE_ID_LENGTH]) {
    struct aws_uuid uuid;
    AWS_FATAL_ASSERT(aws_uuid_init(&uuid) == AWS_OP_SUCCESS);
    char uuid_str[AWS_UUID_STR_LEN] = {0};
    struct aws_byte_buf uuid_buf = aws_byte_buf_from_array(uuid_str, sizeof(uuid_str));
    uuid_buf.len = 0;
    aws_uuid_to_str(&uuid, &uuid_buf);

    memcpy(result, AWS_LITERAL_APPLE_DISPATCH_QUEUE_ID_PREFIX, AWS_IO_APPLE_DISPATCH_QUEUE_ID_PREFIX_LENGTH);
    memcpy(result + AWS_IO_APPLE_DISPATCH_QUEUE_ID_PREFIX_LENGTH, uuid_buf.buffer, uuid_buf.len);
}

static void s_dispatch_event_loop_on_zero_ref_count(void *user_data) {
    struct aws_dispatch_loop *dispatch_loop = user_data;
    if (dispatch_loop == NULL) {
        return;
    }

    s_lock_synced_data(dispatch_loop);
    AWS_FATAL_ASSERT(dispatch_loop->synced_data.execution_state == AWS_DLES_SHUTTING_DOWN);
    dispatch_loop->synced_data.execution_state = AWS_DLES_TERMINATED;
    s_unlock_synced_data(dispatch_loop);

    aws_condition_variable_notify_all(&dispatch_loop->synced_data.signal);
}

/* Setup a dispatch_queue with a scheduler. */
struct aws_event_loop *aws_event_loop_new_with_dispatch_queue(
    struct aws_allocator *alloc,
    const struct aws_event_loop_options *options) {
    AWS_PRECONDITION(options);
    AWS_PRECONDITION(options->clock);

    struct aws_dispatch_loop *dispatch_loop = NULL;
    struct aws_event_loop *loop = aws_mem_calloc(alloc, 1, sizeof(struct aws_event_loop));

    AWS_LOGF_DEBUG(AWS_LS_IO_EVENT_LOOP, "id=%p: Initializing Dispatch Queue Event Loop", (void *)loop);
    if (aws_event_loop_init_base(loop, alloc, options->clock)) {
        goto clean_up;
    }

    loop->vtable = &s_vtable;

    dispatch_loop = aws_mem_calloc(alloc, 1, sizeof(struct aws_dispatch_loop));
    dispatch_loop->allocator = alloc;
    loop->impl_data = dispatch_loop;
    dispatch_loop->base_loop = loop;
    dispatch_loop->base_elg = options->parent_elg;
    dispatch_loop->synced_data.execution_state = AWS_DLES_SUSPENDED;
    aws_ref_count_init(&dispatch_loop->ref_count, dispatch_loop, s_dispatch_event_loop_on_zero_ref_count);

    if (aws_condition_variable_init(&dispatch_loop->synced_data.signal)) {
        goto clean_up;
    }

    if (aws_mutex_init(&dispatch_loop->synced_data.synced_data_lock)) {
        goto clean_up;
    }

    aws_thread_increment_unjoined_count();

    char dispatch_queue_id[AWS_IO_APPLE_DISPATCH_QUEUE_ID_LENGTH] = {0};
    s_get_unique_dispatch_queue_id(dispatch_queue_id);

    /*
     * Apple API dispatch_queue_create returns a dispatch_queue_t. This cannot fail and will crash if it does.
     * A reference to the dispatch queue is retained and must be released explicitly with dispatch_release().
     */
    dispatch_loop->dispatch_queue = dispatch_queue_create(dispatch_queue_id, DISPATCH_QUEUE_SERIAL);

    /*
     * Calling `dispatch_suspend()` on a dispatch queue instructs the dispatch queue to not run any further blocks.
     * Suspending a dispatch_queue will increase the dispatch queue's suspension count and Apple will not release the
     * dispatch_queue. A suspended dispatch queue must be resumed before it can be fully released. We suspend the newly
     * created Apple dispatch queue here to conform with other event loop types. A new event loop is expected to
     * be in a stopped state until run is called.
     *
     * We call `s_run()` during the destruction of the event loop to insure both the execution of the cleanup/destroy
     * task as well as to release the Apple suspension count.
     */
    dispatch_suspend(dispatch_loop->dispatch_queue);

    AWS_LOGF_INFO(
        AWS_LS_IO_EVENT_LOOP, "id=%p: Apple dispatch queue created with id: %s", (void *)loop, dispatch_queue_id);

    /* The dispatch queue is suspended at this point. */
    dispatch_loop->synced_data.is_executing = false;

    if (aws_task_scheduler_init(&dispatch_loop->scheduler, alloc)) {
        AWS_LOGF_ERROR(AWS_LS_IO_EVENT_LOOP, "id=%p: Initialization of task scheduler failed", (void *)loop);
        goto clean_up;
    }

    aws_linked_list_init(&dispatch_loop->synced_data.cross_thread_tasks);
    aws_linked_list_init(&dispatch_loop->synced_data.scheduled_iterations);

    return loop;

clean_up:
    if (dispatch_loop) {
        if (dispatch_loop->dispatch_queue) {
            /*
             * We resume the dispatch queue in the event it has been suspended to decrement the suspension count placed
             * on the dispatch queue by suspending it.
             */
            dispatch_resume(dispatch_loop->dispatch_queue);
        }

        /*
         * We intentionally bypass the ref-count-initiated destruction and go directly to the final destroy here.
         * The ref-counting mechanism is only for event loops that are successfully created (and thus get destroyed
         * by _start_destroy -> _complete_destroy)
         */
        s_dispatch_event_loop_final_destroy(loop);
    } else {
        aws_mem_release(alloc, loop);
    }
    return NULL;
}

static void s_dispatch_queue_purge_cross_thread_tasks(void *context) {
    struct aws_dispatch_loop *dispatch_loop = context;
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Releasing Dispatch Queue.", (void *)dispatch_loop->base_loop);

    s_lock_synced_data(dispatch_loop);
    dispatch_loop->synced_data.current_thread_id = aws_thread_current_thread_id();
    dispatch_loop->synced_data.is_executing = true;
    s_unlock_synced_data(dispatch_loop);

    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Cancelling scheduled tasks.", (void *)dispatch_loop->base_loop);
    /* Cancel all tasks currently scheduled in the task scheduler. */
    aws_task_scheduler_clean_up(&dispatch_loop->scheduler);

    struct aws_linked_list local_cross_thread_tasks;
    aws_linked_list_init(&local_cross_thread_tasks);

    bool done = false;
    while (!done) {
        /* Swap tasks from cross_thread_tasks into local_cross_thread_tasks to cancel them. */
        s_lock_synced_data(dispatch_loop);
        aws_linked_list_swap_contents(&dispatch_loop->synced_data.cross_thread_tasks, &local_cross_thread_tasks);
        s_unlock_synced_data(dispatch_loop);

        if (aws_linked_list_empty(&local_cross_thread_tasks)) {
            done = true;
        }

        /* Cancel all tasks that were in cross_thread_tasks */
        while (!aws_linked_list_empty(&local_cross_thread_tasks)) {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&local_cross_thread_tasks);
            struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
            task->fn(task, task->arg, AWS_TASK_STATUS_CANCELED);
        }
    }

    s_lock_synced_data(dispatch_loop);
    dispatch_loop->synced_data.is_executing = false;
    s_unlock_synced_data(dispatch_loop);
}

static void s_start_destroy(struct aws_event_loop *event_loop) {
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Starting to destroy Dispatch Queue Event Loop", (void *)event_loop);
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;

    s_lock_synced_data(dispatch_loop);
    enum aws_dispatch_loop_execution_state execution_state = dispatch_loop->synced_data.execution_state;
    AWS_FATAL_ASSERT(execution_state == AWS_DLES_RUNNING || execution_state == AWS_DLES_SUSPENDED);
    if (execution_state == AWS_DLES_SUSPENDED) {
        dispatch_resume(dispatch_loop->dispatch_queue);
    }
    dispatch_loop->synced_data.execution_state = AWS_DLES_SHUTTING_DOWN;
    s_unlock_synced_data(dispatch_loop);
}

static bool s_wait_for_terminated_state(void *user_data) {
    struct aws_dispatch_loop *dispatch_loop = user_data;

    return dispatch_loop->synced_data.execution_state == AWS_DLES_TERMINATED;
}

static void s_complete_destroy(struct aws_event_loop *event_loop) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP, "id=%p: Completing destruction of Dispatch Queue Event Loop", (void *)event_loop);
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;

    // This would be deadlock
    AWS_FATAL_ASSERT(!aws_event_loop_thread_is_callers_thread(event_loop));

    /*
     * This is the release of the initial ref count of 1 that the event loop was created with.
     */
    s_dispatch_loop_release(dispatch_loop);

    s_lock_synced_data(dispatch_loop);
    aws_condition_variable_wait_pred(
        &dispatch_loop->synced_data.signal,
        &dispatch_loop->synced_data.synced_data_lock,
        s_wait_for_terminated_state,
        dispatch_loop);
    s_unlock_synced_data(dispatch_loop);

    /*
     * There are no more references to the dispatch loop anywhere.  Purge any remaining cross thread tasks.
     */
    s_dispatch_queue_purge_cross_thread_tasks(dispatch_loop);

    /*
     * We know that all scheduling entries have cleaned up.  We can destroy ourselves now.  Upon return, the caller
     * is guaranteed that all memory related to the event loop has been released,
     */
    s_dispatch_event_loop_final_destroy(event_loop);
}

static int s_wait_for_stop_completion(struct aws_event_loop *event_loop) {
    (void)event_loop;
    /*
     * This is typically called as part of the destroy process to merge running threads during cleanup. The nature
     * of dispatch queue and Apple handling cleanup using its own reference counting system only requires us to
     * drop all references to the dispatch queue and to leave it in a resumed state with no further blocks
     * scheduled to run.
     *
     * We do not call `stop()` on the dispatch loop because a suspended dispatch queue retains a
     * refcount and Apple will not release the dispatch loop.
     */

    return AWS_OP_SUCCESS;
}

static void s_try_schedule_new_iteration(struct aws_dispatch_loop *dispatch_loop, uint64_t timestamp);

/*
 * Called to resume a suspended dispatch queue.
 */
static int s_run(struct aws_event_loop *event_loop) {
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;

    s_lock_synced_data(dispatch_loop);
    if (dispatch_loop->synced_data.execution_state == AWS_DLES_SUSPENDED) {
        AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Starting event-loop thread.", (void *)event_loop);
        dispatch_loop->synced_data.execution_state = AWS_DLES_RUNNING;
        dispatch_resume(dispatch_loop->dispatch_queue);
        s_try_schedule_new_iteration(dispatch_loop, 0);
    }
    s_unlock_synced_data(dispatch_loop);

    return AWS_OP_SUCCESS;
}

/*
 * Called to suspend dispatch queue
 */
static int s_stop(struct aws_event_loop *event_loop) {
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;

    s_lock_synced_data(dispatch_loop);
    if (dispatch_loop->synced_data.execution_state == AWS_DLES_RUNNING) {
        dispatch_loop->synced_data.execution_state = AWS_DLES_SUSPENDED;
        AWS_LOGF_INFO(
            AWS_LS_IO_EVENT_LOOP, "id=%p: Suspending event loop's dispatch queue thread.", (void *)event_loop);

        /*
         * Suspend will increase the Apple's refcount on the dispatch queue. For Apple to fully release the dispatch
         * queue, `dispatch_resume()` must be called on the dispatch queue to release the acquired refcount. Manually
         * decreffing the dispatch queue will result in undetermined behavior.
         */
        dispatch_suspend(dispatch_loop->dispatch_queue);
    }
    s_unlock_synced_data(dispatch_loop);

    return AWS_OP_SUCCESS;
}

/*
 * This function is scheduled as a block to run on Apple's dispatch queue. It will only ever be executed on an Apple
 * dispatch queue and upon completion, will determine whether or not to schedule another iteration of itself on the
 * Apple dispatch queue.
 */
static void s_run_iteration(void *service_entry) {
    struct scheduled_iteration_entry *entry = service_entry;
    struct aws_dispatch_loop *dispatch_loop = entry->dispatch_loop;

    s_lock_synced_data(dispatch_loop);

    AWS_FATAL_ASSERT(aws_linked_list_node_is_in_list(&entry->scheduled_entry_node));
    aws_linked_list_remove(&entry->scheduled_entry_node);

    /*
     * If we're shutting down, then don't do anything.  The destroy task handles purging and canceling tasks.
     *
     * Note that is possible race-wise to end up with execution_state being SUSPENDED here.  In that case, just run
     * normally.
     */
    if (entry->dispatch_loop->synced_data.execution_state == AWS_DLES_SHUTTING_DOWN) {
        goto done;
    }

    dispatch_loop->synced_data.current_thread_id = aws_thread_current_thread_id();
    dispatch_loop->synced_data.is_executing = true;

    // swap the cross-thread tasks into task-local data
    struct aws_linked_list local_cross_thread_tasks;
    aws_linked_list_init(&local_cross_thread_tasks);
    aws_linked_list_swap_contents(&dispatch_loop->synced_data.cross_thread_tasks, &local_cross_thread_tasks);

    s_unlock_synced_data(dispatch_loop);

    // run the full iteration here: local cross-thread tasks
    while (!aws_linked_list_empty(&local_cross_thread_tasks)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&local_cross_thread_tasks);
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);

        /*
         * Timestamp 0 is used to denote "now" tasks
         *
         * Because is_executing is true, no additional entries will be scheduled by these invocations.
         */
        if (task->timestamp == 0) {
            aws_task_scheduler_schedule_now(&dispatch_loop->scheduler, task);
        } else {
            aws_task_scheduler_schedule_future(&dispatch_loop->scheduler, task, task->timestamp);
        }
    }

    aws_event_loop_register_tick_start(dispatch_loop->base_loop);
    // run all scheduled tasks
    uint64_t now_ns = 0;
    aws_event_loop_current_clock_time(dispatch_loop->base_loop, &now_ns);
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: running scheduled tasks.", (void *)dispatch_loop->base_loop);
    aws_task_scheduler_run_all(&dispatch_loop->scheduler, now_ns);
    aws_event_loop_register_tick_end(dispatch_loop->base_loop);

    /* end of iteration cleanup and rescheduling */

    s_lock_synced_data(dispatch_loop);

    dispatch_loop->synced_data.is_executing = false;

    bool should_schedule = false;
    uint64_t should_schedule_at_time = 0;
    /*
     * We first check if there were any cross thread tasks scheduled during the execution of the current
     * iteration. If there were, we schedule a new iteration to execute immediately during which cross thread tasks
     * will be migrated into the dispatch_loop->scheduler.
     */
    if (!aws_linked_list_empty(&dispatch_loop->synced_data.cross_thread_tasks)) {
        should_schedule = true;
    }
    /*
     * If we are not scheduling a new iteration for immediate executuion, we check whether there are any tasks scheduled
     * to execute now or in the future and scheudle the next iteration using that time.
     */
    else if (aws_task_scheduler_has_tasks(&dispatch_loop->scheduler, &should_schedule_at_time)) {
        should_schedule = true;
    }

    if (should_schedule) {
        s_try_schedule_new_iteration(dispatch_loop, should_schedule_at_time);
    }

done:

    s_unlock_synced_data(dispatch_loop);

    /* destroy the completed service entry. */
    s_scheduled_iteration_entry_destroy(entry);
}

/**
 * Helper function to check if another scheduled iteration already exists that will handle our needs.
 *
 * The function should be wrapped with the synced_data_lock to safely access the scheduled_iterations list
 */
static bool s_should_schedule_iteration(
    struct aws_linked_list *scheduled_iterations,
    uint64_t proposed_iteration_time) {
    if (aws_linked_list_empty(scheduled_iterations)) {
        return true;
    }

    struct aws_linked_list_node *entry_node = aws_linked_list_front(scheduled_iterations);
    AWS_FATAL_ASSERT(entry_node != NULL);
    struct scheduled_iteration_entry *entry =
        AWS_CONTAINER_OF(entry_node, struct scheduled_iteration_entry, scheduled_entry_node);
    AWS_FATAL_ASSERT(entry != NULL);

    /* is the next scheduled iteration later than what we require? */
    return entry->timestamp > proposed_iteration_time;
}

/**
 * Checks if a new iteration task needs to be scheduled, given a target timestamp. If so, submits an iteration task to
 * dispatch queue and registers the pending execution in the event loop's list of scheduled_services.
 *
 * If timestamp == 0, the function will always schedule a new iteration as long as the event loop is not suspended or
 * being destroyed.
 *
 * This function should be wrapped with the synced_data_lock as it reads and writes to and from
 * aws_dispatch_loop->sycned_data
 */
static void s_try_schedule_new_iteration(struct aws_dispatch_loop *dispatch_loop, uint64_t timestamp) {
    if (dispatch_loop->synced_data.execution_state != AWS_DLES_RUNNING || dispatch_loop->synced_data.is_executing) {
        return;
    }

    /**
     * Apple dispatch queue uses automatic reference counting (ARC). If an iteration is scheduled to run in the future,
     * the dispatch queue will persist until it is executed. Scheduling a block far into the future will keep the
     * dispatch queue alive unnecessarily long, which blocks event loop group shutdown from completion.
     * To mitigate this, we ensure an iteration is scheduled no longer than
     * AWS_DISPATCH_QUEUE_MAX_FUTURE_SERVICE_INTERVAL second in the future.
     */
    uint64_t now_ns = 0;
    aws_event_loop_current_clock_time(dispatch_loop->base_loop, &now_ns);
    uint64_t delta = timestamp > now_ns ? timestamp - now_ns : 0;
    delta = aws_min_u64(delta, AWS_DISPATCH_QUEUE_MAX_FUTURE_SERVICE_INTERVAL);
    uint64_t clamped_timestamp = now_ns + delta;

    if (!s_should_schedule_iteration(&dispatch_loop->synced_data.scheduled_iterations, clamped_timestamp)) {
        return;
    }

    struct scheduled_iteration_entry *entry = s_scheduled_iteration_entry_new(dispatch_loop, clamped_timestamp);
    aws_linked_list_push_front(&dispatch_loop->synced_data.scheduled_iterations, &entry->scheduled_entry_node);

    if (delta == 0) {
        /*
         * If the timestamp was set to execute immediately or in the past we schedule `s_run_iteration()` to run
         * immediately using `dispatch_async_f()` which schedules a block to run on the dispatch queue in a FIFO order.
         */
        dispatch_async_f(dispatch_loop->dispatch_queue, entry, s_run_iteration);
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP, "id=%p: Scheduling run iteration on event loop.", (void *)dispatch_loop->base_loop);
    } else {
        /*
         * If the timestamp is set to execute sometime in the future, we clamp the time based on a maximum delta,
         * convert the time to the format dispatch queue expects, and then schedule `s_run_iteration()` to run in the
         * future using `dispatch_after_f()`. `dispatch_after_f()` does not immediately place the block onto the
         * dispatch queue but instead obtains a refcount of Apple's dispatch queue and then schedules onto it at the
         * requested time. Any blocks scheduled using `dispatch_async_f()` or `dispatch_after_f()` with a closer
         * dispatch time will be placed on the dispatch queue and execute in order.
         */
        dispatch_time_t when = dispatch_walltime(DISPATCH_WALLTIME_NOW, delta);
        dispatch_after_f(when, dispatch_loop->dispatch_queue, entry, s_run_iteration);
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: Scheduling future run iteration on event loop with next occurring in %llu ns.",
            (void *)dispatch_loop->base_loop,
            delta);
    }
}

static void s_schedule_task_common(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;
    task->timestamp = run_at_nanos;

    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: Scheduling %s task %p cross-thread for timestamp %llu",
        (void *)event_loop,
        task->type_tag,
        (void *)task,
        (unsigned long long)run_at_nanos);

    s_lock_synced_data(dispatch_loop);
    /*
     * As we dont have sustained control of a specific thread when using Apple's dispatch queue. All tasks are treated
     * as cross thread tasks that will be added to the aws_dispatch_loop's task scheduler in `s_run_iteration()`.
     */
    aws_linked_list_push_back(&dispatch_loop->synced_data.cross_thread_tasks, &task->node);

    /*
     * `s_try_schedule_new_iteration()` will determine whether the addition of this task will require a new
     * scheduled_iteration_entry needs to be scheduled on the dispatch queue.
     */
    s_try_schedule_new_iteration(dispatch_loop, run_at_nanos);

    s_unlock_synced_data(dispatch_loop);
}

static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task) {
    s_schedule_task_common(event_loop, task, 0 /* zero denotes "now" task */);
}

static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    s_schedule_task_common(event_loop, task, run_at_nanos);
}

static void s_cancel_task(struct aws_event_loop *event_loop, struct aws_task *task) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP, "id=%p: cancelling %s task %p", (void *)event_loop, task->type_tag, (void *)task);
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;

    /* First we move all cross thread tasks into the scheduler in case the task to be cancelled hasn't moved yet. */
    struct aws_linked_list local_cross_thread_tasks;
    aws_linked_list_init(&local_cross_thread_tasks);
    s_lock_synced_data(dispatch_loop);
    aws_linked_list_swap_contents(&dispatch_loop->synced_data.cross_thread_tasks, &local_cross_thread_tasks);
    s_unlock_synced_data(dispatch_loop);
    while (!aws_linked_list_empty(&local_cross_thread_tasks)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&local_cross_thread_tasks);
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);

        /* Timestamp 0 is used to denote "now" tasks */
        if (task->timestamp == 0) {
            aws_task_scheduler_schedule_now(&dispatch_loop->scheduler, task);
        } else {
            aws_task_scheduler_schedule_future(&dispatch_loop->scheduler, task, task->timestamp);
        }
    }

    /* Then we attempt to cancel the task. */
    aws_task_scheduler_cancel_task(&dispatch_loop->scheduler, task);
}

/*
 * We use this to obtain a direct pointer to the underlying dispatch queue. This is required to perform various
 * operations in the socket, socket handler, and probably anything else that requires use of Apple API needing a
 * dispatch queue.
 */
static int s_connect_to_io_completion_port(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    AWS_PRECONDITION(handle->set_queue);
    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: subscribing to events on handle %p",
        (void *)event_loop,
        (void *)handle->data.handle);

    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;
    handle->set_queue(handle, dispatch_loop->dispatch_queue);

    return AWS_OP_SUCCESS;
}

/*
 * Because dispatch queue is async we may need to acquire a refcount of the parent event loop group to prevent
 * the event loop or dispatch loop from being cleaned out from underneath something that needs it. We expose the
 * base elg so anything that needs to insure the event loops and dispatch loops don't get prematurely cleaned can
 * hold a refcount.
 */
static void *s_get_base_event_loop_group(struct aws_event_loop *event_loop) {
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;
    return dispatch_loop->base_elg;
}

/*
 * We use aws_thread_id_equal with syched_data.current_thread_id and synced_data.is_executing to determine
 * if operation is being executed on the same dispatch queue thread.
 */
static bool s_is_on_callers_thread(struct aws_event_loop *event_loop) {
    struct aws_dispatch_loop *dispatch_queue = event_loop->impl_data;
    s_lock_synced_data(dispatch_queue);
    bool result =
        dispatch_queue->synced_data.is_executing &&
        aws_thread_thread_id_equal(dispatch_queue->synced_data.current_thread_id, aws_thread_current_thread_id());
    s_unlock_synced_data(dispatch_queue);
    return result;
}
