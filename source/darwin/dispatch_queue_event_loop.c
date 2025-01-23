/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/event_loop.h>
#include <aws/io/private/event_loop_impl.h>

#include <aws/common/atomics.h>
#include <aws/common/clock.h>
#include <aws/common/mutex.h>
#include <aws/common/rw_lock.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/uuid.h>

#include <aws/io/logging.h>

#include <unistd.h>

#include "./dispatch_queue_event_loop_private.h" // private header
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

/**
 * DISPATCH QUEUE
 *
 * Event loop is responsible for processing events and tasks by launching an execution loop on a single thread. Each
 * iteration of this loop performs three primary jobs:
 * 1. Process I/O events.
 * 2. Process cross-thread tasks.
 * 3. Execute all runnable tasks.
 *
 * Apple Dispatch queues are FIFO queues to which the application can submit tasks in the form of block objects, and the
 * block objects will be executed on a system defined thread pool. Instead of executing the loop on a single thread, we
 * tried to recurrently run a single iteration of the execution loop as a dispatch queue block object.
 * aws-c-io library use a sequential dispatch queue to make sure the tasks scheduled on the same dispatch queue are
 * executed in a strict execution order, though the tasks might be distributed on different threads in the thread pool.
 *
 * Data Structures ******
 * `dispatch_loop_context`: Context for each execution iteration
 * `scheduled_service_entry`: Each entry maps to each iteration we scheduled on system dispatch queue. As we lost
 * control of the submitted block on the system dispatch queue, the entry is what we used to track the context and user
 * data.
 * `dispatch_loop`: Implementation of the event loop for dispatch queue.
 *
 * Functions ************
 * `s_run_iteration`: The function execute on each single iteration
 * `begin_iteration`: Decide if we should run the iteration
 * `end_iteration`: Clean up the related resource and determine if we should schedule next iteration
 *
 */

/* The dispatch_scheduling_state holds required information to schedule a "block" on the dispatch_queue. */
struct dispatch_scheduling_state {

    /**
     * The lock is used to protect the scheduled_services list cross threads. It should be hold while we add/remove
     * entries from the scheduled_services list.
     */
    struct aws_mutex services_lock;
    /**
     * priority queue of <scheduled_service_entry> in sorted order by timestamp. Each scheduled_service_entry represents
     * a block ALREADY SCHEDULED on apple dispatch queue.
     *
     * When we go to schedule a new iteration, we check here first to see if our scheduling attempt is redundant.
     */
    struct aws_priority_queue scheduled_services;
};

/* Internal ref-counted dispatch loop context to processing Apple Dispatch Queue Resources */
struct dispatch_loop_context {
    /**
     * The conetxt lock is a read-write lock used to protect dispatch_loop.
     * The write lock will be acquired when we make changes to dispatch_loop. And the read lock will be acquired
     * when we need verify if the dispatch_loop is alive. This makes sure that the dispatch_loop will not be destroyed
     * from other thread while we are using it.
     */
    struct aws_rw_lock lock;
    struct dispatch_loop *io_dispatch_loop;
    struct dispatch_scheduling_state scheduling_state;
    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;
};

/**
 * The data structure used to track the dispatch queue execution iteration (block). Each entry associated to an
 * iteration scheduled on Apple Dispatch Queue.
 */
struct scheduled_service_entry {
    struct aws_allocator *allocator;
    uint64_t timestamp;
    struct aws_priority_queue_node priority_queue_node;
    struct dispatch_loop_context *dispatch_queue_context;
};

/** Help functions to track context ref-count */

static void *s_acquire_dispatch_loop_context(struct dispatch_loop_context *context) {
    return aws_ref_count_acquire(&context->ref_count);
}

static size_t s_release_dispatch_loop_context(struct dispatch_loop_context *context) {
    return aws_ref_count_release(&context->ref_count);
}

/** Help functions to lock status */
static int s_rlock_dispatch_loop_context(struct dispatch_loop_context *context) {
    return aws_rw_lock_rlock(&context->lock);
}

static int s_runlock_dispatch_loop_context(struct dispatch_loop_context *context) {
    return aws_rw_lock_runlock(&context->lock);
}

static int s_wlock_dispatch_loop_context(struct dispatch_loop_context *context) {
    return aws_rw_lock_wlock(&context->lock);
}

static int s_wunlock_dispatch_loop_context(struct dispatch_loop_context *context) {
    return aws_rw_lock_wunlock(&context->lock);
}

static int s_lock_cross_thread_data(struct dispatch_loop *loop) {
    return aws_mutex_lock(&loop->synced_data.lock);
}

static int s_unlock_cross_thread_data(struct dispatch_loop *loop) {
    return aws_mutex_unlock(&loop->synced_data.lock);
}

static int s_lock_service_entries(struct dispatch_loop_context *context) {
    return aws_mutex_lock(&context->scheduling_state.services_lock);
}

static int s_unlock_service_entries(struct dispatch_loop_context *context) {
    return aws_mutex_unlock(&context->scheduling_state.services_lock);
}

// Not sure why use 7 as the default queue size. Just follow what we used in task_scheduler.c
static const size_t DEFAULT_QUEUE_SIZE = 7;
static int s_compare_timestamps(const void *a, const void *b) {
    uint64_t a_time = (*(struct scheduled_service_entry **)a)->timestamp;
    uint64_t b_time = (*(struct scheduled_service_entry **)b)->timestamp;
    return a_time > b_time; /* min-heap */
}

static struct scheduled_service_entry *s_scheduled_service_entry_new(
    struct dispatch_loop_context *context,
    uint64_t timestamp) {
    struct scheduled_service_entry *entry =
        aws_mem_calloc(context->allocator, 1, sizeof(struct scheduled_service_entry));

    entry->allocator = context->allocator;
    entry->timestamp = timestamp;
    entry->dispatch_queue_context = s_acquire_dispatch_loop_context(context);
    aws_priority_queue_node_init(&entry->priority_queue_node);

    return entry;
}

/**
 * The function should be wrapped around scheduling_status->lock
 */
static void s_scheduled_service_entry_destroy(
    struct dispatch_scheduling_state scheduling_status,
    struct scheduled_service_entry *entry) {
    if (aws_priority_queue_node_is_in_queue(&entry->priority_queue_node)) {
        aws_priority_queue_remove(&scheduling_status.scheduled_services, entry, &entry->priority_queue_node);
    }
    struct dispatch_loop_context *dispatch_queue_context = entry->dispatch_queue_context;
    s_release_dispatch_loop_context(dispatch_queue_context);

    aws_mem_release(entry->allocator, entry);
}

/**
 * Helper function to check if another scheduled iteration already exists that will handle our needs
 *
 * The function should be wrapped with the following locks:
 *      scheduled_services lock: To safely access the scheduled_services list
 */
static bool s_should_schedule_iteration(
    struct aws_priority_queue *scheduled_services,
    uint64_t proposed_iteration_time) {
    if (aws_priority_queue_size(scheduled_services) == 0) {
        return true;
    }

    struct scheduled_service_entry **entry = NULL;
    aws_priority_queue_top(scheduled_services, (void **)&entry);

    // is the next scheduled iteration later than what we require?
    return (*entry)->timestamp > proposed_iteration_time;
}

/* On dispatch event loop context ref-count reaches 0 */
static void s_dispatch_loop_context_destroy(void *context) {
    struct dispatch_loop_context *dispatch_loop_context = context;
    aws_priority_queue_clean_up(&dispatch_loop_context->scheduling_state.scheduled_services);
    aws_mutex_clean_up(&dispatch_loop_context->scheduling_state.services_lock);
    aws_rw_lock_clean_up(&dispatch_loop_context->lock);
    aws_mem_release(dispatch_loop_context->allocator, dispatch_loop_context);
}

/* On dispatch event loop ref-count reaches 0 */
static void s_dispatch_event_loop_destroy(void *context) {
    // release dispatch loop
    struct aws_event_loop *event_loop = context;
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    if (dispatch_loop->context) {
        // Null out the dispatch queue loop context
        s_wlock_dispatch_loop_context(dispatch_loop->context);
        dispatch_loop->context->io_dispatch_loop = NULL;
        s_wunlock_dispatch_loop_context(dispatch_loop->context);
        s_release_dispatch_loop_context(dispatch_loop->context);
    }

    // The scheduler should be cleaned up and zero out in event loop destroy task. Double check here in case the destroy
    // function is not called or initialize was failed.
    if (aws_task_scheduler_is_valid(&dispatch_loop->scheduler)) {
        aws_task_scheduler_clean_up(&dispatch_loop->scheduler);
    }

    aws_mutex_clean_up(&dispatch_loop->synced_data.lock);
    aws_mem_release(dispatch_loop->allocator, dispatch_loop);
    aws_event_loop_clean_up_base(event_loop);
    aws_mem_release(event_loop->alloc, event_loop);

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
    dispatch_loop->allocator = alloc;
    loop->impl_data = dispatch_loop;
    dispatch_loop->base_loop = loop;

    char dispatch_queue_id[AWS_IO_APPLE_DISPATCH_QUEUE_ID_LENGTH] = {0};
    s_get_unique_dispatch_queue_id(dispatch_queue_id);

    dispatch_loop->dispatch_queue = dispatch_queue_create(dispatch_queue_id, DISPATCH_QUEUE_SERIAL);
    if (!dispatch_loop->dispatch_queue) {
        AWS_LOGF_FATAL(AWS_LS_IO_EVENT_LOOP, "id=%p: Failed to create dispatch queue.", (void *)loop);
        aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        goto clean_up;
    }

    AWS_LOGF_INFO(
        AWS_LS_IO_EVENT_LOOP, "id=%p: Apple dispatch queue created with id: %s", (void *)loop, dispatch_queue_id);

    aws_mutex_init(&dispatch_loop->synced_data.lock);
    dispatch_loop->synced_data.is_executing = false;

    int err = aws_task_scheduler_init(&dispatch_loop->scheduler, alloc);
    if (err) {
        AWS_LOGF_ERROR(AWS_LS_IO_EVENT_LOOP, "id=%p: Initializing task scheduler failed", (void *)loop);
        goto clean_up;
    }

    aws_linked_list_init(&dispatch_loop->synced_data.cross_thread_tasks);

    struct dispatch_loop_context *context = aws_mem_calloc(alloc, 1, sizeof(struct dispatch_loop_context));

    if (aws_priority_queue_init_dynamic(
            &context->scheduling_state.scheduled_services,
            alloc,
            DEFAULT_QUEUE_SIZE,
            sizeof(struct scheduled_service_entry *),
            &s_compare_timestamps)) {
        AWS_LOGF_INFO(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: priority queue creation failed, clean up the context: %s",
            (void *)loop,
            dispatch_queue_id);
        aws_mem_release(alloc, context);
        goto clean_up;
    };

    aws_ref_count_init(&context->ref_count, context, s_dispatch_loop_context_destroy);
    context->allocator = alloc;

    aws_mutex_init(&context->scheduling_state.services_lock);

    aws_rw_lock_init(&context->lock);
    context->io_dispatch_loop = dispatch_loop;
    dispatch_loop->context = context;

    loop->vtable = &s_vtable;

    return loop;

clean_up:
    if (dispatch_loop) {
        if (dispatch_loop->dispatch_queue) {
            dispatch_release(dispatch_loop->dispatch_queue);
        }
        s_dispatch_event_loop_destroy(loop);
    } else {
        aws_mem_release(alloc, loop);
    }
    return NULL;
}

static void s_dispatch_queue_destroy_task(void *context) {
    struct dispatch_loop *dispatch_loop = context;
    s_rlock_dispatch_loop_context(dispatch_loop->context);

    s_lock_cross_thread_data(dispatch_loop);
    dispatch_loop->synced_data.suspended = true;
    dispatch_loop->synced_data.current_thread_id = aws_thread_current_thread_id();
    dispatch_loop->synced_data.is_executing = true;

    // swap the cross-thread tasks into task-local data
    struct aws_linked_list local_cross_thread_tasks;
    aws_linked_list_init(&local_cross_thread_tasks);
    aws_linked_list_swap_contents(&dispatch_loop->synced_data.cross_thread_tasks, &local_cross_thread_tasks);
    s_unlock_cross_thread_data(dispatch_loop);

    aws_task_scheduler_clean_up(&dispatch_loop->scheduler); /* Tasks in scheduler get cancelled*/
    while (!aws_linked_list_empty(&local_cross_thread_tasks)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&local_cross_thread_tasks);
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
        task->fn(task, task->arg, AWS_TASK_STATUS_CANCELED);
    }

    s_lock_cross_thread_data(dispatch_loop);
    dispatch_loop->synced_data.is_executing = false;
    s_unlock_cross_thread_data(dispatch_loop);

    s_runlock_dispatch_loop_context(dispatch_loop->context);
    s_dispatch_event_loop_destroy(dispatch_loop->base_loop);
}

static void s_destroy(struct aws_event_loop *event_loop) {
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Destroying Dispatch Queue Event Loop", (void *)event_loop);
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

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

static void s_try_schedule_new_iteration(struct dispatch_loop_context *loop, uint64_t timestamp);

static int s_run(struct aws_event_loop *event_loop) {
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    s_lock_cross_thread_data(dispatch_loop);
    if (dispatch_loop->synced_data.suspended) {
        AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Starting event-loop thread.", (void *)event_loop);
        dispatch_resume(dispatch_loop->dispatch_queue);
        dispatch_loop->synced_data.suspended = false;
        s_rlock_dispatch_loop_context(dispatch_loop->context);
        s_lock_service_entries(dispatch_loop->context);
        s_try_schedule_new_iteration(dispatch_loop->context, 0);
        s_unlock_service_entries(dispatch_loop->context);
        s_runlock_dispatch_loop_context(dispatch_loop->context);
    }
    s_unlock_cross_thread_data(dispatch_loop);

    return AWS_OP_SUCCESS;
}

static int s_stop(struct aws_event_loop *event_loop) {
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    s_lock_cross_thread_data(dispatch_loop);
    if (!dispatch_loop->synced_data.suspended) {
        dispatch_loop->synced_data.suspended = true;
        AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Stopping event-loop thread.", (void *)event_loop);
        /* Suspend will increase the dispatch reference count. It is required to call resume before
         * releasing the dispatch queue. */
        dispatch_suspend(dispatch_loop->dispatch_queue);
    }
    s_unlock_cross_thread_data(dispatch_loop);

    return AWS_OP_SUCCESS;
}

/**
 * The function decides if we should run this iteration.
 * Returns true if we should execute an iteration, false otherwise
 *
 * The function should be wrapped with dispatch_loop->context.lock to retain the dispatch loop while running.
 */
static bool begin_iteration(struct scheduled_service_entry *entry) {
    struct dispatch_loop *dispatch_loop = entry->dispatch_queue_context->io_dispatch_loop;

    if (!dispatch_loop) {
        return false;
    }
    return true;
}

/**
 * Clean up the related resource and determine if we should schedule next iteration.
 * The function should be wrapped with dispatch_loop->context.lock to retain the dispatch loop while running.
 * */
static void end_iteration(struct scheduled_service_entry *entry) {

    struct dispatch_loop_context *context = entry->dispatch_queue_context;
    struct dispatch_loop *dispatch_loop = context->io_dispatch_loop;

    s_lock_cross_thread_data(dispatch_loop);
    dispatch_loop->synced_data.is_executing = false;

    // Remove the node before do scheduling so we didnt consider the entry itself
    s_lock_service_entries(context);
    aws_priority_queue_remove(&context->scheduling_state.scheduled_services, entry, &entry->priority_queue_node);
    s_unlock_service_entries(context);

    bool should_schedule = false;
    uint64_t should_schedule_at_time = 0;
    if (!aws_linked_list_empty(&dispatch_loop->synced_data.cross_thread_tasks)) {
        should_schedule = true;
    }
    /* we already know there are tasks to be scheduled, we just want the next run time. */
    else if (aws_task_scheduler_has_tasks(&dispatch_loop->scheduler, &should_schedule_at_time)) {
        should_schedule = true;
    }

    if (should_schedule) {
        s_lock_service_entries(context);
        s_try_schedule_new_iteration(context, should_schedule_at_time);
        s_unlock_service_entries(context);
    }

    s_unlock_cross_thread_data(dispatch_loop);
}

// Iteration function that scheduled and executed by the Dispatch Queue API
static void s_run_iteration(void *context) {
    struct scheduled_service_entry *entry = context;
    struct dispatch_loop_context *dispatch_queue_context = entry->dispatch_queue_context;
    s_acquire_dispatch_loop_context(dispatch_queue_context);
    s_rlock_dispatch_loop_context(dispatch_queue_context);

    if (!begin_iteration(entry)) {
        goto iteration_done;
    }

    struct dispatch_loop *dispatch_loop = entry->dispatch_queue_context->io_dispatch_loop;
    // swap the cross-thread tasks into task-local data
    struct aws_linked_list local_cross_thread_tasks;
    aws_linked_list_init(&local_cross_thread_tasks);
    s_lock_cross_thread_data(dispatch_loop);
    dispatch_loop->synced_data.current_thread_id = aws_thread_current_thread_id();
    dispatch_loop->synced_data.is_executing = true;
    aws_linked_list_swap_contents(&dispatch_loop->synced_data.cross_thread_tasks, &local_cross_thread_tasks);
    s_unlock_cross_thread_data(dispatch_loop);

    aws_event_loop_register_tick_start(dispatch_loop->base_loop);

    // run the full iteration here: local cross-thread tasks
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

    // run all scheduled tasks
    uint64_t now_ns = 0;
    aws_event_loop_current_clock_time(dispatch_loop->base_loop, &now_ns);
    aws_task_scheduler_run_all(&dispatch_loop->scheduler, now_ns);
    aws_event_loop_register_tick_end(dispatch_loop->base_loop);

    end_iteration(entry);

iteration_done:
    s_lock_service_entries(dispatch_queue_context);
    s_scheduled_service_entry_destroy(dispatch_queue_context->scheduling_state, entry);
    s_unlock_service_entries(dispatch_queue_context);
    s_runlock_dispatch_loop_context(dispatch_queue_context);
    s_release_dispatch_loop_context(dispatch_queue_context);
}

/**
 * Checks if a new iteration task needs to be scheduled, given a target timestamp. If so, submits an iteration task to
 * dispatch queue and registers the pending execution in the event loop's list of scheduled_services.
 *
 * If timestamp==0, the function will always schedule a new iteration as long as the event loop is not suspended.
 *
 * The function should be wrapped with the following locks:
 *      dispatch_loop->context->lock: To retain the dispatch loop
 *      dispatch_loop->synced_data.lock : To verify if the dispatch loop is suspended
 *      dispatch_loop_context->scheduling_state->services_lock: To modify the scheduled_services list
 */
static void s_try_schedule_new_iteration(struct dispatch_loop_context *dispatch_loop_context, uint64_t timestamp) {
    struct dispatch_loop *dispatch_loop = dispatch_loop_context->io_dispatch_loop;
    if (!dispatch_loop || dispatch_loop->synced_data.suspended) {
        return;
    }
    if (!s_should_schedule_iteration(&dispatch_loop_context->scheduling_state.scheduled_services, timestamp)) {
        return;
    }
    struct scheduled_service_entry *entry = s_scheduled_service_entry_new(dispatch_loop_context, timestamp);
    aws_priority_queue_push_ref(
        &dispatch_loop_context->scheduling_state.scheduled_services, entry, &entry->priority_queue_node);

    uint64_t now_ns = 0;
    aws_event_loop_current_clock_time(dispatch_loop->base_loop, &now_ns);
    uint64_t delta = timestamp > now_ns ? timestamp - now_ns : 0;
    /**
     * The Apple dispatch queue uses automatic reference counting (ARC). If an iteration remains in the queue, it will
     * persist until it is executed. Scheduling a block far into the future can keep the dispatch queue alive
     * unnecessarily, even if the app has shutdown. To avoid this, Ensure an iteration is scheduled within a
     * 1-second interval to prevent it from remaining in the Apple dispatch queue indefinitely.
     */
    delta = aws_min_u64(delta, AWS_TIMESTAMP_NANOS);

    if (delta == 0) {
        // dispatch_after_f(0 , ...) is equivclient to dispatch_async_f(...) functionality wise, while
        // dispatch_after_f(0 , ...) is not as optimal as dispatch_async_f(...)
        // https://developer.apple.com/documentation/dispatch/1452878-dispatch_after_f
        dispatch_async_f(dispatch_loop->dispatch_queue, entry, s_run_iteration);
    } else {
        dispatch_after_f(delta, dispatch_loop->dispatch_queue, entry, s_run_iteration);
    }
}

static void s_schedule_task_common(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    struct dispatch_loop *dispatch_loop = event_loop->impl_data;

    s_rlock_dispatch_loop_context(dispatch_loop->context);
    if (dispatch_loop->context->io_dispatch_loop == NULL) {
        goto schedule_task_common_cleanup;
    }
    s_lock_cross_thread_data(dispatch_loop);
    task->timestamp = run_at_nanos;

    bool was_empty = aws_linked_list_empty(&dispatch_loop->synced_data.cross_thread_tasks);
    // As we dont have control to dispatch queue thread, all tasks are treated as cross thread tasks
    aws_linked_list_push_back(&dispatch_loop->synced_data.cross_thread_tasks, &task->node);

    /**
     * To avoid explicit scheduling event loop iterations, the actual "iteration scheduling" should happened at the end
     * of each iteration run. (The scheduling will happened in function `void end_iteration(struct
     * scheduled_service_entry *entry)`). Therefore, as long as there is an executing iteration, we can guaranteed that
     * the tasks will be scheduled.
     *
     * `was_empty` is used for a quick validation. If the `cross_thread_tasks` is not empty, we must have a running
     * iteration that is processing the `cross_thread_tasks`.
     */

    bool should_schedule = false;
    if (was_empty || !dispatch_loop->synced_data.is_executing) {
        /** If there is no currently running iteration, then we check if we have already scheduled an iteration
         * scheduled before this task's run time. */
        s_lock_service_entries(dispatch_loop->context);
        should_schedule =
            s_should_schedule_iteration(&dispatch_loop->context->scheduling_state.scheduled_services, run_at_nanos);
        s_unlock_service_entries(dispatch_loop->context);
    }

    // If there is no scheduled iteration, start one right now to process the `cross_thread_task`.
    if (should_schedule) {
        s_lock_service_entries(dispatch_loop->context);
        s_try_schedule_new_iteration(dispatch_loop->context, 0);
        s_unlock_service_entries(dispatch_loop->context);
    }

    s_unlock_cross_thread_data(dispatch_loop);
schedule_task_common_cleanup:
    s_runlock_dispatch_loop_context(dispatch_loop->context);
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
    s_lock_cross_thread_data(dispatch_queue);
    bool result =
        dispatch_queue->synced_data.is_executing &&
        aws_thread_thread_id_equal(dispatch_queue->synced_data.current_thread_id, aws_thread_current_thread_id());
    s_unlock_cross_thread_data(dispatch_queue);
    return result;
}
