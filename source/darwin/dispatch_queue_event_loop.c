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
 * Apple Dispatch queues can be given a concurrent or serial attribute on creation. We use Serial Dispatch Queues that
 * are FIFO queues to which the application can submit tasks in the form of block objects. The block objects will be
 * executed on a system defined thread pool. Instead of executing the loop on a single thread, we recurrently run a
 * single iteration of the execution loop as a dispatch queue block object. aws-c-io library uses a serial dispatch
 * queue to make sure the tasks scheduled on the event loop task scheduler are executed in the correct order.
 *
 * Data Structures ******
 * `dispatch_loop_context`: Context for each execution iteration
 * `scheudled_iteration_entry`: Each entry maps to an iteration we scheduled on Apple's dispatch queue. As we lose
 * control of the submitted block once transferred to Apple's dispatch queue, this entry acquires a refcount on the
 * dispatch_loop_context which checks whether it has a non-NULL dispatch_loop to run on.
 * `dispatch_loop`: Implementation of the event loop for dispatch queue.
 *
 * Functions ************
 * `s_run_iteration`: This function executes scheduled tasks
 * `s_end_iteration`: Clean up the related resource and determine if we should schedule next iteration
 *
 */

/* Holds required information to schedule a "block" on the dispatch_queue. */ // WIP DELETING
// struct dispatch_scheduling_state {

//     /**
//      * The lock is used to protect the scheduled_services list cross threads. It must be held when we add or remove
//      * scheudled_iteration_entry entries from the scheduled_services list.
//      */
//     struct aws_mutex schedule_services_lock;
//     /**
//      * priority queue of <scheudled_iteration_entry> in sorted order by timestamp. Each scheudled_iteration_entry
//      represents
//      * a block ALREADY SCHEDULED on apple dispatch queue.
//      *
//      * When we schedule a new run iteration, scheduled_services is checked to see if the scheduling attempt is
//      * redundant.
//      */
//     struct aws_priority_queue scheduled_services;
// };

/* Internal ref-counted dispatch loop context to processing Apple Dispatch Queue Resources */ // WIP DELETING
// struct dispatch_loop_context {
//     /**
//      * This is a read-write lock used to protect dispatch_loop.
//      * The write lock needs to be acquired when we make changes to dispatch_loop.
//      * The read lock needs to be acquired when we verify whether dispatch_loop is alive.
//      * This insures dispatch_loop will not be destroyed from other threads while we are using it.
//      */
//     struct aws_allocator *allocator;
//     struct aws_rw_lock dispatch_loop_context_lock;
//     struct aws_dispatch_loop *io_dispatch_loop;
//     // struct dispatch_scheduling_state scheduling_state; // WIP DELETING
//     struct aws_ref_count ref_count;
// };

/**
 * The data structure used to track the dispatch queue execution iteration (block). Each entry is associated with
 * an run iteration scheduled on Apple Dispatch Queue.
 */
struct scheudled_iteration_entry {
    struct aws_allocator *allocator;
    uint64_t timestamp;
    struct aws_priority_queue_node priority_queue_node;
    struct aws_dispatch_loop *dispatch_loop;
};

/** Help functions to track context ref-count */
// WIP DELETING
// static void *s_acquire_dispatch_loop_context(struct dispatch_loop_context *context) {
//     return aws_ref_count_acquire(&context->ref_count);
// }

// static size_t s_release_dispatch_loop_context(struct dispatch_loop_context *context) {
//     return aws_ref_count_release(&context->ref_count);
// }

/** Help functions to lock status */
/*
 * When multiple locks are used, they should always follow the same layerd ordering pattern.
 * Top level:    dispatch_loop_context_lock
 * Middle level: synced_data_lock
 * Bottom level: schedule_services_lock
 *
 * Adhering to this structure will help prevent a deadlock where two locks are attempting to
 * acquire the lock for each other from within themselves.
 */
// WIP DELETING
// static int s_rlock_dispatch_loop_context(struct dispatch_loop_context *context) {
//     return aws_rw_lock_rlock(&context->dispatch_loop_context_lock);
// }

// static int s_runlock_dispatch_loop_context(struct dispatch_loop_context *context) {
//     return aws_rw_lock_runlock(&context->dispatch_loop_context_lock);
// }

// static int s_wlock_dispatch_loop_context(struct dispatch_loop_context *context) {
//     return aws_rw_lock_wlock(&context->dispatch_loop_context_lock);
// }

// static int s_wunlock_dispatch_loop_context(struct dispatch_loop_context *context) {
//     return aws_rw_lock_wunlock(&context->dispatch_loop_context_lock);
// }

static int s_lock_synced_data(struct aws_dispatch_loop *loop) {
    return aws_mutex_lock(&loop->synced_data.synced_data_lock);
}

static int s_unlock_synced_data(struct aws_dispatch_loop *loop) {
    return aws_mutex_unlock(&loop->synced_data.synced_data_lock);
}

// WIP DELETING
// static int s_lock_service_entries(struct dispatch_loop_context *context) {
//     return aws_mutex_lock(&context->scheduling_state.schedule_services_lock);
// }

// static int s_unlock_service_entries(struct dispatch_loop_context *context) {
//     return aws_mutex_unlock(&context->scheduling_state.schedule_services_lock);
// }

// Not sure why use 7 as the default queue size. Just follow what we used in task_scheduler.c
static const size_t DEFAULT_QUEUE_SIZE = 7;
static int s_compare_timestamps(const void *a, const void *b) {
    uint64_t a_time = (*(struct scheudled_iteration_entry **)a)->timestamp;
    uint64_t b_time = (*(struct scheudled_iteration_entry **)b)->timestamp;
    return a_time > b_time; /* min-heap */
}

static struct scheudled_iteration_entry *s_scheudled_iteration_entry_new(
    struct aws_dispatch_loop *dispatch_loop,
    uint64_t timestamp) {
    struct scheudled_iteration_entry *entry =
        aws_mem_calloc(dispatch_loop->allocator, 1, sizeof(struct scheudled_iteration_entry));

    entry->allocator = dispatch_loop->allocator;
    entry->timestamp = timestamp;
    entry->dispatch_loop = dispatch_loop;
    aws_priority_queue_node_init(&entry->priority_queue_node);

    return entry;
}

/**
 * Helper function to check if another scheduled iteration already exists that will handle our needs
 *
 * The function should be wrapped with the synced_data_lock to safely access the scheduled_iterations list
 */
static bool s_should_schedule_iteration(
    struct aws_priority_queue *scheduled_iterations,
    uint64_t proposed_iteration_time) {
    if (aws_priority_queue_size(scheduled_iterations) == 0) {
        return true;
    }

    struct scheudled_iteration_entry **entry = NULL;
    aws_priority_queue_top(scheduled_iterations, (void **)&entry);

    // is the next scheduled iteration later than what we require?
    return (*entry)->timestamp > proposed_iteration_time;
}

/* Called when dispatch_loop_context ref-count reaches 0 */ // WIP DELETING
// static void s_dispatch_loop_context_destroy(void *context) {
//     struct dispatch_loop_context *dispatch_loop_context = context;
//     aws_priority_queue_clean_up(&dispatch_loop_context->scheduling_state.scheduled_services);
//     aws_mutex_clean_up(&dispatch_loop_context->scheduling_state.schedule_services_lock);
//     aws_rw_lock_clean_up(&dispatch_loop_context->dispatch_loop_context_lock);
//     aws_mem_release(dispatch_loop_context->allocator, dispatch_loop_context);
// }

// Manually called to destroy an aws_event_loop
static void s_dispatch_event_loop_destroy(struct aws_event_loop *event_loop) {
    // release dispatch loop
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;

    // The scheduler should be cleaned up and zeroed out in s_dispatch_queue_destroy_task.
    // Double-check here in case the destroy function is not called or event loop initialization failed.
    if (aws_task_scheduler_is_valid(&dispatch_loop->scheduler)) {
        aws_task_scheduler_clean_up(&dispatch_loop->scheduler);
    }

    aws_mutex_clean_up(&dispatch_loop->synced_data.synced_data_lock);
    aws_priority_queue_clean_up(&dispatch_loop->synced_data.scheduled_iterations);
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

    struct aws_dispatch_loop *dispatch_loop = NULL;
    struct aws_event_loop *loop = aws_mem_calloc(alloc, 1, sizeof(struct aws_event_loop));

    AWS_LOGF_DEBUG(AWS_LS_IO_EVENT_LOOP, "id=%p: Initializing dispatch_queue event-loop", (void *)loop);
    if (aws_event_loop_init_base(loop, alloc, options->clock)) {
        goto clean_up;
    }

    loop->vtable = &s_vtable;

    dispatch_loop = aws_mem_calloc(alloc, 1, sizeof(struct aws_dispatch_loop));
    dispatch_loop->allocator = alloc;
    loop->impl_data = dispatch_loop;
    dispatch_loop->base_loop = loop;

    char dispatch_queue_id[AWS_IO_APPLE_DISPATCH_QUEUE_ID_LENGTH] = {0};
    s_get_unique_dispatch_queue_id(dispatch_queue_id);

    /*
     * Apple API dispatch_queue_create returns a dispatch_queue_t. This cannot fail and will crash if it does.
     * A reference to the dispatch queue is retained and must be released explicitly with dispatch_release().
     */
    dispatch_loop->dispatch_queue = dispatch_queue_create(dispatch_queue_id, DISPATCH_QUEUE_SERIAL);

    /*
     * Suspend will increase the dispatch reference count.
     * A suspended dispatch queue must have dispatch_release() called on it for Apple to release the dispatch queue.
     * We suspend the newly created Apple dispatch queue here to conform with other event loop types. A new event loop
     * should start in a non-running state until run() is called.
     */
    dispatch_suspend(dispatch_loop->dispatch_queue);

    AWS_LOGF_INFO(
        AWS_LS_IO_EVENT_LOOP, "id=%p: Apple dispatch queue created with id: %s", (void *)loop, dispatch_queue_id);

    aws_mutex_init(&dispatch_loop->synced_data.synced_data_lock);

    /* The dispatch queue has no active blocks processing on it at this point. */
    dispatch_loop->synced_data.stopped = true;
    /* The dispatch queue is suspended at this point. */
    dispatch_loop->synced_data.suspended = true;
    dispatch_loop->synced_data.is_executing = false;

    if (aws_task_scheduler_init(&dispatch_loop->scheduler, alloc)) {
        AWS_LOGF_ERROR(AWS_LS_IO_EVENT_LOOP, "id=%p: Initialization of task scheduler failed", (void *)loop);
        goto clean_up;
    }

    aws_linked_list_init(&dispatch_loop->synced_data.cross_thread_tasks);
    if (aws_priority_queue_init_dynamic(
            &dispatch_loop->synced_data.scheduled_iterations,
            alloc,
            DEFAULT_QUEUE_SIZE,
            sizeof(struct scheudled_iteration_entry *),
            &s_compare_timestamps)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: Priority queue creation failed, cleaning up the dispatch queue: %s",
            (void *)loop,
            dispatch_queue_id);
        goto clean_up;
    };

    return loop;

clean_up:
    if (dispatch_loop) {
        if (dispatch_loop->dispatch_queue) {
            /* Apple API for releasing reference count on a dispatch object. */
            dispatch_release(dispatch_loop->dispatch_queue);
        }
        s_dispatch_event_loop_destroy(loop);
    } else {
        aws_mem_release(alloc, loop);
    }
    return NULL;
}

static void s_dispatch_queue_destroy_task(void *context) {
    struct aws_dispatch_loop *dispatch_loop = context;

    s_lock_synced_data(dispatch_loop);
    dispatch_loop->synced_data.is_destroying = true;
    dispatch_loop->synced_data.current_thread_id = aws_thread_current_thread_id();
    dispatch_loop->synced_data.is_executing = true;

    // swap the cross-thread tasks into task-local data
    struct aws_linked_list local_cross_thread_tasks;
    aws_linked_list_init(&local_cross_thread_tasks);
    aws_linked_list_swap_contents(&dispatch_loop->synced_data.cross_thread_tasks, &local_cross_thread_tasks);

    aws_task_scheduler_clean_up(&dispatch_loop->scheduler); /* Tasks in scheduler get cancelled */
    while (!aws_linked_list_empty(&local_cross_thread_tasks)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&local_cross_thread_tasks);
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
        task->fn(task, task->arg, AWS_TASK_STATUS_CANCELED);
    }

    // DEBUG WIP we need to iterate through the scheduled_iterations and set the service entry dispatch_loops to NULL
    // struct aws_linked_list *scheduled_iterations = *dispatch_loop->synced_data.scheduled_iterations.container;

    dispatch_loop->synced_data.is_executing = false;
    s_unlock_synced_data(dispatch_loop);

    s_dispatch_event_loop_destroy(dispatch_loop->base_loop);
}

static void s_destroy(struct aws_event_loop *event_loop) {
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Destroying Dispatch Queue Event Loop", (void *)event_loop);
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;

    /* make sure the loop is running so we can schedule a last task. */
    s_run(event_loop);

    /*
     * Schedules `s_dispatch_queue_destroy_task()` to run on the Apple dispatch queue of the event loop.
     *
     * Any block that is currently running or already scheduled on the dispatch queue will be completed before
     * `s_dispatch_queue_destroy_task()` block is executed.
     *
     * `s_dispatch_queue_destroy_task()` will cancel outstanding tasks and then run `s_dispatch_event_loop_destroy()`'
     *
     * It is possible that there are scheduled_iterations that are be queued to run s_run_iteration() up to 1 second
     * AFTER s_dispatch_queue_destroy_task() has executued.
     */
    dispatch_async_and_wait_f(dispatch_loop->dispatch_queue, dispatch_loop, s_dispatch_queue_destroy_task);

    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Releasing Dispatch Queue.", (void *)event_loop);
}

// DEBUG WIP what is this and do we need to do anything here to have parity with other event loops?
static int s_wait_for_stop_completion(struct aws_event_loop *event_loop) {
    (void)event_loop;

    return AWS_OP_SUCCESS;
}

static void s_try_schedule_new_iteration(struct aws_dispatch_loop *dispatch_loop, uint64_t timestamp);

/*
 * Called to resume a suspended dispatch queue.
 *
 * synched_data_lock held during check of synced_data.suspended and attempt to schedule a new iteration.
 */
static int s_run(struct aws_event_loop *event_loop) {
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;

    s_lock_synced_data(dispatch_loop);
    if (dispatch_loop->synced_data.suspended) {
        AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Starting event-loop thread.", (void *)event_loop);
        dispatch_resume(dispatch_loop->dispatch_queue);
        dispatch_loop->synced_data.suspended = false;
        s_try_schedule_new_iteration(dispatch_loop, 0);
    }
    s_unlock_synced_data(dispatch_loop);

    return AWS_OP_SUCCESS;
}

static int s_stop(struct aws_event_loop *event_loop) {
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;

    s_lock_synced_data(dispatch_loop);
    if (!dispatch_loop->synced_data.suspended) {
        dispatch_loop->synced_data.suspended = true;
        AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Stopping event-loop thread.", (void *)event_loop);

        /*
         * Suspend will increase the Apple's ref count on the dispatch queue by one. For Apple to fully release the
         * dispatch queue, it must be manually released to drop its ref count or dispatch_resume() must be called on the
         * dispatch queue to release the acquired ref count.
         */
        dispatch_suspend(dispatch_loop->dispatch_queue);
    }
    s_unlock_synced_data(dispatch_loop);

    return AWS_OP_SUCCESS;
}

/*
 * Clean up the related resources and determine if we should schedule next iteration.
 */
// static void s_end_iteration(struct scheudled_iteration_entry *entry) {

//     struct aws_dispatch_loop *dispatch_loop = entry->dispatch_loop;

//     s_lock_synced_data(dispatch_loop);
//     dispatch_loop->synced_data.is_executing = false;

//     // Remove the entry that's ending its iteration before further scheduling
//     aws_priority_queue_remove(&dispatch_loop->synced_data.scheduled_iterations, entry, &entry->priority_queue_node);

//     bool should_schedule = false;
//     uint64_t should_schedule_at_time = 0;
//     /*
//      * We first check if there were any cross thread tasks scheduled during the execution of the current
//      * iteration. If there were, we schedule a new iteration to execute immediately during which cross thread tasks
//      * will be migrated into the dispatch_loop->scheduler.
//      */
//     if (!aws_linked_list_empty(&dispatch_loop->synced_data.cross_thread_tasks)) {
//         should_schedule = true;
//     }
//     /*
//      * If we are not scheduling a new iteration for immediate executuion, we check whether there are any tasks
//      scheduled
//      * to execute now or in the future and scheudle the next iteration using that time.
//      */
//     else if (aws_task_scheduler_has_tasks(&dispatch_loop->scheduler, &should_schedule_at_time)) {
//         should_schedule = true;
//     }

//     if (should_schedule) {
//         s_try_schedule_new_iteration(dispatch_loop, should_schedule_at_time);
//     }

//     s_unlock_synced_data(dispatch_loop);
// }

/*
 * This function is scheduled as a block to run on Apple's dispatch queue. It will only ever be executed on an Apple
 * dispatch queue and upon completion, will determine whether or not to schedule another iteration of itself on the
 * Apple dispatch queue.
 */
static void s_run_iteration(void *service_entry) {
    struct scheudled_iteration_entry *entry = service_entry;
    struct aws_dispatch_loop *dispatch_loop = entry->dispatch_loop;

    /*
     * A scheduled_iteration_entry can have been enqueued by Apple to run AFTER s_dispatch_queue_destroy_task() has been
     * executed and the aws_dispatch_loop and parent aws_event_loop have been cleaned up. During the execution of
     * s_dispatch_queue_destroy_task(), all scheduled_iteration_entry nodes within the aws_dispath_loop's
     * scheduled_iterations will have had their dispatch_loop members set to NULL. That value is being checked here to
     * determine whether this iteration is executing on an Apple dispatch queue that is no longer associated with an
     * aws_dispatch_loop or aws_event_loop.
     */
    if (dispatch_loop == NULL) {
        // WIP TODO we need to clear out the cross thread tasks that may have been scheduled and are waiting to be
        // executed here as well as clearing out the scheduled entry.
        s_lock_synced_data(dispatch_loop);
        if (aws_priority_queue_node_is_in_queue(&entry->priority_queue_node)) {
            aws_priority_queue_remove(
                &dispatch_loop->synced_data.scheduled_iterations, entry, &entry->priority_queue_node);
        }
        aws_mem_release(entry->allocator, entry);
        s_unlock_synced_data(dispatch_loop);
        return;
    }

    // swap the cross-thread tasks into task-local data
    struct aws_linked_list local_cross_thread_tasks;
    aws_linked_list_init(&local_cross_thread_tasks);
    s_lock_synced_data(dispatch_loop);
    dispatch_loop->synced_data.stopped = false;
    dispatch_loop->synced_data.current_thread_id = aws_thread_current_thread_id();
    dispatch_loop->synced_data.is_executing = true;
    aws_linked_list_swap_contents(&dispatch_loop->synced_data.cross_thread_tasks, &local_cross_thread_tasks);
    s_unlock_synced_data(dispatch_loop);

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

    /* end of iteration cleanup and rescheduling */

    s_lock_synced_data(dispatch_loop);

    dispatch_loop->synced_data.is_executing = false;

    /* Remove the entry that's ending its iteration before further scheduling */
    aws_priority_queue_remove(&dispatch_loop->synced_data.scheduled_iterations, entry, &entry->priority_queue_node);
    /* destroy the completed service entry. */
    aws_mem_release(entry->allocator, entry);

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

    s_unlock_synced_data(dispatch_loop);
}

/**
 * Checks if a new iteration task needs to be scheduled, given a target timestamp. If so, submits an iteration task to
 * dispatch queue and registers the pending execution in the event loop's list of scheduled_services.
 *
 * If timestamp == 0, the function will always schedule a new iteration as long as the event loop is not suspended or
 * being destroyed.
 *
 * The function should be wrapped with the synced_data_lock
 */
static void s_try_schedule_new_iteration(struct aws_dispatch_loop *dispatch_loop, uint64_t timestamp) {
    if (!dispatch_loop || dispatch_loop->synced_data.suspended || dispatch_loop->synced_data.is_destroying) {
        return;
    }

    if (!s_should_schedule_iteration(&dispatch_loop->synced_data.scheduled_iterations, timestamp)) {
        return;
    }
    struct scheudled_iteration_entry *entry = s_scheudled_iteration_entry_new(dispatch_loop, timestamp);
    aws_priority_queue_push_ref(&dispatch_loop->synced_data.scheduled_iterations, entry, &entry->priority_queue_node);

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
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;
    task->timestamp = run_at_nanos;

    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: Scheduling task %p cross-thread for timestamp %llu",
        (void *)event_loop,
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
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: cancelling task %p", (void *)event_loop, (void *)task);
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;
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
    struct aws_dispatch_loop *dispatch_loop = event_loop->impl_data;
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
