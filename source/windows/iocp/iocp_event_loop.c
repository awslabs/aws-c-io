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

#include <aws/common/clock.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/thread.h>
#include <aws/io/event_loop.h>

typedef enum event_thread_state {
    EVENT_THREAD_STATE_READY_TO_RUN,
    EVENT_THREAD_STATE_RUNNING,
    EVENT_THREAD_STATE_STOPPING,
} event_thread_state;

struct iocp_loop {
    HANDLE iocp_handle;
    struct aws_thread thread;

    /* synced_data holds things that must be communicated across threads.
     * When the event-thread is running, the mutex must be locked while anyone touches anything in synced_data.
     * If this data is modified outside the event-thread, the thread is signaled via activity on a pipe. */
    struct {
        struct aws_mutex mutex;
        bool thread_signaled; /* whether thread has been signaled about changes to synced_data */
        struct aws_linked_list tasks_to_schedule;
        event_thread_state state;
    } synced_data;

    /* thread_data holds things which, when the event-thread is running, may only be touched by the thread */
    struct {
        struct aws_task_scheduler scheduler;

        /* These variables duplicate ones in synced_data.
         * We move values out while holding the mutex and operate on them later */
        event_thread_state state;
    } thread_data;
};

enum {
    DEFAULT_TIMEOUT_MS = 100000,

    /* Max I/O completion packets to process per loop of the event-thread */
    MAX_COMPLETION_PACKETS_PER_LOOP = 100,
};

static void s_destroy(struct aws_event_loop *event_loop);
static int s_run(struct aws_event_loop *event_loop);
static int s_stop(struct aws_event_loop *event_loop);
static int s_wait_for_stop_completion(struct aws_event_loop *event_loop);
static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task);
static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos);
static int s_connect_to_io_completion_port(struct aws_event_loop *event_loop, struct aws_io_handle *handle);
static bool s_is_event_thread(struct aws_event_loop *event_loop);

static void s_event_thread_main(void *user_data);

void aws_overlapped_init(
    struct aws_overlapped *overlapped,
    aws_event_loop_on_completion_fn *on_completion,
    void *user_data) {

    assert(overlapped);

    AWS_ZERO_STRUCT(overlapped->overlapped);
    overlapped->on_completion = on_completion;
    overlapped->user_data = user_data;
}

void aws_overlapped_reset(struct aws_overlapped *overlapped) {
    assert(overlapped);

    AWS_ZERO_STRUCT(overlapped->overlapped);
}

struct aws_event_loop *aws_event_loop_new_default(struct aws_allocator *alloc, aws_io_clock_fn *clock) {
    assert(alloc);
    assert(clock);
    int err = 0;

    struct aws_event_loop *event_loop = NULL;
    bool clean_up_event_loop_base = false;
    struct iocp_loop *impl = NULL;
    bool clean_up_iocp_handle = false;
    bool clean_up_thread = false;
    bool clean_up_mutex = false;
    bool clean_up_scheduler = false;

    event_loop = aws_mem_acquire(alloc, sizeof(struct aws_event_loop));
    if (!event_loop) {
        return NULL;
    }

    err = aws_event_loop_init_base(event_loop, alloc, clock);
    if (err) {
        goto clean_up;
    }
    clean_up_event_loop_base = true;

    impl = aws_mem_acquire(alloc, sizeof(struct iocp_loop));
    if (!impl) {
        goto clean_up;
    }
    AWS_ZERO_STRUCT(*impl);

    impl->iocp_handle = CreateIoCompletionPort(
        INVALID_HANDLE_VALUE, /* FileHandle: passing invalid handle creates a new IOCP */
        NULL,                 /* ExistingCompletionPort: should be NULL when file handle is invalid. */
        0,                    /* CompletionKey: should be 0 when file handle is invalid */
        1);                   /* NumberOfConcurrentThreads */
    if (impl->iocp_handle == NULL) {
        aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
        goto clean_up;
    }
    clean_up_iocp_handle = true;

    err = aws_thread_init(&impl->thread, alloc);
    if (err) {
        goto clean_up;
    }
    clean_up_thread = true;

    err = aws_mutex_init(&impl->synced_data.mutex);
    if (err) {
        goto clean_up;
    }
    clean_up_mutex = true;

    aws_linked_list_init(&impl->synced_data.tasks_to_schedule);

    err = aws_task_scheduler_init(&impl->thread_data.scheduler, alloc);
    if (err) {
        goto clean_up;
    }
    clean_up_scheduler = true;

    event_loop->impl_data = impl;

    event_loop->vtable.destroy = s_destroy;
    event_loop->vtable.run = s_run;
    event_loop->vtable.stop = s_stop;
    event_loop->vtable.wait_for_stop_completion = s_wait_for_stop_completion;
    event_loop->vtable.schedule_task_now = s_schedule_task_now;
    event_loop->vtable.schedule_task_future = s_schedule_task_future;
    event_loop->vtable.connect_to_io_completion_port = s_connect_to_io_completion_port;
    event_loop->vtable.is_on_callers_thread = s_is_event_thread;

    return event_loop;

clean_up:

    if (clean_up_scheduler) {
        aws_task_scheduler_clean_up(&impl->thread_data.scheduler);
    }

    if (clean_up_mutex) {
        aws_mutex_clean_up(&impl->synced_data.mutex);
    }

    if (clean_up_thread) {
        aws_thread_clean_up(&impl->thread);
    }

    if (clean_up_iocp_handle) {
        CloseHandle(impl->iocp_handle);
    }

    if (impl) {
        aws_mem_release(alloc, impl);
    }

    if (clean_up_event_loop_base) {
        aws_event_loop_clean_up_base(event_loop);
    }

    if (event_loop) {
        aws_mem_release(alloc, event_loop);
    }

    return NULL;
}

/* Should not be called from event-thread */
static void s_destroy(struct aws_event_loop *event_loop) {
    struct iocp_loop *impl = event_loop->impl_data;
    assert(impl);

    /* Stop the event-thread. This might have already happened. It's safe to call multiple times. */
    aws_event_loop_stop(event_loop);
    int err = aws_event_loop_wait_for_stop_completion(event_loop);
    if (err) {
        assert(0 && "Failed to destroy event-thread, resources have been leaked.");
        return;
    }

    /* Clean up task-related stuff first.
     * It's possible the a cancelled task adds further tasks to this event_loop, these new tasks would end up in
     * synced_data.tasks_to_schedule, so clean that up last */

    aws_task_scheduler_clean_up(&impl->thread_data.scheduler); /* cancels remaining tasks in scheduler */

    while (!aws_linked_list_empty(&impl->synced_data.tasks_to_schedule)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&impl->synced_data.tasks_to_schedule);
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
        task->fn(task, task->arg, AWS_TASK_STATUS_CANCELED);
    }

    /* Clean up everything else */
    bool close_iocp_success = CloseHandle(impl->iocp_handle);
    assert(close_iocp_success);
    (void)close_iocp_success;

    aws_mutex_clean_up(&impl->synced_data.mutex);
    aws_thread_clean_up(&impl->thread);
    aws_mem_release(event_loop->alloc, impl);
    aws_event_loop_clean_up_base(event_loop);
    aws_mem_release(event_loop->alloc, event_loop);
}

/* Called from any thread.
/* Signal to the event-loop thread that synced_data has changed.
 * This should only be called after changing synced_data.thread_signaled from false to true. */
static void s_signal_synced_data_changed(struct aws_event_loop *event_loop) {
    struct iocp_loop *impl = event_loop->impl_data;
    assert(impl);

    /* Enqueue a special completion packet to inform the event-loop that synced_data has changed.
     * We identify the special packet by using the iocp handle as the completion key.
     * This wakes the event-loop thread if it was idle. */
    ULONG_PTR completion_key = (ULONG_PTR)impl->iocp_handle;
    PostQueuedCompletionStatus(
        impl->iocp_handle, /* CompletionPort */
        0,                 /* dwNumberOfBytesTransferred */
        completion_key,    /* dwCompletionKey */
        NULL);             /* lpOverlapped */
}

static int s_run(struct aws_event_loop *event_loop) {
    struct iocp_loop *impl = event_loop->impl_data;

    /* Since thread isn't running it's ok to touch thread_data,
     * and it's ok to touch synced_data without locking the mutex */

    /* If asserts hit, you must call stop() and wait_for_stop_completion() before calling run() again */
    assert(impl->thread_data.state == EVENT_THREAD_STATE_READY_TO_RUN);
    assert(impl->synced_data.state == EVENT_THREAD_STATE_READY_TO_RUN);

    impl->synced_data.state = EVENT_THREAD_STATE_RUNNING;

    int err = aws_thread_launch(&impl->thread, s_event_thread_main, event_loop, NULL);
    if (err) {
        goto clean_up;
    }

    return AWS_OP_SUCCESS;

clean_up:
    impl->synced_data.state = EVENT_THREAD_STATE_READY_TO_RUN;
    return AWS_OP_ERR;
}

/* Called from any thread */
static int s_stop(struct aws_event_loop *event_loop) {
    struct iocp_loop *impl = event_loop->impl_data;
    assert(impl);

    bool signal_thread = false;

    { /* Begin critical section */
        aws_mutex_lock(&impl->synced_data.mutex);
        if (impl->synced_data.state == EVENT_THREAD_STATE_RUNNING) {
            impl->synced_data.state = EVENT_THREAD_STATE_STOPPING;
            signal_thread = !impl->synced_data.thread_signaled;
            impl->synced_data.thread_signaled = true;
        }
        aws_mutex_unlock(&impl->synced_data.mutex);
    } /* End critical section */

    if (signal_thread) {
        s_signal_synced_data_changed(event_loop);
    }

    return AWS_OP_SUCCESS;
}

/* Should not be called from event-thread */
static int s_wait_for_stop_completion(struct aws_event_loop *event_loop) {
    struct iocp_loop *impl = event_loop->impl_data;
    assert(impl);

#ifdef DEBUG_BUILD
    aws_mutex_lock(&impl->synced_data.mutex);
    /* call stop() before wait_for_stop_completion() or you'll wait forever */
    assert(impl->synced_data.state != EVENT_THREAD_STATE_RUNNING);
    aws_mutex_unlock(&impl->synced_data.mutex);
#endif

    int err = aws_thread_join(&impl->thread);
    if (err) {
        return AWS_OP_ERR;
    }

    /* Since thread is no longer running it's ok to touch thread_data,
     * and it's ok to touch synced_data without locking the mutex */
    impl->synced_data.state = EVENT_THREAD_STATE_READY_TO_RUN;
    impl->thread_data.state = EVENT_THREAD_STATE_READY_TO_RUN;

    return AWS_OP_SUCCESS;
}

/* Common function used by schedule_task_now() and schedule_task_future().
 * When run_at_nanos is 0, it's treated as a "now" task.
 * Called from any thread */
static void s_schedule_task_common(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    struct iocp_loop *impl = event_loop->impl_data;
    assert(impl);
    assert(task);

    /* If we're on the event-thread, just schedule it directly */
    if (s_is_event_thread(event_loop)) {
        if (run_at_nanos == 0) {
            aws_task_scheduler_schedule_now(&impl->thread_data.scheduler, task);
        } else {
            aws_task_scheduler_schedule_future(&impl->thread_data.scheduler, task, run_at_nanos);
        }
        return;
    }

    /* Otherwise, add it to synced_data.tasks_to_schedule and signal the event-thread to process it */
    task->timestamp = run_at_nanos;
    bool should_signal_thread = false;

    { /* Begin critical section */
        aws_mutex_lock(&impl->synced_data.mutex);
        aws_linked_list_push_back(&impl->synced_data.tasks_to_schedule, &task->node);

        /* Signal thread that synced_data has changed (unless it's been signaled already) */
        if (!impl->synced_data.thread_signaled) {
            should_signal_thread = true;
            impl->synced_data.thread_signaled = true;
        }

        aws_mutex_unlock(&impl->synced_data.mutex);
    } /* End critical section */

    if (should_signal_thread) {
        s_signal_synced_data_changed(event_loop);
    }
}

/* Called from any thread */
static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task) {
    s_schedule_task_common(event_loop, task, 0 /* use zero to denote it's a "now" task */);
}

/* Called from any thread */
static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    s_schedule_task_common(event_loop, task, run_at_nanos);
}
/* Called from any thread */
static bool s_is_event_thread(struct aws_event_loop *event_loop) {
    struct iocp_loop *impl = event_loop->impl_data;
    assert(impl);
    assert(aws_thread_get_detach_state(&impl->thread) == AWS_THREAD_JOINABLE);

    return aws_thread_get_id(&impl->thread) == aws_thread_current_thread_id();
}

/* Called from any thread */
static int s_connect_to_io_completion_port(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    struct iocp_loop *impl = event_loop->impl_data;
    assert(impl);
    assert(handle);

    bool success = CreateIoCompletionPort(
        handle->data.handle, /* FileHandle */
        impl->iocp_handle,   /* ExistingCompletionPort */
        0,                   /* CompletionKey */
        1);                  /* NumberOfConcurrentThreads */

    if (!success) {
        return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }

    /* As an optimization, tell Windows not to bother signaling the handle when async I/O completes.
     * We're using I/O completion ports, we don't need further mechanisms to know when I/O completes. */
    SetFileCompletionNotificationModes(handle->data.handle, FILE_SKIP_SET_EVENT_ON_HANDLE);

    /* iocp_event_loop has no need to store additional data per aws_io_handle */
    handle->additional_data = NULL;

    return AWS_OP_SUCCESS;
}

/* Called from event-thread.
 * Takes tasks from tasks_to_schedule and adds them to the scheduler. */
static void s_process_tasks_to_schedule(struct aws_event_loop *event_loop, struct aws_linked_list *tasks_to_schedule) {
    struct iocp_loop *impl = event_loop->impl_data;
    assert(impl);

    while (!aws_linked_list_empty(tasks_to_schedule)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(tasks_to_schedule);
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);

        /* We use timestamp of 0 to denote that it's a "now" task */
        if (task->timestamp == 0) {
            aws_task_scheduler_schedule_now(&impl->thread_data.scheduler, task);
        } else {
            aws_task_scheduler_schedule_future(&impl->thread_data.scheduler, task, task->timestamp);
        }
    }
}

/* Runs on the event-thread. */
static void s_process_synced_data(struct aws_event_loop *event_loop) {
    struct iocp_loop *impl = event_loop->impl_data;

    /* If there are tasks to schedule, grab them all out of synced_data.tasks_to_schedule.
     * We'll process them later, so that we minimize time spent holding the mutex. */
    struct aws_linked_list tasks_to_schedule;
    aws_linked_list_init(&tasks_to_schedule);

    { /* Begin critical section */
        aws_mutex_lock(&impl->synced_data.mutex);
        impl->synced_data.thread_signaled = false;

        bool initiate_stop = (impl->synced_data.state == EVENT_THREAD_STATE_STOPPING) &&
                             (impl->thread_data.state == EVENT_THREAD_STATE_RUNNING);
        if (AWS_UNLIKELY(initiate_stop)) {
            impl->thread_data.state = EVENT_THREAD_STATE_STOPPING;
        }

        aws_linked_list_swap_contents(&impl->synced_data.tasks_to_schedule, &tasks_to_schedule);

        aws_mutex_unlock(&impl->synced_data.mutex);
    } /* End critical section */

    s_process_tasks_to_schedule(event_loop, &tasks_to_schedule);
}

/* Called from event-thread */
static void s_event_thread_main(void *user_data) {

    struct aws_event_loop *event_loop = user_data;
    struct iocp_loop *impl = event_loop->impl_data;

    assert(impl->thread_data.state == EVENT_THREAD_STATE_READY_TO_RUN);
    impl->thread_data.state = EVENT_THREAD_STATE_RUNNING;

    DWORD timeout_ms = DEFAULT_TIMEOUT_MS;

    OVERLAPPED_ENTRY completion_packets[MAX_COMPLETION_PACKETS_PER_LOOP];
    AWS_ZERO_ARRAY(completion_packets);

    while (impl->thread_data.state == EVENT_THREAD_STATE_RUNNING) {
        ULONG num_entries = 0;
        bool should_process_synced_data = false;

        bool has_completion_entries = GetQueuedCompletionStatusEx(
            impl->iocp_handle,               /* Completion port */
            completion_packets,              /* Out: completion port entries */
            MAX_COMPLETION_PACKETS_PER_LOOP, /* max number of entries to remove */
            &num_entries,                    /* Out: number of entries removed */
            timeout_ms,                      /* Timeout in ms. If timeout reached then FALSE is returned. */
            false);                          /* fAlertable */

        if (has_completion_entries) {
            for (ULONG i = 0; i < num_entries; ++i) {
                OVERLAPPED_ENTRY *completion = &completion_packets[i];

                /* Is this a special completion packet which signals that synced_data has changed?
                 * (We use iocp_handle's value as the completion key for these special packets) */
                if (completion->lpCompletionKey == (ULONG_PTR)impl->iocp_handle) {
                    should_process_synced_data = true;
                } else {
                    /* Otherwise this was a normal completion on a connected aws_io_handle.
                     * Get our hands on the aws_overlapped which owns this OVERLAPPED,
                     * and invoke its callback */
                    struct aws_overlapped *overlapped =
                        AWS_CONTAINER_OF(completion->lpOverlapped, struct aws_overlapped, overlapped);

                    if (overlapped->on_completion) {
                        overlapped->on_completion(event_loop, overlapped);
                    }
                }
            }
        } else {
            /* If no completion entries were dequeued then the timeout must have triggered */
            assert(GetLastError() == WAIT_TIMEOUT);
        }

        /* Process synced_data */
        if (should_process_synced_data) {
            s_process_synced_data(event_loop);
        }

        /* Run scheduled tasks */
        uint64_t now_ns = 0;
        event_loop->clock(&now_ns); /* If clock fails, now_ns will be 0 and tasks scheduled for a specific time
                                       will not be run. That's ok, we'll handle them next time around. */
        aws_task_scheduler_run_all(&impl->thread_data.scheduler, now_ns);

        /* Set timeout for next GetQueuedCompletionStatus() call.
         * If clock fails, or scheduler has no tasks, use default timeout */
        bool use_default_timeout = false;

        int err = event_loop->clock(&now_ns);
        if (err) {
            use_default_timeout = true;
        }

        uint64_t next_run_time_ns;
        if (!aws_task_scheduler_has_tasks(&impl->thread_data.scheduler, &next_run_time_ns)) {
            use_default_timeout = true;
        }

        if (use_default_timeout) {
            timeout_ms = DEFAULT_TIMEOUT_MS;
        } else {
            /* Translate timestamp (in nanoseconds) to timeout (in milliseconds) */
            uint64_t timeout_ns = (next_run_time_ns > now_ns) ? (next_run_time_ns - now_ns) : 0;
            uint64_t timeout_ms64 = aws_timestamp_convert(AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_MILLIS, timeout_ns, NULL);
            timeout_ms = timeout_ms64 > MAXDWORD ? MAXDWORD : (DWORD)timeout_ms64;
        }
    }
}
