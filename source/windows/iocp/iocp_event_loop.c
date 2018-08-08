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
        struct aws_array_list tasks_to_schedule;
        event_thread_state state;
    } synced_data;

    /* thread_data holds things which, when the event-thread is running, may only be touched by the thread */
    struct {
        struct aws_task_scheduler scheduler;

        /* These variables duplicate ones in synced_data.
         * We move values out while holding the mutex and operate on them later */
        struct aws_array_list tasks_to_schedule;
        event_thread_state state;
    } thread_data;
};

/* A task that needs to be added to the scheduler */
struct task_to_schedule {
    struct aws_task task;
    uint64_t run_at;
};

enum {
    DEFAULT_TIMEOUT_MS = 100000,
    NANOSEC_PER_MS = 1000000,

    /* Max I/O completion packets to process per loop of the event-thread */
    MAX_COMPLETION_PACKETS_PER_LOOP = 100,

    DEFAULT_ARRAY_LIST_RESERVE = 32,
};

static void s_destroy(struct aws_event_loop *event_loop);
static int s_run(struct aws_event_loop *event_loop);
static int s_stop(struct aws_event_loop *event_loop);
static int s_wait_for_stop_completion(struct aws_event_loop *event_loop);
static int s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task);
static int s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at);
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
    bool clean_up_synced_data_tasks_to_schedule = false;
    bool clean_up_scheduler = false;
    bool clean_up_thread_data_tasks_to_schedule = false;

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

    err = aws_array_list_init_dynamic(
        &impl->synced_data.tasks_to_schedule, alloc, DEFAULT_ARRAY_LIST_RESERVE, sizeof(struct task_to_schedule));
    if (err) {
        goto clean_up;
    }
    clean_up_synced_data_tasks_to_schedule = true;

    err = aws_task_scheduler_init(&impl->thread_data.scheduler, alloc, clock);
    if (err) {
        goto clean_up;
    }
    clean_up_scheduler = true;

    err = aws_array_list_init_dynamic(
        &impl->thread_data.tasks_to_schedule, alloc, DEFAULT_ARRAY_LIST_RESERVE, sizeof(struct task_to_schedule));
    if (err) {
        goto clean_up;
    }
    clean_up_thread_data_tasks_to_schedule = true;

    event_loop->impl_data = impl;

    event_loop->vtable.destroy = s_destroy;
    event_loop->vtable.run = s_run;
    event_loop->vtable.stop = s_stop;
    event_loop->vtable.wait_for_stop_completion = s_wait_for_stop_completion;
    event_loop->vtable.schedule_task = s_schedule_task_future;
    event_loop->vtable.connect_to_io_completion_port = s_connect_to_io_completion_port;
    event_loop->vtable.is_on_callers_thread = s_is_event_thread;

    return event_loop;

clean_up:

    if (clean_up_thread_data_tasks_to_schedule) {
        aws_array_list_clean_up(&impl->thread_data.tasks_to_schedule);
    }

    if (clean_up_scheduler) {
        aws_task_scheduler_clean_up(&impl->thread_data.scheduler);
    }

    if (clean_up_synced_data_tasks_to_schedule) {
        aws_array_list_clean_up(&impl->synced_data.tasks_to_schedule);
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

    struct task_to_schedule task_to_schedule;
    for (size_t i = 0; i < aws_array_list_length(&impl->thread_data.tasks_to_schedule); ++i) {
        aws_array_list_get_at(&impl->thread_data.tasks_to_schedule, &task_to_schedule, i);
        task_to_schedule.task.fn(task_to_schedule.task.arg, AWS_TASK_STATUS_CANCELED);
    }
    aws_array_list_clean_up(&impl->thread_data.tasks_to_schedule);

    for (size_t i = 0; i < aws_array_list_length(&impl->synced_data.tasks_to_schedule); ++i) {
        aws_array_list_get_at(&impl->synced_data.tasks_to_schedule, &task_to_schedule, i);
        task_to_schedule.task.fn(task_to_schedule.task.arg, AWS_TASK_STATUS_CANCELED);
    }
    aws_array_list_clean_up(&impl->synced_data.tasks_to_schedule);

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

/* Called from any thread */
static int s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task) {
    uint64_t now;
    int err = event_loop->clock(&now);
    if (err) {
        return AWS_OP_ERR;
    }

    return aws_event_loop_schedule_task(event_loop, task, now);
}

/* Called from any thread */
static int s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at) {
    struct iocp_loop *impl = event_loop->impl_data;
    assert(impl);
    assert(task);

    /* If we're on the event-thread, just schedule it directly */
    if (s_is_event_thread(event_loop)) {
        return aws_task_scheduler_schedule_future(&impl->thread_data.scheduler, task, run_at);
    }

    /* Otherwise, add it to synced_data.tasks_to_schedule and signal the event-thread to process it */
    struct task_to_schedule task_to_schedule;
    task_to_schedule.task = *task;
    task_to_schedule.run_at = run_at;

    int push_back_err;
    bool should_signal_thread = false;

    { /* Begin critical section */
        aws_mutex_lock(&impl->synced_data.mutex);
        push_back_err = aws_array_list_push_back(&impl->synced_data.tasks_to_schedule, &task_to_schedule);

        /* If successful, signal thread that synced_data has changed (unless it's been signaled already) */
        if (!push_back_err) {
            should_signal_thread = !impl->synced_data.thread_signaled;
            impl->synced_data.thread_signaled = true;
        }

        aws_mutex_unlock(&impl->synced_data.mutex);
    } /* End critical section */

    if (should_signal_thread) {
        s_signal_synced_data_changed(event_loop);
    }

    if (push_back_err) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
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
 * Takes tasks from tasks_to_schedule and adds them to the scheduler.
 * If everything is successful, tasks_to_schedule will be emptied.
 * If anything goes wrong, tasks_to_schedule will be left with the unprocessed tasks */
static int s_process_tasks_to_schedule(struct aws_event_loop *event_loop) {
    struct iocp_loop *impl = event_loop->impl_data;
    assert(impl);

    const size_t num_tasks = aws_array_list_length(&impl->thread_data.tasks_to_schedule);
    if (num_tasks == 0) {
        return AWS_OP_SUCCESS;
    }

    /* Add tasks to scheduler, stop if anything goes wrong */
    size_t task_i;
    for (task_i = 0; task_i < num_tasks; ++task_i) {
        struct task_to_schedule *task_to_schedule;
        aws_array_list_get_at_ptr(&impl->thread_data.tasks_to_schedule, (void **)&task_to_schedule, task_i);
        int err = aws_task_scheduler_schedule_future(
            &impl->thread_data.scheduler, &task_to_schedule->task, task_to_schedule->run_at);
        if (err) {
            break;
        }
    }

    if (task_i < num_tasks) {
        /* Not all tasks were scheduled, modify list so only unprocessed tasks remain */
        aws_array_list_pop_front_n(&impl->thread_data.tasks_to_schedule, task_i);
        return AWS_OP_ERR;
    } else {
        /* Success, clear list */
        aws_array_list_clear(&impl->thread_data.tasks_to_schedule);
        return AWS_OP_SUCCESS;
    }
}

/* Runs on the event-thread. */
static void s_process_synced_data(struct aws_event_loop *event_loop) {
    struct iocp_loop *impl = event_loop->impl_data;

    bool should_resignal_synced_data_changed = false;

    { /* Begin critical section */
        aws_mutex_lock(&impl->synced_data.mutex);
        impl->synced_data.thread_signaled = false;

        bool initiate_stop = (impl->synced_data.state == EVENT_THREAD_STATE_STOPPING) &&
                             (impl->thread_data.state == EVENT_THREAD_STATE_RUNNING);
        if (AWS_UNLIKELY(initiate_stop)) {
            impl->thread_data.state = EVENT_THREAD_STATE_STOPPING;
        }

        /* If there are tasks to schedule, move them from synced_data to thread_data.
         * We'll process them later, so that we minimize time spent holding the mutex. */
        bool tasks_to_schedule = aws_array_list_length(&impl->synced_data.tasks_to_schedule) > 0;
        if (AWS_LIKELY(tasks_to_schedule)) {
            /* Swapping the contents of the two lists is the fastest and safest way to move this data,
             * but requires the other list to be empty. */
            bool swap_possible = aws_array_list_length(&impl->thread_data.tasks_to_schedule) == 0;
            if (AWS_LIKELY(swap_possible)) {
                aws_array_list_swap_contents(
                    &impl->synced_data.tasks_to_schedule, &impl->thread_data.tasks_to_schedule);
            } else {
                /* If swap not possible, signal the thread to try again next loop */
                should_resignal_synced_data_changed = true;
                impl->synced_data.thread_signaled = true;
            }
        }

        aws_mutex_unlock(&impl->synced_data.mutex);
    } /* End critical section */

    s_process_tasks_to_schedule(event_loop);

    if (should_resignal_synced_data_changed) {
        s_signal_synced_data_changed(event_loop);
    }
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

        /* Just in case anything in thread_data.tasks_to_schedule failed to process in the past, try again. */
        s_process_tasks_to_schedule(event_loop);

        /* Process synced_data */
        if (should_process_synced_data) {
            s_process_synced_data(event_loop);
        }

        /* Run scheduled tasks */
        uint64_t next_run_time_ns = 0;
        aws_task_scheduler_run_all(&impl->thread_data.scheduler, &next_run_time_ns);

        /* Set timeout for next GetQueuedCompletionStatus() call */
        uint64_t now_ns;
        if ((next_run_time_ns != 0) && (event_loop->clock(&now_ns) == AWS_OP_SUCCESS)) {
            uint64_t timeout_ns = (next_run_time_ns > now_ns) ? (next_run_time_ns - now_ns) : 0;
            uint64_t timeout_ms64 = timeout_ns / NANOSEC_PER_MS;
            timeout_ms = timeout_ms64 > MAXDWORD ? MAXDWORD : (DWORD)timeout_ms64;
        } else {
            timeout_ms = DEFAULT_TIMEOUT_MS;
        }
    }
}
