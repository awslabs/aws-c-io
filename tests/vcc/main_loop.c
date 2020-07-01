/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

/* clang-format off */
#include "preamble.h"

#define DEFAULT_TIMEOUT 100000
#define MAX_EVENTS 100

static void s_on_tasks_to_schedule(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data _(ghost \claim(c_event_loop))
) {
    (void)handle;
    (void)user_data;

    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: notified of cross-thread tasks to schedule", (void *)event_loop);
    struct epoll_loop *epoll_loop = event_loop->impl_data;
    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        epoll_loop->should_process_task_pre_queue = true;
    }
}

static void s_main_loop(void *args _(ghost \claim(c_mutex))) {
    struct aws_event_loop *event_loop = args;
    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: main loop started", (void *)event_loop);
    struct epoll_loop *epoll_loop = event_loop->impl_data;
    _(ghost \claim c_event_loop;)
    _(ghost c_event_loop = \make_claim({event_loop}, event_loop->\closed);)

    /* set thread id to the thread of the event loop */
    _(unwrap &epoll_loop->running_thread_id)
    aws_atomic_store_ptr(&epoll_loop->running_thread_id, &epoll_loop->thread_created_on.thread_id);
    _(wrap &epoll_loop->running_thread_id)

    int err = s_subscribe_to_io_events(
        event_loop, &epoll_loop->read_task_handle, AWS_IO_EVENT_TYPE_READABLE, s_on_tasks_to_schedule, NULL _(ghost c_event_loop));
    if (err) {
        return;
    }

    int timeout = DEFAULT_TIMEOUT;

    struct epoll_event events[MAX_EVENTS];

    AWS_LOGF_INFO(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: default timeout %d, and max events to process per tick %d",
        (void *)event_loop,
        timeout,
        MAX_EVENTS);

    /*
     * until stop is called,
     * call epoll_wait, if a task is scheduled, or a file descriptor has activity, it will
     * return.
     *
     * process all events,
     *
     * run all scheduled tasks.
     *
     * process queued subscription cleanups.
     */
    while (epoll_loop->should_continue)
      _(invariant \extent_mutable((struct epoll_event[MAX_EVENTS]) events))
      _(invariant (&epoll_loop->read_task_handle)->\closed)
      _(invariant \wrapped(&epoll_loop->scheduler))
      _(writes &epoll_loop->scheduler)
      _(writes &epoll_loop->should_process_task_pre_queue)
      _(writes \extent((struct epoll_event[MAX_EVENTS]) events))
    {
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: waiting for a maximum of %d ms", (void *)event_loop, timeout);
        int event_count = epoll_wait(epoll_loop->epoll_fd, events, MAX_EVENTS, timeout);
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP, "id=%p: wake up with %d events to process.", (void *)event_loop, event_count);
        for (int i = 0; i < event_count; ++i)
            _(writes &epoll_loop->should_process_task_pre_queue)
        {
            struct epoll_event_data *event_data = (struct epoll_event_data *)events[i].data.ptr;
            _(assert \wrapped(event_data))
            _(assert \inv(event_data))

            int event_mask = 0;
            if (events[i].events & EPOLLIN) {
                event_mask |= AWS_IO_EVENT_TYPE_READABLE;
            }

            if (events[i].events & EPOLLOUT) {
                event_mask |= AWS_IO_EVENT_TYPE_WRITABLE;
            }

            if (events[i].events & EPOLLRDHUP) {
                event_mask |= AWS_IO_EVENT_TYPE_REMOTE_HANG_UP;
            }

            if (events[i].events & EPOLLHUP) {
                event_mask |= AWS_IO_EVENT_TYPE_CLOSED;
            }

            if (events[i].events & EPOLLERR) {
                event_mask |= AWS_IO_EVENT_TYPE_ERROR;
            }

            if (event_data->is_subscribed) {
                AWS_LOGF_TRACE(
                    AWS_LS_IO_EVENT_LOOP,
                    "id=%p: activity on fd %d, invoking handler.",
                    (void *)event_loop,
                    event_data->handle->data.fd);
                event_data->on_event(event_loop, event_data->handle, event_mask, event_data->user_data _(ghost c_event_loop));
            }
        }

        /* run scheduled tasks */
        s_process_task_pre_queue(event_loop _(ghost c_event_loop) _(ghost c_mutex));

        uint64_t now_ns = 0;
        event_loop->clock(&now_ns); /* if clock fails, now_ns will be 0 and tasks scheduled for a specific time
                                       will not be run. That's ok, we'll handle them next time around. */
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: running scheduled tasks.", (void *)event_loop);
        aws_task_scheduler_run_all(&epoll_loop->scheduler, now_ns);

        /* set timeout for next epoll_wait() call.
         * if clock fails, or scheduler has no tasks, use default timeout */
        bool use_default_timeout = false;

        if (event_loop->clock(&now_ns)) {
            use_default_timeout = true;
        }

        uint64_t next_run_time_ns;
        if (!aws_task_scheduler_has_tasks(&epoll_loop->scheduler, &next_run_time_ns)) {
            use_default_timeout = true;
        }

        if (use_default_timeout) {
            AWS_LOGF_TRACE(
                AWS_LS_IO_EVENT_LOOP, "id=%p: no more scheduled tasks using default timeout.", (void *)event_loop);
            timeout = DEFAULT_TIMEOUT;
        } else {
            /* Translate timestamp (in nanoseconds) to timeout (in milliseconds) */
            uint64_t timeout_ns = (next_run_time_ns > now_ns) ? (next_run_time_ns - now_ns) : 0;
            uint64_t timeout_ms64 = aws_timestamp_convert(timeout_ns, AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_MILLIS, NULL);
            timeout = timeout_ms64 > INT_MAX ? INT_MAX : (int)timeout_ms64;
            AWS_LOGF_TRACE(
                AWS_LS_IO_EVENT_LOOP,
                "id=%p: detected more scheduled tasks with the next occurring at "
                "%llu, using timeout of %d.",
                (void *)event_loop,
                (unsigned long long)timeout_ns,
                timeout);
        }
    }

    AWS_LOGF_DEBUG(AWS_LS_IO_EVENT_LOOP, "id=%p: exiting main loop", (void *)event_loop);
    s_unsubscribe_from_io_events(event_loop, &epoll_loop->read_task_handle _(ghost c_event_loop) _(ghost c_mutex));
    /* set thread id back to NULL. This should be updated again in destroy, before tasks are canceled. */
    _(unwrap &epoll_loop->running_thread_id)
    aws_atomic_store_ptr(&epoll_loop->running_thread_id, NULL);
    _(wrap &epoll_loop->running_thread_id)
}
/* clang-format on */
