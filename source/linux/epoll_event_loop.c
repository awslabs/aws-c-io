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

#include <aws/io/event_loop.h>
#include <aws/io/pipe.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/thread.h>

#include <sys/epoll.h>
#include <unistd.h>

static void destroy(struct aws_event_loop *);
static int run (struct aws_event_loop *);
static int stop (struct aws_event_loop *, aws_event_loop_stopped_promise promise, void *);
static int schedule_task (struct aws_event_loop *, struct aws_task *task, uint64_t run_at);
static int subscribe_to_io_events (struct aws_event_loop *, struct aws_io_handle *handle, int events,
                               aws_event_loop_on_event on_event, void *ctx);
static int unsubscribe_from_io_events (struct aws_event_loop *, struct aws_io_handle *handle);
static bool is_on_callers_thread (struct aws_event_loop *);


static void main_loop (void *args);

static struct aws_event_loop_vtable vtable = {
        .destroy = destroy,
        .run = run,
        .stop = stop,
        .schedule_task = schedule_task,
        .subscribe_to_io_events = subscribe_to_io_events,
        .unsubscribe_from_io_events = unsubscribe_from_io_events,
        .is_on_callers_thread = is_on_callers_thread,
};

struct epoll_loop {
    struct aws_task_scheduler scheduler;
    struct aws_thread thread;
    struct aws_io_handle read_task_handle;
    struct aws_io_handle write_task_handle;
    int epoll_fd;
    bool should_continue;
    aws_event_loop_stopped_promise stopped_promise;
    void *stop_ctx;
};

struct stop_task_args {
    struct aws_event_loop *event_loop;
    aws_event_loop_stopped_promise promise;
    void *stop_ctx;
};

struct pipe_task_data {
    struct aws_task task;
    uint64_t timestamp;
};

struct epoll_event_data {
    struct aws_allocator *alloc;
    struct aws_io_handle *handle;
    aws_event_loop_on_event on_event;
    void *ctx;
};

/* default timeout is 100 seconds */
static const int DEFAULT_TIMEOUT = 100 * 1000;
static const int MAX_EVENTS = 100;
static const int NANO_TO_MILLIS = 1000000;

/* Setup edge triggered epoll with a scheduler. */
struct aws_event_loop *aws_event_loop_default_new(struct aws_allocator *alloc, aws_io_clock clock) {
    struct aws_event_loop *loop = aws_mem_acquire(alloc, sizeof(struct aws_event_loop));

    if (!loop) {
        aws_raise_error(AWS_ERROR_OOM);
        goto cleanup_error;
    }

    bool base_init = false;
    if (aws_event_loop_base_init(loop, alloc, clock)) {
        goto cleanup_error;
    }
    base_init = true;

    struct epoll_loop *epoll_loop = aws_mem_acquire(alloc, sizeof(struct epoll_loop));

    if (!epoll_loop) {
        aws_raise_error(AWS_ERROR_OOM);
        goto cleanup_error;
    }

    bool thread_init = false;
    if (aws_thread_init(&epoll_loop->thread, alloc)) {
        goto cleanup_error;
    }
    thread_init = true;

    bool pipe_init = false;
    /* this pipe is for task scheduling. */
    if (aws_pipe_open(alloc, &epoll_loop->read_task_handle, &epoll_loop->write_task_handle)) {
        goto cleanup_error;
    }
    pipe_init = true;

    epoll_loop->epoll_fd = epoll_create(100);
    if (epoll_loop->epoll_fd < 0) {
        goto cleanup_error;
    }

    epoll_loop->should_continue = true;
    epoll_loop->stopped_promise = NULL;
    epoll_loop->stop_ctx = NULL;

    loop->impl_data = epoll_loop;
    loop->vtable = vtable;

    return loop;

cleanup_error:
    if (epoll_loop) {
        if (thread_init) {
            aws_thread_clean_up(&epoll_loop->thread);
        }

        if (pipe_init) {
            aws_pipe_close(alloc, &epoll_loop->read_task_handle, &epoll_loop->write_task_handle);
        }

        if (epoll_loop->epoll_fd < 0) {
            close (epoll_loop->epoll_fd);
        }

        aws_mem_release(alloc, epoll_loop);
    }

    if (loop) {

        if (base_init) {
            aws_event_loop_base_clean_up(loop);
        }

        aws_mem_release(alloc, loop);
    }

    return NULL;
}

static void destroy(struct aws_event_loop *event_loop) {
    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;

    aws_thread_clean_up(&epoll_loop->thread);
    aws_pipe_close(event_loop->alloc, &epoll_loop->read_task_handle, &epoll_loop->write_task_handle);
    close (epoll_loop->epoll_fd);
    aws_mem_release(event_loop->alloc, epoll_loop);
    aws_mem_release(event_loop->alloc, event_loop);
}

static int run (struct aws_event_loop *event_loop) {
    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;

    return aws_thread_launch(&epoll_loop->thread, &main_loop, event_loop, NULL);
}

static void stop_task (void *args) {
    struct stop_task_args *stop_task = (struct stop_task_args *)args;
    struct epoll_loop *epoll_loop = (struct epoll_loop *)stop_task->event_loop->impl_data;

    /*
     * this allows the event loop to invoke the promise once the event loop has completed.
     */
    epoll_loop->should_continue = false;
    epoll_loop->stopped_promise = stop_task->promise;
    epoll_loop->stop_ctx = stop_task->stop_ctx;

    aws_mem_release(stop_task->event_loop->alloc, args);
}

static int stop (struct aws_event_loop *event_loop, aws_event_loop_stopped_promise promise, void *ctx) {
    struct stop_task_args *stop_args = (struct stop_task_args *)aws_mem_acquire (event_loop->alloc, sizeof(struct stop_task_args));

    if (!stop_args) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    stop_args->event_loop = event_loop;
    stop_args->stop_ctx = ctx;
    stop_args->promise = promise;

    struct aws_task task = {
            .arg = stop_args,
            .fn = stop_task,
    };

    uint64_t timestamp = 0;
    event_loop->clock(&timestamp);

    if (schedule_task(event_loop, &task, timestamp)) {
        aws_mem_release(event_loop->alloc, (void *)stop_args);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int schedule_task (struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at) {
    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;

    /* if event loop and the caller are the same thread, just schedule and be done with it. */
    if (is_on_callers_thread(event_loop)) {
        return aws_task_scheduler_schedule_future(&epoll_loop->scheduler, task, run_at);
    }

    /* otherwise write the memory to a pipe and the event loop will pick it up */
    struct pipe_task_data *pipe_data = (struct pipe_task_data *)aws_mem_acquire(event_loop->alloc, sizeof(struct pipe_task_data));
    pipe_data->task = *task;
    pipe_data->timestamp;

    size_t written = 0;
    struct aws_byte_buf task_buf = {
            .buffer = (uint8_t *)&pipe_data,
            .len = sizeof(void *),
    };

    if (aws_pipe_write(&epoll_loop->write_task_handle, &task_buf, &written) || written != sizeof(void *)) {
        aws_mem_release(event_loop->alloc, pipe_data);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int subscribe_to_io_events (struct aws_event_loop *event_loop, struct aws_io_handle *handle, int events,
                                   aws_event_loop_on_event on_event, void *ctx) {

    struct epoll_event_data *epoll_event_data = (struct epoll_event_data *)aws_mem_acquire(event_loop->alloc, sizeof(struct epoll_event_data));
    handle->private_event_loop_data = NULL;

    if (!epoll_event_data) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    epoll_event_data->alloc = event_loop->alloc;
    epoll_event_data->ctx = ctx;
    epoll_event_data->handle = handle;
    epoll_event_data->on_event = on_event;

    /*everyone is always registered for edge-triggered, hang up, remote hang up, errors. */
    uint32_t event_mask = EPOLLET | EPOLLHUP | EPOLLRDHUP | EPOLLERR;

    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        event_mask |= EPOLLIN;
    }

    if (events & AWS_IO_EVENT_TYPE_WRITABLE) {
        event_mask |= EPOLLOUT;
    }

    /* this guy is copied by epoll_ctl */
    struct epoll_event epoll_event = {
            .data = {
                    .ptr = epoll_event_data
            },
            .events = event_mask
    };

    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;

    if (epoll_ctl(epoll_loop->epoll_fd, EPOLL_CTL_ADD, handle->handle, &epoll_event)) {
        aws_mem_release(event_loop->alloc, epoll_event_data);
        return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }

    handle->private_event_loop_data = epoll_event_data;

    return AWS_OP_SUCCESS;
}

static int unsubscribe_from_io_events (struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;

    struct epoll_event compat_event = {
        .data = { .ptr = NULL },
        .events = 0
    };

    if (epoll_ctl(epoll_loop->epoll_fd, EPOLL_CTL_DEL, handle->handle, &compat_event)) {
        return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }

    if (handle->private_event_loop_data) {
        aws_mem_release(event_loop->alloc, handle->private_event_loop_data);
        handle->private_event_loop_data = NULL;
    }

    return AWS_OP_SUCCESS;
}

static bool is_on_callers_thread (struct aws_event_loop * event_loop) {
    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;

    return aws_thread_current_thread_id() == aws_thread_get_id(&epoll_loop->thread);
}

/* We treat the pipe fd with a subscription to io events just like any other managed file descriptor.
 * This is the event handler for events on that pipe.*/
static void on_tasks_to_schedule(struct aws_event_loop *event_loop, struct aws_io_handle *handle, int events, void *ctx) {
    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;

    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        struct pipe_task_data *task_data = NULL;

        size_t read = 0;
        struct aws_byte_buf pipe_read_buf = {
                .buffer = (uint8_t *)&task_data,
                .len = sizeof(void *),
        };

        /* several tasks could have been written, make sure we process all of them. */
        while (!aws_pipe_read(handle, &pipe_read_buf, &read) && read == sizeof(void *)) {
            aws_task_scheduler_schedule_future(&epoll_loop->scheduler, &task_data->task, task_data->timestamp);
            aws_mem_release(event_loop->alloc, task_data);
        }
    }
}

static void main_loop (void *args) {
    struct aws_event_loop *event_loop = (struct aws_event_loop *)args;
    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;

    if (aws_task_scheduler_init(&epoll_loop->scheduler, event_loop->alloc, event_loop->clock)) {
        return;
    }

    if (subscribe_to_io_events(event_loop, &epoll_loop->read_task_handle, AWS_IO_EVENT_TYPE_READABLE, on_tasks_to_schedule, NULL)) {
        return;
    }

    int timeout = DEFAULT_TIMEOUT;

    struct epoll_event events[MAX_EVENTS];

    /*
     * until stop is called,
     * call epoll_wait, if a task is scheduled, or a file descriptor has activity, it will
     * return.
     *
     * Then run all currently scheduled tasks.
     *
     * Then process all events,
     *
     * then run all scheduled tasks again.
     */
    while ( epoll_loop->should_continue ) {
        int event_count = epoll_wait(epoll_loop->epoll_fd, events, MAX_EVENTS, timeout);
        aws_task_scheduler_run_all(&epoll_loop->scheduler, NULL);

        for (int i = 0; i < event_count; ++i) {
            struct epoll_event_data *event_data = (struct epoll_event_data *)events[i].data.ptr;

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

            event_data->on_event(event_loop, event_data->handle, event_mask, event_data->ctx);
        }

        /* timeout should be the next scheduled task time if that time is closer than the default timeout. */
        timeout = DEFAULT_TIMEOUT;
        uint64_t next_run_time = 0;
        aws_task_scheduler_run_all(&epoll_loop->scheduler, &next_run_time);

        int scheduler_timeout = (int)(next_run_time / NANO_TO_MILLIS);
        timeout = scheduler_timeout > 0 && timeout > scheduler_timeout ? scheduler_timeout : timeout;
    }

    unsubscribe_from_io_events(event_loop, &epoll_loop->read_task_handle);

    /*
     * If the user passed a promise to stop, execute it now.
     */
    if (epoll_loop->stopped_promise) {
        epoll_loop->stopped_promise(event_loop, epoll_loop->stop_ctx);
    }

    aws_task_scheduler_clean_up(&epoll_loop->scheduler);
}

