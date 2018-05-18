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
#include <aws/common/mutex.h>
#include <aws/common/condition_variable.h>

#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>

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
        return NULL;
    }

    if (aws_event_loop_base_init(loop, alloc, clock)) {
        goto clean_up_loop;
    }

    struct epoll_loop *epoll_loop = aws_mem_acquire(alloc, sizeof(struct epoll_loop));

    if (!epoll_loop) {
        aws_raise_error(AWS_ERROR_OOM);
        goto clean_up_loop;
    }

    epoll_loop->epoll_fd = epoll_create(100);
    if (epoll_loop->epoll_fd < 0) {
        goto clean_up_epoll;
    }

    if (aws_thread_init(&epoll_loop->thread, alloc)) {
        goto clean_up_epoll;
    }

    /* this pipe is for task scheduling. */
    if (aws_pipe_open(&epoll_loop->read_task_handle, &epoll_loop->write_task_handle)) {
        goto clean_up_thread;
    }

    if (aws_task_scheduler_init(&epoll_loop->scheduler, alloc, loop->clock)) {
        goto clean_up_pipe;
    }

    epoll_loop->should_continue = false;
    epoll_loop->stopped_promise = NULL;
    epoll_loop->stop_ctx = NULL;

    loop->impl_data = epoll_loop;
    loop->vtable = vtable;

    return loop;

clean_up_pipe:
    aws_pipe_close(&epoll_loop->read_task_handle, &epoll_loop->write_task_handle);

clean_up_thread:
    aws_thread_clean_up(&epoll_loop->thread);

clean_up_epoll:
    if (epoll_loop->epoll_fd >= 0) {
        close (epoll_loop->epoll_fd);
    }

    aws_mem_release(alloc, epoll_loop);

clean_up_loop:

     aws_event_loop_base_clean_up(loop);
     aws_mem_release(alloc, loop);

    return NULL;
}

struct epoll_loop_stopped_args {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    bool stopped;
};

static void on_epoll_loop_stopped(struct aws_event_loop *event_loop, void *ctx) {
    struct epoll_loop_stopped_args *args = (struct epoll_loop_stopped_args *)ctx;

    args->stopped = true;
    aws_condition_variable_notify_one(&args->condition_variable);
}

static bool epoll_loop_stopped_predicate(void *arg) {
    struct epoll_loop_stopped_args *event_loop_stopped_args = (struct epoll_loop_stopped_args *)arg;

    return event_loop_stopped_args->stopped;
}

static void destroy(struct aws_event_loop *event_loop) {
    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;

    /* if event loop is still running, it needs to be shut down in line */
    if (epoll_loop->should_continue) {
        struct epoll_loop_stopped_args stop_args = {
                .mutex = AWS_MUTEX_INIT,
                .condition_variable = AWS_CONDITION_VARIABLE_INIT,
                .stopped = false
        };

        aws_mutex_lock(&stop_args.mutex);
        aws_event_loop_stop(event_loop, on_epoll_loop_stopped, &stop_args);
        aws_condition_variable_wait_pred(&stop_args.condition_variable, &stop_args.mutex, epoll_loop_stopped_predicate, &stop_args);
    }

    aws_task_scheduler_clean_up(&epoll_loop->scheduler);
    aws_thread_clean_up(&epoll_loop->thread);
    aws_pipe_close(&epoll_loop->read_task_handle, &epoll_loop->write_task_handle);
    close (epoll_loop->epoll_fd);
    aws_mem_release(event_loop->alloc, epoll_loop);
    aws_mem_release(event_loop->alloc, event_loop);
}

static int run (struct aws_event_loop *event_loop) {
    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;

    epoll_loop->should_continue = true;
    return aws_thread_launch(&epoll_loop->thread, &main_loop, event_loop, NULL);
}

static void stop_task (void *args, aws_task_status status) {
    struct stop_task_args *stop_task = (struct stop_task_args *)args;
    struct epoll_loop *epoll_loop = (struct epoll_loop *)stop_task->event_loop->impl_data;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        /*
         * this allows the event loop to invoke the promise once the event loop has completed.
         */
        epoll_loop->should_continue = false;
        epoll_loop->stopped_promise = stop_task->promise;
        epoll_loop->stop_ctx = stop_task->stop_ctx;
    }

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

    struct pipe_task_data pipe_data = {
            .task = *task,
            .timestamp = run_at
    };

    size_t written = 0;
    struct aws_byte_buf task_buf = {
            .buffer = (uint8_t *)&pipe_data,
            .len = sizeof(struct pipe_task_data),
    };

    if (aws_pipe_write(&epoll_loop->write_task_handle, &task_buf, &written) || written != sizeof(struct pipe_task_data)) {
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

struct finalize_unsubscribe_args {
    struct aws_allocator *alloc;
    struct epoll_event_data *event_data;
};

static void finalize_unsubscribe(void *args, aws_task_status status) {
    struct finalize_unsubscribe_args *unsubscribe_args = (struct finalize_unsubscribe_args *)args;
    aws_mem_release(unsubscribe_args->alloc, unsubscribe_args->event_data);
    aws_mem_release(unsubscribe_args->alloc, unsubscribe_args);
}

/*
 * This is here to address a race condition where an event handler, unsubscribed another event from notifications,
 * in that case the epoll set would contain bad memory when we try to access it. Instead, free up the memory in a task
 * that is guaranteed to run after the events are handled.
 */
static int schedule_unsubscribe_cleanup(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;

    /*
     * The task scheduler pipe should only ever be getting unregistered from the event loop's termination.
     * go ahead and clean it up immediately without out a task.
     */
    if (AWS_UNLIKELY(epoll_loop->read_task_handle.handle == handle->handle)) {
        aws_mem_release(event_loop->alloc, handle->private_event_loop_data);
        handle->private_event_loop_data = NULL;
    }

    if(handle->private_event_loop_data) {
        struct finalize_unsubscribe_args *unsubscribe_args =
                (struct finalize_unsubscribe_args *) aws_mem_acquire(event_loop->alloc,
                                                                     sizeof(struct finalize_unsubscribe_args));

        if (!unsubscribe_args) {
            return aws_raise_error(AWS_ERROR_OOM);
        }

        unsubscribe_args->alloc = event_loop->alloc;
        unsubscribe_args->event_data = handle->private_event_loop_data;

        struct aws_task task = {
                .fn = finalize_unsubscribe,
                .arg = unsubscribe_args
        };

        uint64_t now = 0;
        if (event_loop->clock(&now)) {
            aws_mem_release(event_loop->alloc, unsubscribe_args);
            return AWS_OP_ERR;
        }

        handle->private_event_loop_data = NULL;

        return aws_event_loop_schedule_task(event_loop, &task, now);
    }
}

static int unsubscribe_from_io_events (struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;

    struct epoll_event compat_event = {
        .data = { .ptr = handle->private_event_loop_data },
        .events = 0
    };

    if (AWS_UNLIKELY(epoll_ctl(epoll_loop->epoll_fd, EPOLL_CTL_DEL, handle->handle, &compat_event))) {
        int err = errno;
        if (handle->private_event_loop_data && (err == ENOENT || err == EBADF)) {
            schedule_unsubscribe_cleanup(event_loop, handle);
        }

        return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }

    if (handle->private_event_loop_data) {
        return schedule_unsubscribe_cleanup(event_loop, handle);
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
        struct pipe_task_data task_data = {0};

        size_t read = 0;
        struct aws_byte_buf pipe_read_buf = {
                .buffer = (uint8_t *)&task_data,
                .len = sizeof(struct pipe_task_data),
        };

        /* several tasks could have been written, make sure we process all of them. */
        while (!aws_pipe_read(handle, &pipe_read_buf, &read) && read == sizeof(struct pipe_task_data)) {
            aws_task_scheduler_schedule_future(&epoll_loop->scheduler, &task_data.task, task_data.timestamp);
        }
    }
}

static void main_loop (void *args) {
    struct aws_event_loop *event_loop = (struct aws_event_loop *)args;
    struct epoll_loop *epoll_loop = (struct epoll_loop *)event_loop->impl_data;

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
        uint64_t next_run_time = 0;
        aws_task_scheduler_run_all(&epoll_loop->scheduler, &next_run_time);

        if (next_run_time) {
            uint64_t offset = 0;
            event_loop->clock(&offset);
            next_run_time -= offset;
            int scheduler_timeout = (int)(next_run_time / NANO_TO_MILLIS);
            /* this conversion is lossy, 0 means the task is scheduled within the millisecond,
             * but not quite ready. so just sleep one ms*/
            timeout = scheduler_timeout > 0 ?
                                              scheduler_timeout < DEFAULT_TIMEOUT ? scheduler_timeout :DEFAULT_TIMEOUT
                      : 1;
        }
        else {
            timeout = DEFAULT_TIMEOUT;
        }
    }

    unsubscribe_from_io_events(event_loop, &epoll_loop->read_task_handle);

    /*
     * If the user passed a promise to stop, execute it now.
     */
    if (epoll_loop->stopped_promise) {
        epoll_loop->stopped_promise(event_loop, epoll_loop->stop_ctx);
    }
}

