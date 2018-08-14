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

#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/thread.h>
#include <sys/epoll.h>

#include <errno.h>
#include <unistd.h>

#if !defined(COMPAT_MODE) && defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 8
#    define USE_EFD 1
#else
#    define USE_EFD 0
#endif

#if USE_EFD
#    include <sys/eventfd.h>
#else
#    include <aws/io/pipe.h>
#endif

static void s_destroy(struct aws_event_loop *event_loop);
static int s_run(struct aws_event_loop *event_loop);
static int s_stop(struct aws_event_loop *event_loop);
static int s_wait_for_stop_completion(struct aws_event_loop *event_loop);
static int s_schedule_task(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at);
static int s_subscribe_to_io_events(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    aws_event_loop_on_event_fn *on_event,
    void *user_data);
static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle);
static bool s_is_on_callers_thread(struct aws_event_loop *event_loop);

static void s_main_loop(void *args);

static struct aws_event_loop_vtable s_vtable = {
    .destroy = s_destroy,
    .run = s_run,
    .stop = s_stop,
    .wait_for_stop_completion = s_wait_for_stop_completion,
    .schedule_task = s_schedule_task,
    .subscribe_to_io_events = s_subscribe_to_io_events,
    .unsubscribe_from_io_events = s_unsubscribe_from_io_events,
    .is_on_callers_thread = s_is_on_callers_thread,
};

struct epoll_loop {
    struct aws_task_scheduler scheduler;
    struct aws_thread thread;
    struct aws_io_handle read_task_handle;
    struct aws_io_handle write_task_handle;
    struct aws_mutex task_pre_queue_mutex;
    struct aws_linked_list task_pre_queue;
    struct aws_linked_list cleanup_list;
    int epoll_fd;
    bool should_continue;
};

struct task_data {
    struct aws_task task;
    uint64_t timestamp;
    struct aws_linked_list_node queue_handle;
};

struct epoll_event_data {
    struct aws_allocator *alloc;
    struct aws_io_handle *handle;
    aws_event_loop_on_event_fn *on_event;
    void *user_data;
    struct aws_linked_list_node list_handle;
};

/* default timeout is 100 seconds */
enum {
    DEFAULT_TIMEOUT = 100 * 1000,
    MAX_EVENTS = 100,
    NANO_TO_MILLIS = 1000000,
};

/* Setup edge triggered epoll with a scheduler. */
struct aws_event_loop *aws_event_loop_new_default(struct aws_allocator *alloc, aws_io_clock_fn *clock) {
    struct aws_event_loop *loop = aws_mem_acquire(alloc, sizeof(struct aws_event_loop));

    if (!loop) {
        return NULL;
    }

    if (aws_event_loop_init_base(loop, alloc, clock)) {
        goto clean_up_loop;
    }

    struct epoll_loop *epoll_loop = aws_mem_acquire(alloc, sizeof(struct epoll_loop));

    if (!epoll_loop) {
        goto clean_up_loop;
    }

    aws_linked_list_init(&epoll_loop->task_pre_queue);
    epoll_loop->task_pre_queue_mutex = (struct aws_mutex)AWS_MUTEX_INIT;

    epoll_loop->epoll_fd = epoll_create(100);
    if (epoll_loop->epoll_fd < 0) {
        aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
        goto cleanup_base_loop;
    }

    if (aws_thread_init(&epoll_loop->thread, alloc)) {
        goto clean_up_epoll;
    }

#if USE_EFD
    int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

    if (fd < 0) {
        aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
        goto clean_up_thread;
    }

    epoll_loop->write_task_handle = (struct aws_io_handle){.data.fd = fd, .additional_data = NULL};
    epoll_loop->read_task_handle = (struct aws_io_handle){.data.fd = fd, .additional_data = NULL};
#else
    /* this pipe is for task scheduling. */
    if (aws_pipe_open(&epoll_loop->read_task_handle, &epoll_loop->write_task_handle)) {
        goto clean_up_thread;
    }
#endif

    if (aws_task_scheduler_init(&epoll_loop->scheduler, alloc, loop->clock)) {
        goto clean_up_pipe;
    }

    epoll_loop->should_continue = false;
    aws_linked_list_init(&epoll_loop->cleanup_list);

    loop->impl_data = epoll_loop;
    loop->vtable = s_vtable;

    return loop;

clean_up_pipe:
#if USE_EFD
    close(epoll_loop->write_task_handle.data.fd);
    epoll_loop->write_task_handle.data.fd = -1;
    epoll_loop->read_task_handle.data.fd = -1;
#else
    aws_pipe_close(&epoll_loop->read_task_handle, &epoll_loop->write_task_handle);
#endif

clean_up_thread:
    aws_thread_clean_up(&epoll_loop->thread);

clean_up_epoll:
    if (epoll_loop->epoll_fd >= 0) {
        close(epoll_loop->epoll_fd);
    }

    aws_mem_release(alloc, epoll_loop);

cleanup_base_loop:
    aws_event_loop_clean_up_base(loop);

clean_up_loop:
    aws_mem_release(alloc, loop);

    return NULL;
}

static void s_destroy(struct aws_event_loop *event_loop) {
    struct epoll_loop *epoll_loop = event_loop->impl_data;

    /* we don't know if stop() has been called by someone else,
     * just call stop() again and wait for event-loop to finish. */
    aws_event_loop_stop(event_loop);
    s_wait_for_stop_completion(event_loop);

    aws_task_scheduler_clean_up(&epoll_loop->scheduler);
    aws_thread_clean_up(&epoll_loop->thread);
#if USE_EFD
    close(epoll_loop->write_task_handle.data.fd);
    epoll_loop->write_task_handle.data.fd = -1;
    epoll_loop->read_task_handle.data.fd = -1;
#else
    aws_pipe_close(&epoll_loop->read_task_handle, &epoll_loop->write_task_handle);
#endif

    close(epoll_loop->epoll_fd);
    aws_mem_release(event_loop->alloc, epoll_loop);
    aws_event_loop_clean_up_base(event_loop);
    aws_mem_release(event_loop->alloc, event_loop);
}

static int s_run(struct aws_event_loop *event_loop) {
    struct epoll_loop *epoll_loop = event_loop->impl_data;

    epoll_loop->should_continue = true;
    if (aws_thread_launch(&epoll_loop->thread, &s_main_loop, event_loop, NULL)) {
        epoll_loop->should_continue = false;
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_stop_task(void *args, enum aws_task_status status) {

    struct aws_event_loop *event_loop = args;
    struct epoll_loop *epoll_loop = event_loop->impl_data;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        /*
         * this allows the event loop to invoke the callback once the event loop has completed.
         */
        epoll_loop->should_continue = false;
    }
}

static int s_stop(struct aws_event_loop *event_loop) {
    struct aws_task task = {
        .arg = event_loop,
        .fn = s_stop_task,
    };

    uint64_t timestamp = 0;
    event_loop->clock(&timestamp);

    if (s_schedule_task(event_loop, &task, timestamp)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_wait_for_stop_completion(struct aws_event_loop *event_loop) {
    struct epoll_loop *epoll_loop = event_loop->impl_data;
    return aws_thread_join(&epoll_loop->thread);
}

static int s_schedule_task(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at) {
    struct epoll_loop *epoll_loop = event_loop->impl_data;

    /* if event loop and the caller are the same thread, just schedule and be done with it. */
    if (s_is_on_callers_thread(event_loop)) {
        return aws_task_scheduler_schedule_future(&epoll_loop->scheduler, task, run_at);
    }

    struct task_data *task_data = aws_mem_acquire(event_loop->alloc, sizeof(struct task_data));

    if (!task_data) {
        return AWS_OP_ERR;
    }

    task_data->task = *task;
    task_data->timestamp = run_at;
    aws_mutex_lock(&epoll_loop->task_pre_queue_mutex);

    uint64_t counter = 1;

    /* if the list is not empty, we already have a pending read on the pipe/eventfd, no need to write again. */
    if (aws_linked_list_empty(&epoll_loop->task_pre_queue)) {
        /* If the write fails because the buffer is full, we don't actually care because that means there's a pending
         * read on the pipe/eventfd and thus the event loop will end up checking to see if something has been queued.*/
        if (AWS_UNLIKELY(
                write(epoll_loop->write_task_handle.data.fd, (void *)&counter, sizeof(counter)) != sizeof(counter) &&
                errno != EAGAIN)) {
            aws_mutex_unlock(&epoll_loop->task_pre_queue_mutex);
            return AWS_OP_ERR;
        }
    }

    aws_linked_list_push_back(&epoll_loop->task_pre_queue, &task_data->queue_handle);
    aws_mutex_unlock(&epoll_loop->task_pre_queue_mutex);

    return AWS_OP_SUCCESS;
}

static int s_subscribe_to_io_events(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    aws_event_loop_on_event_fn *on_event,
    void *user_data) {

    struct epoll_event_data *epoll_event_data = aws_mem_acquire(event_loop->alloc, sizeof(struct epoll_event_data));
    handle->additional_data = NULL;

    if (!epoll_event_data) {
        return AWS_OP_ERR;
    }

    struct epoll_loop *epoll_loop = event_loop->impl_data;

    epoll_event_data->alloc = event_loop->alloc;
    epoll_event_data->user_data = user_data;
    epoll_event_data->handle = handle;
    epoll_event_data->on_event = on_event;
    epoll_event_data->list_handle.next = NULL;
    epoll_event_data->list_handle.prev = NULL;

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
        .data = {.ptr = epoll_event_data},
        .events = event_mask,
    };

    if (epoll_ctl(epoll_loop->epoll_fd, EPOLL_CTL_ADD, handle->data.fd, &epoll_event)) {
        aws_mem_release(event_loop->alloc, epoll_event_data);
        return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }

    handle->additional_data = epoll_event_data;

    return AWS_OP_SUCCESS;
}

static void s_process_unsubscribe_cleanup_list(struct epoll_loop *event_loop) {

    while (!aws_linked_list_empty(&event_loop->cleanup_list)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&event_loop->cleanup_list);
        struct epoll_event_data *event_data = AWS_CONTAINER_OF(node, struct epoll_event_data, list_handle);
        aws_mem_release(event_data->alloc, (void *)event_data);
    }
}

static void s_unsubscribe_cleanup_task(void *arg, enum aws_task_status status) {
    struct epoll_event_data *event_data = (struct epoll_event_data *)arg;
    aws_mem_release(event_data->alloc, (void *)event_data);
}

static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    struct epoll_loop *epoll_loop = event_loop->impl_data;

    struct epoll_event compat_event = {
        .data = {.ptr = handle->additional_data},
        .events = 0,
    };

    /* We can't clean up yet, because we have schedule tasks and more events to process, add it to the cleanup list
     * and we'll process it after everything is finished for this event loop tick. */
    if (s_is_on_callers_thread(event_loop) && handle->additional_data) {
        aws_linked_list_push_back(
            &epoll_loop->cleanup_list, &((struct epoll_event_data *)handle->additional_data)->list_handle);
    } else if (handle->additional_data) {
        struct aws_task task = {
            .arg = handle->additional_data,
            .fn = s_unsubscribe_cleanup_task,
        };

        uint64_t timestamp = 0;
        if (event_loop->clock(&timestamp)) {
            return AWS_OP_ERR;
        }

        if (s_schedule_task(event_loop, &task, timestamp)) {
            return AWS_OP_ERR;
        }
    }

    handle->additional_data = NULL;

    if (AWS_UNLIKELY(epoll_ctl(epoll_loop->epoll_fd, EPOLL_CTL_DEL, handle->data.fd, &compat_event))) {
        return aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    }

    return AWS_OP_SUCCESS;
}

static bool s_is_on_callers_thread(struct aws_event_loop *event_loop) {
    struct epoll_loop *epoll_loop = event_loop->impl_data;

    return aws_thread_current_thread_id() == aws_thread_get_id(&epoll_loop->thread);
}

/* We treat the pipe fd with a subscription to io events just like any other managed file descriptor.
 * This is the event handler for events on that pipe.*/
static void s_on_tasks_to_schedule(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data) {
    struct epoll_loop *epoll_loop = event_loop->impl_data;
    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        uint64_t count_ignore = 0;

        aws_mutex_lock(&epoll_loop->task_pre_queue_mutex);

        /* several tasks could theoretically have been written (though this should never happen), make sure we drain the
         * eventfd/pipe. */
        while (read(epoll_loop->read_task_handle.data.fd, &count_ignore, sizeof(count_ignore)) > -1) {
            continue;
        }

        while (!aws_linked_list_empty(&epoll_loop->task_pre_queue)) {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&epoll_loop->task_pre_queue);
            struct task_data *task_data = AWS_CONTAINER_OF(node, struct task_data, queue_handle);
            aws_task_scheduler_schedule_future(&epoll_loop->scheduler, &task_data->task, task_data->timestamp);
            aws_mem_release(event_loop->alloc, task_data);
        }

        aws_linked_list_init(&epoll_loop->task_pre_queue);
        aws_mutex_unlock(&epoll_loop->task_pre_queue_mutex);
    }
}

static void s_main_loop(void *args) {
    struct aws_event_loop *event_loop = args;
    struct epoll_loop *epoll_loop = event_loop->impl_data;

    int err = s_subscribe_to_io_events(
        event_loop, &epoll_loop->read_task_handle, AWS_IO_EVENT_TYPE_READABLE, s_on_tasks_to_schedule, NULL);
    if (err) {
        return;
    }

    int timeout = DEFAULT_TIMEOUT;

    struct epoll_event events[MAX_EVENTS];

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
    while (epoll_loop->should_continue) {
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

            event_data->on_event(event_loop, event_data->handle, event_mask, event_data->user_data);
        }

        /* timeout should be the next scheduled task time if that time is closer than the default timeout. */
        uint64_t next_run_time = 0;
        aws_task_scheduler_run_all(&epoll_loop->scheduler, &next_run_time);
        s_process_unsubscribe_cleanup_list(epoll_loop);

        if (next_run_time) {
            uint64_t offset = 0;
            event_loop->clock(&offset);

            if (offset >= next_run_time) {
                timeout = 0;
            } else {
                next_run_time -= offset;
                int scheduler_timeout = (int)(next_run_time / NANO_TO_MILLIS);
                /* this conversion is lossy, 0 means the task is scheduled within the millisecond,
                 * but not quite ready. so just sleep one ms*/
                timeout = scheduler_timeout > 0
                              ? scheduler_timeout < DEFAULT_TIMEOUT ? scheduler_timeout : DEFAULT_TIMEOUT
                              : 1;
            }
        } else {
            timeout = DEFAULT_TIMEOUT;
        }
    }

    s_unsubscribe_from_io_events(event_loop, &epoll_loop->read_task_handle);
    s_process_unsubscribe_cleanup_list(epoll_loop);
}
