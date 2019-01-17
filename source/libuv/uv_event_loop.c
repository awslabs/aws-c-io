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

#include <aws/common/clock.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/thread.h>

#include <uv.h>

/* Poison queue_work, this spawns threads */
#pragma GCC poison uv_queue_work

struct libuv_loop {
    uv_loop_t *uv_loop;
    bool owns_uv_loop;
    union {
        struct libuv_owned *uv_owned;
        struct libuv_unowned *uv_unowned;
    } ownership_specific;

    uv_idle_t task_runner_idle;

    struct {
        struct aws_mutex mutex;
        struct aws_linked_list tasks_to_schedule;
        uv_async_t schedule_tasks_async;
    } cross_thread_data;

    struct {
        struct aws_task_scheduler scheduler;
    } on_thread_data;
};

enum event_thread_state {
    EVENT_THREAD_STATE_READY_TO_RUN,
    EVENT_THREAD_STATE_RUNNING,
    EVENT_THREAD_STATE_STOPPING,
};

/** This struct is owned by libuv_loop if the uv_loop is owned by us */
struct libuv_owned {
    struct aws_thread thread;
    enum event_thread_state state;
    /* Send this to stop the event loop */
    uv_async_t stop_thread_async;
};
static struct libuv_owned *s_owned(struct libuv_loop *loop) {
    assert(loop->owns_uv_loop);
    return loop->ownership_specific.uv_owned;
}

/** This struct is owned by libuv_loop if the uv_loop is NOT owned by us */
struct libuv_unowned {
    uint64_t uv_thread_id;
    uv_async_t get_thread_id_async;
};
static struct libuv_unowned *s_unowned(struct libuv_loop *loop) {
    assert(!loop->owns_uv_loop);
    return loop->ownership_specific.uv_unowned;
}

struct handle_data {
    uv_poll_t poll;
    struct aws_io_handle *owner;
    struct aws_event_loop *event_loop;
    aws_event_loop_on_event_fn *on_event;
    void *on_event_user_data;
};

/* vtable declarations */
static void s_destroy(struct aws_event_loop *event_loop);
static bool s_is_on_callers_thread(struct aws_event_loop *event_loop);
static int s_run(struct aws_event_loop *event_loop);
static int s_stop(struct aws_event_loop *event_loop);
static int s_wait_for_stop_completion(struct aws_event_loop *event_loop);
static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task);
static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos);

static void s_uv_close_handle(uv_handle_t *handle) {
    struct libuv_loop *impl = handle->data;

    if (handle == (uv_handle_t *)&impl->task_runner_idle) {
        printf("Closing task_runner_idle\n");
    } else if (handle == (uv_handle_t *)&impl->cross_thread_data.schedule_tasks_async) {
        printf("Closing schedule_tasks_async\n");
    } else if (impl->owns_uv_loop) {
        if (handle == (uv_handle_t *)&s_owned(impl)->stop_thread_async) {
            printf("Closing stop_thread_async\n");
        }
    } else if (!impl->owns_uv_loop) {
        if (handle == (uv_handle_t *)&s_unowned(impl)->get_thread_id_async) {
            printf("Closing get_thread_id_async\n");
        }
    }
}

/* vtable implementations */
static void s_destroy(struct aws_event_loop *event_loop) {

    s_stop(event_loop);
    s_wait_for_stop_completion(event_loop);

    struct libuv_loop *impl = event_loop->impl_data;

    if (impl->owns_uv_loop) {
        assert(!uv_loop_alive(impl->uv_loop));
        int result = uv_loop_close(impl->uv_loop);
        assert(result == 0);
        aws_thread_clean_up(&s_owned(impl)->thread);
    }
    impl->uv_loop = NULL;

    aws_mutex_clean_up(&impl->cross_thread_data.mutex);
    /* Tasks in scheduler get cancelled*/
    aws_task_scheduler_clean_up(&impl->on_thread_data.scheduler);

    /* Cancel pending tasks */
    while (!aws_linked_list_empty(&impl->cross_thread_data.tasks_to_schedule)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&impl->cross_thread_data.tasks_to_schedule);
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
        task->fn(task, task->arg, AWS_TASK_STATUS_CANCELED);
    }

    aws_event_loop_clean_up_base(event_loop);
    aws_mem_release(event_loop->alloc, event_loop);
}

static void s_run_tasks(uv_idle_t *idle) {
    struct libuv_loop *impl = idle->data;

    // printf("running tasks\n");

    struct aws_event_loop *event_loop = (struct aws_event_loop *)((uint8_t *)impl - sizeof(struct aws_event_loop));

    /* Run scheduled tasks */
    uint64_t now_ns = 0;
    event_loop->clock(&now_ns);
    aws_task_scheduler_run_all(&impl->on_thread_data.scheduler, now_ns);
}

static void s_thread_loop(void *args) {
    struct libuv_loop *impl = args;

    s_owned(impl)->state = EVENT_THREAD_STATE_RUNNING;

    while (true) {
        uv_run(impl->uv_loop, UV_RUN_DEFAULT);

        if (s_owned(impl)->state == EVENT_THREAD_STATE_STOPPING) {
            printf("Stopping loop, no more uv runs\n");
            break;
        }
    }

    s_owned(impl)->state = EVENT_THREAD_STATE_READY_TO_RUN;
}

/* Wakes up the event loop and passes pending tasks to the real task scheduler */
static void s_uv_async_schedule_tasks(uv_async_t *request) {
    struct libuv_loop *impl = request->data;
    assert(impl);

    // printf("Scheduling tasks\n");

    /* If there are tasks to schedule, grab them all out of synced_data.tasks_to_schedule.
     * We'll process them later, so that we minimize time spent holding the mutex. */
    struct aws_linked_list tasks_to_schedule;
    aws_linked_list_init(&tasks_to_schedule);

    {
        aws_mutex_lock(&impl->cross_thread_data.mutex);
        aws_linked_list_swap_contents(&impl->cross_thread_data.tasks_to_schedule, &tasks_to_schedule);
        aws_mutex_unlock(&impl->cross_thread_data.mutex);
    }

    while (!aws_linked_list_empty(&tasks_to_schedule)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&tasks_to_schedule);
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);

        /* Timestamp 0 is used to denote "now" tasks */
        if (task->timestamp == 0) {
            aws_task_scheduler_schedule_now(&impl->on_thread_data.scheduler, task);
        } else {
            aws_task_scheduler_schedule_future(&impl->on_thread_data.scheduler, task, task->timestamp);
        }
    }
}

/* Wakes up the event loop and stops it */
static void s_uv_async_stop_loop(uv_async_t *request) {
    struct libuv_loop *impl = request->data;
    assert(impl);

    s_owned(impl)->state = EVENT_THREAD_STATE_STOPPING;
    uv_close((uv_handle_t *)request, s_uv_close_handle);
    uv_stop(impl->uv_loop);
}

static int s_run(struct aws_event_loop *event_loop) {
    struct libuv_loop *impl = event_loop->impl_data;

    if (uv_async_init(impl->uv_loop, &impl->cross_thread_data.schedule_tasks_async, s_uv_async_schedule_tasks)) {
        return AWS_OP_ERR;
    }
    impl->cross_thread_data.schedule_tasks_async.data = impl;

    if (uv_idle_init(impl->uv_loop, &impl->task_runner_idle)) {
        return AWS_OP_ERR;
    }
    impl->task_runner_idle.data = impl;
    uv_idle_start(&impl->task_runner_idle, s_run_tasks);

    if (impl->owns_uv_loop) {
        assert(s_owned(impl)->state == EVENT_THREAD_STATE_READY_TO_RUN);

        /* Prep the stop async */
        uv_async_init(impl->uv_loop, &s_owned(impl)->stop_thread_async, s_uv_async_stop_loop);
        s_owned(impl)->stop_thread_async.data = impl;

        if (aws_thread_launch(&s_owned(impl)->thread, &s_thread_loop, impl, NULL)) {
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_stop(struct aws_event_loop *event_loop) {
    struct libuv_loop *impl = event_loop->impl_data;

    if (uv_idle_stop(&impl->task_runner_idle)) {
        return AWS_OP_ERR;
    }
    uv_close((uv_handle_t *)&impl->task_runner_idle, s_uv_close_handle);

    if (impl->owns_uv_loop) {
        if (uv_async_send(&s_owned(impl)->stop_thread_async)) {
            return AWS_OP_ERR;
        }
    }

    uv_close((uv_handle_t *)&impl->cross_thread_data.schedule_tasks_async, s_uv_close_handle);

    return AWS_OP_SUCCESS;
}

static int s_wait_for_stop_completion(struct aws_event_loop *event_loop) {
    struct libuv_loop *impl = event_loop->impl_data;

    int status = AWS_OP_SUCCESS;

    if (impl->owns_uv_loop) {
        status = aws_thread_join(&s_owned(impl)->thread);
    }

    return status;
}

static void s_schedule_task_common(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    struct libuv_loop *impl = event_loop->impl_data;

    /* If we're on the event-thread, just schedule it directly */
    if (s_is_on_callers_thread(event_loop)) {
        if (run_at_nanos == 0) {
            aws_task_scheduler_schedule_now(&impl->on_thread_data.scheduler, task);
        } else {
            aws_task_scheduler_schedule_future(&impl->on_thread_data.scheduler, task, run_at_nanos);
        }
        return;
    }

    /* Otherwise, add it to cross_thread_data.tasks_to_schedule and signal the event-thread to process it */
    task->timestamp = run_at_nanos;

    /* Begin critical section */
    aws_mutex_lock(&impl->cross_thread_data.mutex);

    bool should_signal_thread = aws_linked_list_empty(&impl->cross_thread_data.tasks_to_schedule);
    aws_linked_list_push_back(&impl->cross_thread_data.tasks_to_schedule, &task->node);

    /* Signal thread that cross_thread_data has changed (unless it's been signaled already) */
    if (should_signal_thread) {
        uv_async_send(&impl->cross_thread_data.schedule_tasks_async);
    }

    aws_mutex_unlock(&impl->cross_thread_data.mutex);
    /* End critical section */
}

static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task) {
    s_schedule_task_common(event_loop, task, 0 /* zero denotes "now" task */);
}

static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    s_schedule_task_common(event_loop, task, run_at_nanos);
}

static void s_cancel_task(struct aws_event_loop *event_loop, struct aws_task *task) {
    struct libuv_loop *impl = event_loop->impl_data;
    aws_task_scheduler_cancel_task(&impl->on_thread_data.scheduler, task);
}

static void s_uv_poll_cb(uv_poll_t *handle, int status, int events) {

    struct handle_data *handle_data = handle->data;
    int aws_events = 0;

    if (status >= 0) {
        if (events & UV_DISCONNECT) {
            aws_events |= AWS_IO_EVENT_TYPE_CLOSED;
        }
        if (events & UV_READABLE) {
            aws_events |= AWS_IO_EVENT_TYPE_READABLE;
        }
        if (events & UV_WRITABLE) {
            aws_events |= AWS_IO_EVENT_TYPE_WRITABLE;
        }
    } else {
        aws_events = AWS_IO_EVENT_TYPE_ERROR;
    }

    handle_data->on_event(handle_data->event_loop, handle_data->owner, aws_events, handle_data->on_event_user_data);
}

static int s_subscribe_to_io_events(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    aws_event_loop_on_event_fn *on_event,
    void *user_data) {

    assert(event_loop);
    assert(handle->data.fd != -1);
    assert(handle->additional_data == NULL);
    assert(on_event);
    /* Must subscribe for read, write, or both */
    assert(events & (AWS_IO_EVENT_TYPE_READABLE | AWS_IO_EVENT_TYPE_WRITABLE));

    struct libuv_loop *impl = event_loop->impl_data;

    struct handle_data *handle_data = aws_mem_acquire(event_loop->alloc, sizeof(struct handle_data));
    if (!handle_data) {
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*handle_data);
    handle_data->owner = handle;
    handle_data->event_loop = event_loop;
    handle_data->on_event = on_event;
    handle_data->on_event_user_data = user_data;

    handle->additional_data = handle_data;

    int uv_events = UV_DISCONNECT;
    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        uv_events |= UV_READABLE;
    }
    if (events & AWS_IO_EVENT_TYPE_WRITABLE) {
        uv_events |= UV_WRITABLE;
    }

    if (uv_poll_init(impl->uv_loop, &handle_data->poll, handle->data.fd)) {
        return AWS_OP_ERR;
    }
    handle_data->poll.data = handle_data;
    if (uv_poll_start(&handle_data->poll, uv_events, s_uv_poll_cb)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/* Handles opened in s_subscribe_to_io_events have a different data pointer, so we need a wrapper */
static void s_uv_close_sub(uv_handle_t *handle) {

    struct handle_data *handle_data = handle->data;
    struct aws_event_loop *event_loop = handle_data->event_loop;
    struct libuv_loop *impl = event_loop->impl_data;

    handle->data = impl;
    s_uv_close_handle(handle);

    aws_mem_release(event_loop->alloc, handle_data);
}

static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {

    (void)event_loop;
    assert(handle->additional_data);

    struct handle_data *handle_data = handle->additional_data;

    if (uv_poll_stop(&handle_data->poll)) {
        return AWS_OP_ERR;
    }

    uv_close((uv_handle_t *)&handle_data->poll, s_uv_close_sub);

    handle->additional_data = NULL;

    return AWS_OP_SUCCESS;
}

static void s_free_io_event_resources(void *user_data) {

    struct handle_data *handle_data = user_data;

    aws_mem_release(handle_data->event_loop->alloc, handle_data);
}

static bool s_is_on_callers_thread(struct aws_event_loop *event_loop) {
    struct libuv_loop *impl = event_loop->impl_data;

    const uint64_t uv_tid =
        impl->owns_uv_loop ? aws_thread_get_id(&s_owned(impl)->thread) : s_unowned(impl)->uv_thread_id;

    return uv_tid == aws_thread_current_thread_id();
}

struct aws_event_loop_vtable s_libuv_vtable = {
    .destroy = s_destroy,
    .run = s_run,
    .stop = s_stop,
    .wait_for_stop_completion = s_wait_for_stop_completion,
    .schedule_task_now = s_schedule_task_now,
    .schedule_task_future = s_schedule_task_future,
    .cancel_task = s_cancel_task,
    .subscribe_to_io_events = s_subscribe_to_io_events,
    .unsubscribe_from_io_events = s_unsubscribe_from_io_events,
    .free_io_event_resources = s_free_io_event_resources,
    .is_on_callers_thread = s_is_on_callers_thread,
};

static int s_libuv_loop_init(
    struct aws_event_loop *event_loop,
    struct aws_allocator *alloc,
    struct libuv_loop *impl,
    uv_loop_t *uv_loop,
    aws_io_clock_fn *clock) {

    bool clean_up_event_loop_base = false;
    bool clean_up_mutex = false;

    int err = aws_event_loop_init_base(event_loop, alloc, clock);
    if (err) {
        goto clean_up;
    }
    clean_up_event_loop_base = true;

    impl->uv_loop = uv_loop;

    if (aws_mutex_init(&impl->cross_thread_data.mutex)) {
        goto clean_up;
    }
    clean_up_mutex = true;

    aws_linked_list_init(&impl->cross_thread_data.tasks_to_schedule);

    if (aws_task_scheduler_init(&impl->on_thread_data.scheduler, alloc)) {
        goto clean_up;
    }

    event_loop->impl_data = impl;
    event_loop->vtable = &s_libuv_vtable;

    return AWS_OP_SUCCESS;

clean_up:
    if (clean_up_mutex) {
        aws_mutex_clean_up(&impl->cross_thread_data.mutex);
    }
    if (clean_up_event_loop_base) {
        aws_event_loop_clean_up_base(event_loop);
    }
    return AWS_OP_ERR;
}

struct aws_event_loop *aws_event_loop_new_libuv(struct aws_allocator *alloc, aws_io_clock_fn *clock) {
    assert(alloc);
    assert(clock);

    bool clean_up_event_loop_mem = false;
    bool clean_up_uv = false;
    bool clean_up_thread = false;

    struct aws_event_loop *event_loop = NULL;
    struct libuv_loop *impl = NULL;
    struct libuv_owned *owned = NULL;
    uv_loop_t *uv_loop = NULL;
    aws_mem_acquire_many(
        alloc,
        4,
        &event_loop,
        sizeof(*event_loop),
        &impl,
        sizeof(*impl),
        &owned,
        sizeof(*owned),
        &uv_loop,
        sizeof(*uv_loop));

    if (!event_loop) {
        return NULL;
    }
    clean_up_event_loop_mem = true;

    AWS_ZERO_STRUCT(*event_loop);
    AWS_ZERO_STRUCT(*impl);
    AWS_ZERO_STRUCT(*owned);
    AWS_ZERO_STRUCT(*uv_loop);

    impl->uv_loop = uv_loop;
    impl->owns_uv_loop = true;
    impl->ownership_specific.uv_owned = owned;

    if (uv_loop_init(impl->uv_loop)) {
        goto clean_up;
    }
    clean_up_uv = true;

    if (aws_thread_init(&owned->thread, alloc)) {
        goto clean_up;
    }
    clean_up_thread = true;

    if (s_libuv_loop_init(event_loop, alloc, impl, uv_loop, clock)) {
        goto clean_up;
    }

    return event_loop;

clean_up:
    if (clean_up_thread) {
        aws_thread_clean_up(&owned->thread);
    }
    if (clean_up_uv) {
        uv_loop_close(impl->uv_loop);
    }
    if (clean_up_event_loop_mem) {
        aws_mem_release(alloc, event_loop);
    }

    return NULL;
}

static void s_get_uv_thread_id(uv_async_t *request) {
    struct libuv_loop *impl = request->data;

    s_unowned(impl)->uv_thread_id = aws_thread_current_thread_id();

    uv_close((uv_handle_t *)request, NULL);
}

struct aws_event_loop *aws_event_loop_existing_libuv(
    struct aws_allocator *alloc,
    struct uv_loop_s *uv_loop,
    aws_io_clock_fn *clock) {
    assert(alloc);
    assert(clock);

    bool clean_up_event_loop_mem = false;

    struct aws_event_loop *event_loop = NULL;
    struct libuv_loop *impl = NULL;
    struct libuv_unowned *unowned = NULL;
    aws_mem_acquire_many(
        alloc,
        3,
        &event_loop,
        sizeof(struct aws_event_loop),
        &impl,
        sizeof(struct libuv_loop),
        &unowned,
        sizeof(*unowned));

    if (!event_loop) {
        return NULL;
    }
    clean_up_event_loop_mem = true;

    AWS_ZERO_STRUCT(*event_loop);
    AWS_ZERO_STRUCT(*impl);
    AWS_ZERO_STRUCT(*unowned);

    impl->owns_uv_loop = false;
    impl->ownership_specific.uv_unowned = unowned;

    if (s_libuv_loop_init(event_loop, alloc, impl, uv_loop, clock)) {
        goto clean_up;
    }

    /* Schedule work task to harvest thread id */
    uv_async_init(uv_loop, &unowned->get_thread_id_async, s_get_uv_thread_id);
    unowned->get_thread_id_async.data = impl;
    uv_async_send(&unowned->get_thread_id_async);

    return event_loop;

clean_up:
    if (clean_up_event_loop_mem) {
        aws_mem_release(alloc, event_loop);
    }

    return NULL;
}
