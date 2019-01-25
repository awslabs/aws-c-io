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
    /* The underlying libuv loop */
    uv_loop_t *uv_loop;
    /* True if the loop is created and pumped by us, false if someone else owns and pumps it */
    bool owns_uv_loop;

    /* Contains data specific to the ownership of the loop */
    union {
        struct libuv_owned *uv_owned;
        struct libuv_unowned *uv_unowned;
    } ownership_specific;

    /* Send this to stop the event loop */
    uv_async_t stop_async;
    /* Number of outstanding libuv handles. Must be 0 before closing the loop. */
    struct aws_atomic_var num_open_handles;
    /* Send this when there are pending tasks to schedule */
    uv_async_t schedule_tasks_async;

    /* Data that may be manipulated across threads (while mutex is held) */
    struct {
        struct aws_mutex mutex;
        /* A list of pending tasks that must be scheduled on the libuv event loop thread */
        struct aws_linked_list tasks_to_schedule;
    } cross_thread_data;

    struct {
        /* Map of aws_task * -> task_data * */
        struct aws_hash_table running_tasks;
        /* List of aws_io_handle * */
        struct aws_linked_list open_subscriptions;
    } el_thread_data;
};
/* Requires that the event_loop and impl be allocated next to eachother */
struct aws_event_loop *s_loop_from_impl(struct libuv_loop *impl) {
    return (struct aws_event_loop *)((uint8_t *)impl - sizeof(struct aws_event_loop));
}

enum event_thread_state {
    EVENT_THREAD_STATE_READY_TO_RUN,
    EVENT_THREAD_STATE_RUNNING,
    EVENT_THREAD_STATE_STOPPING,
};

/** This struct is owned by libuv_loop if the uv_loop is owned by us */
struct libuv_owned {
    struct aws_thread thread;
    enum event_thread_state state;
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
    int uv_events;
    aws_event_loop_on_event_fn *on_event;
    void *on_event_user_data;

    uv_async_t poll_start_async;
    struct aws_linked_list_node open_subs_node;
};

struct task_data {
    uv_timer_t timer;
    struct aws_event_loop *event_loop;
    struct aws_task *task;
};

/* vtable declarations */
static void s_destroy(struct aws_event_loop *event_loop);
static bool s_is_on_callers_thread(struct aws_event_loop *event_loop);
static int s_run(struct aws_event_loop *event_loop);
static int s_stop(struct aws_event_loop *event_loop);
static int s_wait_for_stop_completion(struct aws_event_loop *event_loop);
static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task);
static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos);

static uint64_t s_timestamp_to_uv_millis(struct aws_event_loop *event_loop, const uint64_t timestamp) {
    /* Put task in relative time if non-0 */
    uint64_t time_to_run = 0;
    if (timestamp) {
        uint64_t now = 0;
        event_loop->clock(&now);

        /* If task was scheduled in the future, convert the times */
        if (now < timestamp) {
            time_to_run = timestamp - now;
            /* Convert to millis per libuv expectations */
            time_to_run = aws_timestamp_convert(time_to_run, AWS_TIMESTAMP_NANOS, AWS_TIMESTAMP_MILLIS, NULL);
        }
    }

    return time_to_run;
}

static void s_uv_poll_cb(uv_poll_t *handle, int status, int events) {

    struct handle_data *handle_data = handle->data;
    int aws_events = 0;

    uv_os_fd_t fd = 0;
    if (uv_fileno((uv_handle_t *)handle, &fd)) {
        return;
    }

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

static void s_uv_close_handle(uv_handle_t *handle) {
    struct libuv_loop *impl = handle->data;

    aws_atomic_fetch_sub(&impl->num_open_handles, 1);
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

static void s_uv_close_timer(uv_handle_t *handle) {
    struct task_data *task = handle->data;

    handle->data = task->event_loop->impl_data;
    s_uv_close_handle(handle);

    aws_mem_release(task->event_loop->alloc, task);
}

static void s_uv_close_timer_no_free(uv_handle_t *handle) {
    struct task_data *task = handle->data;

    handle->data = task->event_loop->impl_data;
    s_uv_close_handle(handle);
}

static int s_running_tasks_destroy(void *context, struct aws_hash_element *element) {

    (void)context;

    struct task_data *task = element->value;
    aws_task_run(task->task, AWS_TASK_STATUS_CANCELED);

    aws_mem_release(task->event_loop->alloc, task);

    return AWS_COMMON_HASH_TABLE_ITER_CONTINUE | AWS_COMMON_HASH_TABLE_ITER_DELETE;
}

/* vtable implementations */
static void s_destroy(struct aws_event_loop *event_loop) {

    struct libuv_loop *impl = event_loop->impl_data;

    s_stop(event_loop);

    /* Wait for completion */
    s_wait_for_stop_completion(event_loop);

    /* Tasks in scheduler get cancelled*/
    aws_hash_table_foreach(&impl->el_thread_data.running_tasks, s_running_tasks_destroy, NULL);

    aws_hash_table_clean_up(&impl->el_thread_data.running_tasks);

    if (impl->owns_uv_loop) {
        assert(!uv_loop_alive(impl->uv_loop));
        int result = uv_loop_close(impl->uv_loop);
        assert(result == 0);
        aws_thread_clean_up(&s_owned(impl)->thread);
    }
    impl->uv_loop = NULL;

    aws_mutex_clean_up(&impl->cross_thread_data.mutex);

    /* Cancel pending tasks */
    while (!aws_linked_list_empty(&impl->cross_thread_data.tasks_to_schedule)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&impl->cross_thread_data.tasks_to_schedule);
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
        task->fn(task, task->arg, AWS_TASK_STATUS_CANCELED);
    }

    aws_event_loop_clean_up_base(event_loop);
    aws_mem_release(event_loop->alloc, event_loop);
}

static void s_thread_loop(void *args) {
    struct libuv_loop *impl = args;

    s_owned(impl)->state = EVENT_THREAD_STATE_RUNNING;

    while (s_owned(impl)->state == EVENT_THREAD_STATE_RUNNING) {
        uv_run(impl->uv_loop, UV_RUN_ONCE);
    }

    s_owned(impl)->state = EVENT_THREAD_STATE_READY_TO_RUN;
}

static void s_uv_task_timer_cb(uv_timer_t *handle) {
    struct task_data *task = handle->data;
    struct libuv_loop *impl = task->event_loop->impl_data;

    /* Remove handle from hash table to prevent future collsions when rescheduling */
    int was_present = 0;
    aws_hash_table_remove(&impl->el_thread_data.running_tasks, task->task, NULL, &was_present);
    assert(was_present);

    /* Run the task */
    aws_task_run(task->task, AWS_TASK_STATUS_RUN_READY);

    /* Close the handle */
    uv_close((uv_handle_t *)handle, s_uv_close_timer);
}

static void s_schedule_task_impl(struct libuv_loop *impl, struct aws_task *task) {

    struct aws_event_loop *event_loop = s_loop_from_impl(impl);

    aws_atomic_fetch_add(&impl->num_open_handles, 1);

    /* Allocate and initalize timer */
    struct task_data *task_data = aws_mem_acquire(event_loop->alloc, sizeof(struct task_data));
    uv_timer_init(impl->uv_loop, &task_data->timer);
    task_data->timer.data = task_data;

    task_data->event_loop = s_loop_from_impl(impl);
    task_data->task = task;

    uv_timer_start(&task_data->timer, s_uv_task_timer_cb, s_timestamp_to_uv_millis(event_loop, task->timestamp), 0);

    int was_created = 0;
    aws_hash_table_put(&impl->el_thread_data.running_tasks, task, task_data, &was_created);
    assert(was_created == 1);
}

/* Wakes up the event loop and passes pending tasks to the real task scheduler */
static void s_uv_async_schedule_tasks(uv_async_t *request) {
    struct libuv_loop *impl = request->data;
    assert(impl);

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

        s_schedule_task_impl(impl, task);
    }
}

static int s_running_tasks_stop(void *context, struct aws_hash_element *element) {

    (void)context;

    struct task_data *task = element->value;

    /* Stop task and close the handle */
    uv_timer_stop(&task->timer);
    uv_close((uv_handle_t *)&task->timer, s_uv_close_timer_no_free);

    return AWS_COMMON_HASH_TABLE_ITER_CONTINUE;
}

/* Wakes up the event loop and stops it */
static void s_uv_async_stop_loop(uv_async_t *request) {
    struct libuv_loop *impl = request->data;
    assert(impl);

    s_owned(impl)->state = EVENT_THREAD_STATE_STOPPING;

    /* Stop all open subscriptions */
    struct aws_linked_list_node *it = aws_linked_list_begin(&impl->el_thread_data.open_subscriptions);
    const struct aws_linked_list_node *end = aws_linked_list_end(&impl->el_thread_data.open_subscriptions);
    while (it != end) {
        struct handle_data *handle_data = AWS_CONTAINER_OF(it, struct handle_data, open_subs_node);
        uv_poll_stop(&handle_data->poll);
        uv_close((uv_handle_t *)&handle_data->poll, s_uv_close_sub);

        it = aws_linked_list_next(it);
    }

    /* Stop all open timers */
    aws_hash_table_foreach(&impl->el_thread_data.running_tasks, s_running_tasks_stop, NULL);

    uv_close((uv_handle_t *)&impl->stop_async, s_uv_close_handle);
    uv_close((uv_handle_t *)&impl->schedule_tasks_async, s_uv_close_handle);
}

static int s_running_tasks_start(void *context, struct aws_hash_element *element) {

    struct task_data *task = element->value;
    struct libuv_loop *impl = context;

    uv_timer_start(
        &task->timer, s_uv_task_timer_cb, s_timestamp_to_uv_millis(task->event_loop, task->task->timestamp), 0);

    aws_atomic_fetch_add(&impl->num_open_handles, 1);

    return AWS_COMMON_HASH_TABLE_ITER_CONTINUE;
}

static int s_run(struct aws_event_loop *event_loop) {

    bool cleanup_polls = false;
    bool cleanup_timers = false;

    struct libuv_loop *impl = event_loop->impl_data;

    impl->schedule_tasks_async.data = impl;
    if (uv_async_init(impl->uv_loop, &impl->schedule_tasks_async, s_uv_async_schedule_tasks)) {
        return AWS_OP_ERR;
    }
    aws_atomic_fetch_add(&impl->num_open_handles, 1);

    /* Prep the stop async */
    impl->stop_async.data = impl;
    if (uv_async_init(impl->uv_loop, &impl->stop_async, s_uv_async_stop_loop)) {
        goto clean_up;
    }
    aws_atomic_fetch_add(&impl->num_open_handles, 1);

    /* Start all existing subscriptions */
    struct aws_linked_list_node *open_subs_it = aws_linked_list_begin(&impl->el_thread_data.open_subscriptions);
    const struct aws_linked_list_node *open_subs_end = aws_linked_list_end(&impl->el_thread_data.open_subscriptions);
    while (open_subs_it != open_subs_end) {
        struct handle_data *handle_data = AWS_CONTAINER_OF(open_subs_it, struct handle_data, open_subs_node);
        if (uv_poll_start(&handle_data->poll, handle_data->uv_events, s_uv_poll_cb)) {
            goto clean_up;
        }
        aws_atomic_fetch_add(&impl->num_open_handles, 1);

        open_subs_it = open_subs_it->next;
    }
    cleanup_polls = true;

    /* Start all existing timers */
    aws_hash_table_foreach(&impl->el_thread_data.running_tasks, s_running_tasks_start, impl);
    cleanup_timers = true;

    if (impl->owns_uv_loop) {
        assert(s_owned(impl)->state == EVENT_THREAD_STATE_READY_TO_RUN);

        if (aws_thread_launch(&s_owned(impl)->thread, &s_thread_loop, impl, NULL)) {
            goto clean_up;
        }
    }

    return AWS_OP_SUCCESS;

clean_up:
    if (cleanup_timers) {
        aws_hash_table_foreach(&impl->el_thread_data.running_tasks, s_running_tasks_stop, impl);
    }
    if (cleanup_polls) {
        struct aws_linked_list_node *open_subs_it = aws_linked_list_begin(&impl->el_thread_data.open_subscriptions);
        const struct aws_linked_list_node *open_subs_end =
            aws_linked_list_end(&impl->el_thread_data.open_subscriptions);
        while (open_subs_it != open_subs_end) {
            struct handle_data *handle_data = AWS_CONTAINER_OF(open_subs_it, struct handle_data, open_subs_node);

            uv_close((uv_handle_t *)&handle_data->poll, s_uv_close_sub);

            open_subs_it = open_subs_it->next;
        }
    }
    if (impl->stop_async.loop) {
        uv_close((uv_handle_t *)&impl->stop_async, s_uv_close_handle);
    }
    uv_close((uv_handle_t *)&impl->schedule_tasks_async, s_uv_close_handle);

    return AWS_OP_ERR;
}

static int s_stop(struct aws_event_loop *event_loop) {
    struct libuv_loop *impl = event_loop->impl_data;

    if (uv_async_send(&impl->stop_async)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_wait_for_stop_completion(struct aws_event_loop *event_loop) {
    struct libuv_loop *impl = event_loop->impl_data;

    int status = AWS_OP_SUCCESS;

    if (impl->owns_uv_loop) {
        status = aws_thread_join(&s_owned(impl)->thread);
    }

    /* Wait for all handles to close */
    while (aws_atomic_load_int(&impl->num_open_handles)) {
    }

    return status;
}

static void s_schedule_task_common(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    struct libuv_loop *impl = event_loop->impl_data;

    task->timestamp = run_at_nanos;

    /* Begin critical section */
    aws_mutex_lock(&impl->cross_thread_data.mutex);

    bool should_signal_thread = aws_linked_list_empty(&impl->cross_thread_data.tasks_to_schedule);
    aws_linked_list_push_back(&impl->cross_thread_data.tasks_to_schedule, &task->node);

    /* Signal thread that cross_thread_data has changed (unless it's been signaled already) */
    if (should_signal_thread) {
        uv_async_send(&impl->schedule_tasks_async);
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

    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&impl->el_thread_data.running_tasks, task, &elem);
    if (elem) {
        struct task_data *task_data = elem->value;

        /* Remove handle from hash table to prevent future collsions when rescheduling */
        int was_present = 0;
        aws_hash_table_remove(&impl->el_thread_data.running_tasks, task_data->task, NULL, &was_present);
        assert(was_present);

        aws_task_run(task_data->task, AWS_TASK_STATUS_CANCELED);

        uv_timer_stop(&task_data->timer);
        uv_close((uv_handle_t *)&task_data->timer, s_uv_close_timer);
    }
}

static void s_uv_close_sub_async(uv_handle_t *handle) {

    struct handle_data *handle_data = handle->data;
    struct libuv_loop *impl = handle_data->event_loop->impl_data;

    handle->data = impl;
    s_uv_close_handle(handle);
}

static void s_uv_async_poll_start(uv_async_t *handle) {

    struct handle_data *handle_data = handle->data;
    struct libuv_loop *impl = handle_data->event_loop->impl_data;

    uv_poll_init(impl->uv_loop, &handle_data->poll, handle_data->owner->data.fd);
    uv_poll_start(&handle_data->poll, handle_data->uv_events, s_uv_poll_cb);

    uv_close((uv_handle_t *)handle, s_uv_close_sub_async);
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

    aws_atomic_fetch_add(&impl->num_open_handles, 1);

    struct handle_data *handle_data = aws_mem_acquire(event_loop->alloc, sizeof(struct handle_data));
    if (!handle_data) {
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*handle_data);

    handle_data->poll.data = handle_data;
    handle_data->owner = handle;
    handle_data->event_loop = event_loop;
    handle_data->on_event = on_event;
    handle_data->on_event_user_data = user_data;

    aws_linked_list_push_back(&impl->el_thread_data.open_subscriptions, &handle_data->open_subs_node);

    handle->additional_data = handle_data;

    handle_data->uv_events = UV_DISCONNECT;
    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        handle_data->uv_events |= UV_READABLE;
    }
    if (events & AWS_IO_EVENT_TYPE_WRITABLE) {
        handle_data->uv_events |= UV_WRITABLE;
    }

    if (s_is_on_callers_thread(event_loop)) {
        /* If on UV thread, directly start sub */
        uv_poll_init(impl->uv_loop, &handle_data->poll, handle_data->owner->data.fd);
        uv_poll_start(&handle_data->poll, handle_data->uv_events, s_uv_poll_cb);
    } else {
        /* Otherwise, schedule async to do sub */
        aws_atomic_fetch_add(&impl->num_open_handles, 1);

        handle_data->poll_start_async.data = handle_data;
        uv_async_init(impl->uv_loop, &handle_data->poll_start_async, s_uv_async_poll_start);
        uv_async_send(&handle_data->poll_start_async);
    }

    return AWS_OP_SUCCESS;
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

    aws_linked_list_remove(&handle_data->open_subs_node);

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

    if (aws_event_loop_init_base(event_loop, alloc, clock)) {
        return AWS_OP_ERR;
    }

    impl->uv_loop = uv_loop;
    aws_atomic_init_int(&impl->num_open_handles, 0);

    /* Init cross-thread data */
    if (aws_mutex_init(&impl->cross_thread_data.mutex)) {
        goto clean_up;
    }

    aws_linked_list_init(&impl->cross_thread_data.tasks_to_schedule);

    /* Init on-thread data */
    if (aws_hash_table_init(&impl->el_thread_data.running_tasks, alloc, 5, aws_hash_ptr, aws_ptr_eq, NULL, NULL)) {
        goto clean_up;
    }
    aws_linked_list_init(&impl->el_thread_data.open_subscriptions);

    event_loop->impl_data = impl;
    event_loop->vtable = &s_libuv_vtable;

    return AWS_OP_SUCCESS;

clean_up:
    aws_mutex_clean_up(&impl->cross_thread_data.mutex);
    aws_event_loop_clean_up_base(event_loop);
    return AWS_OP_ERR;
}

struct aws_event_loop *aws_event_loop_new_libuv(struct aws_allocator *alloc, aws_io_clock_fn *clock) {
    assert(alloc);
    assert(clock);

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

    if (aws_thread_init(&owned->thread, alloc)) {
        goto clean_up;
    }

    if (s_libuv_loop_init(event_loop, alloc, impl, uv_loop, clock)) {
        goto clean_up;
    }

    return event_loop;

clean_up:
    if (owned->thread.thread_id) {
        aws_thread_clean_up(&owned->thread);
    }
    if (impl->uv_loop) {
        uv_loop_close(impl->uv_loop);
    }
    aws_mem_release(alloc, event_loop);

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
    aws_mem_release(alloc, event_loop);

    return NULL;
}
