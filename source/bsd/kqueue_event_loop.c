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

#include <assert.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/thread.h>
#include <aws/io/event_loop.h>
#include <aws/io/pipe.h>
#include <sys/event.h>
#include <unistd.h>

static void s_destroy(struct aws_event_loop *);
static int s_run(struct aws_event_loop *);
static int s_stop(struct aws_event_loop *);
static int s_wait_for_stop_completion(struct aws_event_loop *);
static int s_schedule_task(struct aws_event_loop *, struct aws_task *task, uint64_t run_at);
static int s_subscribe_to_io_events(
    struct aws_event_loop *,
    struct aws_io_handle *handle,
    int events,
    aws_event_loop_on_event_fn *on_event,
    void *ctx);
static int s_unsubscribe_from_io_events(struct aws_event_loop *, struct aws_io_handle *handle);
static bool s_is_event_thread(struct aws_event_loop *);

static void s_event_thread_main(void *user_data);

enum event_thread_state {
    EVENT_THREAD_STATE_READY_TO_RUN,
    EVENT_THREAD_STATE_RUNNING,
    EVENT_THREAD_STATE_STOPPING,
};

struct kqueue_loop {
    struct aws_thread thread;
    int kq_fd; /* kqueue file descriptor */

    /* Pipe for signaling to event-thread that cross_thread_data has changed */
    struct aws_io_handle cross_thread_signal_pipe_read;
    struct aws_io_handle cross_thread_signal_pipe_write;

    /* cross_thread_data holds things that must be communicated across threads.
     * When the event-thread is running, the mutex must be locked while anyone touches anything in cross_thread_data.
     * If this data is modified outside the thread, the thread is signaled via activity on a pipe. */
    struct {
        struct aws_mutex mutex;
        bool thread_signaled; /* whether thread has been signaled about changes to cross_thread_data */
        struct aws_array_list tasks_to_schedule;
        enum event_thread_state state;
    } cross_thread_data;

    /* thread_data holds things which, when the event-thread is running, may only be touched by the thread */
    struct {
        struct aws_task_scheduler scheduler;

        /* These variables duplicate ones in cross_thread_data. We move values out while holding the mutex and operate
         * on them later */
        struct aws_array_list tasks_to_schedule;
        enum event_thread_state state;
    } thread_data;
};

/* A task that needs to be added to the scheduler */
struct task_to_schedule {
    struct aws_task task;
    uint64_t run_at;
};

/* Data attached to aws_io_handle while the handle is subscribed to io events */
struct handle_data {
    struct aws_io_handle *owner;
    struct aws_event_loop *event_loop;
    aws_event_loop_on_event_fn *on_event;
    void *on_event_user_data;

    int events_subscribed; /* aws_io_event_types this handle is subscribed to */
    int events_this_loop;  /* aws_io_event_types received during current loop of the event-thread */

    bool kevent_added_successfully;
};

enum {
    DEFAULT_TIMEOUT_SEC = 100, /* Max kevent() timeout per loop of the event-thread */
    NANOSEC_PER_SEC = 1000000000,
    MAX_EVENTS = 100, /* Max kevents to process per loop of the event-thread */
    DEFAULT_ARRAY_LIST_RESERVE = 32,
};

struct aws_event_loop *aws_event_loop_default_new(struct aws_allocator *alloc, aws_io_clock_fn *clock) {
    assert(alloc);
    assert(clock);

    bool clean_up_event_loop_mem = false;
    bool clean_up_event_loop_base = false;
    bool clean_up_impl_mem = false;
    bool clean_up_thread = false;
    bool clean_up_kqueue = false;
    bool clean_up_signal_pipe = false;
    bool clean_up_signal_kevent = false;
    bool clean_up_mutex = false;
    bool clean_up_cross_thread_array = false;
    bool clean_up_scheduler = false;

    struct aws_event_loop *event_loop = aws_mem_acquire(alloc, sizeof(struct aws_event_loop));
    if (!event_loop) {
        return NULL;
    }
    clean_up_event_loop_mem = true;

    int err = aws_event_loop_base_init(event_loop, alloc, clock);
    if (err) {
        goto clean_up;
    }
    clean_up_event_loop_base = true;

    struct kqueue_loop *impl = aws_mem_acquire(alloc, sizeof(struct kqueue_loop));
    if (!impl) {
        goto clean_up;
    }
    clean_up_impl_mem = true;

    err = aws_thread_init(&impl->thread, alloc);
    if (err) {
        goto clean_up;
    }
    clean_up_thread = true;

    impl->kq_fd = kqueue();
    if (impl->kq_fd == -1) {
        aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
        goto clean_up;
    }
    clean_up_kqueue = true;

    err = aws_pipe_open(&impl->cross_thread_signal_pipe_read, &impl->cross_thread_signal_pipe_write);
    if (err) {
        goto clean_up;
    }
    clean_up_signal_pipe = true;

    /* Set up kevent to handle activity on the cross_thread_signal_pipe */
    struct kevent thread_signal_kevent;
    EV_SET(
        &thread_signal_kevent,
        impl->cross_thread_signal_pipe_read.data.fd,
        EVFILT_READ /*filter*/,
        EV_ADD /*flags*/,
        0 /*fflags*/,
        0 /*data*/,
        NULL /*udata*/);

    int res = kevent(
        impl->kq_fd,
        &thread_signal_kevent /*changelist*/,
        1 /*nchanges*/,
        NULL /*eventlist*/,
        0 /*nevents*/,
        NULL /*timeout*/);

    if (res == -1) {
        aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
        goto clean_up;
    }
    clean_up_signal_kevent = true;

    err = aws_mutex_init(&impl->cross_thread_data.mutex);
    if (err) {
        goto clean_up;
    }
    clean_up_mutex = true;

    impl->cross_thread_data.thread_signaled = false;

    err = aws_array_list_init_dynamic(
        &impl->cross_thread_data.tasks_to_schedule, alloc, DEFAULT_ARRAY_LIST_RESERVE, sizeof(struct task_to_schedule));
    if (err) {
        goto clean_up;
    }
    clean_up_cross_thread_array = true;

    impl->cross_thread_data.state = EVENT_THREAD_STATE_READY_TO_RUN;

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

    impl->thread_data.state = EVENT_THREAD_STATE_READY_TO_RUN;

    event_loop->impl_data = impl;

    event_loop->vtable.destroy = s_destroy;
    event_loop->vtable.run = s_run;
    event_loop->vtable.stop = s_stop;
    event_loop->vtable.wait_for_stop_completion = s_wait_for_stop_completion;
    event_loop->vtable.schedule_task = s_schedule_task;
    event_loop->vtable.subscribe_to_io_events = s_subscribe_to_io_events;
    event_loop->vtable.unsubscribe_from_io_events = s_unsubscribe_from_io_events;
    event_loop->vtable.is_on_callers_thread = s_is_event_thread;

    /* success */
    return event_loop;

clean_up:
    if (clean_up_scheduler) {
        aws_task_scheduler_clean_up(&impl->thread_data.scheduler);
    }
    if (clean_up_cross_thread_array) {
        aws_array_list_clean_up(&impl->cross_thread_data.tasks_to_schedule);
    }
    if (clean_up_mutex) {
        aws_mutex_clean_up(&impl->cross_thread_data.mutex);
    }
    if (clean_up_signal_kevent) {
        thread_signal_kevent.flags = EV_DELETE;
        kevent(
            impl->kq_fd,
            &thread_signal_kevent /*changelist*/,
            1 /*nchanges*/,
            NULL /*eventlist*/,
            0 /*nevents*/,
            NULL /*timeout*/);
    }
    if (clean_up_signal_pipe) {
        aws_pipe_close(&impl->cross_thread_signal_pipe_read, &impl->cross_thread_signal_pipe_write);
    }
    if (clean_up_kqueue) {
        close(impl->kq_fd);
    }
    if (clean_up_thread) {
        aws_thread_clean_up(&impl->thread);
    }
    if (clean_up_impl_mem) {
        aws_mem_release(alloc, impl);
    }
    if (clean_up_event_loop_base) {
        aws_event_loop_base_clean_up(event_loop);
    }
    if (clean_up_event_loop_mem) {
        aws_mem_release(alloc, event_loop);
    }
    return NULL;
}

static void s_destroy(struct aws_event_loop *event_loop) {
    struct kqueue_loop *impl = event_loop->impl_data;

    /* Stop the event-thread. This might have already happened. It's safe to call multiple times. */
    s_stop(event_loop);
    int err = s_wait_for_stop_completion(event_loop);
    if (err) {
        assert("Failed to destroy event-thread, resources have been leaked." == NULL);
        return;
    }

    /* Cancel tasks before cleaning up, in case a cancelled task tries to do something with this event_loop.
     * Remember that some tasks might still be stuck in a tasks_to_schedule list */
    struct task_to_schedule task_to_schedule;
    size_t num_tasks = aws_array_list_length(&impl->thread_data.tasks_to_schedule);
    for (size_t i = 0; i < num_tasks; ++i) {
        aws_array_list_get_at(&impl->thread_data.tasks_to_schedule, &task_to_schedule, i);
        task_to_schedule.task.fn(task_to_schedule.task.arg, AWS_TASK_STATUS_CANCELED);
    }

    num_tasks = aws_array_list_length(&impl->cross_thread_data.tasks_to_schedule);
    for (size_t i = 0; i < num_tasks; ++i) {
        aws_array_list_get_at(&impl->cross_thread_data.tasks_to_schedule, &task_to_schedule, i);
        task_to_schedule.task.fn(task_to_schedule.task.arg, AWS_TASK_STATUS_CANCELED);
    }

    aws_task_scheduler_clean_up(&impl->thread_data.scheduler); /* cancels remaining tasks */

    /* Clean up everything else */
    aws_array_list_clean_up(&impl->thread_data.tasks_to_schedule);
    aws_array_list_clean_up(&impl->cross_thread_data.tasks_to_schedule);
    aws_mutex_clean_up(&impl->cross_thread_data.mutex);

    struct kevent thread_signal_kevent;
    EV_SET(
        &thread_signal_kevent,
        impl->cross_thread_signal_pipe_read.data.fd,
        EVFILT_READ /*filter*/,
        EV_DELETE /*flags*/,
        0 /*fflags*/,
        0 /*data*/,
        NULL /*udata*/);

    kevent(
        impl->kq_fd,
        &thread_signal_kevent /*changelist*/,
        1 /*nchanges*/,
        NULL /*eventlist*/,
        0 /*nevents*/,
        NULL /*timeout*/);

    aws_pipe_close(&impl->cross_thread_signal_pipe_read, &impl->cross_thread_signal_pipe_write);
    close(impl->kq_fd);
    aws_thread_clean_up(&impl->thread);
    aws_mem_release(event_loop->alloc, impl);
    aws_event_loop_base_clean_up(event_loop);
    aws_mem_release(event_loop->alloc, event_loop);
}

static int s_run(struct aws_event_loop *event_loop) {
    struct kqueue_loop *impl = event_loop->impl_data;

    /* to re-run, call stop() and wait_for_stop_completion() */
    assert(impl->cross_thread_data.state == EVENT_THREAD_STATE_READY_TO_RUN);
    assert(impl->thread_data.state == EVENT_THREAD_STATE_READY_TO_RUN);

    /* Since thread isn't running it's ok to touch thread_data,
     * and it's ok to touch cross_thread_data without locking the mutex */
    impl->cross_thread_data.state = EVENT_THREAD_STATE_RUNNING;

    int err = aws_thread_launch(&impl->thread, s_event_thread_main, (void *)event_loop, NULL);
    if (err) {
        goto clean_up;
    }

    return AWS_OP_SUCCESS;

clean_up:
    impl->cross_thread_data.state = EVENT_THREAD_STATE_READY_TO_RUN;
    return AWS_OP_ERR;
}

/* This function can't fail, we're relying on the thread responding to critical messages (ex: stop thread) */
void signal_cross_thread_data_changed(struct aws_event_loop *event_loop) {
    struct kqueue_loop *impl = event_loop->impl_data;

    /* Doesn't actually matter what we write, any activity on pipe signals that cross_thread_data has changed,
     * If the pipe is full and the write fails, that's fine, the event-thread will get the signal from some previous
     * write */
    uint32_t write_whatever = 0xC0FFEE;
    write(impl->cross_thread_signal_pipe_write.data.fd, &write_whatever, sizeof(write_whatever));
}

static int s_stop(struct aws_event_loop *event_loop) {
    struct kqueue_loop *impl = event_loop->impl_data;

    bool signal_thread = false;

    { /* Begin critical section */
        aws_mutex_lock(&impl->cross_thread_data.mutex);
        if (impl->cross_thread_data.state == EVENT_THREAD_STATE_RUNNING) {
            impl->cross_thread_data.state = EVENT_THREAD_STATE_STOPPING;
            signal_thread = !impl->cross_thread_data.thread_signaled;
            impl->cross_thread_data.thread_signaled = true;
        }
        aws_mutex_unlock(&impl->cross_thread_data.mutex);
    } /* End critical section */

    if (signal_thread) {
        signal_cross_thread_data_changed(event_loop);
    }

    return AWS_OP_SUCCESS;
}

static int s_wait_for_stop_completion(struct aws_event_loop *event_loop) {
    struct kqueue_loop *impl = event_loop->impl_data;

#ifdef DEBUG_BUILD
    aws_mutex_lock(&impl->cross_thread_data.mutex);
    /* call stop() before wait_for_stop_completion() or you'll wait forever */
    assert(impl->cross_thread_data.state != EVENT_THREAD_STATE_RUNNING);
    aws_mutex_unlock(&impl->cross_thread_data.mutex);
#endif

    int err = aws_thread_join(&impl->thread);
    if (err) {
        return AWS_OP_ERR;
    }

    /* Since thread is no longer running it's ok to touch thread_data,
     * and it's ok to touch cross_thread_data without locking the mutex */
    impl->cross_thread_data.state = EVENT_THREAD_STATE_READY_TO_RUN;
    impl->thread_data.state = EVENT_THREAD_STATE_READY_TO_RUN;

    return AWS_OP_SUCCESS;
}

static int s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task) {
    uint64_t now;
    int err = event_loop->clock(&now);
    if (err) {
        return AWS_OP_ERR;
    }
    return s_schedule_task(event_loop, task, now);
}

static int s_schedule_task(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at) {
    assert(task);
    struct kqueue_loop *impl = event_loop->impl_data;

    /* If we're on the event-thread, just schedule it directly */
    if (s_is_event_thread(event_loop)) {
        return aws_task_scheduler_schedule_future(&impl->thread_data.scheduler, task, run_at);
    }

    /* Otherwise, add it to cross_thread_data.tasks_to_schedule and signal the event-thread to process it */
    struct task_to_schedule task_to_schedule = {
        .task = *task,
        .run_at = run_at,
    };

    int push_back_result;
    bool thread_already_signaled;

    { /* Begin critical section */
        aws_mutex_lock(&impl->cross_thread_data.mutex);
        push_back_result = aws_array_list_push_back(&impl->cross_thread_data.tasks_to_schedule, &task_to_schedule);
        thread_already_signaled = impl->cross_thread_data.thread_signaled;
        impl->cross_thread_data.thread_signaled = true;
        aws_mutex_unlock(&impl->cross_thread_data.mutex);
    } /* End critical section */

    if (push_back_result) {
        return AWS_OP_ERR;
    }

    /* Signal thread that cross_thread_data has changed (unless it's been signaled already) */
    if (!thread_already_signaled) {
        signal_cross_thread_data_changed(event_loop);
    }

    return AWS_OP_SUCCESS;
}

/* Scheduled task that connects aws_io_handle with the kqueue */
static void s_subscribe_task(void *user_data, enum aws_task_status status) {
    struct handle_data *handle_data = user_data;
    struct kqueue_loop *impl = handle_data->event_loop->impl_data;

    /* if task was cancelled, nothing to do */
    if (status == AWS_TASK_STATUS_CANCELED) {
        return;
    }

    /* In order to monitor both reads and writes, kqueue requires you to add two separate kevents.
     * If we're adding two separate kevents, but one of those fails, we need to remove the other kevent.
     * Therefore we use the EV_RECEIPT flag. This causes kevent() to tell whether each EV_ADD succeeded,
     * rather than the usual behavior of telling us about recent events. */
    struct kevent changelist[2];
    AWS_ZERO_ARRAY(changelist);

    int changelist_size = 0;

    if (handle_data->events_subscribed & AWS_IO_EVENT_TYPE_READABLE) {
        EV_SET(
            &changelist[changelist_size++],
            handle_data->owner->data.fd,
            EVFILT_READ /*filter*/,
            EV_ADD | EV_RECEIPT /*flags*/,
            0 /*fflags*/,
            0 /*data*/,
            handle_data /*udata*/);
    }
    if (handle_data->events_subscribed & AWS_IO_EVENT_TYPE_WRITABLE) {
        EV_SET(
            &changelist[changelist_size++],
            handle_data->owner->data.fd,
            EVFILT_WRITE /*filter*/,
            EV_ADD | EV_RECEIPT /*flags*/,
            0 /*fflags*/,
            0 /*data*/,
            handle_data /*udata*/);
    }

    /* It's OK to re-use the same memory for changelist input and eventlist output */
    int num_events = kevent(
        impl->kq_fd,
        changelist /*changelist*/,
        changelist_size /*nchanges*/,
        changelist /*eventlist*/,
        changelist_size /*nevents*/,
        NULL /*timeout*/);
    if (num_events == -1) {
        goto subscribe_failed;
    }

    /* Look through results to see if any failed */
    for (int i = 0; i < num_events; ++i) {
        /* Every result should be flagged as error, that's just how EV_RECEIPT works */
        assert(changelist[i].flags & EV_ERROR);

        /* If a real error occurred, .data contains the error code */
        if (changelist[i].data != 0) {
            goto subscribe_failed;
        }
    }

    /* Success */
    handle_data->kevent_added_successfully = true;
    return;

subscribe_failed:
    handle_data->kevent_added_successfully = false;

    /* Remove any related kevents that succeeded */
    for (int i = 0; i < num_events; ++i) {
        if (changelist[i].data == 0) {
            changelist[i].flags = EV_DELETE;
            kevent(
                impl->kq_fd,
                &changelist[i] /*changelist*/,
                1 /*nchanges*/,
                NULL /*eventlist*/,
                0 /*nevents*/,
                NULL /*timeout*/);
        }
    }

    /* We can't return an error code because this was a scheduled task.
     * Notify the user of the failed subscription by passing AWS_IO_EVENT_TYPE_ERROR to the callback.
     * Also raise AWS_IO_SYS_CALL_FAILURE, which might be helpful to anyone monitoring */
    aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
    handle_data->on_event(
        handle_data->event_loop, handle_data->owner, AWS_IO_EVENT_TYPE_ERROR, handle_data->on_event_user_data);
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

    struct handle_data *handle_data = aws_mem_acquire(event_loop->alloc, sizeof(struct handle_data));
    if (!handle_data) {
        return AWS_OP_ERR;
    }

    handle_data->owner = handle;
    handle_data->event_loop = event_loop;
    handle_data->on_event = on_event;
    handle_data->on_event_user_data = user_data;
    handle_data->events_subscribed = events;
    handle_data->events_this_loop = 0;
    handle_data->kevent_added_successfully = false;

    handle->additional_data = handle_data;

    /* We schedule a task to perform the actual changes to the kqueue, read on for an explanation why...
     *
     * kqueue requires separate registrations for read and write events.
     * If the user wants to know about both read and write, we need register once for read and once for write.
     * If the first registration succeeds, but the second registration fails, we need to delete the first registration.
     * If this all happened outside the event-thread, the successful registration's events could begin processing
     * in the brief window of time before the registration is deleted. */

    struct aws_task task = {
        .fn = s_subscribe_task,
        .arg = handle_data,
    };

    int err = s_schedule_task_now(event_loop, &task);
    if (err) {
        goto clean_up;
    }

    return AWS_OP_SUCCESS;

clean_up:
    handle->additional_data = NULL;
    aws_mem_release(event_loop->alloc, handle_data);
    return AWS_OP_ERR;
}

static void s_unsubscribe_task(void *user_data, enum aws_task_status status) {
    struct handle_data *handle_data = user_data;
    struct kqueue_loop *impl = handle_data->event_loop->impl_data;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        if (handle_data->kevent_added_successfully) {
            struct kevent changelist[2];
            int changelist_size = 0;

            if (handle_data->events_subscribed & AWS_IO_EVENT_TYPE_READABLE) {
                EV_SET(
                    &changelist[changelist_size++],
                    handle_data->owner->data.fd,
                    EVFILT_READ /*filter*/,
                    EV_DELETE /*flags*/,
                    0 /*fflags*/,
                    0 /*data*/,
                    handle_data /*udata*/);
            }
            if (handle_data->events_subscribed & AWS_IO_EVENT_TYPE_WRITABLE) {
                EV_SET(
                    &changelist[changelist_size++],
                    handle_data->owner->data.fd,
                    EVFILT_WRITE /*filter*/,
                    EV_DELETE /*flags*/,
                    0 /*fflags*/,
                    0 /*data*/,
                    handle_data /*udata*/);
            }

            kevent(impl->kq_fd, changelist, changelist_size, NULL /*eventlist*/, 0 /*nevents*/, NULL /*timeout*/);
        }
    }

    /* Clean up handle_data even if task was cancelled. */
    aws_mem_release(handle_data->event_loop->alloc, handle_data);
}

static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    assert(handle->additional_data);
    struct handle_data *handle_data = handle->additional_data;
    handle->additional_data = NULL;

    struct aws_task task = {
        .fn = s_unsubscribe_task,
        .arg = handle_data,
    };

    int err = s_schedule_task_now(event_loop, &task);
    if (err) {
        goto clean_up;
    }

    return AWS_OP_SUCCESS;

clean_up:
    return AWS_OP_ERR;
}

static bool s_is_event_thread(struct aws_event_loop *event_loop) {
    struct kqueue_loop *impl = event_loop->impl_data;

    return aws_thread_current_thread_id() == aws_thread_get_id(&impl->thread);
}

/* Called from thread.
 * Takes tasks from tasks_to_schedule and adds them to the scheduler.
 * If everything is successful, tasks_to_schedule will be emptied.
 * If anything goes wrong, tasks_to_schedule will be left with the unprocessed tasks */
static int s_process_tasks_to_schedule(struct aws_event_loop *event_loop) {
    struct kqueue_loop *impl = event_loop->impl_data;

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

static void s_process_cross_thread_data(struct aws_event_loop *event_loop) {
    struct kqueue_loop *impl = event_loop->impl_data;

    bool should_resignal_cross_thread_data = false;

    { /* Begin critical section */
        aws_mutex_lock(&impl->cross_thread_data.mutex);
        impl->cross_thread_data.thread_signaled = false;

        bool initiate_stop = (impl->cross_thread_data.state == EVENT_THREAD_STATE_STOPPING) &&
                             (impl->thread_data.state == EVENT_THREAD_STATE_RUNNING);
        if (AWS_UNLIKELY(initiate_stop)) {
            impl->thread_data.state = EVENT_THREAD_STATE_STOPPING;
        }

        /* If there are tasks to schedule, move them from cross_thread_data to thread_data.
         * We'll process them later, so that we minimize time spent holding the mutex. */
        bool tasks_to_schedule = aws_array_list_length(&impl->cross_thread_data.tasks_to_schedule) > 0;
        if (AWS_LIKELY(tasks_to_schedule)) {
            /* Swapping the contents of the two lists is the fastest and safest way to move this data,
             * but requires the other list to be empty. */
            bool swap_possible = aws_array_list_length(&impl->thread_data.tasks_to_schedule) == 0;
            if (AWS_LIKELY(swap_possible)) {
                aws_array_list_swap_contents(
                    &impl->cross_thread_data.tasks_to_schedule, &impl->thread_data.tasks_to_schedule);
            } else {
                /* If swap not possible, signal the thread to try again next loop */
                should_resignal_cross_thread_data = true;
                impl->cross_thread_data.thread_signaled = true;
            }
        }

        aws_mutex_unlock(&impl->cross_thread_data.mutex);
    } /* End critical section */

    s_process_tasks_to_schedule(event_loop);

    if (should_resignal_cross_thread_data) {
        signal_cross_thread_data_changed(event_loop);
    }
}

static int s_aws_event_flags_from_kevent(struct kevent *kevent) {
    int event_flags = 0;

    if (kevent->flags & EV_ERROR) {
        event_flags |= AWS_IO_EVENT_TYPE_ERROR;
    } else if (kevent->filter == EVFILT_READ) {
        if (kevent->data != 0) {
            event_flags |= AWS_IO_EVENT_TYPE_READABLE;
        }

        if (kevent->flags & EV_EOF) {
            event_flags |= AWS_IO_EVENT_TYPE_CLOSED;
        }
    } else if (kevent->filter == EVFILT_WRITE) {
        if (kevent->data != 0) {
            event_flags |= AWS_IO_EVENT_TYPE_WRITABLE;
        }

        if (kevent->flags & EV_EOF) {
            event_flags |= AWS_IO_EVENT_TYPE_CLOSED;
        }
    }

    return event_flags;
}

static void s_event_thread_main(void *user_data) {
    struct aws_event_loop *event_loop = user_data;
    struct kqueue_loop *impl = event_loop->impl_data;

    assert(impl->thread_data.state == EVENT_THREAD_STATE_READY_TO_RUN);
    impl->thread_data.state = EVENT_THREAD_STATE_RUNNING;

    struct kevent kevents[MAX_EVENTS];

    /* A single aws_io_handle could have two separate kevents if subscribed for both read and write.
     * If both the read and write kevents fire in the same loop of the event-thread,
     * combine the event-flags and deliver them in a single callback.
     * This makes the kqueue_event_loop behave more like the other platform implementations. */
    struct handle_data *io_handle_events[MAX_EVENTS];

    struct timespec timeout = {
        .tv_sec = DEFAULT_TIMEOUT_SEC,
        .tv_nsec = 0,
    };

    while (impl->thread_data.state == EVENT_THREAD_STATE_RUNNING) {
        int num_io_handle_events = 0;
        bool should_process_cross_thread_data = false;

        /* Process kqueue events */
        int num_kevents = kevent(
            impl->kq_fd, NULL /*changelist*/, 0 /*nchanges*/, kevents /*eventlist*/, MAX_EVENTS /*nevents*/, &timeout);

        if (num_kevents == -1) {
            /* Raise an error, in case this is interesting to anyone monitoring,
             * and continue on with this loop. We can't process events,
             * but we can still process scheduled tasks */
            aws_raise_error(AWS_IO_SYS_CALL_FAILURE);

            /* Force the cross_thread_data to be processed.
             * There might be valuable info in there, like the message to stop the thread.
             * It's fine to do this even if nothing has changed, it just costs a mutex lock/unlock. */
            should_process_cross_thread_data = true;
        }

        for (int i = 0; i < num_kevents; ++i) {
            struct kevent *kevent = &kevents[i];

            /* Was this event to signal that cross_thread_data has changed? */
            if (kevent->ident == impl->cross_thread_signal_pipe_read.data.fd) {
                should_process_cross_thread_data = true;

                /* Drain whatever data was written to the signaling pipe */
                uint32_t read_whatever;
                while (read(kevent->ident, &read_whatever, sizeof(read_whatever)) > 0) {
                }

                continue;
            }

            /* Otherwise this was a normal event on a subscribed handle. Figure out which flags to report. */
            int event_flags = s_aws_event_flags_from_kevent(kevent);
            if (event_flags == 0) {
                continue;
            }

            /* Combine flags, in case multiple kevents correspond to one handle. (see notes at top of function) */
            struct handle_data *handle_data = kevent->udata;
            if (handle_data->events_this_loop == 0) {
                io_handle_events[num_io_handle_events++] = handle_data;
            }
            handle_data->events_this_loop |= event_flags;
        }

        /* Invoke each handle's event callback */
        for (int i = 0; i < num_io_handle_events; ++i) {
            struct handle_data *handle_data = io_handle_events[i];
            handle_data->on_event(
                event_loop, handle_data->owner, handle_data->events_this_loop, handle_data->on_event_user_data);
            handle_data->events_this_loop = 0;
        }

        /* Just in case anything in thread_data.tasks_to_schedule failed to process in the past, try again. */
        s_process_tasks_to_schedule(event_loop);

        /* Process cross_thread_data */
        if (should_process_cross_thread_data) {
            s_process_cross_thread_data(event_loop);
        }

        /* Run scheduled tasks */
        uint64_t next_run_time_ns = 0;
        aws_task_scheduler_run_all(&impl->thread_data.scheduler, &next_run_time_ns);

        /* Set timeout for next kevent() call */
        uint64_t now_ns;
        if ((next_run_time_ns != 0) && (event_loop->clock(&now_ns) == AWS_OP_SUCCESS)) {
            uint64_t timeout_ns = next_run_time_ns > now_ns ? next_run_time_ns - now_ns : 0;

            timeout.tv_sec = (time_t)(timeout_ns / NANOSEC_PER_SEC);
            timeout.tv_nsec = (long)(timeout_ns % NANOSEC_PER_SEC);
        } else {
            timeout.tv_sec = DEFAULT_TIMEOUT_SEC;
            timeout.tv_nsec = 0;
        }
    }
}
