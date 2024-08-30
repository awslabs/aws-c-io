/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/event_loop.h>

#include <aws/cal/cal.h>
#include <aws/common/atomics.h>
#include <aws/common/clock.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/thread.h>
#include <aws/io/private/tracing.h>

#include <aws/io/logging.h>

#include <sys/iomsg.h>

#include <errno.h>
#include <limits.h>
#include <unistd.h>

static void s_destroy(struct aws_event_loop *event_loop);
static int s_run(struct aws_event_loop *event_loop);
static int s_stop(struct aws_event_loop *event_loop);
static int s_wait_for_stop_completion(struct aws_event_loop *event_loop);
static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task);
static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos);
static void s_cancel_task(struct aws_event_loop *event_loop, struct aws_task *task);
static int s_subscribe_to_io_events(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    aws_event_loop_on_event_fn *on_event,
    void *user_data);
static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle);
static void s_free_io_event_resources(void *user_data);
static bool s_is_on_callers_thread(struct aws_event_loop *event_loop);

static void aws_event_loop_thread(void *args);

static struct aws_event_loop_vtable s_vtable = {
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

struct ionotify_loop {
    struct aws_task_scheduler scheduler;
    struct aws_thread thread_created_on;
    struct aws_thread_options thread_options;
    aws_thread_id_t thread_joined_to;
    struct aws_atomic_var running_thread_id;
    /* Channel to receive pulses. */
    int pulse_channel_id;
    /* Connection opened on the pulse channel. */
    int pulse_connection_id;
    struct aws_mutex task_pre_queue_mutex;
    struct aws_linked_list task_pre_queue;
    struct aws_task stop_task;
    struct aws_atomic_var stop_task_ptr;
    bool should_continue;
};

struct ionotify_event_data {
    struct aws_allocator *alloc;
    struct aws_io_handle *handle;
    aws_event_loop_on_event_fn *on_event;
    int events_subscribed;
    /* Connection opened on the pulse channel. */
    int pulse_connection_id;
    struct sigevent event;
    void *user_data;
    struct aws_task cleanup_task;
    /* false when handle is unsubscribed, but this struct hasn't been cleaned up yet */
    bool is_subscribed;
};

/* default timeout is 100 seconds */
uint64_t DEFAULT_TIMEOUT = 100ULL * 1000000000;
int MAX_EVENTS = 100;

/**/
short IO_EVENT_PULSE_SIGEV_CODE = _PULSE_CODE_MINAVAIL;
short CROSS_THREAD_PULSE_SIGEV_CODE = _PULSE_CODE_MINAVAIL + 1;


/* Setup edge triggered ionotify with a scheduler. */
struct aws_event_loop *aws_event_loop_new_default_with_options(
    struct aws_allocator *alloc,
    const struct aws_event_loop_options *options) {
    AWS_PRECONDITION(options);
    AWS_PRECONDITION(options->clock);

    struct aws_event_loop *event_loop = aws_mem_calloc(alloc, 1, sizeof(struct aws_event_loop));
    if (!event_loop) {
        return NULL;
    }

    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Initializing edge-triggered ionotify", (void *)event_loop);
    if (aws_event_loop_init_base(event_loop, alloc, options->clock)) {
        goto clean_up_loop;
    }

    struct ionotify_loop *ionotify_loop = aws_mem_calloc(alloc, 1, sizeof(struct ionotify_loop));
    if (!ionotify_loop) {
        goto cleanup_base_loop;
    }

    if (options->thread_options) {
        ionotify_loop->thread_options = *options->thread_options;
    } else {
        ionotify_loop->thread_options = *aws_default_thread_options();
    }

    /* initialize thread id to NULL, it should be updated when the event loop thread starts. */
    aws_atomic_init_ptr(&ionotify_loop->running_thread_id, NULL);

    aws_linked_list_init(&ionotify_loop->task_pre_queue);
    ionotify_loop->task_pre_queue_mutex = (struct aws_mutex)AWS_MUTEX_INIT;
    aws_atomic_init_ptr(&ionotify_loop->stop_task_ptr, NULL);

    if (aws_thread_init(&ionotify_loop->thread_created_on, alloc)) {
        goto clean_up_ionotify;
    }

    /* Setup channel to receive resource manager and cross-thread pulses. */
    ionotify_loop->pulse_channel_id = ChannelCreate(_NTO_CHF_INHERIT_RUNMASK);
    if (ionotify_loop->pulse_channel_id < 0) {
        printf("ChannelCreate failed: %d\n", ionotify_loop->pulse_channel_id);
        goto clean_up_ionotify;
    }

    AWS_LOGF_DEBUG(AWS_LS_IO_EVENT_LOOP, "id=%p: Opened channel with ID %d", (void *)event_loop, ionotify_loop->pulse_channel_id);

    ionotify_loop->pulse_connection_id = ConnectAttach(0, 0, ionotify_loop->pulse_channel_id, _NTO_SIDE_CHANNEL, 0);
    if (ionotify_loop->pulse_connection_id < 0) {
        goto clean_up_ionotify;
    }

    if (aws_task_scheduler_init(&ionotify_loop->scheduler, alloc)) {
        goto clean_up_thread;
    }

    ionotify_loop->should_continue = false;

    event_loop->impl_data = ionotify_loop;
    event_loop->vtable = &s_vtable;

    return event_loop;

clean_up_thread:
    aws_thread_clean_up(&ionotify_loop->thread_created_on);

clean_up_ionotify:
    aws_mem_release(alloc, ionotify_loop);

cleanup_base_loop:
    aws_event_loop_clean_up_base(event_loop);

clean_up_loop:
    aws_mem_release(alloc, event_loop);

    return NULL;
}

static void s_destroy(struct aws_event_loop *event_loop) {
    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Destroying event_loop", (void *)event_loop);

    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    /* we don't know if stop() has been called by someone else,
     * just call stop() again and wait for event-loop to finish. */
    aws_event_loop_stop(event_loop);
    s_wait_for_stop_completion(event_loop);

    /* setting this so that canceled tasks don't blow up when asking if they're on the event-loop thread. */
    ionotify_loop->thread_joined_to = aws_thread_current_thread_id();
    aws_atomic_store_ptr(&ionotify_loop->running_thread_id, &ionotify_loop->thread_joined_to);
    aws_task_scheduler_clean_up(&ionotify_loop->scheduler);

    while (!aws_linked_list_empty(&ionotify_loop->task_pre_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&ionotify_loop->task_pre_queue);
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
        task->fn(task, task->arg, AWS_TASK_STATUS_CANCELED);
    }

    aws_thread_clean_up(&ionotify_loop->thread_created_on);

    aws_mem_release(event_loop->alloc, ionotify_loop);
    aws_event_loop_clean_up_base(event_loop);
    aws_mem_release(event_loop->alloc, event_loop);
}

static int s_run(struct aws_event_loop *event_loop) {
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Starting event-loop thread.", (void *)event_loop);

    ionotify_loop->should_continue = true;
    aws_thread_increment_unjoined_count();
    if (aws_thread_launch(
            &ionotify_loop->thread_created_on, &aws_event_loop_thread, event_loop, &ionotify_loop->thread_options)) {

        aws_thread_decrement_unjoined_count();
        AWS_LOGF_FATAL(AWS_LS_IO_EVENT_LOOP, "id=%p: thread creation failed.", (void *)event_loop);
        ionotify_loop->should_continue = false;
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_stop_task(struct aws_task *task, void *args, enum aws_task_status status) {

    (void)task;
    struct aws_event_loop *event_loop = args;
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    /* now okay to reschedule stop tasks. */
    aws_atomic_store_ptr(&ionotify_loop->stop_task_ptr, NULL);
    if (status == AWS_TASK_STATUS_RUN_READY) {
        /*
         * this allows the event loop to invoke the callback once the event loop has completed.
         */
        ionotify_loop->should_continue = false;
    }
}

static int s_stop(struct aws_event_loop *event_loop) {
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    void *expected_ptr = NULL;
    bool update_succeeded =
        aws_atomic_compare_exchange_ptr(&ionotify_loop->stop_task_ptr, &expected_ptr, &ionotify_loop->stop_task);
    if (!update_succeeded) {
        /* the stop task is already scheduled. */
        return AWS_OP_SUCCESS;
    }
    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Stopping event-loop thread.", (void *)event_loop);
    aws_task_init(&ionotify_loop->stop_task, s_stop_task, event_loop, "ionotify_event_loop_stop");
    s_schedule_task_now(event_loop, &ionotify_loop->stop_task);

    return AWS_OP_SUCCESS;
}

static int s_wait_for_stop_completion(struct aws_event_loop *event_loop) {
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;
    int result = aws_thread_join(&ionotify_loop->thread_created_on);
    aws_thread_decrement_unjoined_count();
    return result;
}

static int s_schedule_task_common(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    /* if event loop and the caller are the same thread, just schedule and be done with it. */
    if (s_is_on_callers_thread(event_loop)) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: scheduling task %p in-thread for timestamp %llu",
            (void *)event_loop,
            (void *)task,
            (unsigned long long)run_at_nanos);
        if (run_at_nanos == 0) {
            /* zero denotes "now" task */
            aws_task_scheduler_schedule_now(&ionotify_loop->scheduler, task);
        } else {
            aws_task_scheduler_schedule_future(&ionotify_loop->scheduler, task, run_at_nanos);
        }
        return AWS_OP_SUCCESS;
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: Scheduling task %p cross-thread for timestamp %llu",
        (void *)event_loop,
        (void *)task,
        (unsigned long long)run_at_nanos);
    task->timestamp = run_at_nanos;
    aws_mutex_lock(&ionotify_loop->task_pre_queue_mutex);

    bool is_first_task = aws_linked_list_empty(&ionotify_loop->task_pre_queue);

    aws_linked_list_push_back(&ionotify_loop->task_pre_queue, &task->node);

    /* if the list was not empty, we already have a pending read on the pipe/eventfd, no need to write again. */
    if (is_first_task) {
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Waking up event-loop thread by sending pulse to connection ID %d", (void *)event_loop, ionotify_loop->pulse_connection_id);
        int rc = MsgSendPulsePtr(ionotify_loop->pulse_connection_id, -1, CROSS_THREAD_PULSE_SIGEV_CODE, NULL);
        int errno_value = errno;
        if (rc < 0) {
            AWS_LOGF_ERROR(AWS_LS_IO_EVENT_LOOP, "id=%p: Failed to send cross-thread pulse: %d (%s)", (void *)event_loop, errno_value, strerror(errno_value));
            aws_mutex_unlock(&ionotify_loop->task_pre_queue_mutex);
            return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
        }
    }

    aws_mutex_unlock(&ionotify_loop->task_pre_queue_mutex);
    return AWS_OP_SUCCESS;
}

static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task) {
    s_schedule_task_common(event_loop, task, 0 /* zero denotes "now" task */);
}

static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    s_schedule_task_common(event_loop, task, run_at_nanos);
}

static void s_cancel_task(struct aws_event_loop *event_loop, struct aws_task *task) {
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: cancelling task %p", (void *)event_loop, (void *)task);
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;
    aws_task_scheduler_cancel_task(&ionotify_loop->scheduler, task);
}

static int s_subscribe_to_io_events(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    aws_event_loop_on_event_fn *on_event,
    void *user_data) {

    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: subscribing to events on fd %d", (void *)event_loop, handle->data.fd);
    struct ionotify_event_data *ionotify_event_data =
        aws_mem_calloc(event_loop->alloc, 1, sizeof(struct ionotify_event_data));
    handle->additional_data = ionotify_event_data;
    if (!ionotify_event_data) {
        return AWS_OP_ERR;
    }

    ionotify_event_data->alloc = event_loop->alloc;
    ionotify_event_data->pulse_connection_id = ionotify_loop->pulse_connection_id;
    ionotify_event_data->user_data = user_data;
    ionotify_event_data->handle = handle;
    ionotify_event_data->on_event = on_event;
    ionotify_event_data->events_subscribed = events;
    ionotify_event_data->is_subscribed = true;

    /* Everyone is always registered for out-of-band data and errors. */
    uint32_t event_mask = _NOTIFY_COND_OBAND;

    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        event_mask |= _NOTIFY_COND_INPUT;
    }

    if (events & AWS_IO_EVENT_TYPE_WRITABLE) {
        event_mask |= _NOTIFY_COND_OUTPUT;
    }

    /* I/O events from ionotify will be delivered as pulses with a user-defined pointer set to ionotify_event_data instance.
     * SIGEV_PULSE_PRIO_INHERIT means the thread that receives the pulse will run at the initial priority of the process. */
    /* TODO Consider using SI_NOTIFY. */
    short pulse_priority = SIGEV_PULSE_PRIO_INHERIT;
    /* Additional code set in all pulses arriving from resource managers. Helps distinguish from pulses from other sources, like cross-treads. */
    short pulse_sigev_code = IO_EVENT_PULSE_SIGEV_CODE;
    SIGEV_PULSE_PTR_INIT(&ionotify_event_data->event, ionotify_event_data->pulse_connection_id, pulse_priority, pulse_sigev_code, ionotify_event_data);

    AWS_LOGF_DEBUG(AWS_LS_IO_EVENT_LOOP, "id=%p: Use connection ID %d to receive pulses", (void *)event_loop, ionotify_event_data->pulse_connection_id);

    /* The application must register the event by calling MsgRegisterEvent() with the fd processed in ionotify().
     * See:
     * https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/i/ionotify.html
     * https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/m/msgregisterevent.html
     *
     * It's enough to register an event only once and then reuse it on followup ionotify rearming calls.
     * NOTE: If you create a new sigevent for the same file descriptor, with the same flags, you HAVE to register it. */
    MsgRegisterEvent(&ionotify_event_data->event, ionotify_event_data->handle->data.fd);

    /* Arm resource manager associated with a given file descriptor in edge-triggered mode. */
    int rc = ionotify(ionotify_event_data->handle->data.fd, _NOTIFY_ACTION_EDGEARM, event_mask, &ionotify_event_data->event);
    int errno_value = errno;
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: ionotify returned %d (input %d; output %d)", (void *)event_loop, rc, rc & _NOTIFY_COND_INPUT, rc & _NOTIFY_COND_OUTPUT);
    if (rc < 0) {
        AWS_LOGF_ERROR(AWS_LS_IO_EVENT_LOOP, "id=%p: Failed to subscribe to events on fd %d: error %d (%s)", (void *)event_loop, ionotify_event_data->handle->data.fd, errno_value, strerror(errno_value));
        return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
    }

    /* File descriptor is rlready eadable. Send notification kick-start the reading process. */
    if ((rc & _NOTIFY_COND_INPUT) == _NOTIFY_COND_INPUT) {
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Sending pulse for fd %d", (void *)event_loop, ionotify_event_data->handle->data.fd);
        int send_rc = MsgSendPulsePtr(ionotify_loop->pulse_connection_id, -1, IO_EVENT_PULSE_SIGEV_CODE, ionotify_event_data);
        if (send_rc < 0) {
            AWS_LOGF_ERROR(AWS_LS_IO_EVENT_LOOP, "id=%p: Failed to send pulse for fd %d", (void *)event_loop, ionotify_event_data->handle->data.fd);
        }
    }

    /* TODO Handle writing available. */

    return AWS_OP_SUCCESS;
}

static void s_free_io_event_resources(void *user_data) {
    struct ionotify_event_data *event_data = user_data;
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "Releasing ionotify_event_data at %p", user_data);
    aws_mem_release(event_data->alloc, (void *)event_data);
}

static void s_unsubscribe_cleanup_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct ionotify_event_data *event_data = (struct ionotify_event_data *)arg;
    s_free_io_event_resources(event_data);
}

static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP, "id=%p: un-subscribing from events on fd %d", (void *)event_loop, handle->data.fd);

    AWS_ASSERT(handle->additional_data);
    struct ionotify_event_data *ionotify_event_data = handle->additional_data;

    /* Disarm resource manager for a given fd. */
    uint32_t event_mask = _NOTIFY_COND_OBAND;
    if (ionotify_event_data->events_subscribed & AWS_IO_EVENT_TYPE_READABLE) {
        event_mask |= _NOTIFY_COND_INPUT;
    }
    if (ionotify_event_data->events_subscribed & AWS_IO_EVENT_TYPE_WRITABLE) {
        event_mask |= _NOTIFY_COND_OUTPUT;
    }
    int rc = ionotify(ionotify_event_data->handle->data.fd, _NOTIFY_ACTION_EDGEARM, event_mask, NULL);
    int errno_value = errno;
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: 2: ionotify returned %d (input %d; output %d)", (void *)event_loop, rc, rc & _NOTIFY_COND_INPUT, rc & _NOTIFY_COND_OUTPUT);
    if (rc < 0) {
        AWS_LOGF_ERROR(AWS_LS_IO_EVENT_LOOP, "id=%p: Failed to unsubscribe from events on fd %d: error %d (%s)", (void *)event_loop, ionotify_event_data->handle->data.fd, errno_value, strerror(errno_value));
        return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
    }

    /* We can't clean up yet, because we have schedule tasks and more events to process,
     * mark it as unsubscribed and schedule a cleanup task. */
    ionotify_event_data->is_subscribed = false;

    aws_task_init(
        &ionotify_event_data->cleanup_task,
        s_unsubscribe_cleanup_task,
        ionotify_event_data,
        "ionotify_event_loop_unsubscribe_cleanup");
    s_schedule_task_now(event_loop, &ionotify_event_data->cleanup_task);

    handle->additional_data = NULL;
    return AWS_OP_SUCCESS;
}

static bool s_is_on_callers_thread(struct aws_event_loop *event_loop) {
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    aws_thread_id_t *thread_id = aws_atomic_load_ptr(&ionotify_loop->running_thread_id);
    return thread_id && aws_thread_thread_id_equal(*thread_id, aws_thread_current_thread_id());
}

static void s_process_task_pre_queue(struct aws_event_loop *event_loop) {
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: processing cross-thread tasks", (void *)event_loop);

    struct aws_linked_list task_pre_queue;
    aws_linked_list_init(&task_pre_queue);

    aws_mutex_lock(&ionotify_loop->task_pre_queue_mutex);
    aws_linked_list_swap_contents(&ionotify_loop->task_pre_queue, &task_pre_queue);
    aws_mutex_unlock(&ionotify_loop->task_pre_queue_mutex);


    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Is cross-thread task list empty: %d", (void *)event_loop, aws_linked_list_empty(&task_pre_queue));

    while (!aws_linked_list_empty(&task_pre_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&task_pre_queue);
        struct aws_task *task = AWS_CONTAINER_OF(node, struct aws_task, node);
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: task %p pulled to event-loop, scheduling now.",
            (void *)event_loop,
            (void *)task);
        /* Timestamp 0 is used to denote "now" tasks */
        if (task->timestamp == 0) {
            aws_task_scheduler_schedule_now(&ionotify_loop->scheduler, task);
        } else {
            aws_task_scheduler_schedule_future(&ionotify_loop->scheduler, task, task->timestamp);
        }
    }
}

/**
 * This just calls MsgReceive()
 *
 * We broke this out into its own function so that the stacktrace clearly shows
 * what this thread is doing. We've had a lot of cases where users think this
 * thread is deadlocked because it's stuck here. We want it to be clear
 * that it's doing nothing on purpose. It's waiting for events to happen...
 */
AWS_NO_INLINE
static rcvid_t aws_event_loop_listen_for_io_events(int pulse_channel_id, const uint64_t *timeout, struct _pulse *pulse, int *errno_value) {
    /* Event of type SIGEV_UNBLOCK makes the timed-out kernel call fail with an error of ETIMEDOUT. */
    struct sigevent notify;
    SIGEV_UNBLOCK_INIT(&notify);
    int rc = TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, &notify, timeout, NULL);
    if (rc < 0) {
        *errno_value = errno;
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "TimerTImeout failed");
        return rc;
    }
    rcvid_t rcvid = MsgReceive(pulse_channel_id, pulse, sizeof(*pulse), NULL);
    if (rcvid < 0) {
        *errno_value = errno;
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "MsgReceive failed");
    }
    return rcvid;
}

static void s_aws_ionotify_cleanup_aws_lc_thread_local_state(void *user_data) {
    (void)user_data;

    aws_cal_thread_clean_up();
}

static void aws_event_loop_thread(void *args) {
    struct aws_event_loop *event_loop = args;
    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: main loop started", (void *)event_loop);
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    /* set thread id to the thread of the event loop */
    aws_atomic_store_ptr(&ionotify_loop->running_thread_id, &ionotify_loop->thread_created_on.thread_id);

    aws_thread_current_at_exit(s_aws_ionotify_cleanup_aws_lc_thread_local_state, NULL);

    uint64_t timeout = DEFAULT_TIMEOUT;

    AWS_LOGF_INFO(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: default timeout %"PRIu64", and max events to process per tick %d",
        (void *)event_loop,
        timeout,
        MAX_EVENTS);

    /*
     * until stop is called,
     * call MsgReceive, if a task is scheduled, or a file descriptor has activity, it will
     * return.
     *
     * process all events,
     *
     * run all scheduled tasks.
     *
     * process queued subscription cleanups.
     */
    while (ionotify_loop->should_continue) {

        bool should_process_cross_thread_tasks = false;

        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: waiting for a maximum of %"PRIu64" ms", (void *)event_loop, timeout);
        struct _pulse pulse;
        int errno_value;
        rcvid_t rcvid = aws_event_loop_listen_for_io_events(ionotify_loop->pulse_channel_id, &timeout, &pulse, &errno_value);
        aws_event_loop_register_tick_start(event_loop);

        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: wake up with rcvid %ld\n", (void *)event_loop, rcvid);
        struct ionotify_event_data *ionotify_event_data = NULL;
        if (rcvid == 0) {
            ionotify_event_data = pulse.value.sival_ptr;
        } else if (rcvid > 0) {
            AWS_LOGF_DEBUG(AWS_LS_IO_EVENT_LOOP, "id=%p: Received message, ignoring\n", (void *)event_loop);
            continue;
        } else {
            if (errno_value == ETIMEDOUT) {
                AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Woke up by timeout\n", (void *)event_loop);
            } else {
                AWS_LOGF_ERROR(AWS_LS_IO_EVENT_LOOP, "id=%p: Listening for I/O events failed with error %d (%s)", (void *)event_loop, errno_value, strerror(errno_value));
            }
        }

        if (pulse.code == CROSS_THREAD_PULSE_SIGEV_CODE) {
            AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: MsgReceived got cross-thread pulse", (void *)event_loop);
            should_process_cross_thread_tasks = true;
        } else if (pulse.code == IO_EVENT_PULSE_SIGEV_CODE) {
            AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: MsgReceived got I/O event pulse", (void *)event_loop);
            if (ionotify_event_data == NULL) {
                AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: MsgReceived got empty ionotify_event_data, ignoring it", (void *)event_loop);
            } else if (ionotify_event_data->is_subscribed) {
                AWS_LOGF_TRACE(
                    AWS_LS_IO_EVENT_LOOP,
                    "id=%p: Activity on fd %d, invoking handler.",
                    (void *)event_loop,
                    ionotify_event_data->handle->data.fd);
                int event_mask = AWS_IO_EVENT_TYPE_READABLE;
                __itt_task_begin(io_tracing_domain, __itt_null, __itt_null, tracing_event_loop_event);
                ionotify_event_data->on_event(event_loop, ionotify_event_data->handle, event_mask, ionotify_event_data->user_data);
                __itt_task_end(io_tracing_domain);
            } else {
                AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: MsgReceived got pulse for unsubscribed fd, ignoring it", (void *)event_loop);
            }
        } else {
            AWS_LOGF_WARN(AWS_LS_IO_EVENT_LOOP, "id=%p: MsgReceived got pulse with unknown code %d, ignoring it", (void *)event_loop, pulse.code);
        }


        __itt_task_end(io_tracing_domain);

        /* run scheduled tasks */
        if (should_process_cross_thread_tasks) {
            AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Processing prequeued tasks", (void *)event_loop);
            s_process_task_pre_queue(event_loop);
        }

        uint64_t now_ns = 0;
        event_loop->clock(&now_ns); /* if clock fails, now_ns will be 0 and tasks scheduled for a specific time
                                       will not be run. That's ok, we'll handle them next time around. */
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Running scheduled tasks", (void *)event_loop);
        __itt_task_begin(io_tracing_domain, __itt_null, __itt_null, tracing_event_loop_run_tasks);
        aws_task_scheduler_run_all(&ionotify_loop->scheduler, now_ns);
        __itt_task_end(io_tracing_domain);

        /* set timeout for next MsgReceive call.
         * if clock fails, or scheduler has no tasks, use default timeout */
        bool use_default_timeout = false;

        if (event_loop->clock(&now_ns)) {
            use_default_timeout = true;
        }

        uint64_t next_run_time_ns;
        if (!aws_task_scheduler_has_tasks(&ionotify_loop->scheduler, &next_run_time_ns)) {
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
                "%llu, using timeout of %"PRIu64,
                (void *)event_loop,
                (unsigned long long)timeout_ns,
                timeout);
        }

        aws_event_loop_register_tick_end(event_loop);
    }

    AWS_LOGF_DEBUG(AWS_LS_IO_EVENT_LOOP, "id=%p: exiting main loop", (void *)event_loop);
    /* set thread id back to NULL. This should be updated again in destroy, before tasks are canceled. */
    aws_atomic_store_ptr(&ionotify_loop->running_thread_id, NULL);
}
