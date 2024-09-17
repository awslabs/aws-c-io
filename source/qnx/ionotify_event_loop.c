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
#include <aws/io/logging.h>
#include <aws/io/private/tracing.h>

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
    /* Channel to receive I/O events. Resource managers open connections to this channel to send their events. */
    int io_events_channel_id;
    /* Connection to the events channel opened by the event loop. It's used by ionotify and some event loop logic (e.g.
     * cross-thread and I/O results notifications) to send pulses to the pulse channel. */
    int pulse_connection_id;
    struct aws_mutex task_pre_queue_mutex;
    struct aws_linked_list task_pre_queue;
    struct aws_task stop_task;
    struct aws_atomic_var stop_task_ptr;
    bool should_continue;
    /* ionotify forces to choose one of the following as user-provided data associated with each received event:
     * 1. A pointer. But events won't contain the triggered flags (i.e. your code has to figure out itself if it was
     * _NOTIFY_COND_INPUT or _NOTIFY_COND_HUP).
     * 2. Some bits of a special field of type int (28 bits on x86_64). QNX will use the remaining bits (4 bits in
     * QNX 8.0) in this field to specify the types of the triggered events.
     *
     * Since event loop must know the types of received I/O events, the second options is used. 28-bit IDs are mapped to
     * each subscribed aws_io_handle. The mapping is stored in this hash table.
     */
    struct aws_hash_table handles;
    int last_handle_id;
};

/* Data associated with a subscribed I/O handle. */
struct ionotify_event_data {
    struct aws_allocator *alloc;
    struct aws_io_handle *handle;
    struct aws_event_loop *event_loop;
    aws_event_loop_on_event_fn *on_event;
    int events_subscribed;
    /* enum aws_io_event_type */
    int latest_io_event_types;
    /* Connection opened on the events channel. Used to send pulses to the main event loop. */
    int pulse_connection_id;
    struct sigevent event;
    void *user_data;
    struct aws_task subscribe_task;
    struct aws_task cleanup_task;
    /* ID with a value that can fit into pulse user data field (only _NOTIFY_COND_MASK bits can be used). */
    int handle_id;
    /* False when handle is unsubscribed, but this struct hasn't been cleaned up yet. */
    bool is_subscribed;
};

/* SI_NOTIFY is a QNX special sigev code requesting resource managers to return active event type along with the event
 * itself. */
static short IO_EVENT_PULSE_SIGEV_CODE = SI_NOTIFY;
static short CROSS_THREAD_PULSE_SIGEV_CODE = _PULSE_CODE_MINAVAIL;
static short IO_EVENT_KICKSTART_SIGEV_CODE = _PULSE_CODE_MINAVAIL + 1;
static short IO_EVENT_UPDATE_ERROR_SIGEV_CODE = _PULSE_CODE_MINAVAIL + 2;

/* Setup edge triggered ionotify with a scheduler. */
struct aws_event_loop *aws_event_loop_new_default_with_options(
    struct aws_allocator *alloc,
    const struct aws_event_loop_options *options) {
    AWS_PRECONDITION(options);
    AWS_PRECONDITION(options->clock);

    struct aws_event_loop *event_loop = aws_mem_calloc(alloc, 1, sizeof(struct aws_event_loop));

    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Initializing edge-triggered ionotify", (void *)event_loop);
    if (aws_event_loop_init_base(event_loop, alloc, options->clock)) {
        goto clean_up_loop;
    }

    struct ionotify_loop *ionotify_loop = aws_mem_calloc(alloc, 1, sizeof(struct ionotify_loop));

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

    /* Setup channel to receive cross-thread pulses and pulses from resource managers. */
    ionotify_loop->io_events_channel_id = ChannelCreate(0);
    int errno_value = errno; /* Always cache errno before potential side-effect */
    if (ionotify_loop->io_events_channel_id == -1) {
        printf("ChannelCreate failed with errno %d (%s)\n", errno_value, strerror(errno_value));
        goto clean_up_thread;
    }
    AWS_LOGF_DEBUG(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: Opened QNX channel with ID %d",
        (void *)event_loop,
        ionotify_loop->io_events_channel_id);

    /* Open connection over the QNX channel for pulses. */
    ionotify_loop->pulse_connection_id = ConnectAttach(0, 0, ionotify_loop->io_events_channel_id, _NTO_SIDE_CHANNEL, 0);
    if (ionotify_loop->pulse_connection_id == -1) {
        goto clean_up_thread;
    }

    if (aws_task_scheduler_init(&ionotify_loop->scheduler, alloc)) {
        goto clean_up_thread;
    }

    ionotify_loop->should_continue = false;

    event_loop->impl_data = ionotify_loop;
    event_loop->vtable = &s_vtable;

    if (aws_hash_table_init(&ionotify_loop->handles, alloc, 32, aws_hash_ptr, aws_ptr_eq, NULL, NULL)) {
        goto clean_up_thread;
    }

    return event_loop;

clean_up_thread:
    aws_thread_clean_up(&ionotify_loop->thread_created_on);

clean_up_ionotify:
    aws_mem_release(alloc, ionotify_loop);

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

    aws_hash_table_clean_up(&ionotify_loop->handles);

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
        AWS_LOGF_FATAL(AWS_LS_IO_EVENT_LOOP, "id=%p: Thread creation failed.", (void *)event_loop);
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
        /* this allows the event loop to invoke the callback once the event loop has completed. */
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
    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Stopping event-loop thread", (void *)event_loop);
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

static void s_schedule_task_common(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    /* if event loop and the caller are the same thread, just schedule and be done with it. */
    if (s_is_on_callers_thread(event_loop)) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: Scheduling task %p in-thread for timestamp %llu",
            (void *)event_loop,
            (void *)task,
            (unsigned long long)run_at_nanos);
        if (run_at_nanos == 0) {
            /* zero denotes "now" task */
            aws_task_scheduler_schedule_now(&ionotify_loop->scheduler, task);
        } else {
            aws_task_scheduler_schedule_future(&ionotify_loop->scheduler, task, run_at_nanos);
        }
        return;
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
    aws_mutex_unlock(&ionotify_loop->task_pre_queue_mutex);

    /* If the list was not empty, we already sent a cross-thread pulse. No need to send it again. */
    if (is_first_task) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: Waking up event-loop thread by sending pulse to connection ID %d",
            (void *)event_loop,
            ionotify_loop->pulse_connection_id);
        /* The pulse itself is enough for cross-thread notifications. */
        int user_data_value = 0;
        int rc = MsgSendPulse(ionotify_loop->pulse_connection_id, -1, CROSS_THREAD_PULSE_SIGEV_CODE, user_data_value);
        int errno_value = errno;
        if (rc == -1) {
            /* The task was scheduled, but we couldn't notify the main loop about it. According to QNX docs, inability
             * to send a pulse indicates that there is no available memory left for the process. Not notifying the loop
             * is the minor thing in such a scenario. So, just log the error. */
            AWS_LOGF_ERROR(
                AWS_LS_IO_EVENT_LOOP,
                "id=%p: Failed to send cross-thread pulse: %d (%s)",
                (void *)event_loop,
                errno_value,
                strerror(errno_value));
        }
    }
}

static void s_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task) {
    s_schedule_task_common(event_loop, task, 0 /* zero denotes "now" task */);
}

static void s_schedule_task_future(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at_nanos) {
    s_schedule_task_common(event_loop, task, run_at_nanos);
}

static void s_cancel_task(struct aws_event_loop *event_loop, struct aws_task *task) {
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Cancelling task %p", (void *)event_loop, (void *)task);
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;
    aws_task_scheduler_cancel_task(&ionotify_loop->scheduler, task);
}

/* Map ionotify_event_data to internal ID. */
static int s_add_handle(struct ionotify_loop *ionotify_loop, struct ionotify_event_data *ionotify_event_data) {
    AWS_ASSERT(s_is_on_callers_thread(ionotify_event_data->event_loop));

    /* Special constant, _NOTIFY_COND_MASK, limits the maximum value that can be used as user data in I/O events. */
    int max_handle_id = _NOTIFY_COND_MASK;

    if (AWS_UNLIKELY(aws_hash_table_get_entry_count(&ionotify_loop->handles) == (size_t)max_handle_id)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: Maximum number of registered handles reached",
            (void *)ionotify_event_data->event_loop);
        return AWS_OP_ERR;
    }

    struct aws_hash_element *elem = NULL;
    int next_handle_id = ionotify_loop->last_handle_id;
    int was_created = 0;
    do {
        ++next_handle_id;
        if (next_handle_id > max_handle_id) {
            next_handle_id = 1;
        }
        aws_hash_table_create(&ionotify_loop->handles, (void *)next_handle_id, &elem, &was_created);
        /* next_handle_id is already present in the hash table, skip it. */
        if (was_created == 0) {
            elem = NULL;
        }
    } while (elem == NULL);

    ionotify_event_data->handle_id = next_handle_id;
    ionotify_loop->last_handle_id = next_handle_id;
    elem->value = ionotify_event_data;

    return AWS_OP_SUCCESS;
}

struct ionotify_event_data *s_find_handle(
    struct aws_event_loop *event_loop,
    struct ionotify_loop *ionotify_loop,
    int handle_id) {
    AWS_ASSERT(s_is_on_callers_thread(event_loop));
    (void)event_loop;
    struct ionotify_event_data *ionotify_event_data = NULL;
    struct aws_hash_element *elem = NULL;
    aws_hash_table_find(&ionotify_loop->handles, (void *)handle_id, &elem);
    if (elem != NULL) {
        ionotify_event_data = elem->value;
    }
    return ionotify_event_data;
}

static void s_remove_handle(struct aws_event_loop *event_loop, struct ionotify_loop *ionotify_loop, int handle_id) {
    AWS_ASSERT(s_is_on_callers_thread(event_loop));
    (void)event_loop;
    aws_hash_table_remove(&ionotify_loop->handles, (void *)handle_id, NULL, NULL);
}

/* Scheduled task that performs the actual subscription using ionotify. */
static void s_subscribe_task(struct aws_task *task, void *user_data, enum aws_task_status status) {
    (void)task;

    /* If task was cancelled, nothing to do. */
    if (status == AWS_TASK_STATUS_CANCELED) {
        return;
    }

    struct ionotify_event_data *ionotify_event_data = user_data;
    struct aws_event_loop *event_loop = ionotify_event_data->event_loop;
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: Subscribing to events on fd %d for events %d",
        (void *)event_loop,
        ionotify_event_data->handle->data.fd,
        ionotify_event_data->events_subscribed);

    /* Map ionotify_event_data to ID. This ID will be returned with the I/O events from ionotify. */
    if (ionotify_event_data->handle_id == 0) {
        s_add_handle(ionotify_loop, ionotify_event_data);
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: Mapped fd %d to handle ID %u",
            (void *)event_loop,
            ionotify_event_data->handle->data.fd,
            ionotify_event_data->handle_id);
        /* I/O events from ionotify will be delivered as pulses with a user-defined 28-bit ID.
         * SIGEV_PULSE_PRIO_INHERIT means the thread that receives the pulse will run at the initial priority of the
         * process. */
        short pulse_priority = SIGEV_PULSE_PRIO_INHERIT;
        short pulse_sigev_code = IO_EVENT_PULSE_SIGEV_CODE;
        SIGEV_PULSE_INT_INIT(
            &ionotify_event_data->event,
            ionotify_event_data->pulse_connection_id,
            pulse_priority,
            pulse_sigev_code,
            ionotify_event_data->handle_id);

        /* From the iomgr.h header:
         *   If extended conditions are requested, and they need to be returned in an armed event, the negative of the
         *   satisfied conditions are returned in (io_notify_t).i.event.sigev_code.
         * Extended conditions are the ones starting with _NOTIFY_CONDE_.
         * For that feature to work, special bits in the event structure must be set. */
        ionotify_event_data->event.sigev_notify |= SIGEV_FLAG_CODE_UPDATEABLE;
        SIGEV_MAKE_UPDATEABLE(&ionotify_event_data->event);

        /* The application must register the event by calling MsgRegisterEvent() with the fd processed in ionotify().
         * See:
         * https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/i/ionotify.html
         * https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.lib_ref/topic/m/msgregisterevent.html
         *
         * It's enough to register an event only once and then reuse it on followup ionotify rearming calls.
         * NOTE: If you create a new sigevent for the same file descriptor, with the same flags, you HAVE to register
         * it again. */
        MsgRegisterEvent(&ionotify_event_data->event, ionotify_event_data->handle->data.fd);
    }

    ionotify_event_data->is_subscribed = true;

    /* Everyone is always registered for errors. */
    int event_mask = _NOTIFY_COND_EXTEN | _NOTIFY_CONDE_ERR | _NOTIFY_CONDE_HUP | _NOTIFY_CONDE_NVAL;
    if (ionotify_event_data->events_subscribed & AWS_IO_EVENT_TYPE_READABLE) {
        event_mask |= _NOTIFY_COND_INPUT;
        event_mask |= _NOTIFY_COND_OBAND;
    }
    if (ionotify_event_data->events_subscribed & AWS_IO_EVENT_TYPE_WRITABLE) {
        event_mask |= _NOTIFY_COND_OUTPUT;
    }

    /* Arm resource manager associated with a given file descriptor in edge-triggered mode.
     * After this call, a corresponding resource manager starts sending events. */
    int rc =
        ionotify(ionotify_event_data->handle->data.fd, _NOTIFY_ACTION_EDGEARM, event_mask, &ionotify_event_data->event);
    int errno_value = errno;
    if (rc == -1) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: Failed to subscribe to events on fd %d: error %d (%s)",
            (void *)event_loop,
            ionotify_event_data->handle->data.fd,
            errno_value,
            strerror(errno_value));
        ionotify_event_data->on_event(
            event_loop, ionotify_event_data->handle, AWS_IO_EVENT_TYPE_ERROR, ionotify_event_data->user_data);
        return;
    }

    /* ionotify can return active conditions if they are among specified. Send notification to kick-start processing fd
     * if it has desired conditions. */

    /* User-provided field has no space for extended conditions, so set field in ionotify_event_data. */
    if (rc & (_NOTIFY_CONDE_ERR | _NOTIFY_CONDE_NVAL)) {
        ionotify_event_data->latest_io_event_types |= AWS_IO_EVENT_TYPE_ERROR;
    }
    if (rc & _NOTIFY_CONDE_HUP) {
        ionotify_event_data->latest_io_event_types |= AWS_IO_EVENT_TYPE_CLOSED;
    }

    if ((rc & (_NOTIFY_COND_OBAND | _NOTIFY_COND_INPUT | _NOTIFY_COND_OUTPUT)) ||
        ionotify_event_data->latest_io_event_types) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: Sending pulse for fd %d because it has desired I/O conditions (rc is %d)",
            (void *)event_loop,
            ionotify_event_data->handle->data.fd,
            rc);
        /* Set _NOTIFY_COND_MASK low bits to ID, the same as ionotify does, so the main loop can process all pulses in
         * unified manner. */
        int kick_start_event_mask = rc & _NOTIFY_COND_MASK;
        kick_start_event_mask |= ionotify_event_data->handle_id;
        int send_rc =
            MsgSendPulse(ionotify_loop->pulse_connection_id, -1, IO_EVENT_KICKSTART_SIGEV_CODE, kick_start_event_mask);
        if (send_rc == -1) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_EVENT_LOOP,
                "id=%p: Failed to send pulse for fd %d",
                (void *)event_loop,
                ionotify_event_data->handle->data.fd);
        }
    }
}

/* This callback is called by I/O operations to notify about their results. */
static void s_process_io_result(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    const struct aws_io_handle_io_op_result *io_op_result) {

    AWS_ASSERT(s_is_on_callers_thread(event_loop));

    AWS_ASSERT(handle->additional_data);
    struct ionotify_event_data *ionotify_event_data = handle->additional_data;

    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: Processing I/O operation result for fd %d: status %d (%s); read status %d (%s); write status %d (%s)",
        (void *)event_loop,
        handle->data.fd,
        io_op_result->error_code,
        aws_error_str(io_op_result->error_code),
        io_op_result->read_error_code,
        aws_error_str(io_op_result->read_error_code),
        io_op_result->write_error_code,
        aws_error_str(io_op_result->write_error_code));

    int event_types = 0;
    if (io_op_result->error_code == AWS_IO_SOCKET_CLOSED) {
        ionotify_event_data->latest_io_event_types = AWS_IO_EVENT_TYPE_CLOSED;
    }
    if (io_op_result->read_error_code == AWS_IO_READ_WOULD_BLOCK) {
        event_types |= AWS_IO_EVENT_TYPE_READABLE;
    }
    if (io_op_result->write_error_code == AWS_IO_READ_WOULD_BLOCK) {
        event_types |= AWS_IO_EVENT_TYPE_WRITABLE;
    }

    /* Rearm resource manager. */
    if (event_types != 0) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP, "id=%p: Got EWOULDBLOCK for fd %d, rearming it", (void *)event_loop, handle->data.fd);
        /* We're on the event loop thread, just schedule subscribing task. */
        ionotify_event_data->events_subscribed = event_types;
        struct ionotify_loop *ionotify_loop = event_loop->impl_data;
        aws_task_scheduler_schedule_now(&ionotify_loop->scheduler, &ionotify_event_data->subscribe_task);
    }

    /* Notify event loop of error conditions. */
    if (ionotify_event_data->latest_io_event_types != 0) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: fd errored, sending pulse for fd %d",
            (void *)event_loop,
            ionotify_event_data->handle->data.fd);
        struct ionotify_loop *ionotify_loop = event_loop->impl_data;
        int send_rc = MsgSendPulse(
            ionotify_loop->pulse_connection_id, -1, IO_EVENT_UPDATE_ERROR_SIGEV_CODE, ionotify_event_data->handle_id);
        int errno_value = errno;
        if (send_rc == -1) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_EVENT_LOOP,
                "id=%p: Failed to send UPDATE_ERROR pulse for fd %d: error %d (%s)",
                (void *)event_loop,
                ionotify_event_data->handle->data.fd,
                errno_value,
                strerror(errno_value));
        }
    }
}

struct ionotify_io_op_results {
    struct aws_io_handle_io_op_result io_op_result;
    struct aws_event_loop *event_loop;
    struct aws_io_handle *handle;
};

static void s_update_io_result_task(struct aws_task *task, void *user_data, enum aws_task_status status) {
    struct ionotify_io_op_results *ionotify_io_op_results = user_data;
    struct aws_event_loop *event_loop = ionotify_io_op_results->event_loop;

    aws_mem_release(event_loop->alloc, task);

    /* If task was cancelled, nothing to do. */
    if (status == AWS_TASK_STATUS_CANCELED) {
        aws_mem_release(event_loop->alloc, ionotify_io_op_results);
        return;
    }

    s_process_io_result(event_loop, ionotify_io_op_results->handle, &ionotify_io_op_results->io_op_result);

    aws_mem_release(event_loop->alloc, ionotify_io_op_results);
}

/* This callback is called by I/O operations to notify about their results. */
static void s_update_io_result(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    const struct aws_io_handle_io_op_result *io_op_result) {

    if (!s_is_on_callers_thread(event_loop)) {
        /* Move processing I/O operation results to the epoll thread if the operation is performed in another thread.*/
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Got I/O operation result from another thread", (void *)event_loop);
        struct aws_task *task = aws_mem_calloc(event_loop->alloc, 1, sizeof(struct aws_task));
        struct ionotify_io_op_results *ionotify_io_op_results =
            aws_mem_calloc(event_loop->alloc, 1, sizeof(struct ionotify_io_op_results));
        ionotify_io_op_results->event_loop = event_loop;
        ionotify_io_op_results->handle = handle;
        memcpy(&ionotify_io_op_results->io_op_result, io_op_result, sizeof(struct aws_io_handle_io_op_result));
        aws_task_init(task, s_update_io_result_task, ionotify_io_op_results, "ionotify_event_loop_resubscribe_ct");
        struct ionotify_loop *ionotify_loop = event_loop->impl_data;
        aws_task_scheduler_schedule_now(&ionotify_loop->scheduler, task);
        return;
    }

    s_process_io_result(event_loop, handle, io_op_result);
}

static int s_subscribe_to_io_events(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    aws_event_loop_on_event_fn *on_event,
    void *user_data) {

    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Subscribing to events on fd %d", (void *)event_loop, handle->data.fd);
    struct ionotify_event_data *ionotify_event_data =
        aws_mem_calloc(event_loop->alloc, 1, sizeof(struct ionotify_event_data));
    handle->additional_data = ionotify_event_data;

    ionotify_event_data->alloc = event_loop->alloc;
    ionotify_event_data->handle = handle;
    ionotify_event_data->event_loop = event_loop;
    ionotify_event_data->on_event = on_event;
    ionotify_event_data->events_subscribed = events;
    ionotify_event_data->pulse_connection_id = ionotify_loop->pulse_connection_id;
    ionotify_event_data->user_data = user_data;
    ionotify_event_data->handle->update_io_result = s_update_io_result;

    aws_task_init(
        &ionotify_event_data->subscribe_task, s_subscribe_task, ionotify_event_data, "ionotify_event_loop_subscribe");
    s_schedule_task_now(event_loop, &ionotify_event_data->subscribe_task);

    return AWS_OP_SUCCESS;
}

static void s_free_io_event_resources(void *user_data) {
    struct ionotify_event_data *event_data = user_data;
    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "Releasing ionotify_event_data at %p", user_data);
    aws_mem_release(event_data->alloc, (void *)event_data);
}

static int s_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP, "id=%p: un-subscribing from events on fd %d", (void *)event_loop, handle->data.fd);

    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    AWS_ASSERT(handle->additional_data);
    struct ionotify_event_data *ionotify_event_data = handle->additional_data;

    /* Disarm resource manager for a given fd. */
    int event_mask = _NOTIFY_COND_EXTEN | _NOTIFY_CONDE_ERR | _NOTIFY_CONDE_HUP | _NOTIFY_CONDE_NVAL;
    event_mask |= _NOTIFY_COND_INPUT | _NOTIFY_CONDE_RDNORM | _NOTIFY_COND_OBAND;
    event_mask |= _NOTIFY_COND_OUTPUT | _NOTIFY_CONDE_WRNORM;
    int rc = ionotify(ionotify_event_data->handle->data.fd, _NOTIFY_ACTION_EDGEARM, event_mask, NULL);
    int errno_value = errno;
    if (rc == -1) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: Failed to unsubscribe from events on fd %d: error %d (%s)",
            (void *)event_loop,
            ionotify_event_data->handle->data.fd,
            errno_value,
            strerror(errno_value));
        return aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
    }

    /* We can't clean up yet, because we have schedule tasks and more events to process,
     * mark it as unsubscribed and schedule a cleanup task. */
    ionotify_event_data->is_subscribed = false;

    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: Removing from handles map using ID %u",
        (void *)event_loop,
        ionotify_event_data->handle_id);
    s_remove_handle(event_loop, ionotify_loop, ionotify_event_data->handle_id);

    handle->additional_data = NULL;
    handle->update_io_result = NULL;

    /* Main loop obtains ionotify_event_data instance from hash map, so it's safe to release it right here. */
    s_free_io_event_resources(ionotify_event_data);

    return AWS_OP_SUCCESS;
}

static bool s_is_on_callers_thread(struct aws_event_loop *event_loop) {
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    aws_thread_id_t *thread_id = aws_atomic_load_ptr(&ionotify_loop->running_thread_id);
    return thread_id && aws_thread_thread_id_equal(*thread_id, aws_thread_current_thread_id());
}

static void s_process_task_pre_queue(struct aws_event_loop *event_loop) {
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Processing cross-thread tasks", (void *)event_loop);

    struct aws_linked_list task_pre_queue;
    aws_linked_list_init(&task_pre_queue);

    aws_mutex_lock(&ionotify_loop->task_pre_queue_mutex);
    aws_linked_list_swap_contents(&ionotify_loop->task_pre_queue, &task_pre_queue);
    aws_mutex_unlock(&ionotify_loop->task_pre_queue_mutex);

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
 * This just calls MsgReceive().
 *
 * We broke this out into its own function so that the stacktrace clearly shows
 * what this thread is doing. We've had a lot of cases where users think this
 * thread is deadlocked because it's stuck here. We want it to be clear
 * that it's doing nothing on purpose. It's waiting for events to happen...
 */
AWS_NO_INLINE
static rcvid_t aws_event_loop_listen_for_io_events(
    int io_events_channel_id,
    const uint64_t *timeout,
    struct _pulse *pulse,
    int *errno_value) {
    /* Event of type SIGEV_UNBLOCK makes the timed-out kernel call fail with an error of ETIMEDOUT. */
    struct sigevent notify;
    SIGEV_UNBLOCK_INIT(&notify);
    int rc = TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, &notify, timeout, NULL);
    if (rc == -1) {
        *errno_value = errno;
        return rc;
    }
    rcvid_t rcvid = MsgReceive(io_events_channel_id, pulse, sizeof(*pulse), NULL);
    if (rcvid == -1) {
        *errno_value = errno;
    }
    return rcvid;
}

static void s_aws_ionotify_cleanup_aws_lc_thread_local_state(void *user_data) {
    (void)user_data;
    aws_cal_thread_clean_up();
}

static void s_process_pulse(
    struct aws_event_loop *event_loop,
    const struct _pulse *pulse,
    bool *should_process_cross_thread_tasks) {
    if (pulse->code == CROSS_THREAD_PULSE_SIGEV_CODE) {
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: MsgReceived got cross-thread pulse", (void *)event_loop);
        *should_process_cross_thread_tasks = true;
        return;
    }

    int user_data = pulse->value.sival_int;

    int handle_id = user_data & _NOTIFY_DATA_MASK;
    if (handle_id == 0) {
        AWS_LOGF_ERROR(AWS_LS_IO_EVENT_LOOP, "id=%p: Got pulse with empty handle ID, ignoring it", (void *)event_loop);
        return;
    }

    AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Got pulse for handle ID %u", (void *)event_loop, handle_id);

    struct ionotify_loop *ionotify_loop = event_loop->impl_data;
    struct ionotify_event_data *ionotify_event_data = s_find_handle(event_loop, ionotify_loop, handle_id);
    if (ionotify_event_data == NULL) {
        /* This situation is totally OK when the corresponding fd is already unsubscribed. */
        AWS_LOGF_DEBUG(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: No mapped data found for handle ID %d, fd must be already unsubscribed",
            (void *)event_loop,
            handle_id);
        return;
    }

    if (!ionotify_event_data->is_subscribed) {
        return;
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_EVENT_LOOP,
        "id=%p: Processing fd %d: pulse code %d",
        (void *)event_loop,
        ionotify_event_data->handle->data.fd,
        pulse->code);
    int event_mask = 0;
    if (pulse->value.sival_int & _NOTIFY_COND_OBAND) {
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: fd got out-of-band data", (void *)event_loop);
        event_mask |= AWS_IO_EVENT_TYPE_READABLE;
    }
    if (pulse->value.sival_int & _NOTIFY_COND_INPUT) {
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: fd is readable", (void *)event_loop);
        event_mask |= AWS_IO_EVENT_TYPE_READABLE;
    }
    if (pulse->value.sival_int & _NOTIFY_COND_OUTPUT) {
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: fd is writable", (void *)event_loop);
        event_mask |= AWS_IO_EVENT_TYPE_WRITABLE;
    }
    if (pulse->value.sival_int & _NOTIFY_COND_EXTEN) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP,
            "id=%p: fd has extended condition: %d %d",
            (void *)event_loop,
            pulse->code,
            ionotify_event_data->event.sigev_code);
        if (pulse->code != IO_EVENT_PULSE_SIGEV_CODE) {
            event_mask |= AWS_IO_EVENT_TYPE_ERROR;
        }
    }

    if (ionotify_event_data->latest_io_event_types == AWS_IO_EVENT_TYPE_CLOSED) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP, "id=%p: latest_io_event_types is AWS_IO_EVENT_TYPE_CLOSED", (void *)event_loop);
        event_mask |= AWS_IO_EVENT_TYPE_CLOSED;
    }

    /* Reset the I/O operation code to not process it twice. */
    ionotify_event_data->latest_io_event_types = 0;

    ionotify_event_data->on_event(event_loop, ionotify_event_data->handle, event_mask, ionotify_event_data->user_data);
}

static void aws_event_loop_thread(void *args) {
    struct aws_event_loop *event_loop = args;
    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: main loop started", (void *)event_loop);
    struct ionotify_loop *ionotify_loop = event_loop->impl_data;

    /* set thread id to the thread of the event loop */
    aws_atomic_store_ptr(&ionotify_loop->running_thread_id, &ionotify_loop->thread_created_on.thread_id);

    aws_thread_current_at_exit(s_aws_ionotify_cleanup_aws_lc_thread_local_state, NULL);

    /* Default timeout is 100 seconds. */
    static uint64_t DEFAULT_TIMEOUT_NS = 100ULL * AWS_TIMESTAMP_NANOS;

    uint64_t timeout = DEFAULT_TIMEOUT_NS;

    AWS_LOGF_INFO(AWS_LS_IO_EVENT_LOOP, "id=%p: Default timeout %" PRIu64, (void *)event_loop, timeout);

    /* Until stop is called:
     * - Call MsgReceive. If a task is scheduled, or a file descriptor has activity, it will return.
     * - Process all I/O events.
     * - Run all scheduled tasks.
     * - Process queued subscription cleanups.
     */
    while (ionotify_loop->should_continue) {
        bool should_process_cross_thread_tasks = false;

        AWS_LOGF_TRACE(
            AWS_LS_IO_EVENT_LOOP, "id=%p: Waiting for a maximum of %" PRIu64 " ns", (void *)event_loop, timeout);
        struct _pulse pulse;
        int errno_value;
        rcvid_t rcvid =
            aws_event_loop_listen_for_io_events(ionotify_loop->io_events_channel_id, &timeout, &pulse, &errno_value);
        aws_event_loop_register_tick_start(event_loop);

        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Wake up with rcvid %ld\n", (void *)event_loop, rcvid);
        if (rcvid == 0) {
            s_process_pulse(event_loop, &pulse, &should_process_cross_thread_tasks);
        } else if (rcvid > 0) {
            AWS_LOGF_WARN(AWS_LS_IO_EVENT_LOOP, "id=%p: Received message, ignoring it\n", (void *)event_loop);
        } else {
            if (errno_value == ETIMEDOUT) {
                AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Woke up by timeout\n", (void *)event_loop);
            } else {
                AWS_LOGF_ERROR(
                    AWS_LS_IO_EVENT_LOOP,
                    "id=%p: Listening for I/O events failed with error %d (%s)",
                    (void *)event_loop,
                    errno_value,
                    strerror(errno_value));
            }
        }

        /* Run scheduled tasks. */
        if (should_process_cross_thread_tasks) {
            AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Processing prequeued tasks", (void *)event_loop);
            s_process_task_pre_queue(event_loop);
        }

        uint64_t now_ns = 0;
        event_loop->clock(&now_ns);
        AWS_LOGF_TRACE(AWS_LS_IO_EVENT_LOOP, "id=%p: Running scheduled tasks", (void *)event_loop);
        aws_task_scheduler_run_all(&ionotify_loop->scheduler, now_ns);

        /* Set timeout for next MsgReceive call.
         * If clock fails, or scheduler has no tasks, use default timeout. */
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
                AWS_LS_IO_EVENT_LOOP, "id=%p: No more scheduled tasks using default timeout.", (void *)event_loop);
            timeout = DEFAULT_TIMEOUT_NS;
        } else {
            timeout = (next_run_time_ns > now_ns) ? (next_run_time_ns - now_ns) : 0;
            AWS_LOGF_TRACE(
                AWS_LS_IO_EVENT_LOOP,
                "id=%p: Detected more scheduled tasks with the next occurring at %" PRIu64
                ", using timeout of %" PRIu64,
                (void *)event_loop,
                next_run_time_ns,
                timeout);
        }

        aws_event_loop_register_tick_end(event_loop);
    }

    AWS_LOGF_DEBUG(AWS_LS_IO_EVENT_LOOP, "id=%p: Exiting main loop", (void *)event_loop);
    /* set thread id back to NULL. This should be updated again in destroy, before tasks are canceled. */
    aws_atomic_store_ptr(&ionotify_loop->running_thread_id, NULL);
}
