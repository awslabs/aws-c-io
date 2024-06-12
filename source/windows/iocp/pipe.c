/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/pipe.h>

#include <aws/common/task_scheduler.h>
#include <aws/io/event_loop.h>

#include <stdbool.h>
#include <stdio.h>

#include <Windows.h>

enum read_end_state {
    /* Pipe is open. */
    READ_END_STATE_OPEN,

    /* Pipe is open, user has subscribed, but async monitoring hasn't started yet.
     * Pipe moves to SUBCSCRIBED state if async monitoring starts successfully
     * or SUBSCRIBE_ERROR state if it doesn't start successfully.
     * From any of the SUBSCRIBE* states, the pipe moves to OPEN state if the user unsubscribes. */
    READ_END_STATE_SUBSCRIBING,

    /* Pipe is open, user has subscribed, and user is receiving events delivered by async monitoring.
     * Async monitoring is paused once the file is known to be readable.
     * Async monitoring is resumed once the user reads all available bytes.
     * Pipe moves to SUBSCRIBE_ERROR state if async monitoring reports an error, or fails to restart.
     * Pipe move sto OPEN state if user unsubscribes. */
    READ_END_STATE_SUBSCRIBED,

    /* Pipe is open, use has subscribed, and an error event has been delivered to the user.
     * No further error events are delivered to the user, and no more async monitoring occurs.*/
    READ_END_STATE_SUBSCRIBE_ERROR,
};

/* Reasons to launch async monitoring of the read-end's handle */
enum monitoring_reason {
    MONITORING_BECAUSE_SUBSCRIBING = 1,
    MONITORING_BECAUSE_WAITING_FOR_DATA = 2,
    MONITORING_BECAUSE_ERROR_SUSPECTED = 4,
};

/* Async operations live in their own allocations.
 * This allows the pipe to be cleaned up without waiting for all outstanding operations to complete.  */
struct async_operation {
    union {
        struct aws_overlapped overlapped;
        struct aws_task task;
    } op;

    struct aws_allocator *alloc;
    bool is_active;
    bool is_read_end_cleaned_up;
};

struct read_end_impl {
    struct aws_allocator *alloc;

    enum read_end_state state;

    struct aws_io_handle handle;

    struct aws_event_loop *event_loop;

    /* Async overlapped operation for monitoring pipe status.
     * This operation is re-used each time monitoring resumes.
     * Note that rapidly subscribing/unsubscribing could lead to the monitoring operation from a previous subscribe
     * still pending while the user is re-subscribing. */
    struct async_operation *async_monitoring;

    /* Async task operation used to deliver error reports. */
    struct async_operation *async_error_report;

    aws_pipe_on_readable_fn *on_readable_user_callback;
    void *on_readable_user_data;

    /* Error code that the error-reporting task will report. */
    int error_code_to_report;

    /* Reasons to restart monitoring once current async operation completes.
     * Contains read_end_monitoring_request_t flags.*/
    uint8_t monitoring_request_reasons;
};

enum write_end_state {
    WRITE_END_STATE_CLOSING,
    WRITE_END_STATE_OPEN,
};

/* Data describing an async write request */
struct pipe_write_request {
    struct aws_byte_cursor original_cursor;
    aws_pipe_on_write_completed_fn *user_callback;
    void *user_data;
    struct aws_allocator *alloc;
    struct aws_overlapped overlapped;
    struct aws_linked_list_node list_node;
    bool is_write_end_cleaned_up;
};

struct write_end_impl {
    struct aws_allocator *alloc;
    enum write_end_state state;
    struct aws_io_handle handle;
    struct aws_event_loop *event_loop;

    /* List of currently active pipe_write_requests */
    struct aws_linked_list write_list;

    /* Future optimization idea: avoid an allocation on each write by keeping 1 pre-allocated pipe_write_request around
     * and re-using it whenever possible */
};

enum {
    PIPE_BUFFER_SIZE = 4096,
    PIPE_UNIQUE_NAME_MAX_TRIES = 10,
};

static void s_read_end_on_zero_byte_read_completion(
    struct aws_event_loop *event_loop,
    struct aws_overlapped *overlapped,
    int status_code,
    size_t num_bytes_transferred);
static void s_read_end_report_error_task(struct aws_task *task, void *user_data, enum aws_task_status status);
static void s_write_end_on_write_completion(
    struct aws_event_loop *event_loop,
    struct aws_overlapped *overlapped,
    int status_code,
    size_t num_bytes_transferred);

/* Translate Windows errors into aws_pipe errors */
static int s_translate_windows_error(DWORD win_error) {
    switch (win_error) {
        case ERROR_BROKEN_PIPE:
            return AWS_IO_BROKEN_PIPE;
        case 0xC000014B: /* STATUS_PIPE_BROKEN */
            return AWS_IO_BROKEN_PIPE;
        case 0xC0000120: /* STATUS_CANCELLED */
            return AWS_IO_BROKEN_PIPE;
        default:
            return AWS_ERROR_SYS_CALL_FAILURE;
    }
}

static int s_raise_last_windows_error(void) {
    DWORD win_error = GetLastError();
    int aws_error = s_translate_windows_error(win_error);
    return aws_raise_error(aws_error);
}

AWS_THREAD_LOCAL uint32_t tl_unique_name_counter = 0;

AWS_IO_API int aws_pipe_get_unique_name(char *dst, size_t dst_size) {
    /* For local pipes, name should be unique per-machine.
     * Mix together several sources that should should lead to something unique. */

    DWORD process_id = GetCurrentProcessId();

    DWORD thread_id = GetCurrentThreadId();

    uint32_t counter = tl_unique_name_counter++;

    LARGE_INTEGER timestamp;
    bool success = QueryPerformanceCounter(&timestamp);
    AWS_ASSERT(success);
    (void)success; /* QueryPerformanceCounter() always succeeds on XP and later */

    /* snprintf() returns number of characters (not including '\0') which would have written if dst_size was ignored */
    int ideal_strlen = snprintf(
        dst,
        dst_size,
        "\\\\.\\pipe\\aws_pipe_%08x_%08x_%08x_%08x%08x",
        process_id,
        thread_id,
        counter,
        timestamp.HighPart,
        timestamp.LowPart);

    AWS_ASSERT(ideal_strlen > 0);
    if (dst_size < (size_t)(ideal_strlen + 1)) {
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);
    }

    return AWS_OP_SUCCESS;
}

int aws_pipe_init(
    struct aws_pipe_read_end *read_end,
    struct aws_event_loop *read_end_event_loop,
    struct aws_pipe_write_end *write_end,
    struct aws_event_loop *write_end_event_loop,
    struct aws_allocator *allocator) {

    AWS_ASSERT(read_end);
    AWS_ASSERT(read_end_event_loop);
    AWS_ASSERT(write_end);
    AWS_ASSERT(write_end_event_loop);
    AWS_ASSERT(allocator);

    AWS_ZERO_STRUCT(*write_end);
    AWS_ZERO_STRUCT(*read_end);

    struct write_end_impl *write_impl = NULL;
    struct read_end_impl *read_impl = NULL;

    /* Init write-end */
    write_impl = aws_mem_calloc(allocator, 1, sizeof(struct write_end_impl));
    if (!write_impl) {
        goto clean_up;
    }

    write_impl->alloc = allocator;
    write_impl->state = WRITE_END_STATE_OPEN;
    write_impl->handle.data.handle = INVALID_HANDLE_VALUE;
    aws_linked_list_init(&write_impl->write_list);

    /* Anonymous pipes don't support overlapped I/O so named pipes are used. Names must be unique system-wide.
     * We generate random names, but collisions are theoretically possible, so try several times before giving up. */
    char pipe_name[256];
    int tries = 0;
    while (true) {
        int err = aws_pipe_get_unique_name(pipe_name, sizeof(pipe_name));
        if (err) {
            goto clean_up;
        }

        const DWORD open_mode = PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE;

        const DWORD pipe_mode = PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;

        write_impl->handle.data.handle = CreateNamedPipeA(
            pipe_name,
            open_mode,
            pipe_mode,
            1,                /*nMaxInstances*/
            PIPE_BUFFER_SIZE, /*nOutBufferSize*/
            PIPE_BUFFER_SIZE, /*nInBufferSize*/
            0,                /*nDefaultTimeout: 0 means default*/
            NULL);            /*lpSecurityAttributes: NULL means default */

        if (write_impl->handle.data.handle != INVALID_HANDLE_VALUE) {
            /* Success, break out of loop */
            break;
        }

        if (++tries >= PIPE_UNIQUE_NAME_MAX_TRIES) {
            s_raise_last_windows_error();
            goto clean_up;
        }
    }

    int err = aws_event_loop_connect_handle_to_io_completion_port(write_end_event_loop, &write_impl->handle);
    if (err) {
        goto clean_up;
    }

    write_impl->event_loop = write_end_event_loop;

    /* Init read-end */
    read_impl = aws_mem_calloc(allocator, 1, sizeof(struct read_end_impl));
    if (!read_impl) {
        goto clean_up;
    }

    read_impl->alloc = allocator;
    read_impl->state = READ_END_STATE_OPEN;
    read_impl->handle.data.handle = INVALID_HANDLE_VALUE;

    read_impl->handle.data.handle = CreateFileA(
        pipe_name,     /*lpFileName*/
        GENERIC_READ,  /*dwDesiredAccess*/
        0,             /*dwShareMode: 0 prevents acess by external processes*/
        NULL,          /*lpSecurityAttributes: NULL prevents inheritance by child processes*/
        OPEN_EXISTING, /*dwCreationDisposition*/
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, /*dwFlagsAndAttributes*/
        NULL);                                        /*hTemplateFile: ignored when opening existing file*/

    if (read_impl->handle.data.handle == INVALID_HANDLE_VALUE) {
        s_raise_last_windows_error();
        goto clean_up;
    }

    err = aws_event_loop_connect_handle_to_io_completion_port(read_end_event_loop, &read_impl->handle);
    if (err) {
        goto clean_up;
    }

    read_impl->event_loop = read_end_event_loop;

    /* Init the read-end's async operations */
    read_impl->async_monitoring = aws_mem_calloc(allocator, 1, sizeof(struct async_operation));
    if (!read_impl->async_monitoring) {
        goto clean_up;
    }

    read_impl->async_monitoring->alloc = allocator;
    aws_overlapped_init(&read_impl->async_monitoring->op.overlapped, s_read_end_on_zero_byte_read_completion, read_end);

    read_impl->async_error_report = aws_mem_calloc(allocator, 1, sizeof(struct async_operation));
    if (!read_impl->async_error_report) {
        goto clean_up;
    }

    read_impl->async_error_report->alloc = allocator;
    aws_task_init(
        &read_impl->async_error_report->op.task, s_read_end_report_error_task, read_end, "pipe_read_end_report_error");

    /* Success */
    write_end->impl_data = write_impl;
    read_end->impl_data = read_impl;
    return AWS_OP_SUCCESS;

clean_up:
    if (write_impl) {
        if (write_impl->handle.data.handle != INVALID_HANDLE_VALUE) {
            CloseHandle(write_impl->handle.data.handle);
        }

        aws_mem_release(allocator, write_impl);
        write_impl = NULL;
    }

    if (read_impl) {
        if (read_impl->handle.data.handle != INVALID_HANDLE_VALUE) {
            CloseHandle(read_impl->handle.data.handle);
        }

        if (read_impl->async_monitoring) {
            aws_mem_release(allocator, read_impl->async_monitoring);
        }

        if (read_impl->async_error_report) {
            aws_mem_release(allocator, read_impl->async_error_report);
        }

        aws_mem_release(allocator, read_impl);
        read_impl = NULL;
    }

    return AWS_OP_ERR;
}

struct aws_event_loop *aws_pipe_get_read_end_event_loop(const struct aws_pipe_read_end *read_end) {
    struct read_end_impl *read_impl = read_end->impl_data;
    if (!read_impl) {
        aws_raise_error(AWS_IO_BROKEN_PIPE);
        return NULL;
    }

    return read_impl->event_loop;
}

struct aws_event_loop *aws_pipe_get_write_end_event_loop(const struct aws_pipe_write_end *write_end) {
    struct write_end_impl *write_impl = write_end->impl_data;
    if (!write_impl) {
        aws_raise_error(AWS_IO_BROKEN_PIPE);
        return NULL;
    }

    return write_impl->event_loop;
}

int aws_pipe_clean_up_read_end(struct aws_pipe_read_end *read_end) {

    struct read_end_impl *read_impl = read_end->impl_data;
    if (!read_impl) {
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    if (!aws_event_loop_thread_is_callers_thread(read_impl->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    CloseHandle(read_impl->handle.data.handle);

    /* If the async operations are inactive they can be deleted now.
     * Otherwise, inform the operations of the clean-up so they can delete themselves upon completion. */
    if (!read_impl->async_monitoring->is_active) {
        aws_mem_release(read_impl->alloc, read_impl->async_monitoring);
    } else {
        read_impl->async_monitoring->is_read_end_cleaned_up = true;
    }

    if (!read_impl->async_error_report->is_active) {
        aws_mem_release(read_impl->alloc, read_impl->async_error_report);
    } else {
        read_impl->async_error_report->is_read_end_cleaned_up = true;
    }

    aws_mem_release(read_impl->alloc, read_impl);
    AWS_ZERO_STRUCT(*read_end);

    return AWS_OP_SUCCESS;
}

/* Return whether a user is subscribed to receive read events */
static bool s_read_end_is_subscribed(struct aws_pipe_read_end *read_end) {
    struct read_end_impl *read_impl = read_end->impl_data;
    switch (read_impl->state) {
        case READ_END_STATE_SUBSCRIBING:
        case READ_END_STATE_SUBSCRIBED:
        case READ_END_STATE_SUBSCRIBE_ERROR:
            return true;
        default:
            return false;
    }
}

/* Detect events on the pipe by kicking off an async zero-byte-read.
 * When the pipe becomes readable or an error occurs, the read will
 * complete and we will report the event. */
static void s_read_end_request_async_monitoring(struct aws_pipe_read_end *read_end, int request_reason) {
    struct read_end_impl *read_impl = read_end->impl_data;
    AWS_ASSERT(read_impl);

    /* We only do async monitoring while user is subscribed, but not if we've
     * reported an error and moved into the SUBSCRIBE_ERROR state */
    bool async_monitoring_allowed =
        s_read_end_is_subscribed(read_end) && (read_impl->state != READ_END_STATE_SUBSCRIBE_ERROR);
    if (!async_monitoring_allowed) {
        return;
    }

    /* We can only have one monitoring operation active at a time. Save off
     * the reason for the request. When the current operation completes,
     * if this reason is still valid, we'll re-launch async monitoring */
    if (read_impl->async_monitoring->is_active) {
        read_impl->monitoring_request_reasons |= request_reason;
        return;
    }

    AWS_ASSERT(read_impl->error_code_to_report == 0);

    read_impl->monitoring_request_reasons = 0;
    read_impl->state = READ_END_STATE_SUBSCRIBED;

    /* aws_overlapped must be reset before each use */
    aws_overlapped_reset(&read_impl->async_monitoring->op.overlapped);

    int fake_buffer;
    bool success = ReadFile(
        read_impl->handle.data.handle,
        &fake_buffer,
        0,    /*nNumberOfBytesToRead*/
        NULL, /*lpNumberOfBytesRead: NULL for an overlapped operation*/
        aws_overlapped_to_windows_overlapped(&read_impl->async_monitoring->op.overlapped));

    if (success || (GetLastError() == ERROR_IO_PENDING)) {
        /* Success launching zero-byte-read, aka async monitoring operation */
        read_impl->async_monitoring->is_active = true;
        return;
    }

    /* User is subscribed for IO events and expects to be notified of errors via the event callback.
     * We schedule this as a task so the callback doesn't happen before the user expects it.
     * We also set the state to SUBSCRIBE_ERROR so we don't keep trying to monitor the file. */
    read_impl->state = READ_END_STATE_SUBSCRIBE_ERROR;
    read_impl->error_code_to_report = s_translate_windows_error(GetLastError());
    read_impl->async_error_report->is_active = true;
    aws_event_loop_schedule_task_now(read_impl->event_loop, &read_impl->async_error_report->op.task);
}

static void s_read_end_report_error_task(struct aws_task *task, void *user_data, enum aws_task_status status) {
    (void)status; /* Do same work whether or not this is a "cancelled" task */

    struct async_operation *async_op = AWS_CONTAINER_OF(task, struct async_operation, op);
    AWS_ASSERT(async_op->is_active);
    async_op->is_active = false;

    /* If the read end has been cleaned up, don't report the error, just free the task's memory. */
    if (async_op->is_read_end_cleaned_up) {
        aws_mem_release(async_op->alloc, async_op);
        return;
    }

    struct aws_pipe_read_end *read_end = user_data;
    struct read_end_impl *read_impl = read_end->impl_data;
    AWS_ASSERT(read_impl);

    /* Only report the error if we're still in the SUBSCRIBE_ERROR state.
     * If the user unsubscribed since this task was queued, then we'd be in a different state. */
    if (read_impl->state == READ_END_STATE_SUBSCRIBE_ERROR) {
        AWS_ASSERT(read_impl->error_code_to_report != 0);

        if (read_impl->on_readable_user_callback) {
            read_impl->on_readable_user_callback(
                read_end, read_impl->error_code_to_report, read_impl->on_readable_user_data);
        }
    }
}

static void s_read_end_on_zero_byte_read_completion(
    struct aws_event_loop *event_loop,
    struct aws_overlapped *overlapped,
    int status_code,
    size_t num_bytes_transferred) {

    (void)event_loop;
    (void)num_bytes_transferred;

    struct async_operation *async_op = AWS_CONTAINER_OF(overlapped, struct async_operation, op);

    /* If the read-end has been cleaned up, simply free the operation's memory and return. */
    if (async_op->is_read_end_cleaned_up) {
        aws_mem_release(async_op->alloc, async_op);
        return;
    }

    struct aws_pipe_read_end *read_end = overlapped->user_data;
    struct read_end_impl *read_impl = read_end->impl_data;
    AWS_ASSERT(read_impl);

    /* Only report events to user when in the SUBSCRIBED state.
     * If in the SUBSCRIBING state, this completion is from an operation begun during a previous subscription. */
    if (read_impl->state == READ_END_STATE_SUBSCRIBED) {
        int readable_error_code;

        if (status_code == 0) {
            readable_error_code = AWS_ERROR_SUCCESS;

            /* Clear out the "waiting for data" reason to restart zero-byte-read, since we're about to tell the user
             * that the pipe is readable. If the user consumes all the data, the "waiting for data" reason will get set
             * again and async-monitoring will be relaunched at the end of this function. */
            read_impl->monitoring_request_reasons &= ~MONITORING_BECAUSE_WAITING_FOR_DATA;

        } else {
            readable_error_code = AWS_IO_BROKEN_PIPE;

            /* Move pipe to SUBSCRIBE_ERROR state to prevent further monitoring */
            read_impl->state = READ_END_STATE_SUBSCRIBE_ERROR;
        }

        if (read_impl->on_readable_user_callback) {
            read_impl->on_readable_user_callback(read_end, readable_error_code, read_impl->on_readable_user_data);
        }
    }

    /* Note that the user callback might have invoked aws_pipe_clean_up_read_end().
     * If so, clean up the operation's memory.
     * Otherwise, relaunch the monitoring operation if there's a reason to do so */
    AWS_ASSERT(async_op->is_active);
    async_op->is_active = false;

    if (async_op->is_read_end_cleaned_up) {
        aws_mem_release(async_op->alloc, async_op);
    } else if (read_impl->monitoring_request_reasons != 0) {
        s_read_end_request_async_monitoring(read_end, read_impl->monitoring_request_reasons);
    }
}

int aws_pipe_subscribe_to_readable_events(
    struct aws_pipe_read_end *read_end,
    aws_pipe_on_readable_fn *on_readable,
    void *user_data) {

    struct read_end_impl *read_impl = read_end->impl_data;
    if (!read_impl) {
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    if (read_impl->state != READ_END_STATE_OPEN) {
        /* Return specific error about why user can't subscribe */
        if (s_read_end_is_subscribed(read_end)) {
            return aws_raise_error(AWS_ERROR_IO_ALREADY_SUBSCRIBED);
        }

        AWS_ASSERT(0); /* Unexpected state */
        return aws_raise_error(AWS_ERROR_UNKNOWN);
    }

    if (!aws_event_loop_thread_is_callers_thread(read_impl->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    read_impl->state = READ_END_STATE_SUBSCRIBING;
    read_impl->on_readable_user_callback = on_readable;
    read_impl->on_readable_user_data = user_data;

    s_read_end_request_async_monitoring(read_end, MONITORING_BECAUSE_SUBSCRIBING);

    return AWS_OP_SUCCESS;
}

int aws_pipe_unsubscribe_from_readable_events(struct aws_pipe_read_end *read_end) {
    struct read_end_impl *read_impl = read_end->impl_data;
    if (!read_impl) {
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    if (!s_read_end_is_subscribed(read_end)) {
        return aws_raise_error(AWS_ERROR_IO_NOT_SUBSCRIBED);
    }

    if (!aws_event_loop_thread_is_callers_thread(read_impl->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    read_impl->state = READ_END_STATE_OPEN;
    read_impl->on_readable_user_callback = NULL;
    read_impl->on_readable_user_data = NULL;
    read_impl->monitoring_request_reasons = 0;
    read_impl->error_code_to_report = 0;

    /* If there's a chance the zero-byte-read is pending, cancel it.
     * s_read_end_on_zero_byte_read_completion() will see status code
     * ERROR_OPERATION_ABORTED, but won't pass the event to the user
     * because we're not in the SUBSCRIBED state anymore. */
    if (read_impl->async_monitoring->is_active) {
        CancelIo(read_impl->handle.data.handle);
    }

    return AWS_OP_SUCCESS;
}

int aws_pipe_read(struct aws_pipe_read_end *read_end, struct aws_byte_buf *dst_buffer, size_t *amount_read) {
    AWS_ASSERT(dst_buffer && dst_buffer->buffer);

    struct read_end_impl *read_impl = read_end->impl_data;
    if (!read_impl) {
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    if (amount_read) {
        *amount_read = 0;
    }

    if (!aws_event_loop_thread_is_callers_thread(read_impl->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    /* Just return success if user requests 0 data */
    if (dst_buffer->capacity <= dst_buffer->len) {
        return AWS_OP_SUCCESS;
    }

    /* ReadFile() will be called in synchronous mode and would block indefinitely if it asked for more bytes than are
     * currently available. Therefore, peek at the available bytes before performing the actual read. */
    DWORD bytes_available = 0;
    bool peek_success = PeekNamedPipe(
        read_impl->handle.data.handle,
        NULL,             /*lpBuffer: NULL so peek doesn't actually copy data */
        0,                /*nBufferSize*/
        NULL,             /*lpBytesRead*/
        &bytes_available, /*lpTotalBytesAvail*/
        NULL);            /*lpBytesLeftThisMessage: doesn't apply to byte-type pipes*/

    /* If operation failed. Request async monitoring so user is informed via aws_pipe_on_readable_fn of handle error. */
    if (!peek_success) {
        s_read_end_request_async_monitoring(read_end, MONITORING_BECAUSE_ERROR_SUSPECTED);
        return s_raise_last_windows_error();
    }

    /* If no data available. Request async monitoring so user is notified when data becomes available. */
    if (bytes_available == 0) {
        s_read_end_request_async_monitoring(read_end, MONITORING_BECAUSE_WAITING_FOR_DATA);
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    size_t bytes_to_read = dst_buffer->capacity - dst_buffer->len;
    if (bytes_to_read > bytes_available) {
        bytes_to_read = bytes_available;
    }

    DWORD bytes_read = 0;
    bool read_success = ReadFile(
        read_impl->handle.data.handle,
        dst_buffer->buffer + dst_buffer->len, /*lpBuffer*/
        (DWORD)bytes_to_read,                 /*nNumberOfBytesToRead*/
        &bytes_read,                          /*lpNumberOfBytesRead*/
        NULL);                                /*lpOverlapped: NULL so read is synchronous*/

    /* Operation failed. Request async monitoring so user is informed via aws_pipe_on_readable_fn of handle error. */
    if (!read_success) {
        s_read_end_request_async_monitoring(read_end, MONITORING_BECAUSE_ERROR_SUSPECTED);
        return s_raise_last_windows_error();
    }

    /* Success */
    dst_buffer->len += bytes_read;

    if (amount_read) {
        *amount_read = bytes_read;
    }

    if (bytes_read < bytes_to_read) {
        /* If we weren't able to read as many bytes as the user requested, that's ok.
         * Request async monitoring so we can alert the user when more data arrives */
        s_read_end_request_async_monitoring(read_end, MONITORING_BECAUSE_WAITING_FOR_DATA);
    }

    return AWS_OP_SUCCESS;
}

int aws_pipe_clean_up_write_end(struct aws_pipe_write_end *write_end) {

    struct write_end_impl *write_impl = write_end->impl_data;
    if (!write_impl) {
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    if (!aws_event_loop_thread_is_callers_thread(write_impl->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    CloseHandle(write_impl->handle.data.handle);

    /* Inform outstanding writes about the clean up. */
    while (!aws_linked_list_empty(&write_impl->write_list)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&write_impl->write_list);
        struct pipe_write_request *write_req = AWS_CONTAINER_OF(node, struct pipe_write_request, list_node);
        write_req->is_write_end_cleaned_up = true;
    }

    aws_mem_release(write_impl->alloc, write_impl);
    AWS_ZERO_STRUCT(*write_end);

    return AWS_OP_SUCCESS;
}

int aws_pipe_write(
    struct aws_pipe_write_end *write_end,
    struct aws_byte_cursor src_buffer,
    aws_pipe_on_write_completed_fn *on_completed,
    void *user_data) {

    struct write_end_impl *write_impl = write_end->impl_data;
    if (!write_impl) {
        return aws_raise_error(AWS_IO_BROKEN_PIPE);
    }

    if (!aws_event_loop_thread_is_callers_thread(write_impl->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (src_buffer.len > MAXDWORD) {
        return aws_raise_error(AWS_ERROR_INVALID_BUFFER_SIZE);
    }
    DWORD num_bytes_to_write = (DWORD)src_buffer.len;

    struct pipe_write_request *write = aws_mem_acquire(write_impl->alloc, sizeof(struct pipe_write_request));
    if (!write) {
        return AWS_OP_ERR;
    }

    AWS_ZERO_STRUCT(*write);
    write->original_cursor = src_buffer;
    write->user_callback = on_completed;
    write->user_data = user_data;
    write->alloc = write_impl->alloc;
    aws_overlapped_init(&write->overlapped, s_write_end_on_write_completion, write_end);

    bool write_success = WriteFile(
        write_impl->handle.data.handle,                            /*hFile*/
        src_buffer.ptr,                                            /*lpBuffer*/
        num_bytes_to_write,                                        /*nNumberOfBytesToWrite*/
        NULL,                                                      /*lpNumberOfBytesWritten*/
        aws_overlapped_to_windows_overlapped(&write->overlapped)); /*lpOverlapped*/

    /* Overlapped WriteFile() calls may succeed immediately, or they may queue the work. In either of these cases, IOCP
     * on the event-loop will alert us when the operation completes and we'll invoke user callbacks then. */
    if (!write_success && GetLastError() != ERROR_IO_PENDING) {
        aws_mem_release(write_impl->alloc, write);
        return s_raise_last_windows_error();
    }

    aws_linked_list_push_back(&write_impl->write_list, &write->list_node);
    return AWS_OP_SUCCESS;
}

void s_write_end_on_write_completion(
    struct aws_event_loop *event_loop,
    struct aws_overlapped *overlapped,
    int status_code,
    size_t num_bytes_transferred) {

    (void)event_loop;
    (void)num_bytes_transferred;

    struct pipe_write_request *write_request = AWS_CONTAINER_OF(overlapped, struct pipe_write_request, overlapped);
    struct aws_pipe_write_end *write_end = write_request->is_write_end_cleaned_up ? NULL : overlapped->user_data;

    AWS_ASSERT((num_bytes_transferred == write_request->original_cursor.len) || status_code);

    struct aws_byte_cursor original_cursor = write_request->original_cursor;
    aws_pipe_on_write_completed_fn *user_callback = write_request->user_callback;
    void *user_data = write_request->user_data;

    /* Clean up write-request.
     * Note that write-end might have been cleaned up before this executes. */
    if (!write_request->is_write_end_cleaned_up) {
        aws_linked_list_remove(&write_request->list_node);
    }

    aws_mem_release(write_request->alloc, write_request);

    /* Report outcome to user */
    if (user_callback) {

        int error_code = AWS_ERROR_SUCCESS;
        if (status_code != 0) {
            error_code = s_translate_windows_error(status_code);
        }

        /* Note that user may choose to clean up write-end in this callback */
        user_callback(write_end, error_code, original_cursor, user_data);
    }
}
