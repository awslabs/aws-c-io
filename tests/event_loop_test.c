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

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/system_info.h>
#include <aws/common/task_scheduler.h>
#include <aws/io/event_loop.h>
#include <aws/io/pipe.h>

#include <aws/testing/aws_test_harness.h>

struct task_args {
    int8_t invoked;
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
};

static void s_test_task(struct aws_task *task, void *user_data, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct task_args *args = user_data;

    aws_mutex_lock(&args->mutex);
    args->invoked += 1;
    aws_condition_variable_notify_one(&args->condition_variable);
    aws_mutex_unlock((&args->mutex));
}

static bool s_task_ran_predicate(void *args) {
    struct task_args *task_args = args;
    return task_args->invoked;
}
/*
 * Test that a scheduled task from a non-event loop owned thread executes.
 */
static int s_test_xthread_scheduled_tasks_execute(struct aws_allocator *allocator, void *ctx) {

    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct task_args task_args = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT, .mutex = AWS_MUTEX_INIT, .invoked = 0};

    struct aws_task task;
    aws_task_init(&task, s_test_task, &task_args);

    /* Test "future" tasks */
    ASSERT_SUCCESS(aws_mutex_lock(&task_args.mutex));

    uint64_t now;
    ASSERT_SUCCESS(aws_event_loop_current_clock_time(event_loop, &now));
    aws_event_loop_schedule_task_future(event_loop, &task, now);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &task_args.condition_variable, &task_args.mutex, s_task_ran_predicate, &task_args));
    ASSERT_INT_EQUALS(1, task_args.invoked);
    aws_mutex_unlock(&task_args.mutex);

    /* Test "now" tasks */
    task_args.invoked = 0;
    ASSERT_SUCCESS(aws_mutex_lock(&task_args.mutex));

    aws_event_loop_schedule_task_now(event_loop, &task);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &task_args.condition_variable, &task_args.mutex, s_task_ran_predicate, &task_args));
    ASSERT_INT_EQUALS(1, task_args.invoked);
    aws_mutex_unlock(&task_args.mutex);

    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(xthread_scheduled_tasks_execute, s_test_xthread_scheduled_tasks_execute)

#if AWS_USE_IO_COMPLETION_PORTS
static uint64_t s_hash_combine(uint64_t a, uint64_t b) {
    return a ^ (b + 0x9e3779b99e3779b9llu + (a << 6) + (a >> 2));
}

static int s_create_random_pipe_name(char *buffer, size_t buffer_size) {
    /* Gin up a random number */
    LARGE_INTEGER timestamp;
    ASSERT_TRUE(QueryPerformanceCounter(&timestamp));
    DWORD process_id = GetCurrentProcessId();
    DWORD thread_id = GetCurrentThreadId();

    uint64_t rand_num = s_hash_combine(timestamp.QuadPart, ((uint64_t)process_id << 32) | process_id);
    rand_num = s_hash_combine(rand_num, ((uint64_t)thread_id << 32) | thread_id);

    int len = snprintf(buffer, buffer_size, "\\\\.\\pipe\\aws_pipe_%llux", rand_num);
    ASSERT_TRUE(len > 0);

    return AWS_OP_SUCCESS;
}

/* Open read/write handles to a pipe with support for async (overlapped) read and write */
static int s_async_pipe_init(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle) {
    char pipe_name[256];
    ASSERT_SUCCESS(s_create_random_pipe_name(pipe_name, sizeof(pipe_name)));

    write_handle->data.handle = CreateNamedPipeA(
        pipe_name,                                                                   /* lpName */
        PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE, /* dwOpenMode */
        PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,                     /* dwPipeMode */
        1,                                                                           /* nMaxInstances */
        2048,                                                                        /* nOutBufferSize */
        2048,                                                                        /* nInBufferSize */
        0,                                                                           /* nDefaultTimeOut */
        NULL);                                                                       /* lpSecurityAttributes */

    ASSERT_TRUE(write_handle->data.handle != INVALID_HANDLE_VALUE);

    read_handle->data.handle = CreateFileA(
        pipe_name,                                    /* lpFileName */
        GENERIC_READ,                                 /* dwDesiredAccess */
        0,                                            /* dwShareMode */
        NULL,                                         /* lpSecurityAttributes */
        OPEN_EXISTING,                                /* dwCreationDisposition */
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, /* dwFlagsAndAttributes */
        NULL);                                        /* hTemplateFile */

    ASSERT_TRUE(read_handle->data.handle != INVALID_HANDLE_VALUE);

    return AWS_OP_SUCCESS;
}

static void s_async_pipe_clean_up(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle) {
    CloseHandle(read_handle->data.handle);
    CloseHandle(write_handle->data.handle);
}

struct overlapped_completion_data {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    bool signaled;
    struct aws_event_loop *event_loop;
    struct aws_overlapped *overlapped;
};

static int s_overlapped_completion_data_init(struct overlapped_completion_data *data) {
    AWS_ZERO_STRUCT(*data);
    ASSERT_SUCCESS(aws_mutex_init(&data->mutex));
    ASSERT_SUCCESS(aws_condition_variable_init(&data->condition_variable));
    return AWS_OP_SUCCESS;
}

static void s_overlapped_completion_data_clean_up(struct overlapped_completion_data *data) {
    aws_condition_variable_clean_up(&data->condition_variable);
    aws_mutex_clean_up(&data->mutex);
}

static void s_on_overlapped_operation_complete(struct aws_event_loop *event_loop, struct aws_overlapped *overlapped) {
    struct overlapped_completion_data *data = overlapped->user_data;
    aws_mutex_lock(&data->mutex);
    data->event_loop = event_loop;
    data->overlapped = overlapped;
    data->signaled = true;
    aws_condition_variable_notify_one(&data->condition_variable);
    aws_mutex_unlock(&data->mutex);
}

static bool s_overlapped_completion_predicate(void *args) {
    struct overlapped_completion_data *data = args;
    return data->signaled;
}

static int s_test_event_loop_completion_events(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* Start event-loop */
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);
    ASSERT_NOT_NULL(event_loop);
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    /* Open a pipe */
    struct aws_io_handle read_handle;
    struct aws_io_handle write_handle;
    ASSERT_SUCCESS(s_async_pipe_init(&read_handle, &write_handle));

    /* Connect to event-loop */
    ASSERT_SUCCESS(aws_event_loop_connect_handle_to_io_completion_port(event_loop, &write_handle));

    /* Set up an async (overlapped) write that will result in s_on_overlapped_operation_complete() getting run
     * and filling out `completion_data` */
    struct overlapped_completion_data completion_data;
    s_overlapped_completion_data_init(&completion_data);

    struct aws_overlapped overlapped;
    aws_overlapped_init(&overlapped, s_on_overlapped_operation_complete, &completion_data);

    /* Do async write */
    const char msg[] = "Cherry Pie";
    bool write_success = WriteFile(write_handle.data.handle, msg, sizeof(msg), NULL, &overlapped.overlapped);
    ASSERT_TRUE(write_success || GetLastError() == ERROR_IO_PENDING);

    /* Wait for completion callbacks */
    ASSERT_SUCCESS(aws_mutex_lock(&completion_data.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &completion_data.condition_variable,
        &completion_data.mutex,
        s_overlapped_completion_predicate,
        &completion_data));
    ASSERT_SUCCESS(aws_mutex_unlock(&completion_data.mutex));

    /* Assert that the aws_event_loop_on_completion_fn passed the appropriate args */
    ASSERT_PTR_EQUALS(event_loop, completion_data.event_loop);
    ASSERT_PTR_EQUALS(&overlapped, completion_data.overlapped);

    /* Assert that the OVERLAPPED structure has the expected data for a successful write */
    ASSERT_INT_EQUALS(0, overlapped.overlapped.Internal);               /* Check status code for I/O operation */
    ASSERT_INT_EQUALS(sizeof(msg), overlapped.overlapped.InternalHigh); /* Check number of bytes transferred */

    /* Shut it all down */
    s_overlapped_completion_data_clean_up(&completion_data);
    s_async_pipe_clean_up(&read_handle, &write_handle);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(event_loop_completion_events, s_test_event_loop_completion_events)

#else /* !AWS_USE_IO_COMPLETION_PORTS */

struct pipe_data {
    struct aws_io_handle handle;
    struct aws_byte_buf buf;
    size_t bytes_processed;
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    uint8_t invoked;
    uint8_t expected_invocations;
    struct aws_event_loop *event_loop;
};

static void s_on_pipe_readable(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data) {

    (void)event_loop;

    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        struct pipe_data *data = user_data;

        aws_mutex_lock(&data->mutex);
        size_t data_read = 0;
        aws_pipe_read(
            handle, data->buf.buffer + data->bytes_processed, data->buf.len - data->bytes_processed, &data_read);
        data->bytes_processed += data_read;
        data->invoked += 1;
        aws_condition_variable_notify_one(&data->condition_variable);
        aws_mutex_unlock(&data->mutex);
    }
}

static void s_on_pipe_writable(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data) {

    (void)event_loop;
    (void)handle;

    if (events & AWS_IO_EVENT_TYPE_WRITABLE) {
        struct pipe_data *data = user_data;
        aws_mutex_lock(&data->mutex);
        data->invoked += 1;
        aws_condition_variable_notify_one(&data->condition_variable);
        aws_mutex_unlock(&data->mutex);
    }
}

static bool s_invocation_predicate(void *args) {
    struct pipe_data *data = args;
    return data->invoked == data->expected_invocations;
}

static void s_unsubscribe_handle_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct pipe_data *data = arg;

    aws_event_loop_unsubscribe_from_io_events(data->event_loop, &data->handle);

    aws_mutex_lock(&data->mutex);
    data->invoked += 1;
    aws_condition_variable_notify_one(&data->condition_variable);
    aws_mutex_unlock(&data->mutex);
}

static int s_wait_for_next_invocation(struct pipe_data *data) {
    data->expected_invocations = data->invoked + 1;
    return aws_condition_variable_wait_pred(&data->condition_variable, &data->mutex, s_invocation_predicate, data);
}

/*
 * Test that read/write subscriptions are functional.
 */
static int s_test_read_write_notifications(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop), "Event loop run failed.");

    uint8_t read_buffer[1024] = {0};
    struct pipe_data read_data = {.buf = aws_byte_buf_from_array(read_buffer, sizeof(read_buffer)),
                                  .bytes_processed = 0,
                                  .condition_variable = AWS_CONDITION_VARIABLE_INIT,
                                  .mutex = AWS_MUTEX_INIT,
                                  .event_loop = event_loop};

    struct pipe_data write_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT, .mutex = AWS_MUTEX_INIT, .event_loop = event_loop};

    ASSERT_SUCCESS(aws_pipe_open(&read_data.handle, &write_data.handle), "Pipe open failed");

    ASSERT_SUCCESS(
        aws_event_loop_subscribe_to_io_events(
            event_loop, &read_data.handle, AWS_IO_EVENT_TYPE_READABLE, s_on_pipe_readable, &read_data),
        "Event loop read subscription failed.");

    ASSERT_SUCCESS(
        aws_event_loop_subscribe_to_io_events(
            event_loop, &write_data.handle, AWS_IO_EVENT_TYPE_WRITABLE, s_on_pipe_writable, &write_data),
        "Event loop write subscription failed.");

    /* Perform 2 writes to pipe. First write takes 1st half of write_buffer, and second write takes 2nd half.*/
    uint8_t write_buffer[1024];
    memset(write_buffer, 1, 512);
    memset(write_buffer + 512, 2, 512);

    ASSERT_SUCCESS(aws_mutex_lock(&read_data.mutex), "read mutex lock failed.");

    size_t written = 0;
    ASSERT_SUCCESS(aws_pipe_write(&write_data.handle, write_buffer, 512, &written), "Pipe write failed");
    ASSERT_UINT_EQUALS(512, written);

    ASSERT_SUCCESS(s_wait_for_next_invocation(&read_data));

    ASSERT_SUCCESS(aws_pipe_write(&write_data.handle, write_buffer + 512, 512, &written), "Pipe write failed");
    ASSERT_UINT_EQUALS(512, written);

    ASSERT_SUCCESS(s_wait_for_next_invocation(&read_data));

    ASSERT_BIN_ARRAYS_EQUALS(
        write_buffer, 1024, read_data.buf.buffer, read_data.buf.len, "Read data didn't match written data");
    ASSERT_INT_EQUALS(2, read_data.invoked, "Read callback should have been invoked twice.");
    ASSERT_TRUE(write_data.invoked > 0, "Write callback should have been invoked at least once.");

    struct aws_task unsubscribe_task;
    aws_task_init(&unsubscribe_task, s_unsubscribe_handle_task, &read_data);
    aws_event_loop_schedule_task_now(event_loop, &unsubscribe_task);
    ASSERT_SUCCESS(s_wait_for_next_invocation(&read_data));

    ASSERT_SUCCESS(aws_mutex_lock(&write_data.mutex), "write mutex lock failed");
    aws_task_init(&unsubscribe_task, s_unsubscribe_handle_task, &write_data);
    aws_event_loop_schedule_task_now(event_loop, &unsubscribe_task);
    ASSERT_SUCCESS(s_wait_for_next_invocation(&write_data));
    ASSERT_SUCCESS(aws_mutex_unlock(&write_data.mutex), "write mutex unlock failed");

    ASSERT_SUCCESS(aws_pipe_close(&read_data.handle, &write_data.handle), "Pipe close failed");

    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(read_write_notifications, s_test_read_write_notifications)

struct unsubrace_data {
    struct aws_event_loop *event_loop;

    struct aws_io_handle read_handle[2];
    struct aws_io_handle write_handle[2];
    bool is_writable[2];
    bool wrote_to_both_pipes;
    bool is_unsubscribed;

    struct aws_task task;

    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    bool done;
    int result_code;
};

void s_unsubrace_error(struct unsubrace_data *data) {
    aws_mutex_lock(&data->mutex);
    data->result_code = -1;
    data->done = true;
    aws_condition_variable_notify_one(&data->condition_variable);
    aws_mutex_unlock(&data->mutex);
}

void s_unsubrace_done(struct unsubrace_data *data) {
    aws_mutex_lock(&data->mutex);
    data->done = true;
    aws_condition_variable_notify_one(&data->condition_variable);
    aws_mutex_unlock(&data->mutex);
}

/* Wait until both pipes are writable, then write data to both of them.
 * This make it likely that both pipes receive events in the same iteration of the event-loop. */
void s_unsubrace_on_write_event(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data) {

    (void)event_loop;
    struct unsubrace_data *data = user_data;

    /* There should be no events after unsubscribe */
    if (data->is_unsubscribed) {
        s_unsubrace_error(data);
        return;
    }

    if (!(events & AWS_IO_EVENT_TYPE_WRITABLE)) {
        return;
    }

    if (data->wrote_to_both_pipes) {
        return;
    }

    bool all_writable = true;

    for (int i = 0; i < 2; ++i) {
        if (&data->write_handle[i] == handle) {
            data->is_writable[i] = true;
        }

        if (!data->is_writable[i]) {
            all_writable = false;
        }
    }

    if (!all_writable) {
        return;
    }

    for (int i = 0; i < 2; ++i) {
        uint8_t buffer[] = "abc";
        size_t bytes_written;
        int err = aws_pipe_write(&data->write_handle[i], buffer, 3, &bytes_written);
        if (err) {
            s_unsubrace_error(data);
            return;
        }

        if (bytes_written == 0) {
            s_unsubrace_error(data);
            return;
        }
    }

    data->wrote_to_both_pipes = true;
}

/* Both pipes should have a readable event on the way.
 * The first pipe to get the event closes both pipes.
 * Since both pipes are unsubscribed, the second readable event shouldn't be delivered */
void s_unsubrace_on_read_event(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data) {

    (void)handle;
    struct unsubrace_data *data = user_data;
    int err;

    if (data->is_unsubscribed) {
        s_unsubrace_error(data);
        return;
    }

    if (!(events & AWS_IO_EVENT_TYPE_READABLE)) {
        return;
    }

    for (int i = 0; i < 2; ++i) {
        err = aws_event_loop_unsubscribe_from_io_events(event_loop, &data->read_handle[i]);
        if (err) {
            s_unsubrace_error(data);
            return;
        }

        err = aws_event_loop_unsubscribe_from_io_events(event_loop, &data->write_handle[i]);
        if (err) {
            s_unsubrace_error(data);
            return;
        }

        err = aws_pipe_close(&data->read_handle[i], &data->write_handle[i]);
        if (err) {
            s_unsubrace_error(data);
            return;
        }
    }

    /* Zero out the handles so that further accesses to the closed pipe are extra likely to cause crashes */
    AWS_ZERO_ARRAY(data->read_handle);
    AWS_ZERO_ARRAY(data->write_handle);

    data->is_unsubscribed = true;
}

void s_unsubrace_done_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    struct unsubrace_data *data = arg;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        s_unsubrace_error(data);
        return;
    }

    s_unsubrace_done(data);
}

static void s_unsubrace_setup_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    struct unsubrace_data *data = arg;
    int err;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        s_unsubrace_error(data);
        return;
    }

    for (int i = 0; i < 2; ++i) {
        err = aws_pipe_open(&data->read_handle[i], &data->write_handle[i]);
        if (err) {
            s_unsubrace_error(data);
            return;
        }

        err = aws_event_loop_subscribe_to_io_events(
            data->event_loop, &data->write_handle[i], AWS_IO_EVENT_TYPE_WRITABLE, s_unsubrace_on_write_event, data);
        if (err) {
            s_unsubrace_error(data);
            return;
        }

        err = aws_event_loop_subscribe_to_io_events(
            data->event_loop, &data->read_handle[i], AWS_IO_EVENT_TYPE_READABLE, s_unsubrace_on_read_event, data);
        if (err) {
            s_unsubrace_error(data);
            return;
        }
    }

    /* Have a short delay before ending test. Any events that fire during that delay would be an error. */
    uint64_t time_ns;
    err = aws_event_loop_current_clock_time(data->event_loop, &time_ns);
    if (err) {
        s_unsubrace_error(data);
        return;
    }
    time_ns += aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);

    aws_task_init(&data->task, s_unsubrace_done_task, data);
    aws_event_loop_schedule_task_future(data->event_loop, &data->task, time_ns);
}

static bool s_unsubrace_predicate(void *arg) {
    struct unsubrace_data *data = arg;
    return data->done;
}

/* Regression test: Ensure that a handle cannot receive an event after it's been unsubscribed.
 * This was occuring in the case that there were events on two handles in the same event-loop tick,
 * and the first handle to receive its event unsubscribed the other handle.
 * Shortname: unsubrace */
static int s_test_event_loop_no_events_after_unsubscribe(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);
    ASSERT_NOT_NULL(event_loop);

    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct unsubrace_data data = {
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .event_loop = event_loop,
    };

    aws_task_init(&data.task, s_unsubrace_setup_task, &data);
    aws_event_loop_schedule_task_now(event_loop, &data.task);

    ASSERT_SUCCESS(aws_mutex_lock(&data.mutex));
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&data.condition_variable, &data.mutex, s_unsubrace_predicate, &data));
    ASSERT_SUCCESS(aws_mutex_unlock(&data.mutex));

    ASSERT_SUCCESS(data.result_code);

    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(event_loop_no_events_after_unsubscribe, s_test_event_loop_no_events_after_unsubscribe)

#endif /* AWS_USE_IO_COMPLETION_PORTS */

static int s_test_stop_then_restart(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct task_args task_args = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT, .mutex = AWS_MUTEX_INIT, .invoked = 0};

    struct aws_task task;
    aws_task_init(&task, s_test_task, &task_args);

    ASSERT_SUCCESS(aws_mutex_lock(&task_args.mutex));

    aws_event_loop_schedule_task_now(event_loop, &task);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &task_args.condition_variable, &task_args.mutex, s_task_ran_predicate, &task_args));
    ASSERT_INT_EQUALS(1, task_args.invoked);

    ASSERT_SUCCESS(aws_event_loop_stop(event_loop));
    ASSERT_SUCCESS(aws_event_loop_wait_for_stop_completion(event_loop));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    aws_event_loop_schedule_task_now(event_loop, &task);

    task_args.invoked = 0;
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &task_args.condition_variable, &task_args.mutex, s_task_ran_predicate, &task_args));
    ASSERT_INT_EQUALS(1, task_args.invoked);

    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(stop_then_restart, s_test_stop_then_restart)

static int test_event_loop_group_setup_and_shutdown(struct aws_allocator *allocator, void *ctx) {

    (void)ctx;
    struct aws_event_loop_group event_loop_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&event_loop_group, allocator));

    size_t cpu_count = aws_system_info_processor_count();
    size_t el_count = 1;

    struct aws_event_loop *event_loop = aws_event_loop_get_next_loop(&event_loop_group);
    struct aws_event_loop *first_loop = event_loop;

    while ((event_loop = aws_event_loop_get_next_loop(&event_loop_group)) != first_loop) {
        ASSERT_NOT_NULL(event_loop);
        el_count++;
    }

    ASSERT_INT_EQUALS(cpu_count, el_count);
    el_count = 1;
    /* now do it again to make sure the counter turns over. */
    while ((event_loop = aws_event_loop_get_next_loop(&event_loop_group)) != first_loop) {
        ASSERT_NOT_NULL(event_loop);
        el_count++;
    }
    ASSERT_INT_EQUALS(cpu_count, el_count);

    aws_event_loop_group_clean_up(&event_loop_group);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(event_loop_group_setup_and_shutdown, test_event_loop_group_setup_and_shutdown)

static int test_event_loop_group_counter_overflow(struct aws_allocator *allocator, void *ctx) {

    (void)ctx;
    struct aws_event_loop_group event_loop_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&event_loop_group, allocator));

    struct aws_event_loop *first_loop = aws_event_loop_get_next_loop(&event_loop_group);
    ASSERT_NOT_NULL(first_loop);

    /*this hurts my feelings to modify the internals of a struct to write a test, but it takes too long to
     * increment UINT32_MAX times. */
    event_loop_group.current_index = UINT32_MAX;
    struct aws_event_loop *event_loop = aws_event_loop_get_next_loop(&event_loop_group);
    ASSERT_NOT_NULL(event_loop);
    event_loop = aws_event_loop_get_next_loop(&event_loop_group);
    ASSERT_NOT_NULL(event_loop);
    ASSERT_PTR_EQUALS(first_loop, event_loop);

    aws_event_loop_group_clean_up(&event_loop_group);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(event_loop_group_counter_overflow, test_event_loop_group_counter_overflow)
