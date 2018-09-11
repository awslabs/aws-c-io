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

#else  /* !AWS_USE_IO_COMPLETION_PORTS */

struct pipe_data {
    struct aws_byte_buf buf;
    size_t bytes_processed;
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    uint8_t invoked;
    uint8_t expected_invocations;
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

/*
 * Test that read/write subscriptions are functional.
 */
static int s_test_read_write_notifications(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop), "Event loop run failed.");

    struct aws_io_handle read_handle = {{0}};
    struct aws_io_handle write_handle = {{0}};

    ASSERT_SUCCESS(aws_pipe_open(&read_handle, &write_handle), "Pipe open failed");

    uint8_t read_buffer[1024] = {0};
    struct pipe_data read_data = {.buf = aws_byte_buf_from_array(read_buffer, sizeof(read_buffer)),
                                  .bytes_processed = 0,
                                  .condition_variable = AWS_CONDITION_VARIABLE_INIT,
                                  .mutex = AWS_MUTEX_INIT};

    struct pipe_data write_data = {{0}};

    ASSERT_SUCCESS(
        aws_event_loop_subscribe_to_io_events(
            event_loop, &read_handle, AWS_IO_EVENT_TYPE_READABLE, s_on_pipe_readable, &read_data),
        "Event loop read subscription failed.");

    ASSERT_SUCCESS(
        aws_event_loop_subscribe_to_io_events(
            event_loop, &write_handle, AWS_IO_EVENT_TYPE_WRITABLE, s_on_pipe_writable, &write_data),
        "Event loop write subscription failed.");

    /* Perform 2 writes to pipe. First write takes 1st half of write_buffer, and second write takes 2nd half.*/
    uint8_t write_buffer[1024];
    memset(write_buffer, 1, 512);
    memset(write_buffer + 512, 2, 512);

    ASSERT_SUCCESS(aws_mutex_lock(&read_data.mutex), "read mutex lock failed.");
    size_t written = 0;
    ASSERT_SUCCESS(aws_pipe_write(&write_handle, write_buffer, 512, &written), "Pipe write failed");
    ASSERT_UINT_EQUALS(512, written);

    read_data.expected_invocations = 1;
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &read_data.condition_variable, &read_data.mutex, s_invocation_predicate, &read_data));
    ASSERT_SUCCESS(aws_pipe_write(&write_handle, write_buffer + 512, 512, &written), "Pipe write failed");
    ASSERT_UINT_EQUALS(512, written);

    read_data.expected_invocations = 2;
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &read_data.condition_variable, &read_data.mutex, s_invocation_predicate, &read_data));

    ASSERT_BIN_ARRAYS_EQUALS(
        write_buffer, 1024, read_data.buf.buffer, read_data.buf.len, "Read data didn't match written data");
    ASSERT_INT_EQUALS(2, read_data.invoked, "Read callback should have been invoked twice.");
    ASSERT_TRUE(write_data.invoked > 0, "Write callback should have been invoked at least once.");

    ASSERT_SUCCESS(
        aws_event_loop_unsubscribe_from_io_events(event_loop, &read_handle), "read unsubscribe from event loop failed");
    ASSERT_SUCCESS(
        aws_event_loop_unsubscribe_from_io_events(event_loop, &write_handle),
        "write unsubscribe from event loop failed");

    ASSERT_SUCCESS(aws_pipe_close(&read_handle, &write_handle), "Pipe close failed");

    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(read_write_notifications, s_test_read_write_notifications)
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
