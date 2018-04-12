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

#include <aws/testing/aws_test_harness.h>
#include <aws/io/event_loop.h>
#include <aws/io/pipe.h>
#include <aws/common/task_scheduler.h>

struct event_loop_stopped_args {
    struct aws_mutex mutex;
};

static void on_event_loop_stopped(struct aws_event_loop *event_loop, void *ctx) {
    struct event_loop_stopped_args *stopped_args = (struct event_loop_stopped_args *)ctx;
    aws_mutex_unlock(&stopped_args->mutex);
}

struct task_args {
    int8_t invoked;
};

static void test_task(void *ctx) {
    struct task_args *args = (struct task_args *)ctx;
    args->invoked += 1;
}

/*
 * Test that a scheduled task from a non-event loop owned thread executes.
 */
static int test_xthread_scheduled_tasks_execute (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop), "Event loop run failed.");

    struct event_loop_stopped_args stopped_args;
    ASSERT_SUCCESS(aws_mutex_init(&stopped_args.mutex), "Mutex initialization failed");

    struct task_args task_args = {0};
    struct aws_task task = {
            .fn = test_task,
            .arg = &task_args
    };

    uint64_t now;
    ASSERT_SUCCESS(aws_high_res_clock_get_ticks(&now), "Clock get ticks failed.");
    ASSERT_SUCCESS(aws_event_loop_schedule_task(event_loop, &task, now), "task schedule failed.");

    ASSERT_SUCCESS(aws_mutex_lock(&stopped_args.mutex), "Mutex lock failed");
    ASSERT_SUCCESS(aws_event_loop_stop(event_loop, on_event_loop_stopped, &stopped_args), "Event loop stop failed.");

    /*using it as a semaphore here. */
    ASSERT_SUCCESS(aws_mutex_lock(&stopped_args.mutex), "Mutex lock failed");
    ASSERT_INT_EQUALS(1, task_args.invoked, "Task was not invoked");

    /* now this should be safe. */
    aws_event_loop_destroy(event_loop);
    aws_mutex_clean_up(&stopped_args.mutex);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(xthread_scheduled_tasks_execute, test_xthread_scheduled_tasks_execute)

struct pipe_data {
    struct aws_byte_buf buf;
    size_t bytes_processed;
    struct aws_mutex semaphore;
    uint8_t invoked;
};

static void on_pipe_readable (struct aws_event_loop *event_loop, struct aws_io_handle *handle, int events, void *ctx) {
    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        struct pipe_data *data = (struct pipe_data *)ctx;

        size_t data_read = 0;
        struct aws_byte_buf read_buf =
                aws_byte_buf_from_array(data->buf.buffer + data->bytes_processed, data->buf.len - data->bytes_processed);
        aws_pipe_read(handle, &read_buf, &data_read);
        data->bytes_processed += data_read;
        data->invoked += 1;
        aws_mutex_unlock(&data->semaphore);
    }
}

static void on_pipe_writable (struct aws_event_loop *event_loop, struct aws_io_handle *handle, int events, void *ctx) {
    if (events & AWS_IO_EVENT_TYPE_WRITABLE) {
        struct pipe_data *data = (struct pipe_data *)ctx;
        data->invoked += 1;
        aws_mutex_unlock(&data->semaphore);
    }
}

/*
 * Test that read/write subscriptions are functional.
 */
static int test_read_write_notifications (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop), "Event loop run failed.");

    struct event_loop_stopped_args stopped_args;
    ASSERT_SUCCESS(aws_mutex_init(&stopped_args.mutex), "Mutex initialization failed");

    struct aws_io_handle read_handle = {0};
    struct aws_io_handle write_handle = {0};

    ASSERT_SUCCESS(aws_pipe_open(allocator, &read_handle, &write_handle), "Pipe open failed");

    uint8_t read_buffer[1024] = {0};
    struct pipe_data read_data = {
            .buf = aws_byte_buf_from_array(read_buffer, sizeof(read_buffer)),
            .bytes_processed = 0,
    };

    struct pipe_data write_data = {0};

    ASSERT_SUCCESS(aws_mutex_init(&read_data.semaphore), "Mutex init failed.");

    ASSERT_SUCCESS(aws_event_loop_subscribe_to_io_events(event_loop, &read_handle,
                           AWS_IO_EVENT_TYPE_READABLE, on_pipe_readable, &read_data), "Event loop read subscription failed.");

    ASSERT_SUCCESS(aws_event_loop_subscribe_to_io_events(event_loop, &write_handle,
                                                         AWS_IO_EVENT_TYPE_WRITABLE, on_pipe_writable,
                                                         &write_data), "Event loop write subscription failed.");


    uint8_t write_buffer[1024] = {1};
    memset(write_buffer + 512, 2, 512);

    struct aws_byte_buf write_byte_buf = aws_byte_buf_from_array(write_buffer, 512);

    ASSERT_SUCCESS(aws_mutex_lock(&read_data.semaphore), "read mutex lock failed.");
    size_t written = 0;
    ASSERT_SUCCESS(aws_pipe_write(&write_handle, &write_byte_buf, &written), "Pipe write failed");

    ASSERT_SUCCESS(aws_mutex_lock(&read_data.semaphore), "read mutex lock failed.");
    write_byte_buf = aws_byte_buf_from_array(write_buffer + 512, 512);
    ASSERT_SUCCESS(aws_pipe_write(&write_handle, &write_byte_buf, &written), "Pipe write failed");

    ASSERT_SUCCESS(aws_mutex_lock(&read_data.semaphore), "read mutex lock failed.");

    ASSERT_BIN_ARRAYS_EQUALS(write_buffer, 1024, read_data.buf.buffer, read_data.buf.len, "Read data didn't match written data");
    ASSERT_INT_EQUALS(2, read_data.invoked, "Read callback should have been invoked twice.");
    ASSERT_TRUE(write_data.invoked > 0, "Write callback should have been invoked at least once.");


    ASSERT_SUCCESS(aws_event_loop_unsubscribe_from_io_events(event_loop, &read_handle), "read unsubscribe from event loop failed");
    ASSERT_SUCCESS(aws_event_loop_unsubscribe_from_io_events(event_loop, &write_handle), "write unsubscribe from event loop failed");

    ASSERT_SUCCESS(aws_pipe_close(allocator, &read_handle, &write_handle), "Pipe close failed");

    ASSERT_SUCCESS(aws_mutex_lock(&stopped_args.mutex), "Mutex lock failed");
    ASSERT_SUCCESS(aws_event_loop_stop(event_loop, on_event_loop_stopped, &stopped_args), "Event loop stop failed.");

    /*using it as a semaphore here. */
    ASSERT_SUCCESS(aws_mutex_lock(&stopped_args.mutex), "Mutex lock failed");

    /* now this should be safe. */
    aws_event_loop_destroy(event_loop);
    aws_mutex_clean_up(&stopped_args.mutex);
    aws_mutex_clean_up(&read_data.semaphore);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(read_write_notifications, test_read_write_notifications)
