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
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>
#include <aws/io/event_loop.h>
#include <aws/io/pipe.h>
#include <aws/testing/aws_test_harness.h>

/* State for pipe testing. Since most pipe operations must be performed on the event-loop thread,
 * the `results` struct is used to signal the main thread that the tests are finished. */
struct pipe_state {
    struct aws_event_loop *event_loop;
    struct aws_event_loop *event_loop2;

    struct aws_pipe_read_end read_end;
    struct aws_pipe_write_end write_end;

    struct {
        struct aws_mutex mutex;
        struct aws_condition_variable condvar;
        bool read_end_closed;
        bool write_end_closed;
        int status_code; /* Set to non-zero if something goes wrong on the thread. */
    } results;

    void *test_data;
};

enum pipe_loop_setup {
    SAME_EVENT_LOOP,
    DIFFERENT_EVENT_LOOPS,
};

static int s_pipe_state_init(struct pipe_state *state, struct aws_allocator *alloc, enum pipe_loop_setup loop_setup) {
    AWS_ZERO_STRUCT(*state);

    state->event_loop = aws_event_loop_new_default(alloc, aws_high_res_clock_get_ticks);
    ASSERT_NOT_NULL(state->event_loop);
    ASSERT_SUCCESS(aws_event_loop_run(state->event_loop));

    struct aws_event_loop *write_loop;
    if (loop_setup == DIFFERENT_EVENT_LOOPS) {
        state->event_loop2 = aws_event_loop_new_default(alloc, aws_high_res_clock_get_ticks);
        ASSERT_NOT_NULL(state->event_loop2);
        ASSERT_SUCCESS(aws_event_loop_run(state->event_loop2));
        write_loop = state->event_loop2;
    } else {
        write_loop = state->event_loop;
    }

    ASSERT_SUCCESS(aws_pipe_init(&state->read_end, state->event_loop, &state->write_end, write_loop, alloc));

    ASSERT_SUCCESS(aws_mutex_init(&state->results.mutex));
    ASSERT_SUCCESS(aws_condition_variable_init(&state->results.condvar));

    return AWS_OP_SUCCESS;
}

static void s_pipe_state_clean_up(struct pipe_state *state) {
    aws_condition_variable_clean_up(&state->results.condvar);
    aws_mutex_clean_up(&state->results.mutex);
    aws_event_loop_destroy(state->event_loop);
    if (state->event_loop2) {
        aws_event_loop_destroy(state->event_loop2);
    }
}

/* Checking if work on thread is done */
static bool s_pipe_state_done_pred(void *user_data) {
    struct pipe_state *state = user_data;

    if (state->results.status_code != 0) {
        return true;
    }

    if (state->results.read_end_closed && state->results.write_end_closed) {
        return true;
    }

    return false;
}

/* Signal that work is done, due to an unexpected error */
static void s_pipe_state_signal_error(struct pipe_state *state, int err) {
    assert(err != 0);

    aws_mutex_lock(&state->results.mutex);
    state->results.status_code = err;
    aws_condition_variable_notify_all(&state->results.condvar);
    aws_mutex_unlock(&state->results.mutex);
}

static void s_pipe_state_on_read_end_closed(struct aws_pipe_read_end *read_end, void *user_data) {
    (void)read_end;
    struct pipe_state *state = user_data;

    /* Signal that work might be done */
    aws_mutex_lock(&state->results.mutex);
    state->results.read_end_closed = true;
    aws_condition_variable_notify_all(&state->results.condvar);
    aws_mutex_unlock(&state->results.mutex);
}

static void s_pipe_state_on_write_end_closed(struct aws_pipe_write_end *write_end, void *user_data) {
    (void)write_end;
    struct pipe_state *state = user_data;

    /* Signal that work might be done */
    aws_mutex_lock(&state->results.mutex);
    state->results.write_end_closed = true;
    aws_condition_variable_notify_all(&state->results.condvar);
    aws_mutex_unlock(&state->results.mutex);
}

/* Schedule function to run on the event-loop thread, and wait for pipe_state to indicate that it's done.
 * `initial_test_fn` should expect `struct pipe_state*` as its `void *arg`. */
static int s_pipe_state_run_test(struct pipe_state *state, aws_task_fn *read_end_fn, aws_task_fn write_end_fn) {
    uint64_t now;

    if (read_end_fn) {
        struct aws_task task;
        task.fn = read_end_fn;
        task.arg = state;

        struct aws_event_loop *event_loop = aws_pipe_get_read_end_event_loop(&state->read_end);
        ASSERT_SUCCESS(aws_event_loop_current_ticks(event_loop, &now));
        ASSERT_SUCCESS(aws_event_loop_schedule_task(event_loop, &task, now));
    }

    if (write_end_fn) {
        struct aws_task task;
        task.fn = write_end_fn;
        task.arg = state;

        struct aws_event_loop *event_loop = aws_pipe_get_write_end_event_loop(&state->write_end);
        ASSERT_SUCCESS(aws_event_loop_current_ticks(event_loop, &now));
        ASSERT_SUCCESS(aws_event_loop_schedule_task(event_loop, &task, now));
    }

    ASSERT_SUCCESS(aws_mutex_lock(&state->results.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &state->results.condvar, &state->results.mutex, s_pipe_state_done_pred, state));
    ASSERT_SUCCESS(aws_mutex_unlock(&state->results.mutex));

    return state->results.status_code;
}

static void s_test_pipe_open_close_initial_task(void *arg, enum aws_task_status status) {
    (void)status;

    struct pipe_state *state = arg;
    int err;

    /* Just clean up the pipe, the test ends successfully if both ends finish closing */
    err = aws_pipe_clean_up_read_end(&state->read_end, s_pipe_state_on_read_end_closed, state);
    if (err) {
        goto error;
    }

    err = aws_pipe_clean_up_write_end(&state->write_end, s_pipe_state_on_write_end_closed, state);
    if (err) {
        goto error;
    }

    return;

error:
    s_pipe_state_signal_error(state, err);
}

/* Just test the pipe being opened and closed */
static int test_pipe_open_close(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct pipe_state state;
    ASSERT_SUCCESS(s_pipe_state_init(&state, allocator, SAME_EVENT_LOOP));

    ASSERT_SUCCESS(s_pipe_state_run_test(&state, s_test_pipe_open_close_initial_task, NULL));

    s_pipe_state_clean_up(&state);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(pipe_open_close, test_pipe_open_close);

struct buffers_to_copy {
    uint8_t *src;
    uint8_t *dst;
    size_t size;
    size_t num_bytes_written;
    size_t num_bytes_read;
};

static void s_test_pipe_read_write_read_and_clean_up(void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    struct buffers_to_copy *buffers = state->test_data;
    int err = 0;

    if (status == AWS_TASK_STATUS_CANCELED) {
        err = status;
        goto error;
    }

    /* Read all bytes */
    err = aws_pipe_read(&state->read_end, buffers->dst, buffers->num_bytes_written, &buffers->num_bytes_read);
    if (err) {
        goto error;
    }

    /* Close pipe */
    err = aws_pipe_clean_up_read_end(&state->read_end, s_pipe_state_on_read_end_closed, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_pipe_state_signal_error(state, err);
}

static void s_test_pipe_read_write_on_write_complete(
    struct aws_pipe_write_end *write_end,
    int write_result,
    size_t num_bytes_written,
    void *user_data) {

    (void)write_end;
    struct pipe_state *state = user_data;
    struct buffers_to_copy *buffers = state->test_data;
    int err = 0;

    if (write_result != 0) {
        err = write_result;
        goto error;
    }

    buffers->num_bytes_written = num_bytes_written;

    /* All done with write-end of pipe */
    err = aws_pipe_clean_up_write_end(&state->write_end, s_pipe_state_on_write_end_closed, state);
    if (err) {
        goto error;
    }

    /* Schedule task for read-end of pipe */
    struct aws_task task;
    task.fn = s_test_pipe_read_write_read_and_clean_up;
    task.arg = state;
    struct aws_event_loop *read_loop = aws_pipe_get_read_end_event_loop(&state->read_end);

    uint64_t now;
    err = aws_event_loop_current_ticks(read_loop, &now);
    if (err) {
        goto error;
    }

    err = aws_event_loop_schedule_task(read_loop, &task, now);
    if (err) {
        goto error;
    }

    return;
error:
    s_pipe_state_signal_error(state, err);
}

static void s_test_pipe_read_write_initial_task(void *arg, enum aws_task_status status) {
    (void)status;

    struct pipe_state *state = arg;
    struct buffers_to_copy *buffers = state->test_data;

    int err =
        aws_pipe_write(&state->write_end, buffers->src, buffers->size, s_test_pipe_read_write_on_write_complete, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_pipe_state_signal_error(state, err);
}

/* Test that a small buffer can be sent through the pipe */
static int s_test_pipe_read_write_common(struct aws_allocator *allocator, enum pipe_loop_setup loop_setup) {

    /* Init pipe state */
    struct pipe_state state;
    ASSERT_SUCCESS(s_pipe_state_init(&state, allocator, loop_setup));

    /* Set up buffers to copy */
    uint8_t src_array[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t dst_array[4] = {0};

    struct buffers_to_copy buffers;
    AWS_ZERO_STRUCT(buffers);
    buffers.src = src_array;
    buffers.dst = dst_array;
    buffers.size = sizeof(src_array);

    state.test_data = &buffers;

    /* Run test on event thread */
    ASSERT_SUCCESS(s_pipe_state_run_test(&state, NULL, s_test_pipe_read_write_initial_task));

    /* Check results */
    ASSERT_UINT_EQUALS(buffers.size, buffers.num_bytes_written);
    ASSERT_UINT_EQUALS(buffers.size, buffers.num_bytes_read);
    ASSERT_INT_EQUALS(0, memcmp(buffers.src, buffers.dst, buffers.size));

    s_pipe_state_clean_up(&state);
    return AWS_OP_SUCCESS;
}

static int test_pipe_read_write(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_test_pipe_read_write_common(allocator, SAME_EVENT_LOOP);
}

AWS_TEST_CASE(pipe_read_write, test_pipe_read_write);

static int test_pipe_read_write_across_event_loops(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_test_pipe_read_write_common(allocator, DIFFERENT_EVENT_LOOPS);
}

AWS_TEST_CASE(pipe_read_write_across_event_loops, test_pipe_read_write_across_event_loops);

static void s_test_pipe_read_write_large_buffer_on_write_complete(
    struct aws_pipe_write_end *write_end,
    int write_result,
    size_t num_bytes_written,
    void *user_data) {

    (void)write_end;
    struct pipe_state *state = user_data;
    struct buffers_to_copy *buffers = state->test_data;
    int err = 0;

    if (write_result != 0) {
        err = write_result;
        goto error;
    }

    buffers->num_bytes_written = num_bytes_written;

    /* If the read has completed, then close the pipe */
    if (buffers->num_bytes_read == buffers->size) {
        err = aws_pipe_clean_up_read_end(&state->read_end, s_pipe_state_on_read_end_closed, state);
        if (err) {
            goto error;
        }

        err = aws_pipe_clean_up_write_end(&state->write_end, s_pipe_state_on_write_end_closed, state);
        if (err) {
            goto error;
        }
    }

    return;
error:
    s_pipe_state_signal_error(state, err);
}

static void s_test_pipe_read_write_large_buffer_read_task(void *arg, enum aws_task_status status) {
    (void)status;

    struct pipe_state *state = arg;
    struct buffers_to_copy *buffers = state->test_data;

    size_t num_bytes_remaining = buffers->size - buffers->num_bytes_read;
    size_t num_bytes_read;
    int err =
        aws_pipe_read(&state->read_end, buffers->dst + buffers->num_bytes_read, num_bytes_remaining, &num_bytes_read);

    /* AWS_IO_READ_WOULD_BLOCK is an acceptable error, it just means the data's not ready yet */
    if (err && (err != AWS_IO_READ_WOULD_BLOCK)) {
        goto error;
    }

    buffers->num_bytes_read += num_bytes_read;

    if (buffers->num_bytes_read == buffers->size) {
        /* Done reading!
         * If the write has completed, then close the pipe */
        if (buffers->num_bytes_written > 0) {
            err = aws_pipe_clean_up_read_end(&state->read_end, s_pipe_state_on_read_end_closed, state);
            if (err) {
                goto error;
            }

            err = aws_pipe_clean_up_write_end(&state->write_end, s_pipe_state_on_write_end_closed, state);
            if (err) {
                goto error;
            }
        }
    } else {
        /* Haven't read everything yet, schedule this read task to run again. */
        uint64_t now;
        err = state->event_loop->clock(&now);
        if (err) {
            goto error;
        }

        struct aws_task task;
        task.arg = state;
        task.fn = s_test_pipe_read_write_large_buffer_read_task;

        err = aws_event_loop_schedule_task(state->event_loop, &task, now);
        if (err) {
            goto error;
        }
    }

    return;
error:
    s_pipe_state_signal_error(state, err);
}

static void s_test_pipe_read_write_large_buffer_initial_task(void *arg, enum aws_task_status status) {
    (void)status;

    struct pipe_state *state = arg;
    struct buffers_to_copy *buffers = state->test_data;

    /* Kick off one big async write */
    int err = aws_pipe_write(
        &state->write_end, buffers->src, buffers->size, s_test_pipe_read_write_large_buffer_on_write_complete, state);
    if (err) {
        goto error;
    }

    /* Manually run the read task, which will repeatedly reschedule itself until the whole buffer is read */
    s_test_pipe_read_write_large_buffer_read_task(state, AWS_TASK_STATUS_RUN_READY);

    return;
error:
    s_pipe_state_signal_error(state, err);
}

/* Test that a large buffer can be sent through the pipe. */
static int test_pipe_read_write_large_buffer(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* Init pipe state */
    struct pipe_state state;
    ASSERT_SUCCESS(s_pipe_state_init(&state, allocator, SAME_EVENT_LOOP));

    /* Set up buffers to copy */
    struct buffers_to_copy buffers;
    AWS_ZERO_STRUCT(buffers);
    buffers.size = 1024 * 1024 * 32; /* 32MB */
    buffers.src = aws_mem_acquire(allocator, buffers.size);
    buffers.dst = aws_mem_acquire(allocator, buffers.size);
    ASSERT_NOT_NULL(buffers.src);
    ASSERT_NOT_NULL(buffers.dst);

    state.test_data = &buffers;

    /* Fill source buffer with random bytes */
    for (size_t i = 0; i < buffers.size; ++i) {
        buffers.src[i] = (uint8_t)rand();
    }

    /* Run test on event thread */
    ASSERT_SUCCESS(s_pipe_state_run_test(&state, NULL, s_test_pipe_read_write_large_buffer_initial_task));

    /* Check results */
    ASSERT_UINT_EQUALS(buffers.size, buffers.num_bytes_written);
    ASSERT_UINT_EQUALS(buffers.size, buffers.num_bytes_read);
    ASSERT_INT_EQUALS(0, memcmp(buffers.src, buffers.dst, buffers.size));

    /* Clean up */
    aws_mem_release(allocator, buffers.src);
    aws_mem_release(allocator, buffers.dst);
    s_pipe_state_clean_up(&state);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(pipe_read_write_large_buffer, test_pipe_read_write_large_buffer);

struct readable_event_data {
    struct buffers_to_copy buffers;

    int monitoring_event;
    int event_count;
    int close_after_n_events;
};

static void s_on_readable_event(struct aws_pipe_read_end *read_end, int events, void *user_data) {

    struct pipe_state *state = user_data;
    struct readable_event_data *data = state->test_data;

    if (events & data->monitoring_event) {
        data->event_count++;

        if (data->event_count == data->close_after_n_events) {
            int err = aws_pipe_clean_up_read_end(read_end, s_pipe_state_on_read_end_closed, state);
            if (err) {
                s_pipe_state_signal_error(state, err);
            }
        }
    }
}

static void s_readable_event_subscribe_task(void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;

    if (status == AWS_TASK_STATUS_CANCELED) {
        s_pipe_state_signal_error(state, status);
        return;
    }

    int err = aws_pipe_subscribe_to_read_events(&state->read_end, s_on_readable_event, state);
    if (err) {
        s_pipe_state_signal_error(state, err);
    }
}

void s_readable_event_clean_up_on_write_complete(
    struct aws_pipe_write_end *write_end,
    int write_result,
    size_t num_bytes_written,
    void *user_data) {

    (void)write_result;

    struct pipe_state *state = user_data;
    struct readable_event_data *data = state->test_data;

    data->buffers.num_bytes_written += num_bytes_written;

    int err = aws_pipe_clean_up_write_end(write_end, s_pipe_state_on_write_end_closed, state);
    if (err) {
        s_pipe_state_signal_error(state, err);
    }
}

static void s_readable_event_write_once_task(void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    struct readable_event_data *data = state->test_data;
    struct buffers_to_copy *buffers = &data->buffers;

    if (status == AWS_TASK_STATUS_CANCELED) {
        s_pipe_state_signal_error(state, status);
        return;
    }

    int err = aws_pipe_write(
        &state->write_end, buffers->src, buffers->size, s_readable_event_clean_up_on_write_complete, state);
    if (err) {
        s_pipe_state_signal_error(state, err);
    }
}

static int test_pipe_readable_event_sent_after_write(struct aws_allocator *allocator, void *arg) {
    (void)arg;

    /* Init pipe state */
    struct pipe_state state;
    ASSERT_SUCCESS(s_pipe_state_init(&state, allocator, SAME_EVENT_LOOP));

    uint8_t src_array[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t dst_array[4] = {0};

    struct readable_event_data data;

    AWS_ZERO_STRUCT(data);
    data.monitoring_event = AWS_IO_EVENT_TYPE_READABLE;
    data.close_after_n_events = 1;

    data.buffers.src = src_array;
    data.buffers.dst = dst_array;
    data.buffers.size = sizeof(src_array);

    state.test_data = &data;

    /* Run test on event thread */
    ASSERT_SUCCESS(s_pipe_state_run_test(&state, s_readable_event_subscribe_task, s_readable_event_write_once_task));

    /* Check results */
    ASSERT_INT_EQUALS(1, data.event_count);

    /* Clean up */
    s_pipe_state_clean_up(&state);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(pipe_readable_event_sent_after_write, test_pipe_readable_event_sent_after_write);

static void s_readable_event_write_once_then_subscribe_task(void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    int err = 0;

    if (status == AWS_TASK_STATUS_CANCELED) {
        err = status;
        goto error;
    }

    /* write date */
    s_readable_event_write_once_task(arg, status);
    if (state->results.status_code) {
        return;
    }


    /* schedule task for read-end to subscribe */
    struct aws_event_loop *read_loop = aws_pipe_get_read_end_event_loop(&state->read_end);

    uint64_t now;
    err = aws_event_loop_current_ticks(read_loop, &now);
    if (err) {
        goto error;
    }

    struct aws_task task;
    task.fn = s_readable_event_subscribe_task;
    task.arg = state;

    err = aws_event_loop_schedule_task(read_loop, &task, now);
    if (err) {
        goto error;
    }

    return;
error:
    s_pipe_state_signal_error(state, status);
}

static int test_pipe_readable_event_sent_on_subscribe_if_data_present(struct aws_allocator *allocator, void *arg) {
    (void)arg;

    /* Init pipe state */
    struct pipe_state state;
    ASSERT_SUCCESS(s_pipe_state_init(&state, allocator, SAME_EVENT_LOOP));

    uint8_t src_array[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t dst_array[4] = {0};

    struct readable_event_data data;

    AWS_ZERO_STRUCT(data);
    data.monitoring_event = AWS_IO_EVENT_TYPE_READABLE;
    data.close_after_n_events = 1;

    data.buffers.src = src_array;
    data.buffers.dst = dst_array;
    data.buffers.size = sizeof(src_array);

    state.test_data = &data;

    /* Run test on event thread */
    ASSERT_SUCCESS(s_pipe_state_run_test(&state, NULL, s_readable_event_write_once_then_subscribe_task));

    /* Check results */
    ASSERT_INT_EQUALS(1, data.event_count);

    /* Clean up */
    s_pipe_state_clean_up(&state);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    pipe_readable_event_sent_on_subscribe_if_data_present,
    test_pipe_readable_event_sent_on_subscribe_if_data_present);

static void s_resubscribe_2_task(void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    struct readable_event_data *data = state->test_data;
    int err = 0;

    if (status == AWS_TASK_STATUS_CANCELED) {
        err = status;
        goto error;
    }

    if (data->event_count != 1) {
        err = 1;
        goto error;
    }

    /* unsubscribe and resubscribe */
    err = aws_pipe_unsubscribe_from_read_events(&state->read_end);
    if (err) {
        goto error;
    }

    s_readable_event_subscribe_task(arg, status);
    if (state->results.status_code) {
        return;
    }

    return;
error:
    s_pipe_state_signal_error(state, err);
}

static void s_resubscribe_1_task(void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    int err = 0;

    if (status == AWS_TASK_STATUS_CANCELED) {
        err = status;
        goto error;
    }

    /* subscribe */
    s_readable_event_subscribe_task(arg, status);
    if (state->results.status_code) {
        return;
    }

    /* schedule a future event that will unsubsribe/resubscribe */
    struct aws_event_loop *loop = aws_pipe_get_read_end_event_loop(&state->read_end);

    uint64_t time_ns;
    err = aws_event_loop_current_ticks(loop, &time_ns);
    if (err) {
        goto error;
    }
    time_ns += aws_timestamp_convert(2, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);

    struct aws_task task;
    task.fn = s_resubscribe_2_task;
    task.arg = state;

    err = aws_event_loop_schedule_task(loop, &task, time_ns);

    return;
error:
    s_pipe_state_signal_error(state, err);
}

static void s_resubscribe_write_task(void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    int err = 0;

    if (status == AWS_TASK_STATUS_CANCELED) {
        err = status;
        goto error;
    }

    /* write date */
    s_readable_event_write_once_task(arg, status);
    if (state->results.status_code) {
        return;
    }

    /* schedule task for read-end to perform 1st subscribe */
    struct aws_event_loop *read_loop = aws_pipe_get_read_end_event_loop(&state->read_end);

    uint64_t now;
    err = aws_event_loop_current_ticks(read_loop, &now);
    if (err) {
        goto error;
    }

    struct aws_task task;
    task.fn = s_resubscribe_1_task;
    task.arg = state;

    err = aws_event_loop_schedule_task(read_loop, &task, now);
    if (err) {
        goto error;
    }

    return;
error:
    s_pipe_state_signal_error(state, status);
}

static int test_pipe_readable_event_sent_on_resubscribe_if_data_present(struct aws_allocator *allocator, void *arg) {
    (void)arg;

    /* Init pipe state */
    struct pipe_state state;
    ASSERT_SUCCESS(s_pipe_state_init(&state, allocator, SAME_EVENT_LOOP));

    uint8_t src_array[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t dst_array[4] = {0};

    struct readable_event_data data;

    AWS_ZERO_STRUCT(data);
    data.monitoring_event = AWS_IO_EVENT_TYPE_READABLE;
    data.close_after_n_events = 2;

    data.buffers.src = src_array;
    data.buffers.dst = dst_array;
    data.buffers.size = sizeof(src_array);

    state.test_data = &data;

    /* Run test on event thread */
    ASSERT_SUCCESS(s_pipe_state_run_test(&state, NULL, s_resubscribe_write_task));

    /* Check results */
    ASSERT_INT_EQUALS(2, data.event_count);

    /* Clean up */
    s_pipe_state_clean_up(&state);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    pipe_readable_event_sent_on_resubscribe_if_data_present,
    test_pipe_readable_event_sent_on_resubscribe_if_data_present);

// pipe_readable_event_sent_again_after_all_data_read
// pipe_readable_event_not_sent_again_until_all_data_read
// pipe_closed_event_sent_after_write_end_cleaned_up
// pipe_clean_up_cancels_pending_writes