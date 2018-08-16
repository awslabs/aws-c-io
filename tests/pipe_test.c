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

static int s_pipe_state_init(struct pipe_state *state, struct aws_allocator *alloc) {
    AWS_ZERO_STRUCT(*state);

    state->event_loop = aws_event_loop_new_default(alloc, aws_high_res_clock_get_ticks);
    ASSERT_NOT_NULL(state->event_loop);
    ASSERT_SUCCESS(aws_event_loop_run(state->event_loop));

    ASSERT_SUCCESS(aws_pipe_init(&state->read_end, state->event_loop, &state->write_end, state->event_loop, alloc));

    ASSERT_SUCCESS(aws_mutex_init(&state->results.mutex));
    ASSERT_SUCCESS(aws_condition_variable_init(&state->results.condvar));

    return AWS_OP_SUCCESS;
}

static void s_pipe_state_clean_up(struct pipe_state *state) {
    aws_condition_variable_clean_up(&state->results.condvar);
    aws_mutex_clean_up(&state->results.mutex);
    aws_event_loop_destroy(state->event_loop);
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
static int s_pipe_state_run_test(struct pipe_state *state, aws_task_fn initial_test_fn) {
    uint64_t now;
    ASSERT_SUCCESS(aws_high_res_clock_get_ticks(&now));

    struct aws_task task;
    task.fn = initial_test_fn;
    task.arg = state;

    ASSERT_SUCCESS(aws_mutex_lock(&state->results.mutex));
    ASSERT_SUCCESS(aws_event_loop_schedule_task(state->event_loop, &task, now));
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
static int s_test_pipe_open_close(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct pipe_state state;
    ASSERT_SUCCESS(s_pipe_state_init(&state, allocator));

    ASSERT_SUCCESS(s_pipe_state_run_test(&state, s_test_pipe_open_close_initial_task));

    s_pipe_state_clean_up(&state);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(pipe_open_close, s_test_pipe_open_close);

struct buffers_to_copy {
    uint8_t *src;
    uint8_t *dst;
    size_t size;
    size_t num_bytes_written;
    size_t num_bytes_read;
};

static void s_test_pipe_read_write_on_write_complete(
    struct aws_pipe_write_end *write_end,
    int write_result,
    size_t num_bytes_written,
    void *user_data) {

    struct pipe_state *state = user_data;
    struct buffers_to_copy *buffers = state->test_data;
    int err = 0;

    if (write_result != 0) {
        err = write_result;
        goto error;
    }

    buffers->num_bytes_written = num_bytes_written;

    /* Read all bytes */
    err = aws_pipe_read(&state->read_end, buffers->dst, num_bytes_written, &buffers->num_bytes_read);
    if (err) {
        goto error;
    }

    /* Close pipe */
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
static int s_test_pipe_read_write(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* Init pipe state */
    struct pipe_state state;
    ASSERT_SUCCESS(s_pipe_state_init(&state, allocator));

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
    ASSERT_SUCCESS(s_pipe_state_run_test(&state, s_test_pipe_read_write_initial_task));

    /* Check results */
    ASSERT_UINT_EQUALS(buffers.size, buffers.num_bytes_written);
    ASSERT_UINT_EQUALS(buffers.size, buffers.num_bytes_read);
    ASSERT_INT_EQUALS(0, memcmp(buffers.src, buffers.dst, buffers.size));

    s_pipe_state_clean_up(&state);
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(pipe_read_write, s_test_pipe_read_write);

static void s_test_pipe_read_write_large_buffer_on_write_complete(
    struct aws_pipe_write_end *write_end,
    int write_result,
    size_t num_bytes_written,
    void *user_data) {

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
static int s_test_pipe_read_write_large_buffer(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* Init pipe state */
    struct pipe_state state;
    ASSERT_SUCCESS(s_pipe_state_init(&state, allocator));

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
    ASSERT_SUCCESS(s_pipe_state_run_test(&state, s_test_pipe_read_write_large_buffer_initial_task));

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

AWS_TEST_CASE(pipe_read_write_large_buffer, s_test_pipe_read_write_large_buffer);
