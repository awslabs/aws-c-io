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

enum pipe_loop_setup {
    SAME_EVENT_LOOP,
    DIFFERENT_EVENT_LOOPS,
};

enum {
    SMALL_BUFFER_SIZE = 4,
    GIANT_BUFFER_SIZE = 1024 * 1024 * 32, /* 32MB */
};

/* Used for tracking state in the pipe tests. */
struct pipe_state {
    /* Begin setup parameters */
    enum pipe_loop_setup loop_setup;
    size_t buffer_size;
    /* End setup parameters */

    struct aws_allocator *alloc;

    struct aws_pipe_read_end read_end;
    struct aws_pipe_write_end write_end;

    struct aws_event_loop *read_loop;
    struct aws_event_loop *write_loop;

    /* Since most pipe operations must be performed on the event-loop thread,
     * the `results` struct is used to signal the main thread that the tests are finished. */
    struct {
        struct aws_mutex mutex;
        struct aws_condition_variable condvar;
        bool read_end_closed;
        bool write_end_closed;
        int status_code; /* Set to non-zero if something goes wrong on the thread. */
    } results;

    struct {
        uint8_t *src;
        uint8_t *dst;
        size_t size;
        size_t num_bytes_written;
        size_t num_bytes_read;
    } buffers;

    struct {
        int monitoring_mask;               /* contains aws_io_event_type flags */
        int count;                         /* count of events that matched the mask */
        int close_read_end_after_n_events; /* if set, close read end when count reaches N */
    } events;

    void *test_data; /* If a test needs special data */
};

static void s_fixture_before(struct aws_allocator *allocator, void *ctx) {
    struct pipe_state *state = ctx;
    int err;

    state->alloc = allocator;

    state->read_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);
    assert(state->read_loop);
    err = aws_event_loop_run(state->read_loop);
    assert(!err);

    if (state->loop_setup == DIFFERENT_EVENT_LOOPS) {
        state->write_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);
        assert(state->write_loop);

        err = aws_event_loop_run(state->write_loop);
        assert(!err);
    } else {
        state->write_loop = state->read_loop;
    }

    err = aws_pipe_init(&state->read_end, state->read_loop, &state->write_end, state->write_loop, allocator);
    assert(!err);

    err = aws_mutex_init(&state->results.mutex);
    assert(!err);

    err = aws_condition_variable_init(&state->results.condvar);
    assert(!err);

    /* Fill src buffer with random content */
    if (state->buffer_size > 0) {

        state->buffers.src = aws_mem_acquire(allocator, state->buffer_size);
        assert(state->buffers.src);

        for (size_t i = 0; i < state->buffer_size; ++i) {
            state->buffers.src[i] = rand() % 256;
        }

        /* Zero out dst buffer */
        state->buffers.dst = aws_mem_acquire(allocator, state->buffer_size);
        assert(state->buffers.dst);

        memset(state->buffers.dst, 0, state->buffer_size);
    }
}

/* Assumes the pipe's read-end and write-end are already cleaned up */
static void s_fixture_after(struct aws_allocator *allocator, void *ctx) {
    struct pipe_state *state = ctx;

    aws_condition_variable_clean_up(&state->results.condvar);
    aws_mutex_clean_up(&state->results.mutex);
    aws_event_loop_destroy(state->read_loop);
    if (state->write_loop != state->read_loop) {
        aws_event_loop_destroy(state->write_loop);
    }

    if (state->buffers.src) {
        aws_mem_release(allocator, state->buffers.src);
    }
    if (state->buffers.dst) {
        aws_mem_release(allocator, state->buffers.dst);
    }

    AWS_ZERO_STRUCT(*state);
}

/* Macro for declaring pipe tests.
 * Add pipe tests to CMakeLists.txt like so: add_pipe_test_case(NAME)
 *
/* Each pipe test is run in 2 different configurations:
 * 1) both ends of the pipe use the same event-loop
 * 2) each end of the pipe is on its own event-loop
 *
 * For each test with NAME, write a function with the following signature:
 * int test_NAME(struct pipe_state *state) {...}
 */
#define PIPE_TEST_CASE(NAME, BUFFER_SIZE)                                                                              \
    static struct pipe_state NAME##_pipe_state_same_loop = {                                                           \
        .loop_setup = SAME_EVENT_LOOP,                                                                                 \
        .buffer_size = (BUFFER_SIZE),                                                                                  \
    };                                                                                                                 \
    static int test_##NAME##_same_loop(struct aws_allocator *allocator, void *ctx) {                                   \
        (void)allocator;                                                                                               \
        struct pipe_state *state = ctx;                                                                                \
        return test_##NAME(state);                                                                                     \
    }                                                                                                                  \
    AWS_TEST_CASE_FIXTURE(                                                                                             \
        NAME, s_fixture_before, test_##NAME##_same_loop, s_fixture_after, &NAME##_pipe_state_same_loop)                \
                                                                                                                       \
    static struct pipe_state NAME##_pipe_state_different_loops = {                                                     \
        .loop_setup = DIFFERENT_EVENT_LOOPS,                                                                           \
        .buffer_size = (BUFFER_SIZE),                                                                                  \
    };                                                                                                                 \
    static int test_##NAME##_different_loops(struct aws_allocator *allocator, void *ctx) {                             \
        (void)allocator;                                                                                               \
        struct pipe_state *state = ctx;                                                                                \
        return test_##NAME(state);                                                                                     \
    }                                                                                                                  \
    AWS_TEST_CASE_FIXTURE(                                                                                             \
        NAME##_2loops,                                                                                                 \
        s_fixture_before,                                                                                              \
        test_##NAME##_different_loops,                                                                                 \
        s_fixture_after,                                                                                               \
        &NAME##_pipe_state_different_loops)

/* Checking if work on thread is done */
static bool s_done_pred(void *user_data) {
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
static void s_signal_error(struct pipe_state *state) {
    aws_mutex_lock(&state->results.mutex);
    state->results.status_code = -1;
    aws_condition_variable_notify_all(&state->results.condvar);
    aws_mutex_unlock(&state->results.mutex);
}

static void s_signal_done_on_read_end_closed(struct pipe_state *state) {
    /* Signal that work might be done */
    aws_mutex_lock(&state->results.mutex);
    state->results.read_end_closed = true;
    aws_condition_variable_notify_all(&state->results.condvar);
    aws_mutex_unlock(&state->results.mutex);
}

static void s_signal_done_on_write_end_closed(struct pipe_state *state) {
    /* Signal that work might be done */
    aws_mutex_lock(&state->results.mutex);
    state->results.write_end_closed = true;
    aws_condition_variable_notify_all(&state->results.condvar);
    aws_mutex_unlock(&state->results.mutex);
}

static int s_pipe_state_check_copied_data(struct pipe_state *state) {
    ASSERT_UINT_EQUALS(state->buffer_size, state->buffers.num_bytes_written);
    ASSERT_UINT_EQUALS(state->buffer_size, state->buffers.num_bytes_read);
    ASSERT_INT_EQUALS(0, memcmp(state->buffers.src, state->buffers.dst, state->buffer_size));
    return AWS_OP_SUCCESS;
}

static void s_schedule_task(struct pipe_state *state, struct aws_event_loop *loop, aws_task_fn *fn) {
    struct aws_task *task = aws_mem_acquire(state->alloc, sizeof(struct aws_task));
    if (!task) {
        goto error;
    }

    aws_task_init(task, fn, state);
    aws_event_loop_schedule_task_now(loop, task);

    return;
error:
    s_signal_error(state);
}

static void s_schedule_read_end_task(struct pipe_state *state, aws_task_fn *fn) {
    s_schedule_task(state, state->read_loop, fn);
}

static void s_schedule_write_end_task(struct pipe_state *state, aws_task_fn *fn) {
    s_schedule_task(state, state->write_loop, fn);
}

/* wait for pipe_state to indicate that it's done */
static int s_wait_for_results(struct pipe_state *state) {
    ASSERT_SUCCESS(aws_mutex_lock(&state->results.mutex));
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&state->results.condvar, &state->results.mutex, s_done_pred, state));
    ASSERT_SUCCESS(aws_mutex_unlock(&state->results.mutex));

    return state->results.status_code;
}

static void s_clean_up_read_end_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    int err;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    err = aws_pipe_clean_up_read_end(&state->read_end);
    if (err) {
        goto error;
    }

    s_signal_done_on_read_end_closed(state);
    return;

error:
    s_signal_error(state);
}

static void s_clean_up_write_end_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    int err;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    err = aws_pipe_clean_up_write_end(&state->write_end);
    if (err) {
        goto error;
    }

    s_signal_done_on_write_end_closed(state);

    return;

error:
    s_signal_error(state);
}

/* Just test the pipe being opened and closed */
static int test_pipe_open_close(struct pipe_state *state) {
    s_schedule_read_end_task(state, s_clean_up_read_end_task);
    s_schedule_write_end_task(state, s_clean_up_write_end_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_open_close, SMALL_BUFFER_SIZE);

void s_clean_up_write_end_on_write_complete(
    struct aws_pipe_write_end *write_end,
    int write_result,
    size_t num_bytes_written,
    void *user_data) {

    (void)write_result;

    struct pipe_state *state = user_data;

    state->buffers.num_bytes_written += num_bytes_written;

    int err = aws_pipe_clean_up_write_end(write_end);
    if (err) {
        goto error;
    }

    s_signal_done_on_write_end_closed(state);

    return;
error:
    s_signal_error(state);
}

/* Write everything in the buffer, clean up write-end when write completes*/
static void s_write_once_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    int err = aws_pipe_write(
        &state->write_end, state->buffers.src, state->buffer_size, s_clean_up_write_end_on_write_complete, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_signal_error(state);
}

/* Task tries to read as much data as possible.
 * Task repeatedly reschedules itself until read-buffer is full, then it cleans up the read-end */
static void s_read_everything_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }
    size_t num_bytes_remaining = state->buffer_size - state->buffers.num_bytes_read;
    size_t num_bytes_read = 0;
    uint8_t *dst_cur = state->buffers.dst + state->buffers.num_bytes_read;
    int err = aws_pipe_read(&state->read_end, dst_cur, num_bytes_remaining, &num_bytes_read);

    state->buffers.num_bytes_read += num_bytes_read;

    /* AWS_IO_READ_WOULD_BLOCK is an acceptable error, it just means the data's not ready yet */
    if (err && (aws_last_error() != AWS_IO_READ_WOULD_BLOCK)) {
        goto error;
    }

    if (num_bytes_read < num_bytes_remaining) {
        s_schedule_read_end_task(state, s_read_everything_task);
    } else {
        err = aws_pipe_clean_up_read_end(&state->read_end);
        if (err) {
            goto error;
        }
        s_signal_done_on_read_end_closed(state);
    }

    return;
error:
    s_signal_error(state);
}

/* common function used by small-buffer test and large-buffer test */
static int s_test_pipe_read_write(struct pipe_state *state) {
    s_schedule_read_end_task(state, s_read_everything_task);
    s_schedule_write_end_task(state, s_write_once_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_SUCCESS(s_pipe_state_check_copied_data(state));

    return AWS_OP_SUCCESS;
}

/* Test that a small buffer can be sent through the pipe */
static int test_pipe_read_write(struct pipe_state *state) {
    return s_test_pipe_read_write(state);
}

PIPE_TEST_CASE(pipe_read_write, SMALL_BUFFER_SIZE);

/* Test that a large buffer can be sent through the pipe. */
static int test_pipe_read_write_large_buffer(struct pipe_state *state) {
    return s_test_pipe_read_write(state);
}

PIPE_TEST_CASE(pipe_read_write_large_buffer, GIANT_BUFFER_SIZE);

static void s_on_readable_event(struct aws_pipe_read_end *read_end, int events, void *user_data) {

    struct pipe_state *state = user_data;

    if (events & state->events.monitoring_mask) {
        state->events.count++;

        if (state->events.count == state->events.close_read_end_after_n_events) {
            int err = aws_pipe_clean_up_read_end(read_end);
            if (err) {
                goto error;
            }
            s_signal_done_on_read_end_closed(state);
        }
    }

    return;
error:
    s_signal_error(state);
}

static void s_subscribe_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    int err = aws_pipe_subscribe_to_read_events(&state->read_end, s_on_readable_event, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_signal_error(state);
}

static int test_pipe_readable_event_sent_after_write(struct pipe_state *state) {
    state->events.monitoring_mask = AWS_IO_EVENT_TYPE_READABLE;
    state->events.close_read_end_after_n_events = 1;

    s_schedule_read_end_task(state, s_subscribe_task);
    s_schedule_write_end_task(state, s_write_once_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(1, state->events.count);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_readable_event_sent_after_write, SMALL_BUFFER_SIZE);

void s_subscribe_on_write_complete(
    struct aws_pipe_write_end *write_end,
    int write_result,
    size_t num_bytes_written,
    void *user_data) {

    (void)write_result;

    struct pipe_state *state = user_data;

    state->buffers.num_bytes_written += num_bytes_written;

    int err = aws_pipe_clean_up_write_end(write_end);
    if (err) {
        goto error;
    }
    s_signal_done_on_write_end_closed(state);

    /* Tell read end to subscribe */
    s_schedule_read_end_task(state, s_subscribe_task);

    return;
error:
    s_signal_error(state);
}

/* Write all data. When write completes, write-end cleans up and tells the read-end to subscribe */
static void s_write_once_then_subscribe_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    int err = 0;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    /* write date */
    err =
        aws_pipe_write(&state->write_end, state->buffers.src, state->buffer_size, s_subscribe_on_write_complete, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_signal_error(state);
}

static int test_pipe_readable_event_sent_on_subscribe_if_data_present(struct pipe_state *state) {
    state->events.monitoring_mask = AWS_IO_EVENT_TYPE_READABLE;
    state->events.close_read_end_after_n_events = 1;

    s_schedule_write_end_task(state, s_write_once_then_subscribe_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(1, state->events.count);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_readable_event_sent_on_subscribe_if_data_present, SMALL_BUFFER_SIZE);

static void s_resubscribe_on_readable_event(struct aws_pipe_read_end *read_end, int events, void *user_data) {
    struct pipe_state *state = user_data;
    int err = 0;

    int prev_events_count = state->events.count;

    /* invoke usual readable callback so the events are logged */
    s_on_readable_event(read_end, events, user_data);
    if (state->results.status_code) { /* bail out if anything went wrong */
        return;
    }

    if ((state->events.count == 1) && (prev_events_count == 0)) {
        /* unsubscribe and resubscribe */
        err = aws_pipe_unsubscribe_from_read_events(&state->read_end);
        if (err) {
            goto error;
        }

        err = aws_pipe_subscribe_to_read_events(&state->read_end, s_on_readable_event, state);
        if (err) {
            goto error;
        }
    }

    return;
error:
    s_signal_error(state);
}

static void s_resubscribe_1_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    int err = 0;

    aws_mem_release(state->alloc, task);

    if (status == AWS_TASK_STATUS_CANCELED) {
        goto error;
    }

    /* subscribe */
    err = aws_pipe_subscribe_to_read_events(&state->read_end, s_resubscribe_on_readable_event, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_signal_error(state);
}

static void s_resubscribe_write_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    int err = 0;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    /* write date */
    err = aws_pipe_write(
        &state->write_end, state->buffers.src, state->buffer_size, s_clean_up_write_end_on_write_complete, state);
    if (err) {
        goto error;
    }

    /* schedule task for read-end to perform 1st subscribe */
    s_schedule_read_end_task(state, s_resubscribe_1_task);

    return;
error:
    s_signal_error(state);
}

static int test_pipe_readable_event_sent_on_resubscribe_if_data_present(struct pipe_state *state) {
    state->events.monitoring_mask = AWS_IO_EVENT_TYPE_READABLE;
    state->events.close_read_end_after_n_events = 2;

    s_schedule_write_end_task(state, s_resubscribe_write_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(2, state->events.count);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_readable_event_sent_on_resubscribe_if_data_present, SMALL_BUFFER_SIZE);

static void s_readall_on_write_complete(
    struct aws_pipe_write_end *write_end,
    int write_result,
    size_t num_bytes_written,
    void *user_data) {

    struct pipe_state *state = user_data;
    int err = 0;

    if (write_result) {
        goto error;
    }

    bool is_2nd_write = (state->buffers.num_bytes_written > 0);

    state->buffers.num_bytes_written += num_bytes_written;

    /* Clean up after 2nd write */
    if (is_2nd_write) {
        err = aws_pipe_clean_up_write_end(write_end);
        if (err) {
            goto error;
        }
        s_signal_done_on_write_end_closed(state);
    }

    return;
error:
    s_signal_error(state);
}

static void s_readall_write_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    int err =
        aws_pipe_write(&state->write_end, state->buffers.src, state->buffer_size, s_readall_on_write_complete, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_signal_error(state);
}

static void s_readall_on_readable(struct aws_pipe_read_end *read_end, int events, void *user_data) {
    struct pipe_state *state = user_data;
    int err = 0;

    int prev_event_count = state->events.count;

    /* invoke usual readable callback so the events are logged */
    s_on_readable_event(read_end, events, user_data);
    if (state->results.status_code) { /* bail out if anything went wrong */
        return;
    }

    if ((state->events.count == 1) && (prev_event_count == 0)) {
        /* After the first write, read data until we're told that further reads would block.
         * This ensures that the next write is sure to trigger a readable event */
        while (true) {
            size_t num_bytes_read = 0;
            err = aws_pipe_read(read_end, state->buffers.dst, state->buffer_size, &num_bytes_read);
            state->buffers.num_bytes_read += num_bytes_read;

            if (err) {
                if (aws_last_error() == AWS_IO_READ_WOULD_BLOCK) {
                    break;
                } else {
                    goto error;
                }
            }
        }

        /* Sanity check that we did in fact read something */
        if (state->buffers.num_bytes_read == 0) {
            goto error;
        }

        /* Schedule the 2nd write */
        s_schedule_write_end_task(state, s_readall_write_task);
    }

    return;
error:
    s_signal_error(state);
}

static void s_readall_subscribe_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    int err = 0;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    err = aws_pipe_subscribe_to_read_events(&state->read_end, s_readall_on_readable, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_signal_error(state);
}

/* Check that the 2nd readable event is sent again in the case of: subscribe, write 1, read all, write 2
 * Short name for test is: readall */
static int test_pipe_readable_event_sent_again_after_all_data_read(struct pipe_state *state) {
    state->events.monitoring_mask = AWS_IO_EVENT_TYPE_READABLE;
    state->events.close_read_end_after_n_events = 2;

    s_schedule_read_end_task(state, s_readall_subscribe_task);
    s_schedule_write_end_task(state, s_readall_write_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(2, state->events.count);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_readable_event_sent_again_after_all_data_read, SMALL_BUFFER_SIZE);

static void s_readsome_on_readable(struct aws_pipe_read_end *read_end, int events, void *user_data) {
    struct pipe_state *state = user_data;
    int err = 0;

    int prev_events_count = state->events.count;

    /* invoke usual readable callback so the events are logged */
    s_on_readable_event(read_end, events, user_data);
    if (state->results.status_code) {
        return; /* bail if callback signaled error */
    }

    /* if this wasn't an event we're tracking, bail */
    if (state->events.count == prev_events_count) {
        return;
    }

    if (state->events.count == 1) {
        /* After the first write, read just some of the data.
         * Further writes shouldn't trigger the readable event */
        size_t num_bytes_read = 0;
        err = aws_pipe_read(read_end, state->buffers.dst, 1, &num_bytes_read);
        state->buffers.num_bytes_read += num_bytes_read;

        if (err) {
            goto error;
        }

        /* Sanity check that we did in fact read something */
        if (state->buffers.num_bytes_read == 0) {
            goto error;
        }

        /* Schedule the 2nd write.
         * Re-use s_readall_write_task, which cleans up after its 2nd run */
        s_schedule_write_end_task(state, s_readall_write_task);

        /* Schedule a task, in the near-future, that shuts down the read-end.
         * We need the subscribed read-end to just hang out for a while to ensure no further events come in. */
        struct aws_task *task = aws_mem_acquire(state->alloc, sizeof(struct aws_task));
        if (!task) {
            goto error;
        }

        aws_task_init(task, s_clean_up_read_end_task, state);

        uint64_t task_time;
        err = aws_event_loop_current_clock_time(state->read_loop, &task_time);
        if (err) {
            goto error;
        }
        task_time += aws_timestamp_convert(2, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);

        aws_event_loop_schedule_task_future(state->read_loop, task, task_time);

    } else if (state->events.count > 1) {
        /* There should only be 1 readable event */
        goto error;
    }

    return;
error:
    s_signal_error(state);
}

static void s_readsome_subscribe_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    int err = 0;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    err = aws_pipe_subscribe_to_read_events(&state->read_end, s_readsome_on_readable, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_signal_error(state);
}

/* Test that only 1 readable event is sent in the case of: subscribe, write 1, read some but not all data, write 2.
 * Short name for test is: readsome */
static int test_pipe_readable_event_not_sent_again_until_all_data_read(struct pipe_state *state) {
    state->events.monitoring_mask = AWS_IO_EVENT_TYPE_READABLE;

    /* not setting close_read_end_after_n_events because we manually shut down read-end in this test */

    s_schedule_read_end_task(state, s_readsome_subscribe_task);

    /* re-use this write task, which shuts down the 2nd time it's run */
    s_schedule_write_end_task(state, s_readall_write_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(1, state->events.count);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_readable_event_not_sent_again_until_all_data_read, SMALL_BUFFER_SIZE);

static void s_subscribe_and_schedule_write_end_clean_up_task(
    struct aws_task *task,
    void *arg,
    enum aws_task_status status) {

    struct pipe_state *state = arg;
    int err;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    err = aws_pipe_subscribe_to_read_events(&state->read_end, s_on_readable_event, state);
    if (err) {
        goto error;
    }

    /* schedule write end to clean up */
    s_schedule_write_end_task(state, s_clean_up_write_end_task);

    return;
error:
    s_signal_error(state);
}

static int test_pipe_hangup_event_sent_after_write_end_closed(struct pipe_state *state) {
    state->events.monitoring_mask = AWS_IO_EVENT_TYPE_REMOTE_HANG_UP;
    state->events.close_read_end_after_n_events = 1;

    s_schedule_read_end_task(state, s_subscribe_and_schedule_write_end_clean_up_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(1, state->events.count);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_hangup_event_sent_after_write_end_closed, SMALL_BUFFER_SIZE);

static void s_clean_up_write_end_then_schedule_subscribe_task(
    struct aws_task *task,
    void *arg,
    enum aws_task_status status) {

    struct pipe_state *state = arg;
    int err;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    err = aws_pipe_clean_up_write_end(&state->write_end);
    if (err) {
        goto error;
    }
    s_signal_done_on_write_end_closed(state);

    s_schedule_read_end_task(state, s_subscribe_task);

    return;
error:
    s_signal_error(state);
}

static int test_pipe_hangup_event_sent_on_subscribe_if_write_end_already_closed(struct pipe_state *state) {
    state->events.monitoring_mask = AWS_IO_EVENT_TYPE_REMOTE_HANG_UP;
    state->events.close_read_end_after_n_events = 1;

    s_schedule_write_end_task(state, s_clean_up_write_end_then_schedule_subscribe_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(1, state->events.count);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_hangup_event_sent_on_subscribe_if_write_end_already_closed, SMALL_BUFFER_SIZE);

static void s_close_write_end_after_all_writes_complete(
    struct aws_pipe_write_end *write_end,
    int write_result,
    size_t num_bytes_written,
    void *user_data) {

    struct pipe_state *state = user_data;

    if (write_result) {
        goto error;
    }

    if (num_bytes_written == 0) {
        goto error;
    }

    state->buffers.num_bytes_written += num_bytes_written;

    if (state->buffers.num_bytes_written == state->buffer_size) {
        int err = aws_pipe_clean_up_write_end(write_end);
        if (err) {
            goto error;
        }
        s_signal_done_on_write_end_closed(state);
    }

    return;
error:
    s_signal_error(state);
}

static void s_write_in_simultaneous_chunks_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    int err;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    /* Write the whole buffer via several successive writes */
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(state->buffers.src, state->buffer_size);
    const size_t chunk_size = cursor.len / 8;
    while (cursor.len > 0) {
        size_t bytes_to_write = (chunk_size < cursor.len) ? chunk_size : cursor.len;

        err = aws_pipe_write(
            &state->write_end, cursor.ptr, bytes_to_write, s_close_write_end_after_all_writes_complete, state);
        if (err) {
            goto error;
        }

        aws_byte_cursor_advance(&cursor, bytes_to_write);
    }

    return;
error:
    s_signal_error(state);
}

static int test_pipe_writes_are_fifo(struct pipe_state *state) {

    s_schedule_read_end_task(state, s_read_everything_task);
    s_schedule_write_end_task(state, s_write_in_simultaneous_chunks_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_SUCCESS(s_pipe_state_check_copied_data(state));

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_writes_are_fifo, GIANT_BUFFER_SIZE);

static void s_cancelled_on_write_complete(
    struct aws_pipe_write_end *write_end,
    int write_result,
    size_t num_bytes_written,
    void *user_data) {

    (void)write_end;
    struct pipe_state *state = user_data;

    int *write_status_code = state->test_data;
    *write_status_code = write_result;

    state->buffers.num_bytes_written += num_bytes_written;

    s_schedule_read_end_task(state, s_clean_up_read_end_task);
}

static void s_write_then_clean_up_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct pipe_state *state = arg;
    int err;

    aws_mem_release(state->alloc, task);

    if (status != AWS_TASK_STATUS_RUN_READY) {
        goto error;
    }

    err =
        aws_pipe_write(&state->write_end, state->buffers.src, state->buffer_size, s_cancelled_on_write_complete, state);
    if (err) {
        goto error;
    }

    err = aws_pipe_clean_up_write_end(&state->write_end);
    if (err) {
        goto error;
    }
    s_signal_done_on_write_end_closed(state);

    return;
error:
    s_signal_error(state);
}

/* Perform an enormous write that can't possibly complete without a bit of reading.
 * After kicking off the write operation, close the write-end.
 * The write operation chould complete with a "cancelled" status */
static int test_pipe_clean_up_cancels_pending_writes(struct pipe_state *state) {
    /* capture the status code from the on-write-complete callback */
    int write_status_code = 0;
    state->test_data = &write_status_code;

    s_schedule_write_end_task(state, s_write_then_clean_up_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(AWS_ERROR_IO_OPERATION_CANCELLED, write_status_code);
    ASSERT_UINT_EQUALS(0, state->buffers.num_bytes_written);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_clean_up_cancels_pending_writes, GIANT_BUFFER_SIZE);