/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
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
        struct aws_byte_buf src;
        struct aws_byte_buf dst;
        size_t num_bytes_written;
    } buffers;

    struct {
        int error_code_to_monitor;         /* By default, monitors AWS_ERROR_SUCCESS aka normal readable events */
        int count;                         /* count of events that we're monitoring */
        int close_read_end_after_n_events; /* if set, close read-end when count reaches N */
    } readable_events;

    void *test_data; /* If a test needs special data */
};

static int s_fixture_before(struct aws_allocator *allocator, void *ctx) {
    struct pipe_state *state = ctx;
    state->alloc = allocator;

    state->read_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);
    ASSERT_NOT_NULL(state->read_loop);
    ASSERT_SUCCESS(aws_event_loop_run(state->read_loop));

    if (state->loop_setup == DIFFERENT_EVENT_LOOPS) {
        state->write_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);
        ASSERT_NOT_NULL(state->write_loop);

        ASSERT_SUCCESS(aws_event_loop_run(state->write_loop));
    } else {
        state->write_loop = state->read_loop;
    }

    ASSERT_SUCCESS(aws_pipe_init(&state->read_end, state->read_loop, &state->write_end, state->write_loop, allocator));

    ASSERT_SUCCESS(aws_mutex_init(&state->results.mutex));

    ASSERT_SUCCESS(aws_condition_variable_init(&state->results.condvar));

    if (state->buffer_size > 0) {
        /* Create full src buffer, containing random content */
        ASSERT_SUCCESS(aws_byte_buf_init(&state->buffers.src, allocator, state->buffer_size));

        state->buffers.src.len = state->buffer_size;
        for (size_t i = 0; i < state->buffer_size; ++i) {
            state->buffers.src.buffer[i] = (uint8_t)(rand() % 256);
        }

        /* Create empty dst buffer, with zeroed out content */
        ASSERT_SUCCESS(aws_byte_buf_init(&state->buffers.dst, allocator, state->buffer_size));

        memset(state->buffers.dst.buffer, 0, state->buffers.dst.capacity);
    }

    return AWS_OP_SUCCESS;
}

/* Assumes the pipe's read-end and write-end are already cleaned up */
static int s_fixture_after(struct aws_allocator *allocator, int setup_res, void *ctx) {
    (void)allocator;
    (void)setup_res;

    struct pipe_state *state = ctx;

    aws_condition_variable_clean_up(&state->results.condvar);
    aws_mutex_clean_up(&state->results.mutex);

    if (state->read_loop) {
        aws_event_loop_destroy(state->read_loop);
    }

    if (state->write_loop != state->read_loop) {
        aws_event_loop_destroy(state->write_loop);
    }

    aws_byte_buf_clean_up(&state->buffers.src);
    aws_byte_buf_clean_up(&state->buffers.dst);

    AWS_ZERO_STRUCT(*state);

    return AWS_OP_SUCCESS;
}

/* Macro for declaring pipe tests.
 * Add pipe tests to CMakeLists.txt like so: add_pipe_test_case(NAME)
 *
 * Each pipe test is run in 2 different configurations:
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
    ASSERT_TRUE(aws_byte_buf_eq(&state->buffers.src, &state->buffers.dst));
    return AWS_OP_SUCCESS;
}

/* Use as "simplified" task functions in pipe_state tasks.
 * The boilerplate of task scheduling and error-checking are handled by wrapper functions */
typedef void(pipe_state_task_fn)(struct pipe_state *state);

struct pipe_state_task_wrapper {
    struct aws_task task;
    struct pipe_state *state;
    pipe_state_task_fn *wrapped_fn;
};

static void s_pipe_state_task_wrapper_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    struct pipe_state_task_wrapper *wrapper = arg;
    struct pipe_state *state = wrapper->state;
    pipe_state_task_fn *wrapped_fn = wrapper->wrapped_fn;

    aws_mem_release(state->alloc, wrapper);

    if (status == AWS_TASK_STATUS_RUN_READY) {
        wrapped_fn(state);
    } else {
        s_signal_error(state);
    }
}

/* Schedules a pipe_state_task_fn */
static void s_schedule_task(
    struct pipe_state *state,
    struct aws_event_loop *loop,
    pipe_state_task_fn *fn,
    int delay_secs) {

    struct pipe_state_task_wrapper *wrapper = aws_mem_acquire(state->alloc, sizeof(struct pipe_state_task_wrapper));
    if (!wrapper) {
        goto error;
    }

    aws_task_init(&wrapper->task, s_pipe_state_task_wrapper_fn, wrapper, "pipe_state");
    wrapper->wrapped_fn = fn;
    wrapper->state = state;

    if (delay_secs == 0) {
        aws_event_loop_schedule_task_now(loop, &wrapper->task);
    } else {
        uint64_t run_at_ns;
        int err = aws_event_loop_current_clock_time(loop, &run_at_ns);
        if (err) {
            goto error;
        }
        run_at_ns += aws_timestamp_convert((uint64_t)delay_secs, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);

        aws_event_loop_schedule_task_future(loop, &wrapper->task, run_at_ns);
    }

    return;
error:
    s_signal_error(state);
}

static void s_schedule_read_end_task(struct pipe_state *state, pipe_state_task_fn *fn) {
    s_schedule_task(state, state->read_loop, fn, 0);
}

static void s_schedule_write_end_task(struct pipe_state *state, pipe_state_task_fn *fn) {
    s_schedule_task(state, state->write_loop, fn, 0);
}

/* wait for pipe_state to indicate that it's done */
static int s_wait_for_results(struct pipe_state *state) {
    ASSERT_SUCCESS(aws_mutex_lock(&state->results.mutex));
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&state->results.condvar, &state->results.mutex, s_done_pred, state));
    ASSERT_SUCCESS(aws_mutex_unlock(&state->results.mutex));

    return state->results.status_code;
}

static void s_clean_up_read_end_task(struct pipe_state *state) {
    int err = aws_pipe_clean_up_read_end(&state->read_end);
    if (err) {
        goto error;
    }

    s_signal_done_on_read_end_closed(state);
    return;

error:
    s_signal_error(state);
}

static void s_clean_up_write_end_task(struct pipe_state *state) {
    int err = aws_pipe_clean_up_write_end(&state->write_end);
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

void s_clean_up_write_end_on_write_completed(
    struct aws_pipe_write_end *write_end,
    int error_code,
    struct aws_byte_cursor src_buffer,
    void *user_data) {

    struct pipe_state *state = user_data;

    if (!error_code) {
        state->buffers.num_bytes_written += src_buffer.len;
    }

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
static void s_write_once_task(struct pipe_state *state) {
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&state->buffers.src);
    int err = aws_pipe_write(&state->write_end, cursor, s_clean_up_write_end_on_write_completed, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_signal_error(state);
}

/* Task tries to read as much data as possible.
 * Task repeatedly reschedules itself until read-buffer is full, then it cleans up the read-end */
static void s_read_everything_task(struct pipe_state *state) {
    int err = aws_pipe_read(&state->read_end, &state->buffers.dst, NULL);

    /* AWS_IO_READ_WOULD_BLOCK is an acceptable error, it just means the data's not ready yet */
    if (err && (aws_last_error() != AWS_IO_READ_WOULD_BLOCK)) {
        goto error;
    }

    if (state->buffers.dst.len < state->buffers.dst.capacity) {
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

static void s_on_readable_event(struct aws_pipe_read_end *read_end, int error_code, void *user_data) {

    struct pipe_state *state = user_data;

    if (error_code == state->readable_events.error_code_to_monitor) {
        state->readable_events.count++;

        if (state->readable_events.count == state->readable_events.close_read_end_after_n_events) {
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

static void s_subscribe_task(struct pipe_state *state) {
    int err = aws_pipe_subscribe_to_readable_events(&state->read_end, s_on_readable_event, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_signal_error(state);
}

static int test_pipe_readable_event_sent_after_write(struct pipe_state *state) {
    state->readable_events.error_code_to_monitor = AWS_ERROR_SUCCESS;
    state->readable_events.close_read_end_after_n_events = 1;

    s_schedule_read_end_task(state, s_subscribe_task);
    s_schedule_write_end_task(state, s_write_once_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(1, state->readable_events.count);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_readable_event_sent_after_write, SMALL_BUFFER_SIZE);

static void s_sentonce_on_readable_event(struct aws_pipe_read_end *read_end, int events, void *user_data) {
    struct pipe_state *state = user_data;

    int prev_events_count = state->readable_events.count;

    /* invoke usual readable callback so the events are logged */
    s_on_readable_event(read_end, events, user_data);
    if (state->results.status_code) { /* bail out if anything went wrong */
        return;
    }

    /* when the 1st readable event comes in, schedule task to close read-end after waiting a bit.
     * this lets us observe any further events that might come in */
    if ((state->readable_events.count == 1) && (prev_events_count == 0)) {
        s_schedule_task(state, state->read_loop, s_clean_up_read_end_task, 1 /*delay*/);
    }
}

static void s_sentonce_subscribe_task(struct pipe_state *state) {
    int err = aws_pipe_subscribe_to_readable_events(&state->read_end, s_sentonce_on_readable_event, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_signal_error(state);
}

/* Check that readable event is only sent once after a write.
 * Short name for test is: sentonce */
static int test_pipe_readable_event_sent_once(struct pipe_state *state) {
    state->readable_events.error_code_to_monitor = AWS_ERROR_SUCCESS;

    s_schedule_read_end_task(state, s_sentonce_subscribe_task);
    s_schedule_write_end_task(state, s_write_once_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    /* Accept 1 or 2 events. Epoll notifies about "readable" when sending "write end closed" event.
     * That's fine, we just don't want dozens of readable events to have come in. */
    ASSERT_TRUE(state->readable_events.count <= 2);

    return AWS_OP_SUCCESS;
}
PIPE_TEST_CASE(pipe_readable_event_sent_once, SMALL_BUFFER_SIZE);

void s_subscribe_on_write_completed(
    struct aws_pipe_write_end *write_end,
    int error_code,
    struct aws_byte_cursor src_buffer,
    void *user_data) {

    struct pipe_state *state = user_data;

    if (!error_code) {
        state->buffers.num_bytes_written += src_buffer.len;
    }

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
static void s_write_once_then_subscribe_task(struct pipe_state *state) {
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&state->buffers.src);
    int err = aws_pipe_write(&state->write_end, cursor, s_subscribe_on_write_completed, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_signal_error(state);
}

static int test_pipe_readable_event_sent_on_subscribe_if_data_present(struct pipe_state *state) {
    state->readable_events.error_code_to_monitor = AWS_ERROR_SUCCESS;
    state->readable_events.close_read_end_after_n_events = 1;

    s_schedule_write_end_task(state, s_write_once_then_subscribe_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(1, state->readable_events.count);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_readable_event_sent_on_subscribe_if_data_present, SMALL_BUFFER_SIZE);

static void s_resubscribe_on_readable_event(struct aws_pipe_read_end *read_end, int events, void *user_data) {
    struct pipe_state *state = user_data;
    int err = 0;

    int prev_events_count = state->readable_events.count;

    /* invoke usual readable callback so the events are logged */
    s_on_readable_event(read_end, events, user_data);
    if (state->results.status_code) { /* bail out if anything went wrong */
        return;
    }

    if ((state->readable_events.count == 1) && (prev_events_count == 0)) {
        /* unsubscribe and resubscribe */
        err = aws_pipe_unsubscribe_from_readable_events(&state->read_end);
        if (err) {
            goto error;
        }

        err = aws_pipe_subscribe_to_readable_events(&state->read_end, s_on_readable_event, state);
        if (err) {
            goto error;
        }
    }

    return;
error:
    s_signal_error(state);
}

static void s_resubscribe_1_task(struct pipe_state *state) {
    int err = aws_pipe_subscribe_to_readable_events(&state->read_end, s_resubscribe_on_readable_event, state);
    if (err) {
        goto error;
    }

    return;
error:
    s_signal_error(state);
}

static void s_resubscribe_write_task(struct pipe_state *state) {
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&state->buffers.src);
    int err = aws_pipe_write(&state->write_end, cursor, s_clean_up_write_end_on_write_completed, state);
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
    state->readable_events.error_code_to_monitor = AWS_ERROR_SUCCESS;
    state->readable_events.close_read_end_after_n_events = 2;

    s_schedule_write_end_task(state, s_resubscribe_write_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(2, state->readable_events.count);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_readable_event_sent_on_resubscribe_if_data_present, SMALL_BUFFER_SIZE);

static void s_readall_on_write_completed(
    struct aws_pipe_write_end *write_end,
    int error_code,
    struct aws_byte_cursor src_buffer,
    void *user_data) {

    struct pipe_state *state = user_data;
    int err = 0;

    if (error_code) {
        goto error;
    }

    bool is_2nd_write = (state->buffers.num_bytes_written > 0);

    state->buffers.num_bytes_written += src_buffer.len;

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

static void s_readall_write_task(struct pipe_state *state) {
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&state->buffers.src);
    int err = aws_pipe_write(&state->write_end, cursor, s_readall_on_write_completed, state);
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

    int prev_event_count = state->readable_events.count;

    /* invoke usual readable callback so the events are logged */
    s_on_readable_event(read_end, events, user_data);
    if (state->results.status_code) { /* bail out if anything went wrong */
        return;
    }

    if ((state->readable_events.count == 1) && (prev_event_count == 0)) {
        size_t total_bytes_read = 0;

        /* After the first write, read data until we're told that further reads would block.
         * This ensures that the next write is sure to trigger a readable event */
        while (true) {
            state->buffers.dst.len = 0;
            err = aws_pipe_read(read_end, &state->buffers.dst, NULL);
            total_bytes_read += state->buffers.dst.len;

            if (err) {
                if (aws_last_error() == AWS_IO_READ_WOULD_BLOCK) {
                    break;
                }
                goto error;
            }
        }

        /* Sanity check that we did in fact read something */
        if (total_bytes_read == 0) {
            goto error;
        }

        /* Schedule the 2nd write */
        s_schedule_write_end_task(state, s_readall_write_task);
    }

    return;
error:
    s_signal_error(state);
}

static void s_readall_subscribe_task(struct pipe_state *state) {
    int err = aws_pipe_subscribe_to_readable_events(&state->read_end, s_readall_on_readable, state);
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
    state->readable_events.error_code_to_monitor = AWS_ERROR_SUCCESS;
    state->readable_events.close_read_end_after_n_events = 2;

    s_schedule_read_end_task(state, s_readall_subscribe_task);
    s_schedule_write_end_task(state, s_readall_write_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(2, state->readable_events.count);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_readable_event_sent_again_after_all_data_read, SMALL_BUFFER_SIZE);

static void s_subscribe_and_schedule_write_end_clean_up_task(struct pipe_state *state) {
    int err = aws_pipe_subscribe_to_readable_events(&state->read_end, s_on_readable_event, state);
    if (err) {
        goto error;
    }

    /* schedule write end to clean up */
    s_schedule_write_end_task(state, s_clean_up_write_end_task);

    return;
error:
    s_signal_error(state);
}

static int test_pipe_error_event_sent_after_write_end_closed(struct pipe_state *state) {
    state->readable_events.error_code_to_monitor = AWS_IO_BROKEN_PIPE;
    state->readable_events.close_read_end_after_n_events = 1;

    s_schedule_read_end_task(state, s_subscribe_and_schedule_write_end_clean_up_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(1, state->readable_events.count);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_error_event_sent_after_write_end_closed, SMALL_BUFFER_SIZE);

static void s_clean_up_write_end_then_schedule_subscribe_task(struct pipe_state *state) {
    int err = aws_pipe_clean_up_write_end(&state->write_end);
    if (err) {
        goto error;
    }
    s_signal_done_on_write_end_closed(state);

    s_schedule_read_end_task(state, s_subscribe_task);

    return;
error:
    s_signal_error(state);
}

static int test_pipe_error_event_sent_on_subscribe_if_write_end_already_closed(struct pipe_state *state) {
    state->readable_events.error_code_to_monitor = AWS_IO_BROKEN_PIPE;
    state->readable_events.close_read_end_after_n_events = 1;

    s_schedule_write_end_task(state, s_clean_up_write_end_then_schedule_subscribe_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(1, state->readable_events.count);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_error_event_sent_on_subscribe_if_write_end_already_closed, SMALL_BUFFER_SIZE);

static void s_close_write_end_after_all_writes_completed(
    struct aws_pipe_write_end *write_end,
    int error_code,
    struct aws_byte_cursor src_buffer,
    void *user_data) {

    struct pipe_state *state = user_data;

    if (error_code) {
        goto error;
    }

    state->buffers.num_bytes_written += src_buffer.len;

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

static void s_write_in_simultaneous_chunks_task(struct pipe_state *state) {
    /* Write the whole buffer via several successive writes */
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&state->buffers.src);
    const size_t chunk_size = cursor.len / 8;
    while (cursor.len > 0) {
        size_t bytes_to_write = (chunk_size < cursor.len) ? chunk_size : cursor.len;
        struct aws_byte_cursor chunk_cursor = aws_byte_cursor_from_array(cursor.ptr, bytes_to_write);

        int err = aws_pipe_write(&state->write_end, chunk_cursor, s_close_write_end_after_all_writes_completed, state);
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

static void s_cancelled_on_write_completed(
    struct aws_pipe_write_end *write_end,
    int error_code,
    struct aws_byte_cursor src_buffer,
    void *user_data) {

    (void)write_end;
    struct pipe_state *state = user_data;

    int *write_status_code = state->test_data;
    *write_status_code = error_code;

    if (!error_code) {
        state->buffers.num_bytes_written += src_buffer.len;
    }

    s_schedule_read_end_task(state, s_clean_up_read_end_task);
}

static void s_write_then_clean_up_task(struct pipe_state *state) {
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&state->buffers.src);
    int err = aws_pipe_write(&state->write_end, cursor, s_cancelled_on_write_completed, state);
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
 * The write operation chould complete with an error status */
static int test_pipe_clean_up_cancels_pending_writes(struct pipe_state *state) {
    /* capture the status code from the on-write-complete callback */
    int write_status_code = 0;
    state->test_data = &write_status_code;

    s_schedule_write_end_task(state, s_write_then_clean_up_task);

    ASSERT_SUCCESS(s_wait_for_results(state));

    ASSERT_INT_EQUALS(AWS_IO_BROKEN_PIPE, write_status_code);
    ASSERT_TRUE(state->buffers.num_bytes_written < state->buffer_size);

    return AWS_OP_SUCCESS;
}

PIPE_TEST_CASE(pipe_clean_up_cancels_pending_writes, GIANT_BUFFER_SIZE);
