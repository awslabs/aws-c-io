/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/atomics.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/system_info.h>
#include <aws/common/task_scheduler.h>
#include <aws/io/event_loop.h>

#include <aws/common/thread.h>
#include <aws/testing/aws_test_harness.h>

struct task_args {
    bool invoked;
    bool was_in_thread;
    aws_thread_id_t thread_id;
    struct aws_event_loop *loop;
    struct aws_event_loop_group *el_group;
    enum aws_task_status status;
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    struct aws_atomic_var thread_complete;
};

static void s_test_task(struct aws_task *task, void *user_data, enum aws_task_status status) {
    (void)task;
    struct task_args *args = user_data;

    aws_mutex_lock(&args->mutex);
    args->thread_id = aws_thread_current_thread_id();
    args->invoked = true;
    args->status = status;
    args->was_in_thread = aws_event_loop_thread_is_callers_thread(args->loop);
    aws_mutex_unlock((&args->mutex));
    aws_condition_variable_notify_one(&args->condition_variable);
}

static bool s_task_ran_predicate(void *args) {
    struct task_args *task_args = args;
    return task_args->invoked;
}
/*
 * Test that a scheduled task from a non-event loop owned thread executes.
 */
static int s_test_event_loop_xthread_scheduled_tasks_execute(struct aws_allocator *allocator, void *ctx) {

    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct task_args task_args = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .mutex = AWS_MUTEX_INIT,
        .invoked = false,
        .was_in_thread = false,
        .status = -1,
        .loop = event_loop,
        .thread_id = 0,
    };

    struct aws_task task;
    aws_task_init(&task, s_test_task, &task_args, "xthread_scheduled_tasks_execute");

    /* Test "future" tasks */
    ASSERT_SUCCESS(aws_mutex_lock(&task_args.mutex));

    uint64_t now;
    ASSERT_SUCCESS(aws_event_loop_current_clock_time(event_loop, &now));
    aws_event_loop_schedule_task_future(event_loop, &task, now);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &task_args.condition_variable, &task_args.mutex, s_task_ran_predicate, &task_args));
    ASSERT_TRUE(task_args.invoked);
    aws_mutex_unlock(&task_args.mutex);

    ASSERT_FALSE(aws_thread_thread_id_equal(task_args.thread_id, aws_thread_current_thread_id()));

    /* Test "now" tasks */
    task_args.invoked = false;
    ASSERT_SUCCESS(aws_mutex_lock(&task_args.mutex));

    aws_event_loop_schedule_task_now(event_loop, &task);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &task_args.condition_variable, &task_args.mutex, s_task_ran_predicate, &task_args));
    ASSERT_TRUE(task_args.invoked);
    aws_mutex_unlock(&task_args.mutex);

    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(event_loop_xthread_scheduled_tasks_execute, s_test_event_loop_xthread_scheduled_tasks_execute)

static bool s_test_cancel_thread_task_predicate(void *args) {
    struct task_args *task_args = args;
    return task_args->invoked;
}
/*
 * Test that a scheduled task from a non-event loop owned thread executes.
 */
static int s_test_event_loop_canceled_tasks_run_in_el_thread(struct aws_allocator *allocator, void *ctx) {

    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct task_args task1_args = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .mutex = AWS_MUTEX_INIT,
        .invoked = false,
        .was_in_thread = false,
        .status = -1,
        .loop = event_loop,
        .thread_id = 0,
    };

    struct task_args task2_args = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .mutex = AWS_MUTEX_INIT,
        .invoked = false,
        .was_in_thread = false,
        .status = -1,
        .loop = event_loop,
        .thread_id = 0,
    };

    struct aws_task task1;
    aws_task_init(&task1, s_test_task, &task1_args, "canceled_tasks_run_in_el_thread1");
    struct aws_task task2;
    aws_task_init(&task2, s_test_task, &task2_args, "canceled_tasks_run_in_el_thread2");

    aws_event_loop_schedule_task_now(event_loop, &task1);
    uint64_t now;
    ASSERT_SUCCESS(aws_event_loop_current_clock_time(event_loop, &now));
    aws_event_loop_schedule_task_future(event_loop, &task2, now + 10000000000);

    ASSERT_FALSE(aws_event_loop_thread_is_callers_thread(event_loop));

    ASSERT_SUCCESS(aws_mutex_lock(&task1_args.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &task1_args.condition_variable, &task1_args.mutex, s_task_ran_predicate, &task1_args));
    ASSERT_TRUE(task1_args.invoked);
    ASSERT_TRUE(task1_args.was_in_thread);
    ASSERT_FALSE(aws_thread_thread_id_equal(task1_args.thread_id, aws_thread_current_thread_id()));
    ASSERT_INT_EQUALS(AWS_TASK_STATUS_RUN_READY, task1_args.status);
    aws_mutex_unlock(&task1_args.mutex);

    aws_event_loop_destroy(event_loop);

    aws_mutex_lock(&task2_args.mutex);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &task2_args.condition_variable, &task2_args.mutex, s_test_cancel_thread_task_predicate, &task2_args));
    ASSERT_TRUE(task2_args.invoked);
    aws_mutex_unlock(&task2_args.mutex);

    ASSERT_TRUE(task2_args.was_in_thread);
    ASSERT_TRUE(aws_thread_thread_id_equal(task2_args.thread_id, aws_thread_current_thread_id()));
    ASSERT_INT_EQUALS(AWS_TASK_STATUS_CANCELED, task2_args.status);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(event_loop_canceled_tasks_run_in_el_thread, s_test_event_loop_canceled_tasks_run_in_el_thread)

#if AWS_USE_IO_COMPLETION_PORTS

int aws_pipe_get_unique_name(char *dst, size_t dst_size);

/* Open read/write handles to a pipe with support for async (overlapped) read and write */
static int s_async_pipe_init(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle) {
    char pipe_name[256];
    ASSERT_SUCCESS(aws_pipe_get_unique_name(pipe_name, sizeof(pipe_name)));

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
    int status_code;
    size_t num_bytes_transferred;
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

static void s_on_overlapped_operation_complete(
    struct aws_event_loop *event_loop,
    struct aws_overlapped *overlapped,
    int status_code,
    size_t num_bytes_transferred) {

    struct overlapped_completion_data *data = overlapped->user_data;
    aws_mutex_lock(&data->mutex);
    data->event_loop = event_loop;
    data->overlapped = overlapped;
    data->status_code = status_code;
    data->num_bytes_transferred = num_bytes_transferred;
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
    bool write_success =
        WriteFile(write_handle.data.handle, msg, sizeof(msg), NULL, aws_overlapped_to_windows_overlapped(&overlapped));
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
    ASSERT_INT_EQUALS(0, completion_data.status_code); /* Check status code for I/O operation */
    ASSERT_INT_EQUALS(sizeof(msg), completion_data.num_bytes_transferred);

    /* Shut it all down */
    s_overlapped_completion_data_clean_up(&completion_data);
    s_async_pipe_clean_up(&read_handle, &write_handle);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(event_loop_completion_events, s_test_event_loop_completion_events)

#else /* !AWS_USE_IO_COMPLETION_PORTS */

#    include <unistd.h>

int aws_open_nonblocking_posix_pipe(int pipe_fds[2]);

/* Define simple pipe for testing. */
int simple_pipe_open(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle) {
    AWS_ZERO_STRUCT(*read_handle);
    AWS_ZERO_STRUCT(*write_handle);

    int pipe_fds[2];
    ASSERT_SUCCESS(aws_open_nonblocking_posix_pipe(pipe_fds));

    read_handle->data.fd = pipe_fds[0];
    write_handle->data.fd = pipe_fds[1];

    return AWS_OP_SUCCESS;
}
void simple_pipe_close(struct aws_io_handle *read_handle, struct aws_io_handle *write_handle) {
    close(read_handle->data.fd);
    close(write_handle->data.fd);
}

/* return number of bytes written */
size_t simple_pipe_write(struct aws_io_handle *handle, const uint8_t *src, size_t src_size) {
    ssize_t write_val = write(handle->data.fd, src, src_size);
    return (write_val < 0) ? 0 : write_val;
}

/* return number of bytes read */
size_t simple_pipe_read(struct aws_io_handle *handle, uint8_t *dst, size_t dst_size) {
    ssize_t read_val = read(handle->data.fd, dst, dst_size);
    return (read_val < 0) ? 0 : read_val;
}

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
void s_unsubrace_on_writable_event(
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
        size_t bytes_written = simple_pipe_write(&data->write_handle[i], buffer, 3);
        if (bytes_written == 0) {
            s_unsubrace_error(data);
            return;
        }
    }

    data->wrote_to_both_pipes = true;
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

/* Both pipes should have a readable event on the way.
 * The first pipe to get the event closes both pipes.
 * Since both pipes are unsubscribed, the second readable event shouldn't be delivered */
void s_unsubrace_on_readable_event(
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

        simple_pipe_close(&data->read_handle[i], &data->write_handle[i]);
    }

    /* Zero out the handles so that further accesses to the closed pipe are extra likely to cause crashes */
    AWS_ZERO_ARRAY(data->read_handle);
    AWS_ZERO_ARRAY(data->write_handle);

    data->is_unsubscribed = true;

    /* Have a short delay before ending test. Any events that fire during that delay would be an error. */
    uint64_t time_ns;
    err = aws_event_loop_current_clock_time(data->event_loop, &time_ns);
    if (err) {
        s_unsubrace_error(data);
        return;
    }
    time_ns += aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);

    aws_task_init(&data->task, s_unsubrace_done_task, data, "unsubrace");
    aws_event_loop_schedule_task_future(data->event_loop, &data->task, time_ns);
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
        err = simple_pipe_open(&data->read_handle[i], &data->write_handle[i]);
        if (err) {
            s_unsubrace_error(data);
            return;
        }

        err = aws_event_loop_subscribe_to_io_events(
            data->event_loop, &data->write_handle[i], AWS_IO_EVENT_TYPE_WRITABLE, s_unsubrace_on_writable_event, data);
        if (err) {
            s_unsubrace_error(data);
            return;
        }

        err = aws_event_loop_subscribe_to_io_events(
            data->event_loop, &data->read_handle[i], AWS_IO_EVENT_TYPE_READABLE, s_unsubrace_on_readable_event, data);
        if (err) {
            s_unsubrace_error(data);
            return;
        }
    }
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

    aws_task_init(&data.task, s_unsubrace_setup_task, &data, "no_events_after_unsubscribe");
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

/* For testing logic that must occur on the event-loop thread.
 * The main thread should give the tester an array of state functions (last entry should be NULL),
 * then kick off the tester and then wait for it to be done.
 * Each function should return one of:
 * - AWS_OP_SUCCESS: continue to next state function
 * - AWS_OP_ERRROR: fail the test
 * - REMAIN_IN_STATE: try this state function again next time
 */
struct thread_tester;
enum { REMAIN_IN_STATE = -2 };
typedef int(thread_tester_state_fn)(struct thread_tester *tester);

struct thread_tester {
    struct aws_allocator *alloc;
    struct aws_event_loop *event_loop;

    bool done;
    int error_code;
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;

    thread_tester_state_fn **state_functions;
    size_t current_state;
    size_t last_printed_state;

    /* data for tests */
    struct aws_io_handle read_handle;
    struct aws_io_handle write_handle;
    int read_handle_event_counts[AWS_IO_EVENT_TYPE_ERROR + 1];
    int write_handle_event_counts[AWS_IO_EVENT_TYPE_ERROR + 1];

    enum { TIMER_NOT_SET, TIMER_WAITING, TIMER_DONE } timer_state;
    struct aws_task timer_task;
};

static void s_thread_tester_abort(struct thread_tester *tester) {
    aws_mutex_lock(&tester->mutex);
    tester->error_code = AWS_OP_ERR;
    tester->done = true;
    aws_condition_variable_notify_one(&tester->condition_variable);
    aws_mutex_unlock(&tester->mutex);
}

static bool s_print_state_transitions = false; /* Set this true to print state transitions */

static void s_thread_tester_print_state(struct thread_tester *tester, const char *state_name) {
    if (tester->last_printed_state != tester->current_state) {
        if (s_print_state_transitions) {
            printf("entering state[%zu]: %s\n", tester->current_state, state_name);
        }
        tester->last_printed_state = tester->current_state;
    }
}
#    define PRINT_STATE() s_thread_tester_print_state(tester, __func__)

static void s_thread_tester_update(struct thread_tester *tester) {
    thread_tester_state_fn *current_fn;
    while (true) {
        current_fn = tester->state_functions[tester->current_state];

        if (!current_fn) {
            /* We've reached the final state, success */
            aws_mutex_lock(&tester->mutex);
            tester->error_code = AWS_OP_SUCCESS;
            tester->done = true;
            aws_condition_variable_notify_one(&tester->condition_variable);
            aws_mutex_unlock(&tester->mutex);
            return;
        }

        int err = current_fn(tester);

        if (err == AWS_OP_SUCCESS) {
            /* Go to next state, loop again */
            tester->current_state++;

        } else if (err == REMAIN_IN_STATE) {
            /* End loop, wait for update function to be invoked again */
            return;

        } else /* AWS_OP_ERR */ {
            /* End loop, end tester, end it all */
            s_thread_tester_abort(tester);
            return;
        }
    }
}

static void s_thread_tester_update_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    struct thread_tester *tester = arg;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        return s_thread_tester_abort(tester);
    }

    s_thread_tester_update(tester);
}

static bool s_thread_tester_pred(void *arg) {
    struct thread_tester *tester = arg;
    return tester->done;
}

static void s_timer_done_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    struct thread_tester *tester = arg;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        return s_thread_tester_abort(tester);
    }

    tester->timer_state = TIMER_DONE;
    s_thread_tester_update(tester);
}

static int s_thread_tester_run(struct aws_allocator *alloc, thread_tester_state_fn *state_functions[]) {

    /* Set up tester */
    struct thread_tester tester = {
        .alloc = alloc,
        .event_loop = aws_event_loop_new_default(alloc, aws_high_res_clock_get_ticks),
        .mutex = AWS_MUTEX_INIT,
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .state_functions = state_functions,
        .last_printed_state = -1,
    };

    ASSERT_NOT_NULL(tester.event_loop);
    ASSERT_SUCCESS(aws_event_loop_run(tester.event_loop));

    /* Set up data to test with */
    ASSERT_SUCCESS(simple_pipe_open(&tester.read_handle, &tester.write_handle));
    aws_task_init(&tester.timer_task, s_timer_done_task, &tester, "timer_done");

    /* Wait for tester to finish running its state functions on the event-loop thread */
    aws_mutex_lock(&tester.mutex);
    struct aws_task task;
    aws_task_init(&task, s_thread_tester_update_task, &tester, "thread_tester_update");
    aws_event_loop_schedule_task_now(tester.event_loop, &task);
    aws_condition_variable_wait_pred(&tester.condition_variable, &tester.mutex, s_thread_tester_pred, &tester);
    aws_mutex_unlock(&tester.mutex);

    /* Clean up tester*/
    aws_event_loop_destroy(tester.event_loop);

    /* Clean up data */
    simple_pipe_close(&tester.read_handle, &tester.write_handle);

    /* Return tester results */
    return tester.error_code;
}

/* Count how many times each type of event fires on the readable and writable handles */
static void s_io_event_counter(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    void *user_data) {

    (void)event_loop;
    (void)handle;
    struct thread_tester *tester = user_data;

    int *event_counts;
    if (handle == &tester->read_handle) {
        event_counts = tester->read_handle_event_counts;

    } else if (handle == &tester->write_handle) {
        event_counts = tester->write_handle_event_counts;

    } else {
        return s_thread_tester_abort(tester);
    }

    for (int flag = 1; flag <= AWS_IO_EVENT_TYPE_ERROR; flag <<= 1) {
        if (events & flag) {
            event_counts[flag] += 1;
        }
    }

    s_thread_tester_update(tester);
}

static int s_state_subscribe(struct thread_tester *tester) {
    PRINT_STATE();
    ASSERT_SUCCESS(aws_event_loop_subscribe_to_io_events(
        tester->event_loop, &tester->read_handle, AWS_IO_EVENT_TYPE_READABLE, s_io_event_counter, tester));

    ASSERT_SUCCESS(aws_event_loop_subscribe_to_io_events(
        tester->event_loop, &tester->write_handle, AWS_IO_EVENT_TYPE_WRITABLE, s_io_event_counter, tester));

    return AWS_OP_SUCCESS;
}

static int s_state_unsubscribe(struct thread_tester *tester) {
    PRINT_STATE();
    ASSERT_SUCCESS(aws_event_loop_unsubscribe_from_io_events(tester->event_loop, &tester->read_handle));
    ASSERT_SUCCESS(aws_event_loop_unsubscribe_from_io_events(tester->event_loop, &tester->write_handle));
    return AWS_OP_SUCCESS;
}

/* Remain in state until readable event fires, then reset readable event count and proceed to next state */
static int s_state_on_readable(struct thread_tester *tester) {
    PRINT_STATE();

    if (tester->read_handle_event_counts[AWS_IO_EVENT_TYPE_READABLE] == 0) {
        return REMAIN_IN_STATE;
    }

    ASSERT_UINT_EQUALS(1, tester->read_handle_event_counts[AWS_IO_EVENT_TYPE_READABLE]);

    tester->read_handle_event_counts[AWS_IO_EVENT_TYPE_READABLE] = 0;
    return AWS_OP_SUCCESS;
}

/* Remain in state until writable event fires, then reset writable event count and proceed to next state. */
static int s_state_on_writable(struct thread_tester *tester) {
    PRINT_STATE();

    if (tester->write_handle_event_counts[AWS_IO_EVENT_TYPE_WRITABLE] == 0) {
        return REMAIN_IN_STATE;
    }

    ASSERT_UINT_EQUALS(1, tester->write_handle_event_counts[AWS_IO_EVENT_TYPE_WRITABLE]);

    tester->write_handle_event_counts[AWS_IO_EVENT_TYPE_WRITABLE] = 0;
    return AWS_OP_SUCCESS;
}

static int s_state_fail_if_more_readable_events(struct thread_tester *tester) {
    PRINT_STATE();
    ASSERT_INT_EQUALS(0, tester->read_handle_event_counts[AWS_IO_EVENT_TYPE_READABLE]);

    return AWS_OP_SUCCESS;
}

static int s_state_fail_if_more_writable_events(struct thread_tester *tester) {
    PRINT_STATE();
    ASSERT_INT_EQUALS(0, tester->write_handle_event_counts[AWS_IO_EVENT_TYPE_WRITABLE]);

    return AWS_OP_SUCCESS;
}

/* Write some data to the pipe */
static int s_state_write_data(struct thread_tester *tester) {
    PRINT_STATE();

    const uint8_t data_to_copy[] = "abcdefghijklmnopqrstuvwxyz";
    size_t num_bytes_written = simple_pipe_write(&tester->write_handle, data_to_copy, sizeof(data_to_copy));
    ASSERT_UINT_EQUALS(sizeof(data_to_copy), num_bytes_written);

    return AWS_OP_SUCCESS;
}

/* Read from pipe until no data remains */
static int s_state_read_until_blocked(struct thread_tester *tester) {
    PRINT_STATE();

    uint8_t buffer[512];
    while (simple_pipe_read(&tester->read_handle, buffer, sizeof(buffer)) > 0) {
    }

    return AWS_OP_SUCCESS;
}

/* Entering the state starts a timer, and we remain in this state until the time completes */
static int s_state_wait_1sec(struct thread_tester *tester) {
    PRINT_STATE();
    uint64_t time_ns;
    switch (tester->timer_state) {
        case TIMER_NOT_SET:
            time_ns = 0;
            ASSERT_SUCCESS(aws_event_loop_current_clock_time(tester->event_loop, &time_ns));
            time_ns += aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
            aws_event_loop_schedule_task_future(tester->event_loop, &tester->timer_task, time_ns);

            tester->timer_state = TIMER_WAITING;
            return REMAIN_IN_STATE;

        case TIMER_WAITING:
            return REMAIN_IN_STATE;

        default:
            ASSERT_INT_EQUALS(TIMER_DONE, tester->timer_state);
            return AWS_OP_SUCCESS;
    }
}

/* Test that subscribe/unubscribe work at all */
static int s_test_event_loop_subscribe_unsubscribe(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    thread_tester_state_fn *state_functions[] = {
        s_state_subscribe,
        s_state_unsubscribe,
        NULL,
    };

    ASSERT_SUCCESS(s_thread_tester_run(allocator, state_functions));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(event_loop_subscribe_unsubscribe, s_test_event_loop_subscribe_unsubscribe)

static int s_test_event_loop_writable_event_on_subscribe(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    thread_tester_state_fn *state_functions[] = {
        s_state_subscribe,
        s_state_on_writable,
        s_state_wait_1sec,
        s_state_fail_if_more_writable_events,
        s_state_unsubscribe,
        NULL,
    };

    ASSERT_SUCCESS(s_thread_tester_run(allocator, state_functions));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(event_loop_writable_event_on_subscribe, s_test_event_loop_writable_event_on_subscribe)

static int s_test_event_loop_no_readable_event_before_write(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    thread_tester_state_fn *state_functions[] = {
        s_state_subscribe,
        s_state_wait_1sec,
        s_state_fail_if_more_readable_events,
        s_state_unsubscribe,
        NULL,
    };

    ASSERT_SUCCESS(s_thread_tester_run(allocator, state_functions));
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(event_loop_no_readable_event_before_write, s_test_event_loop_no_readable_event_before_write);

static int s_test_event_loop_readable_event_on_subscribe_if_data_present(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    thread_tester_state_fn *state_functions[] = {
        s_state_write_data,
        s_state_subscribe,
        s_state_on_readable,
        s_state_wait_1sec,
        s_state_fail_if_more_readable_events,
        s_state_unsubscribe,
        NULL,
    };

    ASSERT_SUCCESS(s_thread_tester_run(allocator, state_functions));
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(
    event_loop_readable_event_on_subscribe_if_data_present,
    s_test_event_loop_readable_event_on_subscribe_if_data_present);

static int s_test_event_loop_readable_event_after_write(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    thread_tester_state_fn *state_functions[] = {
        s_state_subscribe,
        s_state_on_writable,
        s_state_write_data,
        s_state_on_readable,
        s_state_wait_1sec,
        s_state_fail_if_more_readable_events,
        s_state_unsubscribe,
        NULL,
    };

    ASSERT_SUCCESS(s_thread_tester_run(allocator, state_functions));
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(event_loop_readable_event_after_write, s_test_event_loop_readable_event_after_write);

static int s_test_event_loop_readable_event_on_2nd_time_readable(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    thread_tester_state_fn *state_functions[] = {
        s_state_subscribe,
        s_state_on_writable,
        s_state_write_data,
        s_state_on_readable,
        s_state_read_until_blocked,
        s_state_write_data,
        s_state_on_readable,
        s_state_unsubscribe,
        NULL,
    };

    ASSERT_SUCCESS(s_thread_tester_run(allocator, state_functions));
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(event_loop_readable_event_on_2nd_time_readable, s_test_event_loop_readable_event_on_2nd_time_readable);

#endif /* AWS_USE_IO_COMPLETION_PORTS */

static int s_event_loop_test_stop_then_restart(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct task_args task_args = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .mutex = AWS_MUTEX_INIT,
        .invoked = false,
        .was_in_thread = false,
        .status = -1,
        .loop = event_loop,
        .thread_id = 0,
    };

    struct aws_task task;
    aws_task_init(&task, s_test_task, &task_args, "stop_then_restart");

    ASSERT_SUCCESS(aws_mutex_lock(&task_args.mutex));

    aws_event_loop_schedule_task_now(event_loop, &task);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &task_args.condition_variable, &task_args.mutex, s_task_ran_predicate, &task_args));
    ASSERT_TRUE(task_args.invoked);

    ASSERT_SUCCESS(aws_event_loop_stop(event_loop));
    ASSERT_SUCCESS(aws_event_loop_wait_for_stop_completion(event_loop));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    aws_event_loop_schedule_task_now(event_loop, &task);

    task_args.invoked = false;
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &task_args.condition_variable, &task_args.mutex, s_task_ran_predicate, &task_args));
    ASSERT_TRUE(task_args.invoked);

    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(event_loop_stop_then_restart, s_event_loop_test_stop_then_restart)

static int s_event_loop_test_multiple_stops(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));
    for (int i = 0; i < 8; ++i) {
        ASSERT_SUCCESS(aws_event_loop_stop(event_loop));
    }
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(event_loop_multiple_stops, s_event_loop_test_multiple_stops)

static int test_event_loop_group_setup_and_shutdown(struct aws_allocator *allocator, void *ctx) {

    (void)ctx;
    aws_io_library_init(allocator);

    struct aws_event_loop_group *event_loop_group = aws_event_loop_group_new_default(allocator, 0, NULL);

    size_t cpu_count = aws_system_info_processor_count();
    size_t el_count = aws_event_loop_group_get_loop_count(event_loop_group);

    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(event_loop_group);
    ASSERT_NOT_NULL(event_loop);

    if (cpu_count > 1) {
        ASSERT_INT_EQUALS(cpu_count / 2, el_count);
    }

    if (cpu_count > 1) {
        ASSERT_INT_EQUALS(cpu_count / 2, el_count);
    }

    aws_event_loop_group_release(event_loop_group);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(event_loop_group_setup_and_shutdown, test_event_loop_group_setup_and_shutdown)

static int test_numa_aware_event_loop_group_setup_and_shutdown(struct aws_allocator *allocator, void *ctx) {

    (void)ctx;
    aws_io_library_init(allocator);

    size_t cpus_for_group = aws_get_cpu_count_for_group(0);
    size_t el_count = 1;

    /* pass UINT16_MAX here to check the boundary conditions on numa cpu detection. It should never create more threads
     * than hw cpus available */
    struct aws_event_loop_group *event_loop_group =
        aws_event_loop_group_new_default_pinned_to_cpu_group(allocator, UINT16_MAX, 0, NULL);

    el_count = aws_event_loop_group_get_loop_count(event_loop_group);

    size_t hw_thread_count = 0;
    struct aws_cpu_info *cpu_info = aws_mem_calloc(allocator, cpus_for_group, sizeof(struct aws_cpu_info));
    ASSERT_NOT_NULL(cpu_info);

    aws_get_cpu_ids_for_group(0, cpu_info, cpus_for_group);

    for (size_t i = 0; i < cpus_for_group; ++i) {
        if (!cpu_info[i].suspected_hyper_thread) {
            hw_thread_count++;
        }
    }

    aws_mem_release(allocator, cpu_info);

    ASSERT_INT_EQUALS(hw_thread_count, el_count);

    aws_event_loop_group_release(event_loop_group);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(numa_aware_event_loop_group_setup_and_shutdown, test_numa_aware_event_loop_group_setup_and_shutdown)

static void s_async_shutdown_complete_callback(void *user_data) {

    struct task_args *args = user_data;

    aws_mutex_lock(&args->mutex);
    args->thread_id = aws_thread_current_thread_id();
    args->invoked = true;
    aws_mutex_unlock((&args->mutex));
    aws_atomic_store_int(&args->thread_complete, true);
    aws_condition_variable_notify_one(&args->condition_variable);
}

static void s_async_shutdown_task(struct aws_task *task, void *user_data, enum aws_task_status status) {
    (void)task;
    (void)status;

    struct aws_event_loop_group *el_group = user_data;

    aws_event_loop_group_release(el_group);
}

static int test_event_loop_group_setup_and_shutdown_async(struct aws_allocator *allocator, void *ctx) {

    (void)ctx;

    aws_io_library_init(allocator);

    /*
     * Small chicken-and-egg problem here: the task args needs the event loop group and loop, but
     * creating the event loop group needs shutdown options that refer to the task args.
     */
    struct task_args task_args = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .mutex = AWS_MUTEX_INIT,
        .invoked = false,
        .was_in_thread = false,
        .status = -1,
        .loop = NULL,
        .el_group = NULL,
        .thread_id = 0,
    };
    aws_atomic_init_int(&task_args.thread_complete, false);

    struct aws_shutdown_callback_options async_shutdown_options;
    AWS_ZERO_STRUCT(async_shutdown_options);
    async_shutdown_options.shutdown_callback_user_data = &task_args;
    async_shutdown_options.shutdown_callback_fn = s_async_shutdown_complete_callback;

    struct aws_event_loop_group *event_loop_group =
        aws_event_loop_group_new_default(allocator, 0, &async_shutdown_options);

    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(event_loop_group);

    task_args.loop = event_loop;
    task_args.el_group = event_loop_group;

    struct aws_task task;
    aws_task_init(
        &task, s_async_shutdown_task, event_loop_group, "async elg shutdown invoked from an event loop thread");

    /* Test "future" tasks */
    uint64_t now;
    ASSERT_SUCCESS(aws_event_loop_current_clock_time(event_loop, &now));
    aws_event_loop_schedule_task_future(event_loop, &task, now);

    ASSERT_SUCCESS(aws_mutex_lock(&task_args.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &task_args.condition_variable, &task_args.mutex, s_task_ran_predicate, &task_args));
    ASSERT_TRUE(task_args.invoked);
    aws_mutex_unlock(&task_args.mutex);

    while (!aws_atomic_load_int(&task_args.thread_complete)) {
        aws_thread_current_sleep(15);
    }

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(event_loop_group_setup_and_shutdown_async, test_event_loop_group_setup_and_shutdown_async)
