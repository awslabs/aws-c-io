/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifdef AWS_USE_APPLE_NETWORK_FRAMEWORK

#    include <Block.h>
#    include <Network/Network.h>
#    include <aws/testing/aws_test_harness.h>

/* Compile a private copy of the implementation so these tests can control asynchronous sends and connection state
 * changes without exposing test hooks in the library. The real dispatch event loop and socket reference counts run
 * normally. An unstarted Network.framework connection supplies the native object's ownership, but never uses a network.
 */
static void s_mock_connection_send(
    nw_connection_t connection,
    dispatch_data_t content,
    nw_content_context_t context,
    bool is_complete,
    nw_connection_send_completion_t completion);
static void s_mock_connection_cancel(nw_connection_t connection);

#    define aws_socket_init_apple_nw_socket s_test_socket_init
#    define nw_connection_send s_mock_connection_send
#    define nw_connection_cancel s_mock_connection_cancel
#    include "../source/darwin/nw_socket.c"
#    undef nw_connection_cancel
#    undef nw_connection_send
#    undef aws_socket_init_apple_nw_socket

enum close_test_order {
    FAILURE_THEN_CLOSE,
    CLOSE_THEN_FAILURE,
    PARTIAL_WRITE_THEN_FAILURE,
    GRACEFUL_CLOSE,
    WAITING_ERROR_THEN_CLOSE,
    FAILURE_WITHOUT_ERROR_THEN_CLOSE,
};

struct close_test {
    struct aws_allocator *allocator;
    struct aws_event_loop *event_loop;
    struct aws_task start_task;
    struct aws_task cancel_task;
    struct aws_task recover_task;
    struct aws_socket socket;
    struct nw_socket *nw_socket;
    enum close_test_order order;
    nw_connection_send_completion_t sends[3];
    size_t send_count;
    size_t cancel_count;
    size_t write_count;
    size_t close_count;
    size_t cleanup_count;
    const char *failure;
    struct aws_mutex mutex;
    struct aws_condition_variable signal;
    bool cleaned_up;
    bool recovered;
};

/* Only one fixture runs at a time; all accesses to its socket and mock state run on its dispatch event loop. */
static struct close_test *s_close_test;

#    define CHECK_CLOSE_TEST(test, condition)                                                                          \
        do {                                                                                                           \
            if (!(condition) && !(test)->failure) {                                                                    \
                (test)->failure = #condition;                                                                          \
            }                                                                                                          \
        } while (0)

static void s_complete_send(struct close_test *test, size_t index) {
    nw_connection_send_completion_t completion = test->sends[index];
    if (completion) {
        test->sends[index] = NULL;
        /* There is no public constructor for nw_error_t. Failure is injected through the state task below; these
         * completions exercise the production send-reference release regardless of the completion's error value. */
        completion(NULL);
        Block_release(completion);
    }
}

static void s_cancel_test_connection(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct close_test *test = arg;
    for (size_t i = 0; i < test->send_count; ++i) {
        s_complete_send(test, i);
    }
    /* Network.framework completes outstanding sends before its final cancelled state callback. */
    s_handle_connection_state_changed_fn(
        test->nw_socket, test->nw_socket->os_handle.nw_connection, nw_connection_state_cancelled, NULL);
}

static void s_mock_connection_send(
    nw_connection_t connection,
    dispatch_data_t content,
    nw_content_context_t context,
    bool is_complete,
    nw_connection_send_completion_t completion) {
    (void)content;
    (void)context;
    (void)is_complete;
    struct close_test *test = s_close_test;
    AWS_FATAL_ASSERT(connection == test->nw_socket->os_handle.nw_connection);
    AWS_FATAL_ASSERT(test->send_count < AWS_ARRAY_SIZE(test->sends));
    test->sends[test->send_count++] = Block_copy(completion);
}

static void s_mock_connection_cancel(nw_connection_t connection) {
    struct close_test *test = s_close_test;
    AWS_FATAL_ASSERT(connection == test->nw_socket->os_handle.nw_connection);
    if (++test->cancel_count == 1) {
        aws_task_init(&test->cancel_task, s_cancel_test_connection, test, "MockConnectionCancel");
        aws_event_loop_schedule_task_now(test->event_loop, &test->cancel_task);
    }
}

static void s_test_written(struct aws_socket *socket, int error, size_t written, void *arg) {
    (void)socket;
    (void)error;
    struct close_test *test = arg;
    CHECK_CLOSE_TEST(test, written == 1);
    CHECK_CLOSE_TEST(test, test->close_count == 0);
    ++test->write_count;
}

static void s_test_closed(void *arg) {
    struct close_test *test = arg;
    CHECK_CLOSE_TEST(test, test->write_count == AWS_ARRAY_SIZE(test->sends));
    CHECK_CLOSE_TEST(test, test->cleanup_count == 0);
    ++test->close_count;
}

static void s_test_cleaned_up(void *arg) {
    struct close_test *test = arg;
    CHECK_CLOSE_TEST(test, test->close_count == 1);
    ++test->cleanup_count;
    aws_mutex_lock(&test->mutex);
    test->cleaned_up = true;
    aws_condition_variable_notify_one(&test->signal);
    aws_mutex_unlock(&test->mutex);
}

static void s_set_test_connection_state(struct close_test *test, nw_connection_state_t state, int error) {
    struct connection_state_change_args *args = aws_mem_calloc(test->allocator, 1, sizeof(*args));
    args->allocator = test->allocator;
    args->nw_socket = s_socket_acquire_internal_ref(test->nw_socket);
    args->nw_connection = test->nw_socket->os_handle.nw_connection;
    args->state = state;
    args->error = error;
    s_process_connection_state_changed_task(NULL, args, AWS_TASK_STATUS_RUN_READY);
}

static void s_start_close_test(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct close_test *test = arg;
    struct aws_socket_options options = {.type = AWS_SOCKET_STREAM, .domain = AWS_SOCKET_IPV4};
    AWS_FATAL_ASSERT(!s_test_socket_init(&test->socket, test->allocator, &options));
    AWS_FATAL_ASSERT(!s_set_event_loop(&test->socket, test->event_loop));
    test->nw_socket = test->socket.impl;

    nw_parameters_t parameters =
        nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    nw_endpoint_t endpoint = nw_endpoint_create_host("127.0.0.1", "1");
    nw_connection_t connection = nw_connection_create(endpoint, parameters);
    AWS_FATAL_ASSERT(connection);
    nw_release(endpoint);
    nw_release(parameters);
    test->socket.io_handle.data.handle = connection;
    test->nw_socket->os_handle.nw_connection = connection;
    test->nw_socket->connection_setup = true;
    /* Represents the reference normally taken at nw_connection_start() and released by the cancelled state task. */
    s_socket_acquire_internal_ref(test->nw_socket);
    s_lock_socket_synced_data(test->nw_socket);
    s_set_socket_state(test->nw_socket, AWS_NW_SOCKET_STATE_CONNECTED_READ | AWS_NW_SOCKET_STATE_CONNECTED_WRITE);
    s_unlock_socket_synced_data(test->nw_socket);
    aws_socket_set_close_complete_callback(&test->socket, s_test_closed, test);
    aws_socket_set_cleanup_complete_callback(&test->socket, s_test_cleaned_up, test);

    struct aws_byte_cursor byte = aws_byte_cursor_from_c_str("x");
    for (size_t i = 0; i < AWS_ARRAY_SIZE(test->sends); ++i) {
        AWS_FATAL_ASSERT(!aws_socket_write(&test->socket, &byte, s_test_written, test));
    }

    if (test->order == PARTIAL_WRITE_THEN_FAILURE) {
        s_complete_send(test, 0);
    }
    if (test->order == FAILURE_THEN_CLOSE || test->order == PARTIAL_WRITE_THEN_FAILURE) {
        s_set_test_connection_state(test, nw_connection_state_failed, AWS_IO_SOCKET_TIMEOUT);
        CHECK_CLOSE_TEST(test, test->cancel_count == 0);
    }
    if (test->order == WAITING_ERROR_THEN_CLOSE) {
        s_set_test_connection_state(test, nw_connection_state_waiting, AWS_IO_SOCKET_NO_ROUTE_TO_HOST);
        CHECK_CLOSE_TEST(test, test->cancel_count == 0);
    }
    if (test->order == FAILURE_WITHOUT_ERROR_THEN_CLOSE) {
        s_set_test_connection_state(test, nw_connection_state_failed, 0);
        CHECK_CLOSE_TEST(test, test->cancel_count == 0);
    }
    aws_socket_close(&test->socket);
    aws_socket_close(&test->socket);
    if (test->order == CLOSE_THEN_FAILURE) {
        CHECK_CLOSE_TEST(test, test->cancel_count == 0);
        s_set_test_connection_state(test, nw_connection_state_failed, AWS_IO_SOCKET_TIMEOUT);
    }
    if (test->order == GRACEFUL_CLOSE || test->order == WAITING_ERROR_THEN_CLOSE) {
        CHECK_CLOSE_TEST(test, test->cancel_count == 0);
        for (size_t i = 0; i < test->send_count; ++i) {
            s_complete_send(test, i);
        }
    } else {
        CHECK_CLOSE_TEST(test, test->cancel_count == 1);
    }
    /* Release the caller's ownership while write callbacks and cancellation tasks are still queued. */
    aws_socket_clean_up(&test->socket);
}

static bool s_is_cleaned_up(void *arg) {
    return ((struct close_test *)arg)->cleaned_up;
}

static bool s_is_recovered(void *arg) {
    struct close_test *test = arg;
    return test->recovered && test->cleaned_up;
}

static void s_recover_close_test(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct close_test *test = arg;
    /* Force cancellation after a timeout so the regression fails without leaving the test runner hung in cleanup. */
    if (!test->cleaned_up && test->cancel_count == 0) {
        s_mock_connection_cancel(test->nw_socket->os_handle.nw_connection);
    }
    aws_mutex_lock(&test->mutex);
    test->recovered = true;
    aws_condition_variable_notify_one(&test->signal);
    aws_mutex_unlock(&test->mutex);
}

static int s_run_close_test(struct aws_allocator *allocator, enum close_test_order order) {
    aws_io_library_init(allocator);
    struct aws_event_loop_group_options options = {.loop_count = 1};
    struct aws_event_loop_group *group = aws_event_loop_group_new(allocator, &options);
    ASSERT_NOT_NULL(group);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(group);
    int wait_result = AWS_OP_SUCCESS;
    const char *failure = NULL;

    for (size_t cycle = 0; cycle < 10 && !wait_result && !failure; ++cycle) {
        struct close_test test = {
            .allocator = allocator,
            .event_loop = event_loop,
            .order = order,
            .mutex = AWS_MUTEX_INIT,
            .signal = AWS_CONDITION_VARIABLE_INIT,
        };
        s_close_test = &test;
        aws_task_init(&test.start_task, s_start_close_test, &test, "StartCloseTest");
        aws_event_loop_schedule_task_now(event_loop, &test.start_task);
        aws_mutex_lock(&test.mutex);
        wait_result = aws_condition_variable_wait_for_pred(
            &test.signal, &test.mutex, AWS_TIMESTAMP_NANOS, s_is_cleaned_up, &test);
        if (wait_result) {
            aws_task_init(&test.recover_task, s_recover_close_test, &test, "RecoverCloseTest");
            aws_event_loop_schedule_task_now(event_loop, &test.recover_task);
            aws_condition_variable_wait_for_pred(&test.signal, &test.mutex, AWS_TIMESTAMP_NANOS, s_is_recovered, &test);
        }
        /* Returning while callbacks still own this stack fixture would be unsafe, even in a failed test. */
        AWS_FATAL_ASSERT(test.cleaned_up);
        CHECK_CLOSE_TEST(&test, test.cleanup_count == 1);
        CHECK_CLOSE_TEST(&test, test.close_count == 1);
        CHECK_CLOSE_TEST(&test, test.write_count == AWS_ARRAY_SIZE(test.sends));
        failure = test.failure;
        aws_mutex_unlock(&test.mutex);
        aws_condition_variable_clean_up(&test.signal);
        aws_mutex_clean_up(&test.mutex);
    }
    s_close_test = NULL;
    aws_event_loop_group_release(group);
    aws_thread_join_all_managed();
    aws_io_library_clean_up();
    ASSERT_SUCCESS(wait_result, "Socket shutdown stalled with sends pending");
    ASSERT_NULL(failure, "%s", failure ? failure : "");
    return AWS_OP_SUCCESS;
}

static int s_nw_socket_failure_then_close(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_run_close_test(allocator, FAILURE_THEN_CLOSE);
}
AWS_TEST_CASE(nw_socket_failure_then_close, s_nw_socket_failure_then_close)

static int s_nw_socket_close_then_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_run_close_test(allocator, CLOSE_THEN_FAILURE);
}
AWS_TEST_CASE(nw_socket_close_then_failure, s_nw_socket_close_then_failure)

static int s_nw_socket_partial_write_then_failure(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_run_close_test(allocator, PARTIAL_WRITE_THEN_FAILURE);
}
AWS_TEST_CASE(nw_socket_partial_write_then_failure, s_nw_socket_partial_write_then_failure)

static int s_nw_socket_graceful_close_waits_for_writes(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_run_close_test(allocator, GRACEFUL_CLOSE);
}
AWS_TEST_CASE(nw_socket_graceful_close_waits_for_writes, s_nw_socket_graceful_close_waits_for_writes)

static int s_nw_socket_waiting_error_close_waits_for_writes(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_run_close_test(allocator, WAITING_ERROR_THEN_CLOSE);
}
AWS_TEST_CASE(nw_socket_waiting_error_close_waits_for_writes, s_nw_socket_waiting_error_close_waits_for_writes)

static int s_nw_socket_failed_without_error_then_close(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    return s_run_close_test(allocator, FAILURE_WITHOUT_ERROR_THEN_CLOSE);
}
AWS_TEST_CASE(nw_socket_failed_without_error_then_close, s_nw_socket_failed_without_error_then_close)

#endif /* AWS_USE_APPLE_NETWORK_FRAMEWORK */
