/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 *
 * Regression test for: https://github.com/aws/aws-iot-device-sdk-swift/issues/61
 *
 * EXC_BAD_ACCESS crash (247 occurrences / 90 days) in aws_channel_slot_downstream_read_window,
 * triggered via s_process_incoming_data_task calling on_readable after socket close.
 *
 * Root cause:
 *   s_socket_close_fn() does not NULL on_readable. When data arrives from the peer and
 *   Network.framework enqueues s_process_incoming_data_task on the dispatch queue, the task
 *   runs after close and calls on_readable into freed channel/slot memory.
 *
 * This test verifies the invariant:
 *   After aws_socket_close() returns, on_readable MUST NOT be invoked.
 *
 * The test is deterministic on Apple Network Framework because:
 *   1. Server writes data to client (triggers NW receive completion)
 *   2. Client close is scheduled on the same serial dispatch queue
 *   3. The readableTask (s_process_incoming_data_task) is enqueued by NW's completion handler
 *      and runs after close on the serial queue
 *   4. Without the fix: readableTask sees on_readable != NULL and calls it (BUG)
 *   5. With the fix: on_readable is NULLed during close, readableTask skips it (CORRECT)
 */

#include <aws/io/event_loop.h>
#include <aws/io/socket.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/thread.h>
#include <aws/testing/aws_test_harness.h>

struct socket_test_args {
    struct aws_socket *socket;
    struct aws_mutex mutex;
    struct aws_condition_variable cv;
    bool connect_completed;
    bool incoming_ready;
    bool listener_ready;
    bool readable_fired;
    bool close_completed;
    bool shutdown_complete;
    int error_code;
};

static bool s_connect_pred(void *arg) {
    return ((struct socket_test_args *)arg)->connect_completed;
}
static bool s_incoming_pred(void *arg) {
    return ((struct socket_test_args *)arg)->incoming_ready;
}
static bool s_listener_ready_pred(void *arg) {
    return ((struct socket_test_args *)arg)->listener_ready;
}
static bool s_close_pred(void *arg) {
    return ((struct socket_test_args *)arg)->close_completed;
}
static bool s_shutdown_pred(void *arg) {
    return ((struct socket_test_args *)arg)->shutdown_complete;
}

static void s_on_connection_result(struct aws_socket *socket, int error_code, void *user_data) {
    (void)socket;
    struct socket_test_args *args = user_data;
    aws_mutex_lock(&args->mutex);
    args->connect_completed = true;
    args->error_code = error_code;
    aws_mutex_unlock(&args->mutex);
    aws_condition_variable_notify_one(&args->cv);
}

static void s_on_accept_result(
    struct aws_socket *socket,
    int error_code,
    struct aws_socket *new_socket,
    void *user_data) {
    (void)socket;
    (void)error_code;
    struct socket_test_args *args = user_data;
    aws_mutex_lock(&args->mutex);
    if (!error_code) {
        args->socket = new_socket;
        args->incoming_ready = true;
    }
    aws_mutex_unlock(&args->mutex);
    aws_condition_variable_notify_one(&args->cv);
}

static void s_on_accept_start(struct aws_socket *socket, int error_code, void *user_data) {
    (void)socket;
    (void)error_code;
    struct socket_test_args *args = user_data;
    aws_mutex_lock(&args->mutex);
    args->listener_ready = true;
    aws_mutex_unlock(&args->mutex);
    aws_condition_variable_notify_one(&args->cv);
}

/* This is the on_readable callback registered on the client socket.
 * If this fires after close, the bug is present. */
static void s_on_readable_after_close_detector(struct aws_socket *socket, int error_code, void *user_data) {
    (void)socket;
    (void)error_code;
    struct socket_test_args *args = user_data;
    aws_mutex_lock(&args->mutex);
    args->readable_fired = true;
    aws_mutex_unlock(&args->mutex);
}

static void s_on_write_complete(struct aws_socket *socket, int error_code, size_t bytes_written, void *user_data) {
    (void)socket;
    (void)error_code;
    (void)bytes_written;
    (void)user_data;
}

static void s_close_socket_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct socket_test_args *args = arg;
    aws_mutex_lock(&args->mutex);
    aws_socket_close(args->socket);
    args->close_completed = true;
    aws_mutex_unlock(&args->mutex);
    aws_condition_variable_notify_one(&args->cv);
}

static void s_shutdown_complete_fn(void *user_data) {
    struct socket_test_args *args = user_data;
    aws_mutex_lock(&args->mutex);
    args->shutdown_complete = true;
    aws_mutex_unlock(&args->mutex);
    aws_condition_variable_notify_one(&args->cv);
}

/* Writes 1 byte from the server socket to trigger data delivery on the client side */
static void s_write_to_client_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct socket_test_args *args = arg;
    const char data[] = "X";
    struct aws_byte_buf buf = aws_byte_buf_from_array((const uint8_t *)data, 1);
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&buf);
    aws_socket_write(args->socket, &cursor, s_on_write_complete, NULL);
}

static int s_test_nw_socket_close_while_data_pending(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    if (aws_socket_get_default_impl_type() != AWS_SOCKET_IMPL_APPLE_NETWORK_FRAMEWORK) {
        return AWS_OP_SUCCESS;
    }

    aws_io_library_init(allocator);

    struct aws_event_loop_group_options elg_options = {.loop_count = 1};
    struct aws_event_loop_group *el_group = aws_event_loop_group_new(allocator, &elg_options);
    struct aws_event_loop *event_loop = aws_event_loop_group_get_next_loop(el_group);
    ASSERT_NOT_NULL(event_loop);

    struct aws_socket_options sock_opts = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .connect_timeout_ms = 3000,
    };

    /* --- Set up listener on loopback with OS-assigned port --- */
    struct aws_socket_endpoint endpoint = {.address = "127.0.0.1", .port = 0};
    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, &sock_opts));

    struct aws_socket_bind_options bind_opts = {.local_endpoint = &endpoint};
    ASSERT_SUCCESS(aws_socket_bind(&listener, &bind_opts));
    ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));

    struct socket_test_args listener_args = {.mutex = AWS_MUTEX_INIT, .cv = AWS_CONDITION_VARIABLE_INIT};
    struct aws_socket_listener_options listener_options = {
        .on_accept_result = s_on_accept_result,
        .on_accept_result_user_data = &listener_args,
        .on_accept_start = s_on_accept_start,
        .on_accept_start_user_data = &listener_args,
    };
    ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, listener_options));

    /* Wait for listener ready (Apple NW assigns port asynchronously) */
    aws_mutex_lock(&listener_args.mutex);
    aws_condition_variable_wait_pred(&listener_args.cv, &listener_args.mutex, s_listener_ready_pred, &listener_args);
    aws_mutex_unlock(&listener_args.mutex);

    struct aws_socket_endpoint bound_endpoint;
    ASSERT_SUCCESS(aws_socket_get_bound_address(&listener, &bound_endpoint));
    ASSERT_TRUE(bound_endpoint.port > 0);

    /* --- Connect client to server --- */
    struct socket_test_args client_args = {.mutex = AWS_MUTEX_INIT, .cv = AWS_CONDITION_VARIABLE_INIT};
    struct aws_socket client;
    ASSERT_SUCCESS(aws_socket_init(&client, allocator, &sock_opts));

    struct aws_socket_connect_options connect_opts = {
        .remote_endpoint = &bound_endpoint,
        .event_loop = event_loop,
        .on_connection_result = s_on_connection_result,
        .user_data = &client_args,
    };
    ASSERT_SUCCESS(aws_socket_connect(&client, &connect_opts));

    /* Wait for TCP handshake */
    aws_mutex_lock(&client_args.mutex);
    aws_condition_variable_wait_pred(&client_args.cv, &client_args.mutex, s_connect_pred, &client_args);
    aws_mutex_unlock(&client_args.mutex);
    ASSERT_INT_EQUALS(0, client_args.error_code);

    /* Wait for server to accept */
    aws_mutex_lock(&listener_args.mutex);
    aws_condition_variable_wait_pred(&listener_args.cv, &listener_args.mutex, s_incoming_pred, &listener_args);
    aws_mutex_unlock(&listener_args.mutex);
    struct aws_socket *server_sock = listener_args.socket;
    ASSERT_NOT_NULL(server_sock);
    ASSERT_SUCCESS(aws_socket_assign_to_event_loop(server_sock, event_loop));

    /* --- Subscribe client to readable events (sets on_readable — the crash target) --- */
    ASSERT_SUCCESS(aws_socket_subscribe_to_readable_events(&client, s_on_readable_after_close_detector, &client_args));

    /* --- Trigger the bug: write data then close client socket ---
     *
     * Schedule server write: sends 1 byte to client. Network.framework will receive it
     * and enqueue s_process_incoming_data_task (readableTask) on the dispatch queue.
     *
     * Schedule client close: runs after write on the same serial queue.
     *
     * The readableTask arrives on the queue after close. Without the fix, it calls
     * on_readable into potentially freed memory. */
    struct socket_test_args write_args = {
        .socket = server_sock, .mutex = AWS_MUTEX_INIT, .cv = AWS_CONDITION_VARIABLE_INIT};
    struct aws_task write_task = {.fn = s_write_to_client_task, .arg = &write_args};
    aws_event_loop_schedule_task_now(event_loop, &write_task);

    client_args.socket = &client;
    client_args.close_completed = false;
    client_args.shutdown_complete = false;
    aws_socket_set_cleanup_complete_callback(&client, s_shutdown_complete_fn, &client_args);

    struct aws_task close_task = {.fn = s_close_socket_task, .arg = &client_args};
    aws_event_loop_schedule_task_now(event_loop, &close_task);

    /* Wait for close to complete */
    aws_mutex_lock(&client_args.mutex);
    aws_condition_variable_wait_pred(&client_args.cv, &client_args.mutex, s_close_pred, &client_args);
    aws_mutex_unlock(&client_args.mutex);

    /* Reset readable_fired — any on_readable calls before close are legitimate */
    aws_mutex_lock(&client_args.mutex);
    client_args.readable_fired = false;
    aws_mutex_unlock(&client_args.mutex);

    /* Wait for readableTask to execute (it's already enqueued on the serial queue) */
    aws_thread_current_sleep(aws_timestamp_convert(50, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL));

    /* --- Verify invariant: on_readable must not fire after close --- */
    aws_mutex_lock(&client_args.mutex);
    bool readable_fired_after_close = client_args.readable_fired;
    aws_mutex_unlock(&client_args.mutex);

    ASSERT_FALSE(readable_fired_after_close, "on_readable fired after aws_socket_close() — race condition bug");

    /* --- Cleanup --- */
    aws_socket_clean_up(&client);
    aws_mutex_lock(&client_args.mutex);
    aws_condition_variable_wait_pred(&client_args.cv, &client_args.mutex, s_shutdown_pred, &client_args);
    aws_mutex_unlock(&client_args.mutex);

    struct socket_test_args server_close_args = {
        .socket = server_sock, .mutex = AWS_MUTEX_INIT, .cv = AWS_CONDITION_VARIABLE_INIT};
    aws_socket_set_cleanup_complete_callback(server_sock, s_shutdown_complete_fn, &server_close_args);
    struct aws_task server_close_task = {.fn = s_close_socket_task, .arg = &server_close_args};
    aws_event_loop_schedule_task_now(event_loop, &server_close_task);

    aws_mutex_lock(&server_close_args.mutex);
    aws_condition_variable_wait_pred(&server_close_args.cv, &server_close_args.mutex, s_close_pred, &server_close_args);
    aws_mutex_unlock(&server_close_args.mutex);

    aws_socket_clean_up(server_sock);
    aws_mutex_lock(&server_close_args.mutex);
    aws_condition_variable_wait_pred(
        &server_close_args.cv, &server_close_args.mutex, s_shutdown_pred, &server_close_args);
    aws_mutex_unlock(&server_close_args.mutex);
    aws_mem_release(allocator, server_sock);

    aws_socket_stop_accept(&listener);
    aws_socket_close(&listener);
    aws_socket_clean_up(&listener);

    aws_event_loop_group_release(el_group);
    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(nw_socket_close_while_data_pending, s_test_nw_socket_close_while_data_pending)
