/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 *
 * Tests for race condition between socket close and incoming data delivery
 * on Apple Network Framework (nw_socket). Only runs on macOS with dispatch_queue event loop.
 *
 * Reproduces: https://github.com/aws/aws-iot-device-sdk-swift/issues/61
 * Crash: EXC_BAD_ACCESS in aws_channel_slot_downstream_read_window via s_process_incoming_data_task
 * Root cause: on_readable callback fires after socket close because s_socket_close_fn does not
 * NULL on_readable under base_socket_synced_data lock.
 */

#include <aws/io/event_loop.h>
#include <aws/io/socket.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/thread.h>
#include <aws/testing/aws_test_harness.h>

struct close_race_test_args {
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
    return ((struct close_race_test_args *)arg)->connect_completed;
}

static bool s_incoming_pred(void *arg) {
    return ((struct close_race_test_args *)arg)->incoming_ready;
}

static bool s_close_pred(void *arg) {
    return ((struct close_race_test_args *)arg)->close_completed;
}

static bool s_listener_ready_pred(void *arg) {
    return ((struct close_race_test_args *)arg)->listener_ready;
}

static bool s_shutdown_pred(void *arg) {
    return ((struct close_race_test_args *)arg)->shutdown_complete;
}

static void s_race_test_on_connection(struct aws_socket *socket, int error_code, void *user_data) {
    (void)socket;
    struct close_race_test_args *args = user_data;
    aws_mutex_lock(&args->mutex);
    args->connect_completed = true;
    args->error_code = error_code;
    aws_mutex_unlock(&args->mutex);
    aws_condition_variable_notify_one(&args->cv);
}

static void s_race_test_on_accept(
    struct aws_socket *socket,
    int error_code,
    struct aws_socket *new_socket,
    void *user_data) {
    (void)socket;
    (void)error_code;
    struct close_race_test_args *args = user_data;
    aws_mutex_lock(&args->mutex);
    if (!error_code) {
        args->socket = new_socket;
        args->incoming_ready = true;
    }
    aws_mutex_unlock(&args->mutex);
    aws_condition_variable_notify_one(&args->cv);
}

static void s_race_test_on_accept_start(struct aws_socket *socket, int error_code, void *user_data) {
    (void)socket;
    (void)error_code;
    struct close_race_test_args *args = user_data;
    aws_mutex_lock(&args->mutex);
    args->listener_ready = true;
    aws_mutex_unlock(&args->mutex);
    aws_condition_variable_notify_one(&args->cv);
}

static void s_race_test_on_readable(struct aws_socket *socket, int error_code, void *user_data) {
    (void)socket;
    (void)error_code;
    struct close_race_test_args *args = user_data;
    aws_mutex_lock(&args->mutex);
    args->readable_fired = true;
    aws_mutex_unlock(&args->mutex);
}

static void s_race_test_close_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct close_race_test_args *args = arg;
    aws_mutex_lock(&args->mutex);
    aws_socket_close(args->socket);
    args->close_completed = true;
    aws_mutex_unlock(&args->mutex);
    aws_condition_variable_notify_one(&args->cv);
}

static void s_race_test_shutdown_fn(void *user_data) {
    struct close_race_test_args *args = user_data;
    aws_mutex_lock(&args->mutex);
    args->shutdown_complete = true;
    aws_mutex_unlock(&args->mutex);
    aws_condition_variable_notify_one(&args->cv);
}

/**
 * Write data from the server socket then immediately close the client socket.
 * This creates the race window: Network.framework enqueues s_process_incoming_data_task
 * on the dispatch queue, but we close the socket before it fires.
 * Under TSAN, the unsynchronized access to on_readable will be detected.
 */
static void s_race_test_write_then_close_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct close_race_test_args *args = arg;

    /* Write 1 byte from server to client -- this triggers nw_connection_receive completion
     * which enqueues s_process_incoming_data_task on the dispatch queue */
    const char data[] = "X";
    struct aws_byte_buf buf = aws_byte_buf_from_array((const uint8_t *)data, 1);
    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&buf);
    aws_socket_write(args->socket, &cursor, NULL, NULL);
}

/**
 * Test: close socket while data is in-flight from peer.
 *
 * The race window:
 * 1. Server sends data to client
 * 2. Network.framework receives data, enqueues s_process_incoming_data_task
 * 3. Client calls aws_socket_close() -- should NULL on_readable
 * 4. s_process_incoming_data_task fires -- should see on_readable==NULL and skip
 *
 * Without the fix, step 4 calls on_readable with a potentially freed socket/channel,
 * causing EXC_BAD_ACCESS. TSAN detects the data race even without the actual crash.
 */
static int s_test_nw_socket_close_while_data_pending(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    /* This test only applies to Apple Network Framework */
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

    struct aws_socket_endpoint endpoint = {
        .address = "127.0.0.1",
        .port = 0, /* OS-assigned */
    };

    /* Set up listener */
    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, &sock_opts));

    struct aws_socket_bind_options bind_opts = {.local_endpoint = &endpoint};
    ASSERT_SUCCESS(aws_socket_bind(&listener, &bind_opts));
    ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));

    struct close_race_test_args listener_args = {
        .mutex = AWS_MUTEX_INIT,
        .cv = AWS_CONDITION_VARIABLE_INIT,
    };

    struct aws_socket_listener_options listener_options = {
        .on_accept_result = s_race_test_on_accept,
        .on_accept_result_user_data = &listener_args,
        .on_accept_start = s_race_test_on_accept_start,
        .on_accept_start_user_data = &listener_args,
    };
    ASSERT_SUCCESS(aws_socket_start_accept(&listener, event_loop, listener_options));

    /* Wait for listener to be ready -- Apple NW Framework assigns port asynchronously */
    aws_mutex_lock(&listener_args.mutex);
    aws_condition_variable_wait_pred(&listener_args.cv, &listener_args.mutex, s_listener_ready_pred, &listener_args);
    aws_mutex_unlock(&listener_args.mutex);

    /* NOW get the OS-assigned port */
    struct aws_socket_endpoint bound_endpoint;
    ASSERT_SUCCESS(aws_socket_get_bound_address(&listener, &bound_endpoint));
    ASSERT_TRUE(bound_endpoint.port > 0);

    /* Run the race scenario multiple times to increase TSAN detection probability */
    const int iterations = 50;

    for (int i = 0; i < iterations; i++) {
        /* Reset listener accept state */
        aws_mutex_lock(&listener_args.mutex);
        listener_args.socket = NULL;
        listener_args.incoming_ready = false;
        aws_mutex_unlock(&listener_args.mutex);

        /* Connect client */
        struct close_race_test_args client_args = {
            .mutex = AWS_MUTEX_INIT,
            .cv = AWS_CONDITION_VARIABLE_INIT,
        };

        struct aws_socket client;
        ASSERT_SUCCESS(aws_socket_init(&client, allocator, &sock_opts));

        struct aws_socket_connect_options connect_opts = {
            .remote_endpoint = &bound_endpoint,
            .event_loop = event_loop,
            .on_connection_result = s_race_test_on_connection,
            .user_data = &client_args,
        };
        ASSERT_SUCCESS(aws_socket_connect(&client, &connect_opts));

        /* Wait for connection + accept */
        aws_mutex_lock(&client_args.mutex);
        aws_condition_variable_wait_pred(&client_args.cv, &client_args.mutex, s_connect_pred, &client_args);
        aws_mutex_unlock(&client_args.mutex);
        ASSERT_INT_EQUALS(0, client_args.error_code);

        aws_mutex_lock(&listener_args.mutex);
        aws_condition_variable_wait_pred(&listener_args.cv, &listener_args.mutex, s_incoming_pred, &listener_args);
        aws_mutex_unlock(&listener_args.mutex);
        ASSERT_NOT_NULL(listener_args.socket);

        struct aws_socket *server_sock = listener_args.socket;
        ASSERT_SUCCESS(aws_socket_assign_to_event_loop(server_sock, event_loop));

        /* Subscribe client to readable -- this sets on_readable which is the crash target */
        ASSERT_SUCCESS(aws_socket_subscribe_to_readable_events(&client, s_race_test_on_readable, &client_args));

        /* Schedule: server writes data (triggers nw_connection_receive on client side) */
        struct close_race_test_args server_write_args = {
            .socket = server_sock,
            .mutex = AWS_MUTEX_INIT,
            .cv = AWS_CONDITION_VARIABLE_INIT,
        };
        struct aws_task write_task = {
            .fn = s_race_test_write_then_close_task,
            .arg = &server_write_args,
        };
        aws_event_loop_schedule_task_now(event_loop, &write_task);

        /* Small delay to let the write get dispatched but not necessarily delivered */
        aws_thread_current_sleep(aws_timestamp_convert(1, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL));

        /* Close client socket -- the race: data may be in-flight on dispatch queue */
        client_args.socket = &client;
        client_args.close_completed = false;
        client_args.shutdown_complete = false;
        aws_socket_set_cleanup_complete_callback(&client, s_race_test_shutdown_fn, &client_args);

        struct aws_task close_task = {
            .fn = s_race_test_close_task,
            .arg = &client_args,
        };
        aws_event_loop_schedule_task_now(event_loop, &close_task);

        aws_mutex_lock(&client_args.mutex);
        aws_condition_variable_wait_pred(&client_args.cv, &client_args.mutex, s_close_pred, &client_args);
        aws_mutex_unlock(&client_args.mutex);

        aws_socket_clean_up(&client);
        aws_mutex_lock(&client_args.mutex);
        aws_condition_variable_wait_pred(&client_args.cv, &client_args.mutex, s_shutdown_pred, &client_args);
        aws_mutex_unlock(&client_args.mutex);

        /* Clean up server socket */
        struct close_race_test_args server_close_args = {
            .socket = server_sock,
            .mutex = AWS_MUTEX_INIT,
            .cv = AWS_CONDITION_VARIABLE_INIT,
        };
        aws_socket_set_cleanup_complete_callback(server_sock, s_race_test_shutdown_fn, &server_close_args);

        struct aws_task server_close_task = {
            .fn = s_race_test_close_task,
            .arg = &server_close_args,
        };
        aws_event_loop_schedule_task_now(event_loop, &server_close_task);

        aws_mutex_lock(&server_close_args.mutex);
        aws_condition_variable_wait_pred(
            &server_close_args.cv, &server_close_args.mutex, s_close_pred, &server_close_args);
        aws_mutex_unlock(&server_close_args.mutex);

        aws_socket_clean_up(server_sock);
        aws_mutex_lock(&server_close_args.mutex);
        aws_condition_variable_wait_pred(
            &server_close_args.cv, &server_close_args.mutex, s_shutdown_pred, &server_close_args);
        aws_mutex_unlock(&server_close_args.mutex);
        aws_mem_release(allocator, server_sock);
    }

    /* Clean up listener */
    aws_socket_stop_accept(&listener);
    aws_socket_close(&listener);
    aws_socket_clean_up(&listener);

    aws_event_loop_group_release(el_group);
    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(nw_socket_close_while_data_pending, s_test_nw_socket_close_while_data_pending)
