/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/io/socket_channel_handler.h>
#include <aws/io/statistics.h>

#include <aws/common/atomics.h>
#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>

#include <aws/testing/aws_test_harness.h>

#include "statistics_handler_test.h"
#include <read_write_test_handler.h>

#ifdef _WIN32
#    define LOCAL_SOCK_TEST_PATTERN "\\\\.\\pipe\\testsock%llu"
#else
#    define LOCAL_SOCK_TEST_PATTERN "testsock%llu.sock"
#endif

struct socket_test_args {
    struct aws_allocator *allocator;
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_channel *channel;
    struct aws_channel_handler *rw_handler;

    struct aws_atomic_var rw_slot; /* pointer-to struct aws_channel_slot */
    int error_code;
    bool shutdown_invoked;
    bool error_invoked;
    bool creation_callback_invoked;
    bool listener_destroyed;
};

/* common structure for test */
struct socket_common_tester {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    struct aws_event_loop_group el_group;
    struct aws_atomic_var current_time_ns;
    struct aws_atomic_var stats_handler;
};

static struct socket_common_tester c_tester;

static int s_socket_common_tester_init(struct aws_allocator *allocator, struct socket_common_tester *tester) {
    AWS_ZERO_STRUCT(*tester);
    aws_io_library_init(allocator);
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&tester->el_group, allocator, 0));
    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;
    tester->mutex = mutex;
    tester->condition_variable = condition_variable;
    aws_atomic_store_int(&tester->current_time_ns, 0);
    aws_atomic_store_ptr(&tester->stats_handler, NULL);

    return AWS_OP_SUCCESS;
}

static int s_socket_common_tester_clean_up(struct socket_common_tester *tester) {
    aws_mutex_clean_up(&tester->mutex);
    aws_event_loop_group_clean_up(&tester->el_group);
    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

/* common structure for a local server */
struct local_server_tester {
    struct aws_socket_options socket_options;
    struct aws_socket_endpoint endpoint;
    struct aws_server_bootstrap *server_bootstrap;
    struct aws_socket *listener;
    uint64_t timestamp;
};

static bool s_channel_setup_predicate(void *user_data) {
    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;
    return aws_atomic_load_ptr(&setup_test_args->rw_slot) != NULL;
}

static bool s_channel_shutdown_predicate(void *user_data) {
    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;
    bool finished = setup_test_args->shutdown_invoked;
    return finished;
}

static bool s_listener_destroy_predicate(void *user_data) {
    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;
    bool finished = setup_test_args->listener_destroyed;
    return finished;
}

static void s_socket_handler_test_client_setup_callback(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;

    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;

    setup_test_args->channel = channel;

    struct aws_channel_slot *rw_slot = aws_channel_slot_new(channel);
    aws_channel_slot_insert_end(channel, rw_slot);

    aws_channel_slot_set_handler(rw_slot, setup_test_args->rw_handler);
    aws_atomic_store_ptr(&setup_test_args->rw_slot, rw_slot);

    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

static void s_socket_handler_test_server_setup_callback(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;

    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;

    setup_test_args->channel = channel;

    struct aws_channel_slot *rw_slot = aws_channel_slot_new(channel);
    aws_channel_slot_insert_end(channel, rw_slot);

    aws_channel_slot_set_handler(rw_slot, setup_test_args->rw_handler);
    aws_atomic_store_ptr(&setup_test_args->rw_slot, rw_slot);

    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

static void s_socket_handler_test_client_shutdown_callback(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)channel;

    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;
    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->shutdown_invoked = true;
    setup_test_args->error_code = error_code;
    aws_mutex_unlock(setup_test_args->mutex);

    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

static void s_socket_handler_test_server_shutdown_callback(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;
    (void)channel;

    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;
    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->shutdown_invoked = true;
    setup_test_args->error_code = error_code;
    aws_mutex_unlock(setup_test_args->mutex);

    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

struct socket_test_rw_args {
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_byte_buf received_message;
    size_t amount_read;
    size_t expected_read;
    bool invocation_happened;
    bool shutdown_finished;
};

static bool s_socket_test_read_predicate(void *user_data) {
    struct socket_test_rw_args *rw_args = (struct socket_test_rw_args *)user_data;
    return rw_args->invocation_happened;
}

static bool s_socket_test_full_read_predicate(void *user_data) {
    struct socket_test_rw_args *rw_args = (struct socket_test_rw_args *)user_data;
    return rw_args->invocation_happened && rw_args->amount_read == rw_args->expected_read;
}

static struct aws_byte_buf s_socket_test_handle_read(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *data_read,
    void *user_data) {

    (void)handler;
    (void)slot;

    struct socket_test_rw_args *rw_args = (struct socket_test_rw_args *)user_data;

    aws_mutex_lock(rw_args->mutex);
    memcpy(rw_args->received_message.buffer + rw_args->received_message.len, data_read->buffer, data_read->len);
    rw_args->received_message.len += data_read->len;
    rw_args->amount_read += data_read->len;
    rw_args->invocation_happened = true;
    aws_condition_variable_notify_one(rw_args->condition_variable);
    aws_mutex_unlock(rw_args->mutex);

    return rw_args->received_message;
}

static struct aws_byte_buf s_socket_test_handle_write(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *data_read,
    void *user_data) {

    (void)handler;
    (void)slot;
    (void)data_read;
    (void)user_data;

    /*do nothing*/
    return (struct aws_byte_buf){0};
}

static void s_socket_handler_test_server_listener_destroy_callback(
    struct aws_server_bootstrap *bootstrap,
    void *user_data) {

    (void)bootstrap;

    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;
    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->listener_destroyed = true;
    aws_mutex_unlock(setup_test_args->mutex);
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

static int s_rw_args_init(
    struct socket_test_rw_args *args,
    struct socket_common_tester *s_c_tester,
    struct aws_byte_buf received_message,
    int expected_read) {
    AWS_ZERO_STRUCT(*args);
    args->mutex = &s_c_tester->mutex;
    args->condition_variable = &s_c_tester->condition_variable;
    args->received_message = received_message;
    args->expected_read = expected_read;
    return AWS_OP_SUCCESS;
}

static int s_socket_test_args_init(
    struct socket_test_args *args,
    struct socket_common_tester *s_c_tester,
    struct aws_channel_handler *rw_handler) {
    AWS_ZERO_STRUCT(*args);
    args->mutex = &s_c_tester->mutex;
    args->condition_variable = &s_c_tester->condition_variable;
    args->rw_handler = rw_handler;
    return AWS_OP_SUCCESS;
}

static int s_local_server_tester_init(
    struct aws_allocator *allocator,
    struct local_server_tester *tester,
    struct socket_test_args *args,
    struct socket_common_tester *s_c_tester,
    bool enable_back_pressure) {
    AWS_ZERO_STRUCT(*tester);
    tester->socket_options.connect_timeout_ms = 3000;
    tester->socket_options.type = AWS_SOCKET_STREAM;
    tester->socket_options.domain = AWS_SOCKET_LOCAL;

    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&tester->timestamp));
    snprintf(
        tester->endpoint.address,
        sizeof(tester->endpoint.address),
        LOCAL_SOCK_TEST_PATTERN,
        (long long unsigned)tester->timestamp);
    tester->server_bootstrap = aws_server_bootstrap_new(allocator, &s_c_tester->el_group);
    ASSERT_NOT_NULL(tester->server_bootstrap);

    struct aws_server_socket_channel_bootstrap_options bootstrap_options = {
        .bootstrap = tester->server_bootstrap,
        .enable_read_back_pressure = enable_back_pressure,
        .port = tester->endpoint.port,
        .host_name = tester->endpoint.address,
        .socket_options = &tester->socket_options,
        .incoming_callback = s_socket_handler_test_server_setup_callback,
        .shutdown_callback = s_socket_handler_test_server_shutdown_callback,
        .destroy_callback = s_socket_handler_test_server_listener_destroy_callback,
        .user_data = args,
    };
    tester->listener = aws_server_bootstrap_new_socket_listener(&bootstrap_options);
    ASSERT_NOT_NULL(tester->listener);

    return AWS_OP_SUCCESS;
}

static int s_local_server_tester_clean_up(struct local_server_tester *tester) {
    aws_server_bootstrap_release(tester->server_bootstrap);
    return AWS_OP_SUCCESS;
}

static int s_socket_echo_and_backpressure_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_socket_common_tester_init(allocator, &c_tester);

    struct aws_byte_buf read_tag = aws_byte_buf_from_c_str("I'm a little teapot.");
    struct aws_byte_buf write_tag = aws_byte_buf_from_c_str("I'm a big teapot");

    uint8_t incoming_received_message[128] = {0};
    uint8_t outgoing_received_message[128] = {0};

    struct socket_test_rw_args incoming_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &incoming_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(incoming_received_message, sizeof(incoming_received_message)),
        (int)write_tag.len));

    struct socket_test_rw_args outgoing_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &outgoing_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(outgoing_received_message, sizeof(outgoing_received_message)),
        (int)read_tag.len));
    /* make the windows small to make sure back pressure is honored. */
    static size_t s_outgoing_initial_read_window = 9;
    static size_t s_incoming_initial_read_window = 8;
    struct aws_channel_handler *outgoing_rw_handler = rw_handler_new(
        allocator,
        s_socket_test_handle_read,
        s_socket_test_handle_write,
        true,
        s_outgoing_initial_read_window,
        &outgoing_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_channel_handler *incoming_rw_handler = rw_handler_new(
        allocator,
        s_socket_test_handle_read,
        s_socket_test_handle_write,
        true,
        s_incoming_initial_read_window,
        &incoming_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct socket_test_args incoming_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&incoming_args, &c_tester, incoming_rw_handler));

    struct socket_test_args outgoing_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&outgoing_args, &c_tester, outgoing_rw_handler));

    struct local_server_tester local_server_tester;
    ASSERT_SUCCESS(s_local_server_tester_init(allocator, &local_server_tester, &incoming_args, &c_tester, true));

    /* this should never get used for this case. */
    struct aws_host_resolver dummy_resolver;
    AWS_ZERO_STRUCT(dummy_resolver);
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = &c_tester.el_group,
        .host_resolver = &dummy_resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_socket_channel_bootstrap_options channel_options;
    AWS_ZERO_STRUCT(channel_options);
    channel_options.bootstrap = client_bootstrap;
    channel_options.host_name = local_server_tester.endpoint.address;
    channel_options.port = 0;
    channel_options.socket_options = &local_server_tester.socket_options;
    channel_options.setup_callback = s_socket_handler_test_client_setup_callback;
    channel_options.shutdown_callback = s_socket_handler_test_client_shutdown_callback;
    channel_options.user_data = &outgoing_args;
    channel_options.enable_read_back_pressure = true;

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&channel_options));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_setup_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_setup_predicate, &outgoing_args));

    rw_handler_write(outgoing_args.rw_handler, aws_atomic_load_ptr(&outgoing_args.rw_slot), &write_tag);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_socket_test_read_predicate, &incoming_rw_args));

    rw_handler_write(incoming_args.rw_handler, aws_atomic_load_ptr(&incoming_args.rw_slot), &read_tag);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_socket_test_read_predicate, &outgoing_rw_args));
    incoming_rw_args.invocation_happened = false;
    outgoing_rw_args.invocation_happened = false;

    ASSERT_INT_EQUALS(s_outgoing_initial_read_window, outgoing_rw_args.amount_read);
    ASSERT_INT_EQUALS(s_incoming_initial_read_window, incoming_rw_args.amount_read);

    /* Go ahead and verify back-pressure works*/
    rw_handler_trigger_increment_read_window(
        incoming_args.rw_handler, aws_atomic_load_ptr(&incoming_args.rw_slot), 100);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_socket_test_full_read_predicate, &incoming_rw_args));

    rw_handler_trigger_increment_read_window(
        outgoing_args.rw_handler, aws_atomic_load_ptr(&outgoing_args.rw_slot), 100);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_socket_test_full_read_predicate, &outgoing_rw_args));

    ASSERT_INT_EQUALS(read_tag.len, outgoing_rw_args.amount_read);
    ASSERT_INT_EQUALS(write_tag.len, incoming_rw_args.amount_read);

    ASSERT_BIN_ARRAYS_EQUALS(
        write_tag.buffer,
        write_tag.len,
        incoming_rw_args.received_message.buffer,
        incoming_rw_args.received_message.len);
    ASSERT_BIN_ARRAYS_EQUALS(
        read_tag.buffer, read_tag.len, outgoing_rw_args.received_message.buffer, outgoing_rw_args.received_message.len);

    /* only shut down one side, this should cause the other side to shutdown as well.*/
    ASSERT_SUCCESS(aws_channel_shutdown(incoming_args.channel, AWS_OP_SUCCESS));
    ASSERT_SUCCESS(aws_channel_shutdown(outgoing_args.channel, AWS_OP_SUCCESS));

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_shutdown_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_shutdown_predicate, &outgoing_args));
    aws_server_bootstrap_destroy_socket_listener(local_server_tester.server_bootstrap, local_server_tester.listener);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_listener_destroy_predicate, &incoming_args));

    aws_mutex_unlock(&c_tester.mutex);

    /* clean up */
    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_local_server_tester_clean_up(&local_server_tester));
    ASSERT_SUCCESS(s_socket_common_tester_clean_up(&c_tester));
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socket_handler_echo_and_backpressure, s_socket_echo_and_backpressure_test)

static int s_socket_close_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_socket_common_tester_init(allocator, &c_tester);

    uint8_t outgoing_received_message[128];
    uint8_t incoming_received_message[128];

    struct socket_test_rw_args incoming_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &incoming_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(incoming_received_message, sizeof(incoming_received_message)),
        0));

    struct socket_test_rw_args outgoing_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &outgoing_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(outgoing_received_message, sizeof(outgoing_received_message)),
        0));

    struct aws_channel_handler *outgoing_rw_handler = rw_handler_new(
        allocator, s_socket_test_handle_read, s_socket_test_handle_write, true, 10000, &outgoing_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_channel_handler *incoming_rw_handler = rw_handler_new(
        allocator, s_socket_test_handle_read, s_socket_test_handle_write, true, 10000, &incoming_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct socket_test_args incoming_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&incoming_args, &c_tester, incoming_rw_handler));

    struct socket_test_args outgoing_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&outgoing_args, &c_tester, outgoing_rw_handler));

    struct local_server_tester local_server_tester;
    ASSERT_SUCCESS(s_local_server_tester_init(allocator, &local_server_tester, &incoming_args, &c_tester, false));

    /* this should not get used for a unix domain socket. */
    struct aws_host_resolver dummy_resolver;
    AWS_ZERO_STRUCT(dummy_resolver);
    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = &c_tester.el_group,
        .host_resolver = &dummy_resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_socket_channel_bootstrap_options channel_options;
    AWS_ZERO_STRUCT(channel_options);
    channel_options.bootstrap = client_bootstrap;
    channel_options.host_name = local_server_tester.endpoint.address;
    channel_options.port = 0;
    channel_options.socket_options = &local_server_tester.socket_options;
    channel_options.setup_callback = s_socket_handler_test_client_setup_callback;
    channel_options.shutdown_callback = s_socket_handler_test_client_shutdown_callback;
    channel_options.user_data = &outgoing_args;

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&channel_options));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_setup_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_setup_predicate, &outgoing_args));

    aws_channel_shutdown(incoming_args.channel, AWS_OP_SUCCESS);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_shutdown_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_shutdown_predicate, &outgoing_args));

    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, incoming_args.error_code);
    ASSERT_TRUE(
        AWS_IO_SOCKET_CLOSED == outgoing_args.error_code || AWS_IO_SOCKET_NOT_CONNECTED == outgoing_args.error_code);
    aws_server_bootstrap_destroy_socket_listener(local_server_tester.server_bootstrap, local_server_tester.listener);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_listener_destroy_predicate, &incoming_args));

    aws_mutex_unlock(&c_tester.mutex);

    /* clean up */
    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_local_server_tester_clean_up(&local_server_tester));
    ASSERT_SUCCESS(s_socket_common_tester_clean_up(&c_tester));
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socket_handler_close, s_socket_close_test)

static void s_creation_callback_test_channel_creation_callback(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;

    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;

    setup_test_args->creation_callback_invoked = true;

    struct aws_crt_statistics_handler *stats_handler = aws_statistics_handler_new_test(bootstrap->allocator);
    aws_atomic_store_ptr(&c_tester.stats_handler, stats_handler);

    aws_channel_set_statistics_handler(channel, stats_handler);
}

static struct aws_event_loop *s_default_new_event_loop(
    struct aws_allocator *allocator,
    aws_io_clock_fn *clock,
    void *user_data) {

    (void)user_data;
    return aws_event_loop_new_default(allocator, clock);
}

static int s_statistic_test_clock_fn(uint64_t *timestamp) {
    *timestamp = aws_atomic_load_int(&c_tester.current_time_ns);

    return AWS_OP_SUCCESS;
}

static int s_socket_common_tester_statistics_init(
    struct aws_allocator *allocator,
    struct socket_common_tester *tester) {

    aws_io_library_init(allocator);

    AWS_ZERO_STRUCT(*tester);
    ASSERT_SUCCESS(aws_event_loop_group_init(
        &tester->el_group, allocator, s_statistic_test_clock_fn, 1, s_default_new_event_loop, NULL));
    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;
    tester->mutex = mutex;
    tester->condition_variable = condition_variable;
    aws_atomic_store_int(&tester->current_time_ns, 0);
    aws_atomic_store_ptr(&tester->stats_handler, NULL);

    return AWS_OP_SUCCESS;
}

static bool s_stats_processed_predicate(void *user_data) {
    struct aws_crt_statistics_handler *stats_handler = user_data;
    struct aws_statistics_handler_test_impl *stats_impl = stats_handler->impl;

    return stats_impl->total_bytes_read > 0 && stats_impl->total_bytes_written > 0;
}

static int s_open_channel_statistics_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_socket_common_tester_statistics_init(allocator, &c_tester);

    struct aws_byte_buf read_tag = aws_byte_buf_from_c_str("Some bytes");
    struct aws_byte_buf write_tag = aws_byte_buf_from_c_str("Fresh pressed Washington apples");

    uint8_t outgoing_received_message[128];
    uint8_t incoming_received_message[128];

    struct socket_test_rw_args incoming_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &incoming_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(incoming_received_message, sizeof(incoming_received_message)),
        0));

    struct socket_test_rw_args outgoing_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &outgoing_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(outgoing_received_message, sizeof(outgoing_received_message)),
        0));

    struct aws_channel_handler *outgoing_rw_handler = rw_handler_new(
        allocator, s_socket_test_handle_read, s_socket_test_handle_write, true, 10000, &outgoing_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_channel_handler *incoming_rw_handler = rw_handler_new(
        allocator, s_socket_test_handle_read, s_socket_test_handle_write, true, 10000, &incoming_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct socket_test_args incoming_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&incoming_args, &c_tester, incoming_rw_handler));

    struct socket_test_args outgoing_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&outgoing_args, &c_tester, outgoing_rw_handler));

    struct local_server_tester local_server_tester;
    ASSERT_SUCCESS(s_local_server_tester_init(allocator, &local_server_tester, &incoming_args, &c_tester, false));

    /* this should not get used for a unix domain socket. */
    struct aws_host_resolver dummy_resolver;
    AWS_ZERO_STRUCT(dummy_resolver);

    struct aws_client_bootstrap_options bootstrap_options;
    AWS_ZERO_STRUCT(bootstrap_options);
    bootstrap_options.event_loop_group = &c_tester.el_group;
    bootstrap_options.host_resolver = &dummy_resolver;

    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_socket_channel_bootstrap_options channel_options;
    AWS_ZERO_STRUCT(channel_options);
    channel_options.bootstrap = client_bootstrap;
    channel_options.host_name = local_server_tester.endpoint.address;
    channel_options.port = 0;
    channel_options.socket_options = &local_server_tester.socket_options;
    channel_options.creation_callback = s_creation_callback_test_channel_creation_callback;
    channel_options.setup_callback = s_socket_handler_test_client_setup_callback;
    channel_options.shutdown_callback = s_socket_handler_test_client_shutdown_callback;
    channel_options.user_data = &outgoing_args;

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&channel_options));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_setup_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_setup_predicate, &outgoing_args));

    ASSERT_TRUE(outgoing_args.creation_callback_invoked);

    struct aws_channel_slot *outgoing_slot = aws_atomic_load_ptr(&outgoing_args.rw_slot);
    rw_handler_write(outgoing_args.rw_handler, outgoing_slot, &write_tag);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_socket_test_read_predicate, &incoming_rw_args));

    struct aws_channel_slot *incoming_slot = aws_atomic_load_ptr(&incoming_args.rw_slot);
    rw_handler_write(incoming_args.rw_handler, incoming_slot, &read_tag);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_socket_test_read_predicate, &outgoing_rw_args));

    uint64_t ms_to_ns = aws_timestamp_convert(1, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);

    aws_atomic_store_int(&c_tester.current_time_ns, (size_t)ms_to_ns);

    struct aws_crt_statistics_handler *stats_handler = aws_atomic_load_ptr(&c_tester.stats_handler);
    struct aws_statistics_handler_test_impl *stats_impl = stats_handler->impl;

    aws_mutex_lock(&stats_impl->lock);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &stats_impl->signal, &stats_impl->lock, s_stats_processed_predicate, stats_handler));

    ASSERT_TRUE(stats_impl->total_bytes_read == read_tag.len);
    ASSERT_TRUE(stats_impl->total_bytes_written == write_tag.len);

    aws_mutex_unlock(&stats_impl->lock);

    aws_channel_shutdown(incoming_args.channel, AWS_OP_SUCCESS);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_shutdown_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_shutdown_predicate, &outgoing_args));

    aws_server_bootstrap_destroy_socket_listener(local_server_tester.server_bootstrap, local_server_tester.listener);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_listener_destroy_predicate, &incoming_args));

    aws_mutex_unlock(&c_tester.mutex);

    /* clean up */
    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_local_server_tester_clean_up(&local_server_tester));
    ASSERT_SUCCESS(s_socket_common_tester_clean_up(&c_tester));
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(open_channel_statistics_test, s_open_channel_statistics_test)
