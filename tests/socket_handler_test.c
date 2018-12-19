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
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/io/socket_channel_handler.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>

#include <aws/testing/aws_test_harness.h>

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
    struct aws_channel_slot *rw_slot;
    int error_code;
    bool shutdown_invoked;
    bool error_invoked;
};

static bool s_channel_setup_predicate(void *user_data) {
    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;
    return setup_test_args->rw_slot != NULL;
}

static bool s_channel_shutdown_predicate(void *user_data) {
    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;
    bool finished = setup_test_args->shutdown_invoked;
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
    setup_test_args->rw_slot = rw_slot;

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
    setup_test_args->rw_slot = rw_slot;

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

static int s_socket_echo_and_backpressure_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_event_loop_group el_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&el_group, allocator, 0));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct aws_byte_buf read_tag = aws_byte_buf_from_c_str("I'm a little teapot.");
    struct aws_byte_buf write_tag = aws_byte_buf_from_c_str("I'm a big teapot");

    uint8_t incoming_received_message[128] = {0};
    uint8_t outgoing_received_message[128] = {0};

    struct socket_test_rw_args incoming_rw_args = {
        .mutex = &mutex,
        .condition_variable = &condition_variable,
        .received_message = aws_byte_buf_from_array(incoming_received_message, sizeof(incoming_received_message)),
        .invocation_happened = false,
        .shutdown_finished = false,
        .amount_read = 0,
        .expected_read = (int)write_tag.len,
    };
    incoming_rw_args.received_message.len = 0;

    struct socket_test_rw_args outgoing_rw_args = {
        .mutex = &mutex,
        .condition_variable = &condition_variable,
        .received_message = aws_byte_buf_from_array(outgoing_received_message, 0),
        .invocation_happened = false,
        .shutdown_finished = false,
        .amount_read = 0,
        .expected_read = (int)read_tag.len,
    };
    outgoing_rw_args.received_message.len = 0;

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

    struct socket_test_args incoming_args = {
        .mutex = &mutex,
        .allocator = allocator,
        .condition_variable = &condition_variable,
        .error_invoked = false,
        .shutdown_invoked = false,
        .error_code = 0,
        .rw_handler = incoming_rw_handler,
    };

    struct socket_test_args outgoing_args = {
        .mutex = &mutex,
        .allocator = allocator,
        .condition_variable = &condition_variable,
        .error_invoked = false,
        .shutdown_invoked = false,
        .error_code = 0,
        .rw_handler = outgoing_rw_handler,
    };

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));

    struct aws_socket_endpoint endpoint;

    snprintf(endpoint.address, sizeof(endpoint.address), LOCAL_SOCK_TEST_PATTERN, (long long unsigned)timestamp);

    struct aws_server_bootstrap *server_bootstrap = aws_server_bootstrap_new(allocator, &el_group);
    ASSERT_NOT_NULL(server_bootstrap);
    struct aws_socket *listener = aws_server_bootstrap_new_socket_listener(
        server_bootstrap,
        &endpoint,
        &options,
        s_socket_handler_test_server_setup_callback,
        s_socket_handler_test_server_shutdown_callback,
        &incoming_args);
    ASSERT_NOT_NULL(listener);

    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &el_group, NULL, NULL);
    ASSERT_NOT_NULL(client_bootstrap);

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(
        client_bootstrap,
        endpoint.address,
        0,
        &options,
        s_socket_handler_test_client_setup_callback,
        s_socket_handler_test_client_shutdown_callback,
        &outgoing_args));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_channel_setup_predicate, &incoming_args));
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_channel_setup_predicate, &outgoing_args));

    rw_handler_write(outgoing_args.rw_handler, outgoing_args.rw_slot, &write_tag);
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_socket_test_read_predicate, &incoming_rw_args));

    rw_handler_write(incoming_args.rw_handler, incoming_args.rw_slot, &read_tag);
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_socket_test_read_predicate, &outgoing_rw_args));
    incoming_rw_args.invocation_happened = false;
    outgoing_rw_args.invocation_happened = false;

    ASSERT_INT_EQUALS(s_outgoing_initial_read_window, outgoing_rw_args.amount_read);
    ASSERT_INT_EQUALS(s_incoming_initial_read_window, incoming_rw_args.amount_read);

    /* Go ahead and verify back-pressure works*/
    rw_handler_trigger_increment_read_window(incoming_args.rw_handler, incoming_args.rw_slot, 100);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_socket_test_full_read_predicate, &incoming_rw_args));

    rw_handler_trigger_increment_read_window(outgoing_args.rw_handler, outgoing_args.rw_slot, 100);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_socket_test_full_read_predicate, &outgoing_rw_args));

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

    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_channel_shutdown_predicate, &incoming_args));
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_channel_shutdown_predicate, &outgoing_args));

    aws_mutex_unlock(&mutex);
    ASSERT_SUCCESS(aws_server_bootstrap_destroy_socket_listener(server_bootstrap, listener));
    aws_client_bootstrap_destroy(client_bootstrap);
    aws_server_bootstrap_destroy(server_bootstrap);
    aws_event_loop_group_clean_up(&el_group);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socket_handler_echo_and_backpressure, s_socket_echo_and_backpressure_test)

static int s_socket_close_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_event_loop_group el_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&el_group, allocator, 0));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    uint8_t outgoing_received_message[128];
    uint8_t incoming_received_message[128];

    struct socket_test_rw_args incoming_rw_args = {
        .mutex = &mutex,
        .condition_variable = &condition_variable,
        .received_message = aws_byte_buf_from_array(incoming_received_message, sizeof(incoming_received_message)),
    };

    struct socket_test_rw_args outgoing_rw_args = {
        .mutex = &mutex,
        .condition_variable = &condition_variable,
        .received_message = aws_byte_buf_from_array(outgoing_received_message, sizeof(outgoing_received_message)),
    };

    struct aws_channel_handler *outgoing_rw_handler = rw_handler_new(
        allocator, s_socket_test_handle_read, s_socket_test_handle_write, true, 10000, &outgoing_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_channel_handler *incoming_rw_handler = rw_handler_new(
        allocator, s_socket_test_handle_read, s_socket_test_handle_write, true, 10000, &incoming_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct socket_test_args incoming_args = {.mutex = &mutex,
                                             .allocator = allocator,
                                             .condition_variable = &condition_variable,
                                             .error_invoked = false,
                                             .shutdown_invoked = false,
                                             .rw_handler = incoming_rw_handler,
                                             .error_code = 0,
                                             .rw_slot = NULL};

    struct socket_test_args outgoing_args = {.mutex = &mutex,
                                             .allocator = allocator,
                                             .condition_variable = &condition_variable,
                                             .error_invoked = false,
                                             .shutdown_invoked = false,
                                             .rw_handler = outgoing_rw_handler,
                                             .error_code = 0,
                                             .rw_slot = NULL};

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));

    struct aws_socket_endpoint endpoint;

    snprintf(endpoint.address, sizeof(endpoint.address), LOCAL_SOCK_TEST_PATTERN, (long long unsigned)timestamp);

    struct aws_server_bootstrap *server_bootstrap = aws_server_bootstrap_new(allocator, &el_group);
    ASSERT_NOT_NULL(server_bootstrap);
    struct aws_socket *listener = aws_server_bootstrap_new_socket_listener(
        server_bootstrap,
        &endpoint,
        &options,
        s_socket_handler_test_server_setup_callback,
        s_socket_handler_test_server_shutdown_callback,
        &incoming_args);
    ASSERT_NOT_NULL(listener);

    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &el_group, NULL, NULL);
    ASSERT_NOT_NULL(client_bootstrap);

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(
        client_bootstrap,
        endpoint.address,
        0,
        &options,
        s_socket_handler_test_client_setup_callback,
        s_socket_handler_test_client_shutdown_callback,
        &outgoing_args));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_channel_setup_predicate, &incoming_args));
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_channel_setup_predicate, &outgoing_args));

    aws_channel_shutdown(incoming_args.channel, AWS_OP_SUCCESS);

    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_channel_shutdown_predicate, &incoming_args));
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_channel_shutdown_predicate, &outgoing_args));

    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, incoming_args.error_code);
    ASSERT_TRUE(
        AWS_IO_SOCKET_CLOSED == outgoing_args.error_code || AWS_IO_SOCKET_NOT_CONNECTED == outgoing_args.error_code);

    ASSERT_SUCCESS(aws_server_bootstrap_destroy_socket_listener(server_bootstrap, listener));
    aws_client_bootstrap_destroy(client_bootstrap);
    aws_server_bootstrap_destroy(server_bootstrap);
    aws_event_loop_group_clean_up(&el_group);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socket_handler_close, s_socket_close_test)
