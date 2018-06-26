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

#include <aws/testing/aws_test_harness.h>
#include <aws/io/socket_channel_handler.h>
#include <aws/io/socket.h>
#include <aws/io/channel_bootstrap.h>
#include <read_write_test_handler.c>

struct socket_test_args {
    struct aws_allocator *allocator;
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_channel *channel;
    struct aws_channel_handler *rw_handler;
    struct aws_channel_slot *rw_slot;
    bool shutdown_invoked;
    bool error_invoked;
};

static bool channel_setup_predicate(void *user_data) {
    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;
    return setup_test_args->rw_slot != NULL;
}

static bool channel_shutdown_predicate(void *user_data) {
    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;
    return setup_test_args->shutdown_invoked;
}

static int socket_handler_test_client_setup_callback (struct aws_client_bootstrap *bootstrap, int error_code, struct aws_channel *channel, void *user_data) {
    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;

    setup_test_args->channel = channel;

    struct aws_channel_slot *rw_slot = aws_channel_slot_new(channel);
    aws_channel_slot_insert_end(channel, rw_slot);

    aws_channel_slot_set_handler(rw_slot, setup_test_args->rw_handler);
    setup_test_args->rw_slot = rw_slot;

    aws_condition_variable_notify_one(setup_test_args->condition_variable);
    return 0;
}

static int socket_handler_test_server_setup_callback (struct aws_server_bootstrap *bootstrap, int error_code, struct aws_channel *channel, void *user_data) {
    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;

    setup_test_args->channel = channel;

    struct aws_channel_slot *rw_slot = aws_channel_slot_new(channel);
    aws_channel_slot_insert_end(channel, rw_slot);

    aws_channel_slot_set_handler(rw_slot, setup_test_args->rw_handler);
    setup_test_args->rw_slot = rw_slot;

    aws_condition_variable_notify_one(setup_test_args->condition_variable);
    return 0;
}

static int socket_handler_test_client_shutdown_callback(struct aws_client_bootstrap *bootstrap, int error_code, struct aws_channel *channel, void *user_data) {
    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;

    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->shutdown_invoked = true;
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
    aws_mutex_unlock(setup_test_args->mutex);

    return 0;
}

static int socket_handler_test_server_shutdown_callback(struct aws_server_bootstrap *bootstrap, int error_code, struct aws_channel *channel, void *user_data) {
    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;

    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->shutdown_invoked = true;
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
    aws_mutex_unlock(setup_test_args->mutex);

    return 0;
}

struct socket_test_rw_args {
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_byte_buf received_message;
    int read_invocations;
    bool invocation_happened;
    bool shutdown_finished;
};

static bool socket_test_read_predicate(void *user_data) {
    struct socket_test_rw_args *rw_args = (struct socket_test_rw_args *)user_data;
    return rw_args->invocation_happened;
}

struct aws_byte_buf socket_test_handle_read(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                             struct aws_byte_buf *data_read, void *user_data) {
    struct socket_test_rw_args *rw_args = (struct socket_test_rw_args *)user_data;

    aws_mutex_lock(rw_args->mutex);
    memcpy(rw_args->received_message.buffer + rw_args->received_message.len, data_read->buffer, data_read->len);
    rw_args->received_message.len += data_read->len;
    rw_args->read_invocations += 1;
    rw_args->invocation_happened = true;
    aws_condition_variable_notify_one(rw_args->condition_variable);
    aws_mutex_unlock(rw_args->mutex);

    return rw_args->received_message;
}

struct aws_byte_buf socket_test_handle_write(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                            struct aws_byte_buf *data_read, void *user_data) {
    /*do nothing*/
    return (struct aws_byte_buf){0};
}

static int socket_echo_and_backpressure_test (struct aws_allocator *allocator, void *user_data) {
    struct aws_event_loop_group el_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&el_group, allocator));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct aws_byte_buf read_tag = aws_byte_buf_from_c_str("I'm a little teapot");
    struct aws_byte_buf write_tag = aws_byte_buf_from_c_str("I'm a big teapot");

    uint8_t incoming_received_message[128] = {0};
    uint8_t outgoing_received_message[128] = {0};

    struct socket_test_rw_args incoming_rw_args = {
            .mutex = &mutex,
            .condition_variable = &condition_variable,
            .received_message = aws_byte_buf_from_array(incoming_received_message, sizeof(incoming_received_message)),
            .invocation_happened = false,
            .shutdown_finished = false,
    };
    incoming_rw_args.received_message.len = 0;

    struct socket_test_rw_args outgoing_rw_args = {
            .mutex = &mutex,
            .condition_variable = &condition_variable,
            .received_message = aws_byte_buf_from_array(outgoing_received_message, 0),
            .invocation_happened = false,
            .shutdown_finished = false,
    };
    outgoing_rw_args.received_message.len = 0;


    /* make the windows small to make sure back pressure is honored. */
    struct aws_channel_handler *outgoing_rw_handler = rw_test_handler_new(allocator, socket_test_handle_read,
                                                                          socket_test_handle_write, true, write_tag.len / 2, &outgoing_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_channel_handler *incoming_rw_handler = rw_test_handler_new(allocator, socket_test_handle_read,
                                                                          socket_test_handle_write, true, read_tag.len / 2, &incoming_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct socket_test_args incoming_args = {
            .mutex = &mutex,
            .allocator = allocator,
            .condition_variable = &condition_variable,
            .error_invoked = false,
            .shutdown_invoked = false,
            .rw_handler = incoming_rw_handler,
    };

    struct socket_test_args outgoing_args = {
            .mutex = &mutex,
            .allocator = allocator,
            .condition_variable = &condition_variable,
            .error_invoked = false,
            .shutdown_invoked = false,
            .rw_handler = outgoing_rw_handler,
    };

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));

    struct aws_socket_endpoint endpoint;

    snprintf(endpoint.socket_name, sizeof(endpoint.socket_name), "testsock%llu.sock", (long long unsigned)timestamp);

    struct aws_server_bootstrap server_bootstrap;
    ASSERT_SUCCESS(aws_server_bootstrap_init(&server_bootstrap, allocator, &el_group));
    struct aws_socket *listener = aws_server_bootstrap_add_socket_listener(&server_bootstrap, &endpoint, &options,
                                                                                    socket_handler_test_server_setup_callback, socket_handler_test_server_shutdown_callback, &incoming_args);
    ASSERT_NOT_NULL(listener);

    struct aws_client_bootstrap client_bootstrap;
    ASSERT_SUCCESS(aws_client_bootstrap_init(&client_bootstrap, allocator, &el_group));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&client_bootstrap, &endpoint, &options,
                                                           socket_handler_test_client_setup_callback, socket_handler_test_client_shutdown_callback, &outgoing_args));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, channel_setup_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, channel_setup_predicate, &outgoing_args));

    rw_handler_write(outgoing_args.rw_handler, outgoing_args.rw_slot, &write_tag);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, socket_test_read_predicate, &incoming_rw_args));

    rw_handler_write(incoming_args.rw_handler, incoming_args.rw_slot, &read_tag);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, socket_test_read_predicate, &outgoing_rw_args));
    incoming_rw_args.invocation_happened = false;
    outgoing_rw_args.invocation_happened = false;

    ASSERT_INT_EQUALS(1, outgoing_rw_args.read_invocations);
    ASSERT_INT_EQUALS(1, incoming_rw_args.read_invocations);

    /* Go ahead and verify back-pressure works*/
    rw_handler_trigger_increment_read_window(incoming_args.rw_handler, incoming_args.rw_slot, 100);
    rw_handler_trigger_increment_read_window(outgoing_args.rw_handler, outgoing_args.rw_slot, 100);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, socket_test_read_predicate, &incoming_rw_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, socket_test_read_predicate, &outgoing_rw_args));

    ASSERT_INT_EQUALS(2, outgoing_rw_args.read_invocations);
    ASSERT_INT_EQUALS(2, incoming_rw_args.read_invocations);

    ASSERT_BIN_ARRAYS_EQUALS(write_tag.buffer, write_tag.len, incoming_rw_args.received_message.buffer,
                             incoming_rw_args.received_message.len);
    ASSERT_BIN_ARRAYS_EQUALS(read_tag.buffer, read_tag.len, outgoing_rw_args.received_message.buffer,
                             outgoing_rw_args.received_message.len);

    ASSERT_SUCCESS(aws_channel_shutdown(incoming_args.channel, AWS_OP_SUCCESS));
    ASSERT_SUCCESS(aws_channel_shutdown(outgoing_args.channel, AWS_OP_SUCCESS));

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, channel_shutdown_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, channel_shutdown_predicate, &outgoing_args));

    aws_mutex_unlock(&mutex);
    ASSERT_SUCCESS(aws_server_bootstrap_remove_socket_listener(&server_bootstrap, listener));
    aws_event_loop_group_clean_up(&el_group);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socket_handler_echo_and_backpressure, socket_echo_and_backpressure_test)

static int socket_close_test (struct aws_allocator *allocator, void *user_data) {
    struct aws_event_loop_group el_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&el_group, allocator));

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

    struct aws_channel_handler *outgoing_rw_handler = rw_test_handler_new(allocator, socket_test_handle_read,
                                                                          socket_test_handle_write, true, 10000, &outgoing_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_channel_handler *incoming_rw_handler = rw_test_handler_new(allocator, socket_test_handle_read,
                                                                          socket_test_handle_write, true, 10000, &incoming_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct socket_test_args incoming_args = {
            .mutex = &mutex,
            .allocator = allocator,
            .condition_variable = &condition_variable,
            .error_invoked = false,
            .shutdown_invoked = false,
            .rw_handler = incoming_rw_handler,
            .rw_slot = NULL
    };

    struct socket_test_args outgoing_args = {
            .mutex = &mutex,
            .allocator = allocator,
            .condition_variable = &condition_variable,
            .error_invoked = false,
            .shutdown_invoked = false,
            .rw_handler = outgoing_rw_handler,
            .rw_slot = NULL
    };

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));

    struct aws_socket_endpoint endpoint;

    snprintf(endpoint.socket_name, sizeof(endpoint.socket_name), "testsock%llu.sock", (long long unsigned)timestamp);

    struct aws_server_bootstrap server_bootstrap;
    ASSERT_SUCCESS(aws_server_bootstrap_init(&server_bootstrap, allocator, &el_group));
    struct aws_socket *listener = aws_server_bootstrap_add_socket_listener(&server_bootstrap, &endpoint, &options,
                                                                                    socket_handler_test_server_setup_callback, socket_handler_test_server_shutdown_callback, &incoming_args);
    ASSERT_NOT_NULL(listener);

    struct aws_client_bootstrap client_bootstrap;
    ASSERT_SUCCESS(aws_client_bootstrap_init(&client_bootstrap, allocator, &el_group));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&client_bootstrap, &endpoint, &options,
                                                           socket_handler_test_client_setup_callback, socket_handler_test_client_shutdown_callback, &outgoing_args));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, channel_setup_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, channel_setup_predicate, &outgoing_args));

    ASSERT_SUCCESS(aws_mutex_unlock(&mutex));
    aws_channel_shutdown(incoming_args.channel, AWS_OP_SUCCESS);

    ASSERT_SUCCESS(rw_handler_wait_on_shutdown(outgoing_args.rw_handler));
    ASSERT_INT_EQUALS(AWS_IO_SOCKET_CLOSED, rw_handler_last_error_code(outgoing_args.rw_handler));

    ASSERT_SUCCESS(aws_server_bootstrap_remove_socket_listener(&server_bootstrap, listener));
    aws_event_loop_group_clean_up(&el_group);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socket_handler_close, socket_close_test)

