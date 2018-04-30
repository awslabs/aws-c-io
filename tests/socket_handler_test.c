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
#include <read_write_test_handler.c>

struct socket_channel_setup_test_args {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    int error_code;
};

static void socket_channel_setup_test_on_setup_completed(struct aws_channel *channel, int error_code, void *ctx) {
    struct socket_channel_setup_test_args *setup_test_args = (struct socket_channel_setup_test_args *)ctx;

    aws_mutex_lock(&setup_test_args->mutex);
    setup_test_args->error_code |= error_code;
    aws_condition_variable_notify_one(&setup_test_args->condition_variable);
    aws_mutex_unlock(&setup_test_args->mutex);
}

struct socket_test_listener_args {
    struct aws_socket *incoming;
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    bool incoming_invoked;
    bool error_invoked;
};

static void socket_test_listener_incoming(struct aws_socket *socket, struct aws_socket *new_socket, void *ctx) {
    struct socket_test_listener_args *listener_args = (struct socket_test_listener_args *)ctx;
    aws_mutex_lock(listener_args->mutex);
    listener_args->incoming = new_socket;
    listener_args->incoming_invoked = true;
    aws_condition_variable_notify_one(listener_args->condition_variable);
    aws_mutex_unlock(listener_args->mutex);
}

static void socket_test_listener_on_error(struct aws_socket *socket, int err_code, void *ctx) {
    struct socket_test_listener_args *listener_args = (struct socket_test_listener_args *)ctx;
    listener_args->error_invoked = true;
}

static void socket_test_null_connection_handler(struct aws_socket *socket, void *ctx) {}


static int socket_echo_test (struct aws_allocator *allocator, void *ctx) {
    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_channel incoming_channel;
    struct aws_channel outgoing_channel;

    struct channel_setup_test_args test_args = {
            .error_code = 0,
            .mutex = AWS_MUTEX_INIT,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_channel_init(&incoming_channel, allocator, event_loop, socket_channel_setup_test_on_setup_completed, &test_args));
    ASSERT_SUCCESS(aws_channel_init(&outgoing_channel, allocator, event_loop, socket_channel_setup_test_on_setup_completed, &test_args));

    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &test_args.mutex));

    struct aws_channel_slot *incoming_slot_1, *incoming_slot_2;
    incoming_slot_1 = aws_channel_slot_new(&incoming_channel);
    incoming_slot_2 = aws_channel_slot_new(&incoming_channel);

    ASSERT_NOT_NULL(incoming_slot_1);
    ASSERT_NOT_NULL(incoming_slot_2);

    ASSERT_SUCCESS(aws_channel_slot_insert_right(incoming_slot_1, incoming_slot_2));

    struct aws_channel_slot *outgoing_slot_1 = NULL, *outgoing_slot_2 = NULL;
    outgoing_slot_1 = aws_channel_slot_new(&outgoing_channel);
    outgoing_slot_2 = aws_channel_slot_new(&outgoing_channel);

    ASSERT_NOT_NULL(outgoing_slot_1);
    ASSERT_NOT_NULL(outgoing_slot_2);

    ASSERT_SUCCESS(aws_channel_slot_insert_right(outgoing_slot_1, outgoing_slot_2));

    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));

    struct aws_socket_endpoint endpoint;

    sprintf(endpoint.socket_name, "testsock%llu.sock", (long long unsigned)timestamp);
    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct local_listener_args listener_args = {
            .mutex = &mutex,
            .condition_variable = &condition_variable,
            .incoming = NULL,
            .incoming_invoked = false,
            .error_invoked = false,
    };

    struct aws_socket_creation_args listener_creation_args = {
            .on_incoming_connection = socket_test_listener_incoming,
            .on_error = socket_test_listener_on_error,
            .on_connection_established = NULL,
            .ctx = &listener_args,
    };

    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, &options, event_loop, &listener_creation_args));

    ASSERT_SUCCESS(aws_socket_bind(&listener, &endpoint));
    ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));
    ASSERT_SUCCESS(aws_socket_start_accept(&listener));


    struct local_outgoing_args outgoing_args = {
            .mutex = &mutex,
            .condition_variable = &condition_variable,
            .connect_invoked = false,
            .error_invoked = false
    };

    struct aws_socket_creation_args outgoing_creation_args = {
            .on_connection_established = socket_test_null_connection_handler,
            .on_error = NULL,
            .ctx = &outgoing_args
    };

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options, event_loop, &outgoing_creation_args));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint));

    ASSERT_SUCCESS(aws_condition_variable_wait(&condition_variable, &mutex));

    struct aws_channel_handler *outgoing_socket_handler = aws_socket_handler_new(allocator, &outgoing,
                                                                                 outgoing_slot_1, event_loop, 100);
    ASSERT_NOT_NULL(outgoing_socket_handler);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(outgoing_slot_1, outgoing_socket_handler));

    struct aws_channel_handler *incoming_socket_handler = aws_socket_handler_new(allocator, listener_args.incoming,
                                                                                 incoming_slot_1, event_loop, 100);
    ASSERT_NOT_NULL(outgoing_socket_handler);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(incoming_slot_1, incoming_socket_handler));

    struct aws_byte_buf read_tag = aws_byte_buf_from_literal("read from incoming");
    struct aws_byte_buf write_tag = aws_byte_buf_from_literal("write to outgoing");

    struct aws_channel_handler *outgoing_rw_handler = rw_test_handler_new(allocator, read_tag, write_tag);
    ASSERT_NOT_NULL(outgoing_rw_handler);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(outgoing_slot_2, outgoing_rw_handler));

    struct aws_channel_handler *incoming_rw_handler = rw_test_handler_new(allocator, read_tag, write_tag);
    ASSERT_NOT_NULL(outgoing_rw_handler);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(incoming_slot_2, incoming_rw_handler));

    size_t written = 0;
    ASSERT_SUCCESS(aws_socket_write(&outgoing, &write_tag, &written));

    while(true) {}

    aws_channel_clean_up(&incoming_channel);
    aws_channel_clean_up(&outgoing_channel);

    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socket_echo, socket_echo_test)
