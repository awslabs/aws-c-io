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
#include <aws/io/tls_channel_handler.h>
#include <aws/io/socket.h>
#include <read_write_test_handler.c>

struct tls_test_args {
    struct aws_allocator *allocator;
    struct aws_event_loop *event_loop;
    struct aws_socket *socket;
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_channel channel;
    struct aws_channel_handler *tls_handler;
    struct aws_tls_connection_options *options;
    struct aws_channel_slot *tls_slot;
    struct aws_channel_handler *rw_handler;
    struct aws_channel_slot *rw_slot;
    struct aws_tls_ctx *tls_ctx;
    bool error_invoked;
    bool server;
};

static bool tls_channel_setup_predicate(void *ctx) {
    struct tls_test_args *setup_test_args = (struct tls_test_args *)ctx;
    return setup_test_args->rw_slot != NULL;
}

void tls_on_negotiation_result(struct aws_channel_handler *handler, struct aws_channel_slot *slot, int err_code, void *ctx) {
    struct tls_test_args *setup_test_args = (struct tls_test_args *)ctx;
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

static void tls_socket_channel_setup_test_on_setup_completed(struct aws_channel *channel, int error_code, void *ctx) {
    struct tls_test_args *setup_test_args = (struct tls_test_args *)ctx;

    struct aws_channel_slot *socket_slot = aws_channel_slot_new(channel);
    struct aws_channel_handler *socket_handler =
            aws_socket_handler_new(setup_test_args->allocator, setup_test_args->socket, socket_slot, setup_test_args->event_loop,
                                   AWS_SOCKET_HANDLER_DEFAULT_MAX_RW);
    aws_channel_slot_set_handler(socket_slot, socket_handler);

    struct aws_channel_slot *tls_slot = aws_channel_slot_new(channel);

    setup_test_args->options->ctx = setup_test_args;

    if (setup_test_args->server) {
        setup_test_args->tls_handler = aws_tls_server_handler_new(setup_test_args->allocator, setup_test_args->tls_ctx,
                                                                  setup_test_args->options, tls_slot);
    }
    else {
        setup_test_args->tls_handler = aws_tls_client_handler_new(setup_test_args->allocator, setup_test_args->tls_ctx,
                                                                  setup_test_args->options, tls_slot);
    }

    aws_channel_slot_set_handler(tls_slot, setup_test_args->tls_handler);
    aws_channel_slot_insert_right(socket_slot, tls_slot);

    struct aws_channel_slot *rw_slot = aws_channel_slot_new(channel);
    aws_channel_slot_set_handler(rw_slot, setup_test_args->rw_handler);
    aws_channel_slot_insert_right(tls_slot, rw_slot);
    setup_test_args->rw_slot = rw_slot;

    if (!setup_test_args->server) {
        aws_tls_client_handler_start_negotiation(setup_test_args->tls_handler);
    }
}

static void tls_socket_test_listener_incoming(struct aws_socket *socket, struct aws_socket *new_socket, void *ctx) {
    struct tls_test_args *listener_args = (struct tls_test_args *)ctx;
    listener_args->socket = new_socket;
    aws_channel_init(&listener_args->channel, listener_args->allocator,
                     listener_args->event_loop, tls_socket_channel_setup_test_on_setup_completed, listener_args);
}

static void tls_socket_test_listener_on_error(struct aws_socket *socket, int err_code, void *ctx) {
    struct tls_test_args *listener_args = (struct tls_test_args *)ctx;
    listener_args->error_invoked = true;
}

static void tls_socket_test_connection_handler(struct aws_socket *socket, void *ctx) {
    struct tls_test_args *connection_args = (struct tls_test_args *)ctx;
    connection_args->socket = socket;
    aws_channel_init(&connection_args->channel, connection_args->allocator,
                     connection_args->event_loop, tls_socket_channel_setup_test_on_setup_completed, connection_args);
}

struct tls_test_rw_args {
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_byte_buf received_message;
    int read_invocations;
    bool invocation_happened;
};

static bool tls_test_read_predicate(void *ctx) {
    struct tls_test_rw_args *rw_args = (struct tls_test_rw_args *)ctx;

    return rw_args->invocation_happened;
}

struct aws_byte_buf tls_test_handle_read(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                            struct aws_byte_buf *data_read, void *ctx) {
    struct tls_test_rw_args *rw_args = (struct tls_test_rw_args *)ctx;

    memcpy(rw_args->received_message.buffer + rw_args->received_message.len, data_read->buffer, data_read->len);
    rw_args->received_message.len += data_read->len;
    rw_args->read_invocations += 1;
    rw_args->invocation_happened = true;
    aws_condition_variable_notify_one(rw_args->condition_variable);

    return rw_args->received_message;
}

struct aws_byte_buf tls_test_handle_write(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                             struct aws_byte_buf *data_read, void *ctx) {
    /*do nothing*/
    return (struct aws_byte_buf){0};
}

static int tls_channel_echo_and_backpressure_test_fn (struct aws_allocator *allocator, void *ctx) {
    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct aws_byte_buf read_tag = aws_byte_buf_from_literal("I'm a little teapot");
    struct aws_byte_buf write_tag = aws_byte_buf_from_literal("I'm a big teapot");

    uint8_t incoming_received_message[128] = {0};
    uint8_t outgoing_received_message[128] = {0};

    struct tls_test_rw_args incoming_rw_args = {
            .mutex = &mutex,
            .condition_variable = &condition_variable,
            .received_message = aws_byte_buf_from_array(incoming_received_message, 0),
            .invocation_happened = false,
    };

    struct tls_test_rw_args outgoing_rw_args = {
            .mutex = &mutex,
            .condition_variable = &condition_variable,
            .received_message = aws_byte_buf_from_array(outgoing_received_message, 0),
            .invocation_happened = false,
    };

    /* make the windows small to make sure back pressure is honored. */
    struct aws_channel_handler *outgoing_rw_handler = rw_test_handler_new(allocator, tls_test_handle_read,
                                                                         tls_test_handle_write, true, write_tag.len / 2, &outgoing_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_channel_handler *incoming_rw_handler = rw_test_handler_new(allocator, tls_test_handle_read,
                                                                          tls_test_handle_write, true, read_tag.len / 2, &incoming_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    aws_tls_init_static_state(allocator);

    struct aws_tls_connection_options tls_conn_options = {
            .server_name = NULL,
            .verify_peer = false,
            .alpn_list = NULL,
            .verify_host_fn = NULL,
            .on_data_read = NULL,
            .on_negotiation_result = tls_on_negotiation_result,
            .on_error = NULL,
    };

    struct aws_tls_ctx_options server_ctx_options = {
            .alpn_list = NULL,
            .verify_peer = false,
            .server_name = NULL,
            .ca_path = NULL,
            .ca_file = NULL,
            .private_key_path = NULL,
            .certificate_path = NULL,
            .version_blacklist = 0,
    };

    struct aws_tls_ctx *server_ctx = aws_tls_server_ctx_new(allocator, &server_ctx_options);

    struct tls_test_args incoming_args = {
            .mutex = &mutex,
            .event_loop = event_loop,
            .allocator = allocator,
            .condition_variable = &condition_variable,
            .error_invoked = 0,
            .socket = NULL,
            .rw_handler = incoming_rw_handler,
            .options = &tls_conn_options,
            .tls_handler = NULL,
            .server = true,
            .tls_ctx = server_ctx,
    };

    struct aws_tls_ctx_options client_ctx_options = {
            .alpn_list = NULL,
            .verify_peer = false,
            .server_name = NULL,
            .ca_path = NULL,
            .ca_file = NULL,
            .private_key_path = NULL,
            .certificate_path = NULL,
            .version_blacklist = 0
    };

    struct aws_tls_ctx *client_ctx = aws_tls_client_ctx_new(allocator, &client_ctx_options);

    struct tls_test_args outgoing_args = {
            .mutex = &mutex,
            .event_loop = event_loop,
            .allocator = allocator,
            .condition_variable = &condition_variable,
            .error_invoked = 0,
            .socket = NULL,
            .rw_handler = outgoing_rw_handler,
            .options = &tls_conn_options,
            .tls_handler = NULL,
            .server = false,
            .tls_ctx = client_ctx
    };

    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));

    struct aws_socket_endpoint endpoint;

    sprintf(endpoint.socket_name, "testsock%llu.sock", (long long unsigned)timestamp);

    struct aws_socket_creation_args listener_creation_args = {
            .on_incoming_connection = tls_socket_test_listener_incoming,
            .on_error = tls_socket_test_listener_on_error,
            .on_connection_established = NULL,
            .ctx = &incoming_args,
    };

    struct aws_socket listener;
    ASSERT_SUCCESS(aws_socket_init(&listener, allocator, &options, event_loop, &listener_creation_args));

    ASSERT_SUCCESS(aws_socket_bind(&listener, &endpoint));
    ASSERT_SUCCESS(aws_socket_listen(&listener, 1024));
    ASSERT_SUCCESS(aws_socket_start_accept(&listener));

    struct aws_socket_creation_args outgoing_creation_args = {
            .on_connection_established = tls_socket_test_connection_handler,
            .on_error = NULL,
            .ctx = &outgoing_args
    };

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));

    struct aws_socket outgoing;
    ASSERT_SUCCESS(aws_socket_init(&outgoing, allocator, &options, event_loop, &outgoing_creation_args));
    ASSERT_SUCCESS(aws_socket_connect(&outgoing, &endpoint));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_channel_setup_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_channel_setup_predicate, &outgoing_args));

    rw_handler_write(outgoing_args.rw_handler, outgoing_args.rw_slot, &write_tag);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_test_read_predicate, &incoming_rw_args));

    rw_handler_write(incoming_args.rw_handler, incoming_args.rw_slot, &read_tag);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_test_read_predicate, &outgoing_rw_args));
    incoming_rw_args.invocation_happened = false;
    outgoing_rw_args.invocation_happened = false;

    ASSERT_INT_EQUALS(1, outgoing_rw_args.read_invocations);
    ASSERT_INT_EQUALS(1, incoming_rw_args.read_invocations);

    /* Go ahead and verify back-pressure works*/
    rw_handler_update_window(incoming_args.rw_handler, incoming_args.rw_slot, 100);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_test_read_predicate, &incoming_rw_args));
    rw_handler_update_window(outgoing_args.rw_handler, outgoing_args.rw_slot, 100);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_test_read_predicate, &outgoing_rw_args));

    ASSERT_INT_EQUALS(2, outgoing_rw_args.read_invocations);
    ASSERT_INT_EQUALS(2, incoming_rw_args.read_invocations);

    ASSERT_BIN_ARRAYS_EQUALS(write_tag.buffer, write_tag.len, incoming_rw_args.received_message.buffer,
                             incoming_rw_args.received_message.len);
    ASSERT_BIN_ARRAYS_EQUALS(read_tag.buffer, read_tag.len, outgoing_rw_args.received_message.buffer,
                             outgoing_rw_args.received_message.len);

    aws_channel_clean_up(&incoming_args.channel);
    aws_channel_clean_up(&outgoing_args.channel);

    aws_mem_release(allocator, incoming_args.socket);
    aws_socket_clean_up(&listener);

    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(tls_channel_echo_and_backpressure_test, tls_channel_echo_and_backpressure_test_fn)
