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
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_channel *channel;
    struct aws_channel_handler *rw_handler;
    struct aws_channel_slot *rw_slot;
    struct aws_byte_buf negotiated_protocol;
    struct aws_byte_buf server_name;
    struct aws_byte_buf returned_server_name;
    bool tls_negotiated;
    bool error_invoked;
    bool server;
    bool shutdown_finished;
};

static bool tls_channel_shutdown_predicate(void *user_data) {
    struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;
    return setup_test_args->shutdown_finished;
}

static bool tls_channel_setup_predicate(void *user_data) {
    struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;
    return setup_test_args->tls_negotiated || setup_test_args->error_invoked;
}

static int tls_handler_test_client_setup_callback (struct aws_client_bootstrap *bootstrap, int error_code, struct aws_channel *channel, void *user_data) {
    struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;

    if (!error_code) {
        setup_test_args->channel = channel;
        if (setup_test_args->rw_handler) {
            struct aws_channel_slot *rw_slot = aws_channel_slot_new(channel);
            aws_channel_slot_insert_end(channel, rw_slot);
            aws_channel_slot_set_handler(rw_slot, setup_test_args->rw_handler);
            setup_test_args->rw_slot = rw_slot;
        }
        setup_test_args->tls_negotiated = true;
    }
    else {
        setup_test_args->error_invoked = true;
    }

    aws_condition_variable_notify_one(setup_test_args->condition_variable);

    return AWS_OP_SUCCESS;
}

static int tls_handler_test_server_setup_callback (struct aws_server_bootstrap *bootstrap, int error_code, struct aws_channel *channel, void *user_data) {
    struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;

    aws_mutex_lock(setup_test_args->mutex);
    if (!error_code) {
        setup_test_args->channel = channel;

        if (setup_test_args->rw_handler) {
            struct aws_channel_slot *rw_slot = aws_channel_slot_new(channel);
            aws_channel_slot_insert_end(channel, rw_slot);
            aws_channel_slot_set_handler(rw_slot, setup_test_args->rw_handler);
            setup_test_args->rw_slot = rw_slot;
        }
        setup_test_args->tls_negotiated = true;
    }
    else {
        setup_test_args->error_invoked = true;
    }

    aws_condition_variable_notify_one(setup_test_args->condition_variable);
    aws_mutex_unlock(setup_test_args->mutex);

    return AWS_OP_SUCCESS;
}

static int tls_handler_test_client_shutdown_callback(struct aws_client_bootstrap *bootstrap, int error_code, struct aws_channel *channel, void *user_data) {
    struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;

    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->shutdown_finished = true;
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
    aws_mutex_unlock(setup_test_args->mutex);

    return 0;
}

static int tls_handler_test_server_shutdown_callback(struct aws_server_bootstrap *bootstrap, int error_code, struct aws_channel *channel, void *user_data) {
    struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;

    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->shutdown_finished = true;
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
    aws_mutex_unlock(setup_test_args->mutex);
    return 0;
}

static void tls_on_negotiated(struct aws_channel_handler *handler, struct aws_channel_slot *slot, int err_code, void *user_data) {

    if (!err_code) {
        struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;

        setup_test_args->negotiated_protocol = aws_tls_handler_protocol(handler);
        setup_test_args->server_name = aws_tls_handler_server_name(handler);
    }
}

static bool tls_verify_host_trust_all(struct aws_channel_handler *handler, struct aws_byte_buf *buffer, void *user_data) {
    return true;
}


static bool tls_verify_host_trust_none(struct aws_channel_handler *handler, struct aws_byte_buf *buffer, void *user_data) {
    return false;
}
struct tls_test_rw_args {
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_byte_buf received_message;
    int read_invocations;
    bool invocation_happened;
};

static bool tls_test_read_predicate(void *user_data) {
    struct tls_test_rw_args *rw_args = (struct tls_test_rw_args *)user_data;

    return rw_args->invocation_happened;
}

struct aws_byte_buf tls_test_handle_read(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                            struct aws_byte_buf *data_read, void *user_data) {
    struct tls_test_rw_args *rw_args = (struct tls_test_rw_args *)user_data;

    memcpy(rw_args->received_message.buffer + rw_args->received_message.len, data_read->buffer, data_read->len);
    rw_args->received_message.len += data_read->len;
    rw_args->read_invocations += 1;
    rw_args->invocation_happened = true;
    aws_condition_variable_notify_one(rw_args->condition_variable);

    return rw_args->received_message;
}

struct aws_byte_buf tls_test_handle_write(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                             struct aws_byte_buf *data_read, void *user_data) {
    /*do nothing*/
    return (struct aws_byte_buf){0};
}

static int tls_channel_echo_and_backpressure_test_fn (struct aws_allocator *allocator, void *user_data) {
    struct aws_event_loop_group el_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&el_group, allocator));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct aws_byte_buf read_tag = aws_byte_buf_from_c_str("I'm a little teapot");
    struct aws_byte_buf write_tag = aws_byte_buf_from_c_str("I'm a big teapot");

    uint8_t incoming_received_message[128] = {0};
    uint8_t outgoing_received_message[128] = {0};

    struct tls_test_rw_args incoming_rw_args = {
            .mutex = &mutex,
            .condition_variable = &condition_variable,
            .received_message = aws_byte_buf_from_array(incoming_received_message, 0),
            .invocation_happened = false,
            .read_invocations = 0,
    };

    struct tls_test_rw_args outgoing_rw_args = {
            .mutex = &mutex,
            .condition_variable = &condition_variable,
            .received_message = aws_byte_buf_from_array(outgoing_received_message, 0),
            .invocation_happened = false,
            .read_invocations = 0,
    };

    /* make the windows small to make sure back pressure is honored. */
    struct aws_channel_handler *outgoing_rw_handler = rw_test_handler_new(allocator, tls_test_handle_read,
                                                                         tls_test_handle_write, true, write_tag.len / 2, &outgoing_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_channel_handler *incoming_rw_handler = rw_test_handler_new(allocator, tls_test_handle_read,
                                                                          tls_test_handle_write, true, read_tag.len / 2, &incoming_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_tls_ctx_options server_ctx_options = {
            .alpn_list = "h2;http/1.1",
            .server_name = "localhost",
            .verify_peer = false,
            .ca_path = NULL,
            .ca_file = NULL,
#ifdef __APPLE__
            .pkcs12_path = "./unittests.p12",
#else
            .private_key_path = "./unittests.key",
            .certificate_path = "./unittests.crt",
#endif
            .version_blacklist = 0,
    };

    struct aws_tls_ctx *server_ctx = aws_tls_server_ctx_new(allocator, &server_ctx_options);

    struct tls_test_args incoming_args = {
            .mutex = &mutex,
            .allocator = allocator,
            .condition_variable = &condition_variable,
            .error_invoked = 0,
            .rw_handler = incoming_rw_handler,
            .server = true,
            .tls_negotiated = false,
            .shutdown_finished = false,
    };

    struct aws_tls_ctx_options client_ctx_options = {
            .alpn_list = "h2;http/1.1",
            .verify_peer = true,
            .server_name = NULL,
            .ca_path = NULL,
            .ca_file = "./unittests.crt",
#ifdef __APPLE__
            .pkcs12_path = NULL,
#else
            .private_key_path = NULL,
            .certificate_path = NULL,
#endif
            .version_blacklist = 0
    };

    struct aws_tls_ctx *client_ctx = aws_tls_client_ctx_new(allocator, &client_ctx_options);

    struct tls_test_args outgoing_args = {
            .mutex = &mutex,
            .allocator = allocator,
            .condition_variable = &condition_variable,
            .error_invoked = 0,
            .rw_handler = outgoing_rw_handler,
            .server = false,
            .tls_negotiated = false,
            .shutdown_finished = false,
    };

    struct aws_tls_connection_options tls_server_conn_options = {
            .server_name = NULL,
            .verify_peer = false,
            .alpn_list = NULL,
            .verify_host_fn = NULL,
            .on_data_read = NULL,
            .on_negotiation_result = tls_on_negotiated,
            .on_error = NULL,
            .advertise_alpn_message = false,
            .user_data = &incoming_args
    };

    struct aws_tls_connection_options tls_client_conn_options = {
            .verify_peer = true,
            .alpn_list = NULL,
            .verify_host_fn = tls_verify_host_trust_all,
            .on_data_read = NULL,
            .on_negotiation_result = tls_on_negotiated,
            .on_error = NULL,
            .server_name = "localhost",
            .advertise_alpn_message = false,
            .user_data = &outgoing_args
    };

    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));

    struct aws_socket_endpoint endpoint;

    snprintf(endpoint.socket_name, sizeof(endpoint.socket_name), "testsock%llu.sock", (long long unsigned)timestamp);

    struct aws_server_bootstrap server_bootstrap;
    ASSERT_SUCCESS(aws_server_bootstrap_init(&server_bootstrap, allocator, &el_group));
    ASSERT_SUCCESS(aws_server_bootstrap_set_tls_ctx(&server_bootstrap, server_ctx));

    struct aws_socket *listener = aws_server_bootstrap_add_tls_socket_listener(&server_bootstrap, &endpoint, &options, &tls_server_conn_options,
                                                                           tls_handler_test_server_setup_callback,
                                                                           tls_handler_test_server_shutdown_callback,
                                                                           &incoming_args);

    ASSERT_NOT_NULL(listener);

    struct aws_client_bootstrap client_bootstrap;
    ASSERT_SUCCESS(aws_client_bootstrap_init(&client_bootstrap, allocator, &el_group));
    ASSERT_SUCCESS(aws_client_bootstrap_set_tls_ctx(&client_bootstrap, client_ctx));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));

    ASSERT_SUCCESS(aws_client_bootstrap_new_tls_socket_channel(&client_bootstrap, &endpoint, &options, &tls_client_conn_options,
                                                            tls_handler_test_client_setup_callback,
                                                            tls_handler_test_client_shutdown_callback,
                                                            &outgoing_args));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_channel_setup_predicate, &incoming_args));

    ASSERT_FALSE(incoming_args.error_invoked);

    /* check ALPN and SNI was properly negotiated */
    struct aws_byte_buf expected_protocol = aws_byte_buf_from_c_str("h2");
    ASSERT_BIN_ARRAYS_EQUALS(expected_protocol.buffer, expected_protocol.len,
                             incoming_args.negotiated_protocol.buffer, incoming_args.negotiated_protocol.len);

    struct aws_byte_buf server_name = aws_byte_buf_from_c_str("localhost");
    ASSERT_BIN_ARRAYS_EQUALS(server_name.buffer, server_name.len,
                             incoming_args.server_name.buffer, incoming_args.server_name.len);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_channel_setup_predicate, &outgoing_args));

    ASSERT_FALSE(outgoing_args.error_invoked);

    ASSERT_BIN_ARRAYS_EQUALS(expected_protocol.buffer, expected_protocol.len,
                             outgoing_args.negotiated_protocol.buffer, outgoing_args.negotiated_protocol.len);
    ASSERT_BIN_ARRAYS_EQUALS(server_name.buffer, server_name.len,
                             outgoing_args.server_name.buffer, outgoing_args.server_name.len);

    ASSERT_FALSE(outgoing_args.error_invoked);

    /* Do the IO operations */
    rw_handler_write(outgoing_args.rw_handler, outgoing_args.rw_slot, &write_tag);
    rw_handler_write(incoming_args.rw_handler, incoming_args.rw_slot, &read_tag);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_test_read_predicate, &incoming_rw_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_test_read_predicate, &outgoing_rw_args));

    incoming_rw_args.invocation_happened = false;
    outgoing_rw_args.invocation_happened = false;

    ASSERT_INT_EQUALS(1, outgoing_rw_args.read_invocations);
    ASSERT_INT_EQUALS(1, incoming_rw_args.read_invocations);

    /* Go ahead and verify back-pressure works*/
    rw_handler_trigger_increment_read_window(incoming_args.rw_handler, incoming_args.rw_slot, 100);
    rw_handler_trigger_increment_read_window(outgoing_args.rw_handler, outgoing_args.rw_slot, 100);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_test_read_predicate, &incoming_rw_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_test_read_predicate, &outgoing_rw_args));

    ASSERT_INT_EQUALS(2, outgoing_rw_args.read_invocations);
    ASSERT_INT_EQUALS(2, incoming_rw_args.read_invocations);

    ASSERT_BIN_ARRAYS_EQUALS(write_tag.buffer, write_tag.len, incoming_rw_args.received_message.buffer,
                             incoming_rw_args.received_message.len);
    ASSERT_BIN_ARRAYS_EQUALS(read_tag.buffer, read_tag.len, outgoing_rw_args.received_message.buffer,
                             outgoing_rw_args.received_message.len);

    aws_channel_shutdown(incoming_args.channel, AWS_OP_SUCCESS);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_channel_shutdown_predicate, &incoming_args));

    /*now shutdown on the client necessary here (it should have been triggered by shutting down the other side). just wait for the
     * event to fire. */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_channel_shutdown_predicate, &outgoing_args));

    aws_client_bootstrap_clean_up(&client_bootstrap);
    ASSERT_SUCCESS(aws_server_bootstrap_remove_socket_listener(&server_bootstrap, listener));
    aws_server_bootstrap_clean_up(&server_bootstrap);
    aws_tls_ctx_destroy(client_ctx);
    aws_tls_ctx_destroy(server_ctx);

    aws_event_loop_group_clean_up(&el_group);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(tls_channel_echo_and_backpressure_test, tls_channel_echo_and_backpressure_test_fn)

static int tls_channel_negotiation_error_fn (struct aws_allocator *allocator, void *user_data) {
    struct aws_event_loop_group el_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&el_group, allocator));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct aws_tls_connection_options tls_server_conn_options = {
            .server_name = NULL,
            .verify_peer = false,
            .alpn_list = NULL,
            .verify_host_fn = NULL,
            .on_data_read = NULL,
            .on_negotiation_result = tls_on_negotiated,
            .on_error = NULL,
            .advertise_alpn_message = false
    };

    struct aws_tls_connection_options tls_client_conn_options = {
            .verify_peer = true,
            .alpn_list = NULL,
            .verify_host_fn = tls_verify_host_trust_none,
            .on_data_read = NULL,
            .on_negotiation_result = tls_on_negotiated,
            .on_error = NULL,
            .server_name = "localhost",
            .advertise_alpn_message = false
    };

    struct aws_tls_ctx_options server_ctx_options = {
            .alpn_list = "h2;http/1.1",
            .server_name = "localhost",
            .verify_peer = false,
            .ca_path = NULL,
            .ca_file = NULL,
#ifdef __APPLE__
            .pkcs12_path = "./unittests.p12",
#else
            .private_key_path = "./unittests.key",
            .certificate_path = "./unittests.crt",
#endif
            .version_blacklist = 0,
    };

    struct aws_tls_ctx *server_ctx = aws_tls_server_ctx_new(allocator, &server_ctx_options);

    struct tls_test_args incoming_args = {
            .mutex = &mutex,
            .allocator = allocator,
            .condition_variable = &condition_variable,
            .error_invoked = 0,
            .rw_handler = NULL,
            .server = true,
            .tls_negotiated = false,
            .shutdown_finished = false,
    };

    struct aws_tls_ctx_options client_ctx_options = {
            .alpn_list = "h2;http/1.1",
            .verify_peer = true,
            .server_name = NULL,
            .ca_path = NULL,
            .ca_file = "./unittests.crt",
#ifdef __APPLE__
            .pkcs12_path = NULL,
#else
    .private_key_path = NULL,
            .certificate_path = NULL,
#endif
            .version_blacklist = 0
    };

    struct aws_tls_ctx *client_ctx = aws_tls_client_ctx_new(allocator, &client_ctx_options);

    struct tls_test_args outgoing_args = {
            .mutex = &mutex,
            .allocator = allocator,
            .condition_variable = &condition_variable,
            .error_invoked = 0,
            .rw_handler = NULL,
            .server = false,
            .tls_negotiated = false,
            .shutdown_finished = false,
    };

    struct aws_socket_options options = (struct aws_socket_options){0};
    options.connect_timeout = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));

    struct aws_socket_endpoint endpoint;

    snprintf(endpoint.socket_name, sizeof(endpoint.socket_name), "testsock%llu.sock", (long long unsigned)timestamp);

    struct aws_server_bootstrap server_bootstrap;
    ASSERT_SUCCESS(aws_server_bootstrap_init(&server_bootstrap, allocator, &el_group));
    ASSERT_SUCCESS(aws_server_bootstrap_set_tls_ctx(&server_bootstrap, server_ctx));

    struct aws_socket *listener = aws_server_bootstrap_add_tls_socket_listener(&server_bootstrap, &endpoint, &options, &tls_server_conn_options,
                                                                           tls_handler_test_server_setup_callback,
                                                                           tls_handler_test_server_shutdown_callback,
                                                                           &incoming_args);

    ASSERT_NOT_NULL(listener);

    struct aws_client_bootstrap client_bootstrap;
    ASSERT_SUCCESS((aws_client_bootstrap_init(&client_bootstrap, allocator, &el_group)));
    ASSERT_SUCCESS(aws_client_bootstrap_set_tls_ctx(&client_bootstrap, client_ctx));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));

    ASSERT_SUCCESS(aws_client_bootstrap_new_tls_socket_channel(&client_bootstrap, &endpoint, &options, &tls_client_conn_options,
                                                           tls_handler_test_client_setup_callback,
                                                           tls_handler_test_client_shutdown_callback,
                                                           &outgoing_args));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_channel_shutdown_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(&condition_variable, &mutex, tls_channel_shutdown_predicate, &outgoing_args));

    ASSERT_TRUE(outgoing_args.error_invoked);
    aws_client_bootstrap_clean_up(&client_bootstrap);
    ASSERT_SUCCESS(aws_server_bootstrap_remove_socket_listener(&server_bootstrap, listener));
    aws_server_bootstrap_clean_up(&server_bootstrap);
    aws_tls_ctx_destroy(client_ctx);
    aws_tls_ctx_destroy(server_ctx);

    aws_event_loop_group_clean_up(&el_group);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(tls_channel_negotiation_error, tls_channel_negotiation_error_fn)
