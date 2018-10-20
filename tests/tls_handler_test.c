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
#include <aws/io/host_resolver.h>
#include <aws/io/socket.h>
#include <aws/io/tls_channel_handler.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>

#include <aws/testing/aws_test_harness.h>

#include <aws/common/string.h>
#include <read_write_test_handler.h>

#if _MSC_VER
#    pragma warning(disable : 4996) /* sprintf */
#endif

#ifdef _WIN32
#    define LOCAL_SOCK_TEST_PATTERN "\\\\.\\pipe\\testsock%llu"
#else
#    define LOCAL_SOCK_TEST_PATTERN "testsock%llu.sock"
#endif

struct tls_test_args {
    struct aws_allocator *allocator;
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_channel *channel;
    struct aws_channel_handler *rw_handler;
    struct aws_channel_slot *rw_slot;
    struct aws_byte_buf negotiated_protocol;
    struct aws_byte_buf server_name;
    int last_error_code;
    bool tls_negotiated;
    bool error_invoked;
    bool server;
    bool shutdown_finished;
};

static bool s_tls_channel_shutdown_predicate(void *user_data) {
    struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;
    return setup_test_args->shutdown_finished;
}

static bool s_tls_channel_setup_predicate(void *user_data) {
    struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;
    return setup_test_args->tls_negotiated || setup_test_args->error_invoked;
}

static void s_tls_handler_test_client_setup_callback(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;

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
    } else {
        setup_test_args->error_invoked = true;
        setup_test_args->last_error_code = error_code;
    }

    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

static void s_tls_handler_test_server_setup_callback(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;

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
    } else {
        setup_test_args->error_invoked = true;
    }

    aws_condition_variable_notify_one(setup_test_args->condition_variable);
    aws_mutex_unlock(setup_test_args->mutex);
}

static void s_tls_handler_test_client_shutdown_callback(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;
    (void)channel;

    struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;

    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->shutdown_finished = true;
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
    aws_mutex_unlock(setup_test_args->mutex);
}

static void s_tls_handler_test_server_shutdown_callback(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;
    (void)channel;

    struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;

    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->shutdown_finished = true;
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
    aws_mutex_unlock(setup_test_args->mutex);
}

static void s_tls_on_negotiated(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    int err_code,
    void *user_data) {

    (void)slot;

    if (!err_code) {
        struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;

        if (aws_tls_is_alpn_available()) {
            setup_test_args->negotiated_protocol = aws_tls_handler_protocol(handler);
        }
        setup_test_args->server_name = aws_tls_handler_server_name(handler);
    }
}

struct tls_test_rw_args {
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_byte_buf received_message;
    int read_invocations;
    bool invocation_happened;
};

static bool s_tls_test_read_predicate(void *user_data) {
    struct tls_test_rw_args *rw_args = (struct tls_test_rw_args *)user_data;

    return rw_args->invocation_happened;
}

static struct aws_byte_buf s_tls_test_handle_read(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *data_read,
    void *user_data) {

    (void)handler;
    (void)slot;

    struct tls_test_rw_args *rw_args = (struct tls_test_rw_args *)user_data;

    memcpy(rw_args->received_message.buffer + rw_args->received_message.len, data_read->buffer, data_read->len);
    rw_args->received_message.len += data_read->len;
    rw_args->read_invocations += 1;
    rw_args->invocation_happened = true;
    aws_condition_variable_notify_one(rw_args->condition_variable);

    return rw_args->received_message;
}

static struct aws_byte_buf s_tls_test_handle_write(
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

static int s_tls_channel_echo_and_backpressure_test_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_tls_init_static_state(allocator);
    struct aws_event_loop_group el_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&el_group, allocator, 0));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct aws_byte_buf read_tag = aws_byte_buf_from_c_str("I'm a little teapot.");
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
    struct aws_channel_handler *outgoing_rw_handler = rw_handler_new(
        allocator, s_tls_test_handle_read, s_tls_test_handle_write, true, write_tag.len / 2, &outgoing_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_channel_handler *incoming_rw_handler = rw_handler_new(
        allocator, s_tls_test_handle_read, s_tls_test_handle_write, true, read_tag.len / 2, &incoming_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_tls_ctx_options server_ctx_options;
#ifdef __APPLE__
    aws_tls_ctx_options_init_server_pkcs12(&server_ctx_options, "./unittests.p12", "1234");
#else
    aws_tls_ctx_options_init_default_server(&server_ctx_options, "./unittests.crt", "./unittests.key");
#endif /* __APPLE__ */
    aws_tls_ctx_options_set_alpn_list(&server_ctx_options, "h2;http/1.1");

    struct aws_tls_ctx *server_ctx = aws_tls_server_ctx_new(allocator, &server_ctx_options);
    ASSERT_NOT_NULL(server_ctx);

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

    struct aws_tls_ctx_options client_ctx_options;

    aws_tls_ctx_options_init_default_client(&client_ctx_options);
    aws_tls_ctx_options_override_default_trust_store(&client_ctx_options, NULL, "./unittests.crt");

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

    struct aws_tls_connection_options tls_server_conn_options;
    aws_tls_connection_options_init_from_ctx_options(&tls_server_conn_options, &server_ctx_options);
    aws_tls_connection_options_set_callbacks(&tls_server_conn_options, s_tls_on_negotiated, NULL, NULL, &incoming_args);

    struct aws_tls_connection_options tls_client_conn_options;
    aws_tls_connection_options_init_from_ctx_options(&tls_client_conn_options, &client_ctx_options);
    aws_tls_connection_options_set_alpn_list(&tls_client_conn_options, "h2;http/1.1");
    aws_tls_connection_options_set_callbacks(&tls_client_conn_options, s_tls_on_negotiated, NULL, NULL, &outgoing_args);
    aws_tls_connection_options_set_server_name(&tls_client_conn_options, "localhost");

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_LOCAL;

    uint64_t timestamp = 0;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&timestamp));

    struct aws_socket_endpoint endpoint;
    AWS_ZERO_STRUCT(endpoint);
    sprintf(endpoint.address, LOCAL_SOCK_TEST_PATTERN, (long long unsigned)timestamp);

    struct aws_server_bootstrap server_bootstrap;
    ASSERT_SUCCESS(aws_server_bootstrap_init(&server_bootstrap, allocator, &el_group));
    ASSERT_SUCCESS(aws_server_bootstrap_set_tls_ctx(&server_bootstrap, server_ctx));

    struct aws_socket *listener = aws_server_bootstrap_new_tls_socket_listener(
        &server_bootstrap,
        &endpoint,
        &options,
        &tls_server_conn_options,
        s_tls_handler_test_server_setup_callback,
        s_tls_handler_test_server_shutdown_callback,
        &incoming_args);

    ASSERT_NOT_NULL(listener);

    struct aws_client_bootstrap client_bootstrap;
    ASSERT_SUCCESS(aws_client_bootstrap_init(&client_bootstrap, allocator, &el_group));
    ASSERT_SUCCESS(aws_client_bootstrap_set_tls_ctx(&client_bootstrap, client_ctx));

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));

    ASSERT_SUCCESS(aws_client_bootstrap_new_tls_socket_channel(
        &client_bootstrap,
        &endpoint,
        &options,
        &tls_client_conn_options,
        s_tls_handler_test_client_setup_callback,
        s_tls_handler_test_client_shutdown_callback,
        &outgoing_args));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_tls_channel_setup_predicate, &incoming_args));

    ASSERT_FALSE(incoming_args.error_invoked);

    struct aws_byte_buf expected_protocol = aws_byte_buf_from_c_str("h2");
    /* check ALPN and SNI was properly negotiated */

    if (aws_tls_is_alpn_available()) {
        ASSERT_BIN_ARRAYS_EQUALS(
            expected_protocol.buffer,
            expected_protocol.len,
            incoming_args.negotiated_protocol.buffer,
            incoming_args.negotiated_protocol.len);
    }

    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_tls_channel_setup_predicate, &outgoing_args));

    ASSERT_FALSE(outgoing_args.error_invoked);

    if (aws_tls_is_alpn_available()) {
        ASSERT_BIN_ARRAYS_EQUALS(
            expected_protocol.buffer,
            expected_protocol.len,
            outgoing_args.negotiated_protocol.buffer,
            outgoing_args.negotiated_protocol.len);
    }

    ASSERT_FALSE(outgoing_args.error_invoked);

    /* Do the IO operations */
    rw_handler_write(outgoing_args.rw_handler, outgoing_args.rw_slot, &write_tag);
    rw_handler_write(incoming_args.rw_handler, incoming_args.rw_slot, &read_tag);
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_tls_test_read_predicate, &incoming_rw_args));
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_tls_test_read_predicate, &outgoing_rw_args));

    incoming_rw_args.invocation_happened = false;
    outgoing_rw_args.invocation_happened = false;

    ASSERT_INT_EQUALS(1, outgoing_rw_args.read_invocations);
    ASSERT_INT_EQUALS(1, incoming_rw_args.read_invocations);

    /* Go ahead and verify back-pressure works*/
    rw_handler_trigger_increment_read_window(incoming_args.rw_handler, incoming_args.rw_slot, 100);
    rw_handler_trigger_increment_read_window(outgoing_args.rw_handler, outgoing_args.rw_slot, 100);

    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_tls_test_read_predicate, &incoming_rw_args));
    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_tls_test_read_predicate, &outgoing_rw_args));

    ASSERT_INT_EQUALS(2, outgoing_rw_args.read_invocations);
    ASSERT_INT_EQUALS(2, incoming_rw_args.read_invocations);

    ASSERT_BIN_ARRAYS_EQUALS(
        write_tag.buffer,
        write_tag.len,
        incoming_rw_args.received_message.buffer,
        incoming_rw_args.received_message.len);
    ASSERT_BIN_ARRAYS_EQUALS(
        read_tag.buffer, read_tag.len, outgoing_rw_args.received_message.buffer, outgoing_rw_args.received_message.len);

    aws_channel_shutdown(incoming_args.channel, AWS_OP_SUCCESS);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_tls_channel_shutdown_predicate, &incoming_args));

    /*no shutdown on the client necessary here (it should have been triggered by shutting down the other side). just
     * wait for the event to fire. */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_tls_channel_shutdown_predicate, &outgoing_args));

    aws_client_bootstrap_clean_up(&client_bootstrap);
    ASSERT_SUCCESS(aws_server_bootstrap_destroy_socket_listener(&server_bootstrap, listener));
    aws_server_bootstrap_clean_up(&server_bootstrap);
    aws_tls_ctx_destroy(client_ctx);
    aws_tls_ctx_destroy(server_ctx);

    aws_event_loop_group_clean_up(&el_group);
    aws_tls_clean_up_static_state();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(tls_channel_echo_and_backpressure_test, s_tls_channel_echo_and_backpressure_test_fn)

struct default_host_callback_data {
    struct aws_host_address aaaa_address;
    struct aws_host_address a_address;
    bool has_aaaa_address;
    bool has_a_address;
    struct aws_condition_variable condition_variable;
    bool invoked;
};

static bool s_default_host_resolved_predicate(void *arg) {
    struct default_host_callback_data *callback_data = arg;

    return callback_data->invoked;
}

static void s_default_host_resolved_test_callback(
    struct aws_host_resolver *resolver,
    const struct aws_string *host_name,
    int err_code,
    const struct aws_array_list *host_addresses,
    void *user_data) {

    (void)resolver;
    (void)host_name;
    (void)err_code;

    struct default_host_callback_data *callback_data = user_data;

    struct aws_host_address *host_address = NULL;

    if (aws_array_list_length(host_addresses) >= 2) {
        aws_array_list_get_at(host_addresses, &host_address, 0);

        aws_host_address_copy(host_address, &callback_data->aaaa_address);

        aws_array_list_get_at(host_addresses, &host_address, 1);

        aws_host_address_copy(host_address, &callback_data->a_address);
        callback_data->has_aaaa_address = true;
        callback_data->has_a_address = true;
    } else if (aws_array_list_length(host_addresses) == 1) {
        aws_array_list_get_at(host_addresses, &host_address, 0);

        aws_host_address_copy(host_address, &callback_data->a_address);
        callback_data->has_a_address = true;
    }

    callback_data->invoked = true;
    aws_condition_variable_notify_one(&callback_data->condition_variable);
}

static int s_verify_negotiation_fails(struct aws_allocator *allocator, const struct aws_string *host_name) {

    aws_tls_init_static_state(allocator);

    struct aws_event_loop_group el_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&el_group, allocator, 0));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

    struct aws_tls_ctx_options client_ctx_options;
    aws_tls_ctx_options_init_default_client(&client_ctx_options);
    aws_tls_ctx_options_override_default_trust_store(&client_ctx_options, "/etc/ssl/certs", NULL);

    struct aws_tls_ctx *client_ctx = aws_tls_client_ctx_new(allocator, &client_ctx_options);

    struct aws_tls_connection_options tls_client_conn_options;
    aws_tls_connection_options_init_from_ctx_options(&tls_client_conn_options, &client_ctx_options);
    aws_tls_connection_options_set_callbacks(&tls_client_conn_options, s_tls_on_negotiated, NULL, NULL, NULL);
    aws_tls_connection_options_set_server_name(&tls_client_conn_options, (const char *)aws_string_bytes(host_name));

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

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_host_resolver resolver;
    ASSERT_SUCCESS(aws_host_resolver_init_default(&resolver, allocator, 2));

    struct aws_host_resolution_config resolution_config = {
        .impl = aws_default_dns_resolve, .impl_data = NULL, .max_ttl = 1};

    struct default_host_callback_data host_callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
    };

    aws_mutex_lock(&mutex);
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        &resolver, host_name, s_default_host_resolved_test_callback, &resolution_config, &host_callback_data));

    aws_condition_variable_wait_pred(
        &host_callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &host_callback_data);

    aws_host_resolver_clean_up(&resolver);

    ASSERT_TRUE(host_callback_data.has_a_address);
    struct aws_socket_endpoint endpoint = {.port = 443};

    sprintf(endpoint.address, "%s", aws_string_bytes(host_callback_data.a_address.address));

    struct aws_client_bootstrap client_bootstrap;
    ASSERT_SUCCESS((aws_client_bootstrap_init(&client_bootstrap, allocator, &el_group)));
    ASSERT_SUCCESS(aws_client_bootstrap_set_tls_ctx(&client_bootstrap, client_ctx));

    ASSERT_SUCCESS(aws_client_bootstrap_new_tls_socket_channel(
        &client_bootstrap,
        &endpoint,
        &options,
        &tls_client_conn_options,
        s_tls_handler_test_client_setup_callback,
        s_tls_handler_test_client_shutdown_callback,
        &outgoing_args));

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_tls_channel_shutdown_predicate, &outgoing_args));

    ASSERT_TRUE(outgoing_args.error_invoked);
    ASSERT_INT_EQUALS(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE, outgoing_args.last_error_code);
    aws_client_bootstrap_clean_up(&client_bootstrap);

    aws_host_address_clean_up(&host_callback_data.a_address);
    aws_tls_ctx_destroy(client_ctx);

    aws_event_loop_group_clean_up(&el_group);

    aws_tls_clean_up_static_state();
    return AWS_OP_SUCCESS;
}

static int s_tls_client_channel_negotiation_error_expired_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "expired.badssl.com");
    ASSERT_NOT_NULL(host_name);
    int err_code = s_verify_negotiation_fails(allocator, host_name);
    aws_string_destroy((void *)host_name);
    return err_code;
}

AWS_TEST_CASE(tls_client_channel_negotiation_error_expired, s_tls_client_channel_negotiation_error_expired_fn)

static int s_tls_client_channel_negotiation_error_wrong_host_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "wrong.host.badssl.com");
    ASSERT_NOT_NULL(host_name);
    int err_code = s_verify_negotiation_fails(allocator, host_name);
    aws_string_destroy((void *)host_name);
    return err_code;
}

AWS_TEST_CASE(tls_client_channel_negotiation_error_wrong_host, s_tls_client_channel_negotiation_error_wrong_host_fn)

static int s_tls_client_channel_negotiation_error_self_signed_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "self-signed.badssl.com");
    ASSERT_NOT_NULL(host_name);
    int err_code = s_verify_negotiation_fails(allocator, host_name);
    aws_string_destroy((void *)host_name);
    return err_code;
}

AWS_TEST_CASE(tls_client_channel_negotiation_error_self_signed, s_tls_client_channel_negotiation_error_self_signed_fn)

static int s_tls_client_channel_negotiation_error_untrusted_root_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "untrusted-root.badssl.com");
    ASSERT_NOT_NULL(host_name);
    int err_code = s_verify_negotiation_fails(allocator, host_name);
    aws_string_destroy((void *)host_name);
    return err_code;
}

AWS_TEST_CASE(
    tls_client_channel_negotiation_error_untrusted_root,
    s_tls_client_channel_negotiation_error_untrusted_root_fn)

static int s_tls_client_channel_negotiation_error_revoked_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "revoked.badssl.com");
    ASSERT_NOT_NULL(host_name);
    int err_code = s_verify_negotiation_fails(allocator, host_name);
    aws_string_destroy((void *)host_name);
    return err_code;
}

AWS_TEST_CASE(tls_client_channel_negotiation_error_revoked, s_tls_client_channel_negotiation_error_revoked_fn)

static int s_tls_client_channel_negotiation_error_pinning_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "pinning-test.badssl.com");
    ASSERT_NOT_NULL(host_name);
    int err_code = s_verify_negotiation_fails(allocator, host_name);
    aws_string_destroy((void *)host_name);
    return err_code;
}

AWS_TEST_CASE(tls_client_channel_negotiation_error_pinning, s_tls_client_channel_negotiation_error_pinning_fn)

static int s_verify_good_host(struct aws_allocator *allocator, const struct aws_string *host_name) {

    aws_tls_init_static_state(allocator);

    struct aws_event_loop_group el_group;
    ASSERT_SUCCESS(aws_event_loop_group_default_init(&el_group, allocator, 0));

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;

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

    struct aws_tls_ctx_options client_ctx_options;
    aws_tls_ctx_options_init_default_client(&client_ctx_options);
    aws_tls_ctx_options_override_default_trust_store(&client_ctx_options, "/etc/ssl/certs", NULL);
    aws_tls_ctx_options_set_alpn_list(&client_ctx_options, "h2;http/1.1");

    struct aws_tls_ctx *client_ctx = aws_tls_client_ctx_new(allocator, &client_ctx_options);

    struct aws_tls_connection_options tls_client_conn_options;
    aws_tls_connection_options_init_from_ctx_options(&tls_client_conn_options, &client_ctx_options);
    aws_tls_connection_options_set_callbacks(&tls_client_conn_options, s_tls_on_negotiated, NULL, NULL, &outgoing_args);
    aws_tls_connection_options_set_server_name(&tls_client_conn_options, (const char *)aws_string_bytes(host_name));
    aws_tls_connection_options_set_alpn_list(&tls_client_conn_options, "h2;http/1.1");

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 3000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_host_resolver resolver;
    ASSERT_SUCCESS(aws_host_resolver_init_default(&resolver, allocator, 2));

    struct aws_host_resolution_config resolution_config = {
        .impl = aws_default_dns_resolve, .impl_data = NULL, .max_ttl = 1};

    struct default_host_callback_data host_callback_data = {
        .condition_variable = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
    };

    aws_mutex_lock(&mutex);
    ASSERT_SUCCESS(aws_host_resolver_resolve_host(
        &resolver, host_name, s_default_host_resolved_test_callback, &resolution_config, &host_callback_data));

    aws_condition_variable_wait_pred(
        &host_callback_data.condition_variable, &mutex, s_default_host_resolved_predicate, &host_callback_data);

    aws_host_resolver_clean_up(&resolver);

    ASSERT_TRUE(host_callback_data.has_a_address);
    struct aws_socket_endpoint endpoint = {
        .port = 443,
    };

    sprintf(endpoint.address, "%s", aws_string_bytes(host_callback_data.a_address.address));

    struct aws_client_bootstrap client_bootstrap;
    ASSERT_SUCCESS((aws_client_bootstrap_init(&client_bootstrap, allocator, &el_group)));
    ASSERT_SUCCESS(aws_client_bootstrap_set_tls_ctx(&client_bootstrap, client_ctx));

    ASSERT_SUCCESS(aws_client_bootstrap_new_tls_socket_channel(
        &client_bootstrap,
        &endpoint,
        &options,
        &tls_client_conn_options,
        s_tls_handler_test_client_setup_callback,
        s_tls_handler_test_client_shutdown_callback,
        &outgoing_args));

    ASSERT_SUCCESS(
        aws_condition_variable_wait_pred(&condition_variable, &mutex, s_tls_channel_setup_predicate, &outgoing_args));

    ASSERT_FALSE(outgoing_args.error_invoked);
    struct aws_byte_buf expected_protocol = aws_byte_buf_from_c_str("h2");
    /* check ALPN and SNI was properly negotiated */

    if (aws_tls_is_alpn_available()) {
        ASSERT_BIN_ARRAYS_EQUALS(
            expected_protocol.buffer,
            expected_protocol.len,
            outgoing_args.negotiated_protocol.buffer,
            outgoing_args.negotiated_protocol.len);
    }

    ASSERT_BIN_ARRAYS_EQUALS(
        aws_string_bytes(host_name), host_name->len, outgoing_args.server_name.buffer, outgoing_args.server_name.len);

    aws_channel_shutdown(outgoing_args.channel, AWS_OP_SUCCESS);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &condition_variable, &mutex, s_tls_channel_shutdown_predicate, &outgoing_args));

    aws_client_bootstrap_clean_up(&client_bootstrap);

    aws_host_address_clean_up(&host_callback_data.a_address);
    aws_tls_ctx_destroy(client_ctx);

    aws_event_loop_group_clean_up(&el_group);

    aws_tls_clean_up_static_state();
    return AWS_OP_SUCCESS;
}

static int s_tls_client_channel_negotiation_success_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "www.amazon.com");
    ASSERT_NOT_NULL(host_name);
    int err_code = s_verify_good_host(allocator, host_name);
    aws_string_destroy((void *)host_name);
    return err_code;
}

AWS_TEST_CASE(tls_client_channel_negotiation_success, s_tls_client_channel_negotiation_success_fn)
