/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifdef _MSC_VER
/* allow this file to be empty */
#    pragma warning(disable : 4206)
#endif /* MSVC_VER */

/* these tests only get built and run with the BYO_CRYPTO compiler define. */
#ifdef BYO_CRYPTO

#    include <aws/io/channel_bootstrap.h>
#    include <aws/io/event_loop.h>
#    include <aws/io/socket.h>
#    include <aws/io/socket_channel_handler.h>
#    include <aws/io/tls_channel_handler.h>

#    include <aws/common/atomics.h>
#    include <aws/common/condition_variable.h>

#    include <aws/testing/aws_test_harness.h>

#    include "statistics_handler_test.h"
#    include <read_write_test_handler.h>

struct byo_crypto_test_args {
    struct aws_allocator *allocator;
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_channel *channel;
    struct aws_channel_handler *rw_handler;
    struct aws_channel_slot *rw_slot;
    struct aws_tls_ctx tls_ctx;
    struct aws_tls_connection_options tls_options;
    aws_tls_on_negotiation_result_fn *negotiation_result_fn;
    void *cb_data;
    int error_code;
    bool shutdown_invoked;
    bool listener_destroyed;
    bool setup_completed;
};

/* common structure for test */
struct byo_crypto_common_tester {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    struct aws_event_loop_group *el_group;
};

static struct byo_crypto_common_tester c_tester;

static int s_byo_crypto_common_tester_init(struct aws_allocator *allocator, struct byo_crypto_common_tester *tester) {
    AWS_ZERO_STRUCT(*tester);
    aws_io_library_init(allocator);
    tester->el_group = aws_event_loop_group_new_default(allocator, 0, NULL);
    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;
    tester->mutex = mutex;
    tester->condition_variable = condition_variable;
    return AWS_OP_SUCCESS;
}

static int s_byo_crypto_common_tester_clean_up(struct byo_crypto_common_tester *tester) {
    aws_event_loop_group_release(tester->el_group);
    aws_mutex_clean_up(&tester->mutex);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

/* common structure for a local server */
struct local_server_tester {
    struct aws_socket_options socket_options;
    struct aws_socket_endpoint endpoint;
    struct aws_server_bootstrap *server_bootstrap;
    struct aws_socket *listener;
};

static bool s_channel_setup_predicate(void *user_data) {
    struct byo_crypto_test_args *setup_test_args = user_data;
    return setup_test_args->setup_completed;
}

static bool s_channel_shutdown_predicate(void *user_data) {
    struct byo_crypto_test_args *setup_test_args = user_data;
    return setup_test_args->shutdown_invoked;
}

static bool s_listener_destroy_predicate(void *user_data) {
    struct byo_crypto_test_args *setup_test_args = user_data;
    return setup_test_args->listener_destroyed;
}

static void s_byo_crypto_test_client_setup_callback(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;

    struct byo_crypto_test_args *setup_test_args = user_data;

    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->channel = channel;
    setup_test_args->setup_completed = true;
    aws_mutex_unlock(setup_test_args->mutex);
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

static void s_byo_crypto_test_server_setup_callback(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;

    struct byo_crypto_test_args *setup_test_args = user_data;

    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->channel = channel;
    setup_test_args->setup_completed = true;
    aws_mutex_unlock(setup_test_args->mutex);
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

static void s_byo_crypto_test_client_shutdown_callback(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)channel;

    struct byo_crypto_test_args *setup_test_args = user_data;
    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->shutdown_invoked = true;
    setup_test_args->error_code = error_code;
    aws_mutex_unlock(setup_test_args->mutex);

    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

static void s_byo_crypto_test_server_shutdown_callback(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;
    (void)channel;

    struct byo_crypto_test_args *setup_test_args = user_data;
    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->shutdown_invoked = true;
    setup_test_args->error_code = error_code;
    aws_mutex_unlock(setup_test_args->mutex);

    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

struct byo_crypto_test_rw_args {
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_byte_buf received_message;
    struct byo_crypto_test_args *test_args;
    bool invocation_happened;
    bool shutdown_finished;
};

static bool s_byo_crypto_test_predicate(void *user_data) {
    struct byo_crypto_test_rw_args *rw_args = user_data;
    return rw_args->invocation_happened;
}

static struct aws_byte_buf s_byo_crypto_test_handle_read(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *data_read,
    void *user_data) {

    (void)handler;
    (void)slot;

    struct byo_crypto_test_rw_args *rw_args = user_data;

    aws_mutex_lock(rw_args->mutex);
    memcpy(rw_args->received_message.buffer + rw_args->received_message.len, data_read->buffer, data_read->len);
    rw_args->received_message.len += data_read->len;
    rw_args->invocation_happened = true;
    aws_condition_variable_notify_one(rw_args->condition_variable);
    aws_mutex_unlock(rw_args->mutex);
    if (rw_args->test_args->negotiation_result_fn) {
        rw_args->test_args->negotiation_result_fn(handler, slot, AWS_ERROR_SUCCESS, rw_args->test_args->cb_data);
        rw_args->test_args->negotiation_result_fn = NULL;
    }

    return rw_args->received_message;
}

static struct aws_byte_buf s_byo_crypto_test_handle_write(
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

static void s_byo_crypto_test_server_listener_destroy_callback(
    struct aws_server_bootstrap *bootstrap,
    void *user_data) {

    (void)bootstrap;

    struct byo_crypto_test_args *setup_test_args = user_data;
    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->listener_destroyed = true;
    aws_mutex_unlock(setup_test_args->mutex);
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

static int s_rw_args_init(
    struct byo_crypto_test_rw_args *args,
    struct byo_crypto_common_tester *s_c_tester,
    struct aws_byte_buf received_message,
    int expected_read) {
    AWS_ZERO_STRUCT(*args);
    args->mutex = &s_c_tester->mutex;
    args->condition_variable = &s_c_tester->condition_variable;
    args->received_message = received_message;
    return AWS_OP_SUCCESS;
}

static int s_byo_crypto_test_args_init(
    struct byo_crypto_test_args *args,
    struct byo_crypto_common_tester *s_c_tester,
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
    struct byo_crypto_test_args *args,
    struct byo_crypto_common_tester *s_c_tester,
    bool enable_back_pressure) {
    AWS_ZERO_STRUCT(*tester);
    tester->socket_options.connect_timeout_ms = 3000;
    tester->socket_options.type = AWS_SOCKET_STREAM;
    tester->socket_options.domain = AWS_SOCKET_LOCAL;

    aws_socket_endpoint_init_local_address_for_test(&tester->endpoint);

    tester->server_bootstrap = aws_server_bootstrap_new(allocator, s_c_tester->el_group);
    ASSERT_NOT_NULL(tester->server_bootstrap);

    aws_atomic_init_int((volatile struct aws_atomic_var *)&args->tls_ctx.ref_count, 1u);

    args->tls_options.ctx = &args->tls_ctx;

    struct aws_server_socket_channel_bootstrap_options bootstrap_options = {
        .bootstrap = tester->server_bootstrap,
        .enable_read_back_pressure = enable_back_pressure,
        .port = tester->endpoint.port,
        .host_name = tester->endpoint.address,
        .socket_options = &tester->socket_options,
        .incoming_callback = s_byo_crypto_test_server_setup_callback,
        .shutdown_callback = s_byo_crypto_test_server_shutdown_callback,
        .destroy_callback = s_byo_crypto_test_server_listener_destroy_callback,
        .tls_options = &args->tls_options,
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

static const char *s_write_tag = "I'm a big teapot";

static int s_start_negotiation_fn(struct aws_channel_handler *handler, void *user_data) {
    struct aws_byte_buf write_tag = aws_byte_buf_from_c_str(s_write_tag);
    rw_handler_write(handler, handler->slot, &write_tag);

    struct byo_crypto_test_args *test_args = user_data;
    if (test_args->negotiation_result_fn) {
        test_args->negotiation_result_fn(handler, handler->slot, AWS_ERROR_SUCCESS, test_args->cb_data);
        test_args->negotiation_result_fn = NULL;
    }

    return AWS_OP_SUCCESS;
}

struct aws_channel_handler *s_tls_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot,
    void *user_data) {
    (void)allocator;
    (void)options;
    (void)slot;

    struct byo_crypto_test_args *test_args = user_data;
    test_args->negotiation_result_fn = options->on_negotiation_result;
    test_args->cb_data = options->user_data;
    return test_args->rw_handler;
}

static int s_byo_tls_handler_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_byo_crypto_common_tester_init(allocator, &c_tester);

    struct aws_byte_buf read_tag = aws_byte_buf_from_c_str("I'm a little teapot.");
    struct aws_byte_buf write_tag = aws_byte_buf_from_c_str(s_write_tag);

    uint8_t incoming_received_message[128] = {0};
    uint8_t outgoing_received_message[128] = {0};

    struct byo_crypto_test_rw_args incoming_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &incoming_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(incoming_received_message, sizeof(incoming_received_message)),
        (int)write_tag.len));

    struct byo_crypto_test_rw_args outgoing_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &outgoing_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(outgoing_received_message, sizeof(outgoing_received_message)),
        (int)read_tag.len));

    /* doesn't matter what these are, I'm turning back pressure off anyways. */
    static size_t s_outgoing_initial_read_window = 128;
    static size_t s_incoming_initial_read_window = 128;
    struct aws_channel_handler *outgoing_rw_handler = rw_handler_new(
        allocator,
        s_byo_crypto_test_handle_read,
        s_byo_crypto_test_handle_write,
        true,
        s_outgoing_initial_read_window,
        &outgoing_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_channel_handler *incoming_rw_handler = rw_handler_new(
        allocator,
        s_byo_crypto_test_handle_read,
        s_byo_crypto_test_handle_write,
        true,
        s_incoming_initial_read_window,
        &incoming_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct byo_crypto_test_args incoming_args;
    ASSERT_SUCCESS(s_byo_crypto_test_args_init(&incoming_args, &c_tester, incoming_rw_handler));
    incoming_rw_args.test_args = &incoming_args;

    struct byo_crypto_test_args outgoing_args;
    ASSERT_SUCCESS(s_byo_crypto_test_args_init(&outgoing_args, &c_tester, outgoing_rw_handler));
    outgoing_rw_args.test_args = &outgoing_args;

    struct aws_tls_byo_crypto_setup_options client_setup_options = {
        .new_handler_fn = s_tls_handler_new,
        .start_negotiation_fn = s_start_negotiation_fn,
        .user_data = &outgoing_args,
    };

    aws_tls_byo_crypto_set_client_setup_options(&client_setup_options);

    struct aws_tls_byo_crypto_setup_options server_setup_options = {
        .new_handler_fn = s_tls_handler_new,
        .user_data = &incoming_args,
    };

    aws_tls_byo_crypto_set_server_setup_options(&server_setup_options);

    struct local_server_tester local_server_tester;
    ASSERT_SUCCESS(s_local_server_tester_init(allocator, &local_server_tester, &incoming_args, &c_tester, true));

    aws_atomic_init_int((volatile struct aws_atomic_var *)&outgoing_args.tls_ctx.ref_count, 1u);
    outgoing_args.tls_options.ctx = &outgoing_args.tls_ctx;

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = c_tester.el_group,
        .host_resolver = NULL,
    };

    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_socket_channel_bootstrap_options channel_options;
    AWS_ZERO_STRUCT(channel_options);
    channel_options.bootstrap = client_bootstrap;
    channel_options.host_name = local_server_tester.endpoint.address;
    channel_options.port = 0;
    channel_options.socket_options = &local_server_tester.socket_options;
    channel_options.setup_callback = s_byo_crypto_test_client_setup_callback;
    channel_options.shutdown_callback = s_byo_crypto_test_client_shutdown_callback;
    channel_options.user_data = &outgoing_args;
    channel_options.tls_options = &outgoing_args.tls_options;
    channel_options.enable_read_back_pressure = false;

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&channel_options));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_setup_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_channel_setup_predicate, &outgoing_args));

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_byo_crypto_test_predicate, &incoming_rw_args));

    rw_handler_write(incoming_args.rw_handler, incoming_args.rw_handler->slot, &read_tag);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_byo_crypto_test_predicate, &outgoing_rw_args));
    incoming_rw_args.invocation_happened = false;
    outgoing_rw_args.invocation_happened = false;

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
    ASSERT_SUCCESS(s_local_server_tester_clean_up(&local_server_tester));

    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_byo_crypto_common_tester_clean_up(&c_tester));
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(byo_tls_handler_test, s_byo_tls_handler_test)

#endif /* BYO_CRYPTO */
