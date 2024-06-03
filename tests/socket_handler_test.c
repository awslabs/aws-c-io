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

#ifdef _MSC_VER
#    pragma warning(disable : 4996) /* allow strncpy() */
#endif

#define NANOS_PER_SEC ((uint64_t)AWS_TIMESTAMP_NANOS)
#define TIMEOUT (10 * NANOS_PER_SEC)

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
    bool creation_callback_invoked;
    bool listener_destroyed;
};

/* common structure for test */
struct socket_common_tester {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    struct aws_event_loop_group *el_group;
    struct aws_host_resolver *resolver;
    struct aws_atomic_var current_time_ns;
    struct aws_atomic_var stats_handler;

    bool setup_called;
    struct aws_event_loop *requested_callback_event_loop;
    int setup_error_code;
};

static struct socket_common_tester c_tester;

static int s_socket_common_tester_init(struct aws_allocator *allocator, struct socket_common_tester *tester) {
    AWS_ZERO_STRUCT(*tester);
    aws_io_library_init(allocator);

    tester->el_group = aws_event_loop_group_new_default(allocator, 0, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = tester->el_group,
        .max_entries = 8,
    };
    tester->resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;
    tester->mutex = mutex;
    tester->condition_variable = condition_variable;
    aws_atomic_store_int(&tester->current_time_ns, 0);
    aws_atomic_store_ptr(&tester->stats_handler, NULL);

    return AWS_OP_SUCCESS;
}

static int s_socket_common_tester_clean_up(struct socket_common_tester *tester) {
    aws_host_resolver_release(tester->resolver);
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

static bool s_pinned_channel_setup_predicate(void *user_data) {
    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;
    return setup_test_args->channel != NULL;
}

static bool s_channel_setup_predicate(void *user_data) {
    struct socket_test_args *setup_test_args = (struct socket_test_args *)user_data;
    return setup_test_args->rw_slot != NULL;
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

    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->channel = channel;

    struct aws_channel_slot *rw_slot = aws_channel_slot_new(channel);
    aws_channel_slot_insert_end(channel, rw_slot);

    aws_channel_slot_set_handler(rw_slot, setup_test_args->rw_handler);
    setup_test_args->rw_slot = rw_slot;

    aws_mutex_unlock(setup_test_args->mutex);

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

    aws_mutex_lock(setup_test_args->mutex);

    setup_test_args->channel = channel;

    if (setup_test_args->rw_handler != NULL) {
        struct aws_channel_slot *rw_slot = aws_channel_slot_new(channel);
        aws_channel_slot_insert_end(channel, rw_slot);

        aws_channel_slot_set_handler(rw_slot, setup_test_args->rw_handler);
        setup_test_args->rw_slot = rw_slot;
    }

    aws_mutex_unlock(setup_test_args->mutex);

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
    size_t amount_written;
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
    AWS_FATAL_ASSERT(aws_byte_buf_write_from_whole_buffer(&rw_args->received_message, *data_read) == true);
    rw_args->amount_read += data_read->len;
    rw_args->invocation_happened = true;
    aws_condition_variable_notify_one(rw_args->condition_variable);
    aws_mutex_unlock(rw_args->mutex);

    return rw_args->received_message;
}

void s_socket_test_handle_on_write_completed(
    struct aws_channel *channel,
    struct aws_io_message *message,
    int error_code,
    void *user_data) {

    (void)channel;
    AWS_FATAL_ASSERT(error_code == 0);
    struct socket_test_rw_args *rw_args = (struct socket_test_rw_args *)user_data;

    aws_mutex_lock(rw_args->mutex);
    rw_args->amount_written += message->message_data.len;
    rw_args->invocation_happened = true;
    aws_condition_variable_notify_one(rw_args->condition_variable);
    aws_mutex_unlock(rw_args->mutex);
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
    enum aws_socket_domain socket_domain,
    bool enable_back_pressure) {

    AWS_ZERO_STRUCT(*tester);
    tester->socket_options.connect_timeout_ms = 3000;
    tester->socket_options.type = AWS_SOCKET_STREAM;
    tester->socket_options.domain = socket_domain;
    switch (socket_domain) {
        case AWS_SOCKET_LOCAL:
            aws_socket_endpoint_init_local_address_for_test(&tester->endpoint);
            break;
        case AWS_SOCKET_IPV4:
            strncpy(tester->endpoint.address, "127.0.0.1", sizeof(tester->endpoint.address));
            break;
        case AWS_SOCKET_IPV6:
            strncpy(tester->endpoint.address, "::1", sizeof(tester->endpoint.address));
            break;
        default:
            ASSERT_TRUE(false);
            break;
    }

    tester->server_bootstrap = aws_server_bootstrap_new(allocator, s_c_tester->el_group);
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

    /* find out which port the socket is bound to */
    ASSERT_SUCCESS(aws_socket_get_bound_address(tester->listener, &tester->endpoint));

    return AWS_OP_SUCCESS;
}

static int s_local_server_tester_clean_up(struct local_server_tester *tester) {
    aws_server_bootstrap_release(tester->server_bootstrap);
    return AWS_OP_SUCCESS;
}

static int s_socket_pinned_event_loop_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_socket_common_tester_init(allocator, &c_tester);

    struct aws_channel_handler *client_rw_handler =
        rw_handler_new(allocator, s_socket_test_handle_write, s_socket_test_handle_write, true, SIZE_MAX, NULL);
    ASSERT_NOT_NULL(client_rw_handler);

    struct aws_channel_handler *server_rw_handler =
        rw_handler_new(allocator, s_socket_test_handle_write, s_socket_test_handle_write, true, SIZE_MAX, NULL);
    ASSERT_NOT_NULL(server_rw_handler);

    struct socket_test_args server_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&server_args, &c_tester, server_rw_handler));

    struct socket_test_args client_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&client_args, &c_tester, client_rw_handler));

    struct local_server_tester local_server_tester;
    ASSERT_SUCCESS(
        s_local_server_tester_init(allocator, &local_server_tester, &server_args, &c_tester, AWS_SOCKET_LOCAL, true));

    struct aws_client_bootstrap_options client_bootstrap_options = {
        .event_loop_group = c_tester.el_group,
        .host_resolver = c_tester.resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &client_bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_event_loop *pinned_event_loop = aws_event_loop_group_get_next_loop(c_tester.el_group);

    struct aws_socket_channel_bootstrap_options client_channel_options;
    AWS_ZERO_STRUCT(client_channel_options);
    client_channel_options.bootstrap = client_bootstrap;
    client_channel_options.host_name = local_server_tester.endpoint.address;
    client_channel_options.port = local_server_tester.endpoint.port;
    client_channel_options.socket_options = &local_server_tester.socket_options;
    client_channel_options.setup_callback = s_socket_handler_test_client_setup_callback;
    client_channel_options.shutdown_callback = s_socket_handler_test_client_shutdown_callback;
    client_channel_options.enable_read_back_pressure = false;
    client_channel_options.requested_event_loop = pinned_event_loop;
    client_channel_options.user_data = &client_args;

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&client_channel_options));

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_pinned_channel_setup_predicate, &server_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_pinned_channel_setup_predicate, &client_args));

    /* Verify the client channel was placed on the requested event loop */
    ASSERT_PTR_EQUALS(pinned_event_loop, aws_channel_get_event_loop(client_args.channel));

    ASSERT_SUCCESS(aws_channel_shutdown(server_args.channel, AWS_OP_SUCCESS));
    ASSERT_SUCCESS(aws_channel_shutdown(client_args.channel, AWS_OP_SUCCESS));

    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_shutdown_predicate, &server_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_shutdown_predicate, &client_args));
    aws_server_bootstrap_destroy_socket_listener(local_server_tester.server_bootstrap, local_server_tester.listener);
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_listener_destroy_predicate, &server_args));

    aws_mutex_unlock(&c_tester.mutex);

    /* clean up */
    ASSERT_SUCCESS(s_local_server_tester_clean_up(&local_server_tester));

    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_socket_common_tester_clean_up(&c_tester));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socket_pinned_event_loop, s_socket_pinned_event_loop_test)

static void s_dns_failure_test_client_setup_callback(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)channel;

    struct socket_common_tester *socket_tester = (struct socket_common_tester *)user_data;

    aws_mutex_lock(&socket_tester->mutex);

    socket_tester->setup_error_code = error_code;
    socket_tester->setup_called = true;
    AWS_FATAL_ASSERT(aws_event_loop_thread_is_callers_thread(socket_tester->requested_callback_event_loop));
    AWS_FATAL_ASSERT(channel == NULL);

    aws_mutex_unlock(&socket_tester->mutex);
    aws_condition_variable_notify_one(&socket_tester->condition_variable);
}

static void s_dns_failure_handler_test_client_shutdown_callback(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)error_code;
    (void)bootstrap;
    (void)channel;
    (void)user_data;

    // Should never be called
    AWS_FATAL_ASSERT(false);
}

static bool s_dns_failure_channel_setup_predicate(void *user_data) {
    struct socket_common_tester *socket_tester = (struct socket_common_tester *)user_data;
    return socket_tester->setup_called;
}

static int s_socket_pinned_event_loop_dns_failure_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_socket_common_tester_init(allocator, &c_tester);

    struct aws_client_bootstrap_options client_bootstrap_options = {
        .event_loop_group = c_tester.el_group,
        .host_resolver = c_tester.resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &client_bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_event_loop *pinned_event_loop = aws_event_loop_group_get_next_loop(c_tester.el_group);
    c_tester.requested_callback_event_loop = pinned_event_loop;

    struct aws_socket_options socket_options = {
        .domain = AWS_SOCKET_IPV4,
        .type = AWS_SOCKET_STREAM,
        .connect_timeout_ms = 10000,
    };

    struct aws_socket_channel_bootstrap_options client_channel_options;
    AWS_ZERO_STRUCT(client_channel_options);
    client_channel_options.bootstrap = client_bootstrap;
    client_channel_options.host_name = "notavalid.domain-seriously.uffda";
    client_channel_options.port = 443;
    client_channel_options.socket_options = &socket_options;
    client_channel_options.setup_callback = s_dns_failure_test_client_setup_callback;
    client_channel_options.shutdown_callback = s_dns_failure_handler_test_client_shutdown_callback;
    client_channel_options.enable_read_back_pressure = false;
    client_channel_options.requested_event_loop = pinned_event_loop;
    client_channel_options.user_data = &c_tester;

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&client_channel_options));

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_dns_failure_channel_setup_predicate, &c_tester));

    /* Verify the setup callback failure was on the requested event loop */
    ASSERT_TRUE(c_tester.setup_error_code != 0);

    aws_mutex_unlock(&c_tester.mutex);

    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_socket_common_tester_clean_up(&c_tester));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socket_pinned_event_loop_dns_failure, s_socket_pinned_event_loop_dns_failure_test)

static int s_socket_echo_and_backpressure_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_socket_common_tester_init(allocator, &c_tester);

    struct aws_byte_buf msg_from_server = aws_byte_buf_from_c_str("I'm a little teapot.");
    struct aws_byte_buf msg_from_client = aws_byte_buf_from_c_str("I'm a big teapot");

    uint8_t server_received_message[128] = {0};
    uint8_t client_received_message[128] = {0};

    struct socket_test_rw_args server_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &server_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(server_received_message, sizeof(server_received_message)),
        (int)msg_from_client.len));

    struct socket_test_rw_args client_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &client_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(client_received_message, sizeof(client_received_message)),
        (int)msg_from_server.len));
    /* make the windows small to make sure back pressure is honored. */
    static size_t s_client_initial_read_window = 9;
    static size_t s_server_initial_read_window = 8;
    struct aws_channel_handler *client_rw_handler = rw_handler_new(
        allocator,
        s_socket_test_handle_read,
        s_socket_test_handle_write,
        true,
        s_client_initial_read_window,
        &client_rw_args);
    ASSERT_NOT_NULL(client_rw_handler);

    struct aws_channel_handler *server_rw_handler = rw_handler_new(
        allocator,
        s_socket_test_handle_read,
        s_socket_test_handle_write,
        true,
        s_server_initial_read_window,
        &server_rw_args);
    ASSERT_NOT_NULL(server_rw_handler);

    struct socket_test_args server_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&server_args, &c_tester, server_rw_handler));

    struct socket_test_args client_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&client_args, &c_tester, client_rw_handler));

    struct local_server_tester local_server_tester;
    ASSERT_SUCCESS(
        s_local_server_tester_init(allocator, &local_server_tester, &server_args, &c_tester, AWS_SOCKET_LOCAL, true));

    struct aws_client_bootstrap_options client_bootstrap_options = {
        .event_loop_group = c_tester.el_group,
        .host_resolver = c_tester.resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &client_bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_socket_channel_bootstrap_options client_channel_options;
    AWS_ZERO_STRUCT(client_channel_options);
    client_channel_options.bootstrap = client_bootstrap;
    client_channel_options.host_name = local_server_tester.endpoint.address;
    client_channel_options.port = local_server_tester.endpoint.port;
    client_channel_options.socket_options = &local_server_tester.socket_options;
    client_channel_options.setup_callback = s_socket_handler_test_client_setup_callback;
    client_channel_options.shutdown_callback = s_socket_handler_test_client_shutdown_callback;
    client_channel_options.user_data = &client_args;
    client_channel_options.enable_read_back_pressure = true;

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&client_channel_options));

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_setup_predicate, &server_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_setup_predicate, &client_args));

    /* send msg from client to server, and wait for some bytes to be received */
    rw_handler_write(client_args.rw_handler, client_args.rw_slot, &msg_from_client);
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_socket_test_read_predicate, &server_rw_args));

    /* send msg from server to client, and wait for some bytes to be received */
    rw_handler_write(server_args.rw_handler, server_args.rw_slot, &msg_from_server);
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_socket_test_read_predicate, &client_rw_args));

    /* confirm that the initial read window was respected */
    server_rw_args.invocation_happened = false;
    client_rw_args.invocation_happened = false;

    ASSERT_INT_EQUALS(s_client_initial_read_window, client_rw_args.amount_read);
    ASSERT_INT_EQUALS(s_server_initial_read_window, server_rw_args.amount_read);

    /* increment the read window on both sides and confirm they receive the remainder of their message */
    rw_handler_trigger_increment_read_window(server_args.rw_handler, server_args.rw_slot, 100);
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_socket_test_full_read_predicate, &server_rw_args));

    rw_handler_trigger_increment_read_window(client_args.rw_handler, client_args.rw_slot, 100);
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_socket_test_full_read_predicate, &client_rw_args));

    ASSERT_INT_EQUALS(msg_from_server.len, client_rw_args.amount_read);
    ASSERT_INT_EQUALS(msg_from_client.len, server_rw_args.amount_read);

    ASSERT_BIN_ARRAYS_EQUALS(
        msg_from_client.buffer,
        msg_from_client.len,
        server_rw_args.received_message.buffer,
        server_rw_args.received_message.len);
    ASSERT_BIN_ARRAYS_EQUALS(
        msg_from_server.buffer,
        msg_from_server.len,
        client_rw_args.received_message.buffer,
        client_rw_args.received_message.len);

    /* only shut down one side, this should cause the other side to shutdown as well.*/
    ASSERT_SUCCESS(aws_channel_shutdown(server_args.channel, AWS_OP_SUCCESS));
    ASSERT_SUCCESS(aws_channel_shutdown(client_args.channel, AWS_OP_SUCCESS));

    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_shutdown_predicate, &server_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_shutdown_predicate, &client_args));
    aws_server_bootstrap_destroy_socket_listener(local_server_tester.server_bootstrap, local_server_tester.listener);
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_listener_destroy_predicate, &server_args));

    aws_mutex_unlock(&c_tester.mutex);

    /* clean up */
    ASSERT_SUCCESS(s_local_server_tester_clean_up(&local_server_tester));

    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_socket_common_tester_clean_up(&c_tester));
    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socket_handler_echo_and_backpressure, s_socket_echo_and_backpressure_test)

static int s_socket_close_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    s_socket_common_tester_init(allocator, &c_tester);

    uint8_t client_received_message[128];
    uint8_t server_received_message[128];

    struct socket_test_rw_args server_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &server_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(server_received_message, sizeof(server_received_message)),
        0));

    struct socket_test_rw_args client_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &client_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(client_received_message, sizeof(client_received_message)),
        0));

    struct aws_channel_handler *client_rw_handler =
        rw_handler_new(allocator, s_socket_test_handle_read, s_socket_test_handle_write, true, 10000, &client_rw_args);
    ASSERT_NOT_NULL(client_rw_handler);

    struct aws_channel_handler *server_rw_handler =
        rw_handler_new(allocator, s_socket_test_handle_read, s_socket_test_handle_write, true, 10000, &server_rw_args);
    ASSERT_NOT_NULL(server_rw_handler);

    struct socket_test_args server_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&server_args, &c_tester, server_rw_handler));

    struct socket_test_args client_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&client_args, &c_tester, client_rw_handler));

    struct local_server_tester local_server_tester;
    ASSERT_SUCCESS(
        s_local_server_tester_init(allocator, &local_server_tester, &server_args, &c_tester, AWS_SOCKET_LOCAL, false));

    struct aws_client_bootstrap_options client_bootstrap_options = {
        .event_loop_group = c_tester.el_group,
        .host_resolver = c_tester.resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &client_bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_socket_channel_bootstrap_options client_channel_options;
    AWS_ZERO_STRUCT(client_channel_options);
    client_channel_options.bootstrap = client_bootstrap;
    client_channel_options.host_name = local_server_tester.endpoint.address;
    client_channel_options.port = local_server_tester.endpoint.port;
    client_channel_options.socket_options = &local_server_tester.socket_options;
    client_channel_options.setup_callback = s_socket_handler_test_client_setup_callback;
    client_channel_options.shutdown_callback = s_socket_handler_test_client_shutdown_callback;
    client_channel_options.user_data = &client_args;

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&client_channel_options));

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_setup_predicate, &server_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_setup_predicate, &client_args));

    aws_channel_shutdown(server_args.channel, AWS_OP_SUCCESS);

    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_shutdown_predicate, &server_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_shutdown_predicate, &client_args));

    ASSERT_INT_EQUALS(AWS_OP_SUCCESS, server_args.error_code);
    ASSERT_TRUE(
        AWS_IO_SOCKET_CLOSED == client_args.error_code || AWS_IO_SOCKET_NOT_CONNECTED == client_args.error_code);
    aws_server_bootstrap_destroy_socket_listener(local_server_tester.server_bootstrap, local_server_tester.listener);
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_listener_destroy_predicate, &server_args));

    aws_mutex_unlock(&c_tester.mutex);

    /* clean up */
    ASSERT_SUCCESS(s_local_server_tester_clean_up(&local_server_tester));

    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_socket_common_tester_clean_up(&c_tester));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(socket_handler_close, s_socket_close_test)

/* This is a regression test.
 * Once upon a time, if the socket-handler received READABLE and HANGUP events simultaneously,
 * it would read one last time from the socket before closing it. But one read may
 * not be enough to get all remaining data. The correct thing is to do is
 * repeatedly read until the read() call itself reports EOF or an error.
 *
 * Anyway, this test establishes a connection between server and client.
 * The server sends a big chunk of data, and closes the socket immediately
 * after the write completes. The client should still be able to read all the data. */
static int s_socket_read_to_eof_after_peer_hangup_test_common(
    struct aws_allocator *allocator,
    void *ctx,
    enum aws_socket_domain socket_domain) {

    (void)ctx;
    s_socket_common_tester_init(allocator, &c_tester);

    const size_t total_bytes_to_send_from_server = g_aws_channel_max_fragment_size;

    struct aws_byte_buf client_received_message;
    ASSERT_SUCCESS(aws_byte_buf_init(&client_received_message, allocator, total_bytes_to_send_from_server));

    struct aws_byte_buf msg_from_server;
    ASSERT_SUCCESS(aws_byte_buf_init(&msg_from_server, allocator, total_bytes_to_send_from_server));

    struct socket_test_rw_args server_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(&server_rw_args, &c_tester, aws_byte_buf_from_empty_array(NULL, 0), 0));

    struct socket_test_rw_args client_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(&client_rw_args, &c_tester, client_received_message, 0));

    /* NOTE: client starts with window=0, so we can VERY CAREFULLY control when it reads data from the socket */
    struct aws_channel_handler *client_rw_handler = rw_handler_new(
        allocator, s_socket_test_handle_read, s_socket_test_handle_write, true, 0 /*window*/, &client_rw_args);
    ASSERT_NOT_NULL(client_rw_handler);

    struct aws_channel_handler *server_rw_handler =
        rw_handler_new(allocator, s_socket_test_handle_read, s_socket_test_handle_write, true, 10000, &server_rw_args);
    ASSERT_NOT_NULL(server_rw_handler);

    struct socket_test_args server_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&server_args, &c_tester, server_rw_handler));

    struct socket_test_args client_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&client_args, &c_tester, client_rw_handler));

    struct local_server_tester local_server_tester;
    if (s_local_server_tester_init(allocator, &local_server_tester, &server_args, &c_tester, socket_domain, false)) {
        /* Skip test if server can't bind to address (e.g. Gith9ub's ubuntu runners don't allow IPv6) */
        if (aws_last_error() == AWS_IO_SOCKET_INVALID_ADDRESS) {
            return AWS_OP_SKIP;
        } else {
            ASSERT_TRUE(false, "s_local_server_tester_init() failed");
        }
    }

    struct aws_client_bootstrap_options client_bootstrap_options = {
        .event_loop_group = c_tester.el_group,
        .host_resolver = c_tester.resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &client_bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_socket_channel_bootstrap_options client_channel_options = {
        .bootstrap = client_bootstrap,
        .host_name = local_server_tester.endpoint.address,
        .port = local_server_tester.endpoint.port,
        .socket_options = &local_server_tester.socket_options,
        .setup_callback = s_socket_handler_test_client_setup_callback,
        .shutdown_callback = s_socket_handler_test_client_shutdown_callback,
        .user_data = &client_args,
        .enable_read_back_pressure = true,
    };

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&client_channel_options));

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_setup_predicate, &server_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_setup_predicate, &client_args));

    /* We want the server to send some data and hang up IMMEDIATELY after,
     * before the client has fully read the data. This is tricky to do in a test.
     *
     * First, have the server send data... */
    ASSERT_TRUE(aws_byte_buf_write_u8_n(&msg_from_server, 's', total_bytes_to_send_from_server));
    rw_handler_write_with_callback(
        server_rw_handler,
        server_args.rw_slot,
        &msg_from_server,
        s_socket_test_handle_on_write_completed,
        &server_rw_args);

    /* ...now have the client open its read window and receive data in tiny chunks,
     * stopping once the server has sent all data, but BEFORE the client has read all data.
     * This is possible because the client's OS will buffer a certain amount of
     * incoming data, before the client application calls read() on it. */
    while (server_rw_args.amount_written < total_bytes_to_send_from_server) {
        const size_t client_read_chunk_size = 128;
        client_rw_args.expected_read += client_read_chunk_size;
        rw_handler_trigger_increment_read_window(client_args.rw_handler, client_args.rw_slot, client_read_chunk_size);
        ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
            &c_tester.condition_variable,
            &c_tester.mutex,
            TIMEOUT,
            s_socket_test_full_read_predicate,
            &client_rw_args));
    }

    /* Now close the server's socket.*/
    ASSERT_SUCCESS(aws_channel_shutdown(server_args.channel, AWS_OP_SUCCESS));
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_shutdown_predicate, &server_args));

    /* Now sleep a moment to 100% guarantee the OS propagates the socket-close event to the client-side. */
    aws_mutex_unlock(&c_tester.mutex);
    aws_thread_current_sleep(NANOS_PER_SEC / 4);
    aws_mutex_lock(&c_tester.mutex);

    /* Ensure the client hasn't shut down before reading all the data. */
    ASSERT_FALSE(client_args.shutdown_invoked, "Client should read all data before shutting down.");

    /* Ensure the client hasn't read all data yet */
    ASSERT_TRUE(
        client_rw_args.amount_read < total_bytes_to_send_from_server,
        "If this fails, then we're not truly reproducing the regression test."
        " The server needs to finish sending data, and close the socket,"
        " BEFORE the client reads all the data.");

    /* Have the client open its window more-than-enough to receive the rest of the data.
     * If the client socket closes before all the data is received, then we still have the bug. */
    rw_handler_trigger_increment_read_window(
        client_args.rw_handler, client_args.rw_slot, total_bytes_to_send_from_server * 3 /*more-than-enough*/);
    client_rw_args.expected_read = total_bytes_to_send_from_server;
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_socket_test_full_read_predicate, &client_rw_args));

    /* Wait for client to shutdown, due to the server having closed the socket */
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_shutdown_predicate, &client_args));

    aws_server_bootstrap_destroy_socket_listener(local_server_tester.server_bootstrap, local_server_tester.listener);
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_listener_destroy_predicate, &server_args));

    ASSERT_INT_EQUALS(AWS_IO_SOCKET_CLOSED, client_args.error_code);

    aws_mutex_unlock(&c_tester.mutex);

    /* clean up */
    ASSERT_SUCCESS(s_local_server_tester_clean_up(&local_server_tester));
    aws_byte_buf_clean_up(&client_received_message);
    aws_byte_buf_clean_up(&msg_from_server);
    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_socket_common_tester_clean_up(&c_tester));

    return AWS_OP_SUCCESS;
}
static int s_socket_read_to_eof_after_peer_hangup_test(struct aws_allocator *allocator, void *ctx) {
    return s_socket_read_to_eof_after_peer_hangup_test_common(allocator, ctx, AWS_SOCKET_LOCAL);
}
AWS_TEST_CASE(socket_handler_read_to_eof_after_peer_hangup, s_socket_read_to_eof_after_peer_hangup_test)

static int s_socket_ipv4_read_to_eof_after_peer_hangup_test(struct aws_allocator *allocator, void *ctx) {
    return s_socket_read_to_eof_after_peer_hangup_test_common(allocator, ctx, AWS_SOCKET_IPV4);
}
AWS_TEST_CASE(socket_handler_ipv4_read_to_eof_after_peer_hangup, s_socket_ipv4_read_to_eof_after_peer_hangup_test)

static int s_socket_ipv6_read_to_eof_after_peer_hangup_test(struct aws_allocator *allocator, void *ctx) {
    return s_socket_read_to_eof_after_peer_hangup_test_common(allocator, ctx, AWS_SOCKET_IPV6);
}
AWS_TEST_CASE(socket_handler_ipv6_read_to_eof_after_peer_hangup, s_socket_ipv6_read_to_eof_after_peer_hangup_test)

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
    const struct aws_event_loop_options *options,
    void *user_data) {

    (void)user_data;
    return aws_event_loop_new_default_with_options(allocator, options);
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
    tester->el_group =
        aws_event_loop_group_new(allocator, s_statistic_test_clock_fn, 1, s_default_new_event_loop, NULL, NULL);
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

    struct aws_byte_buf msg_from_server = aws_byte_buf_from_c_str("Some bytes");
    struct aws_byte_buf msg_from_client = aws_byte_buf_from_c_str("Fresh pressed Washington apples");

    uint8_t client_received_message[128];
    uint8_t server_received_message[128];

    struct socket_test_rw_args server_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &server_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(server_received_message, sizeof(server_received_message)),
        0));

    struct socket_test_rw_args client_rw_args;
    ASSERT_SUCCESS(s_rw_args_init(
        &client_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(client_received_message, sizeof(client_received_message)),
        0));

    struct aws_channel_handler *client_rw_handler =
        rw_handler_new(allocator, s_socket_test_handle_read, s_socket_test_handle_write, true, 10000, &client_rw_args);
    ASSERT_NOT_NULL(client_rw_handler);

    struct aws_channel_handler *server_rw_handler =
        rw_handler_new(allocator, s_socket_test_handle_read, s_socket_test_handle_write, true, 10000, &server_rw_args);
    ASSERT_NOT_NULL(server_rw_handler);

    struct socket_test_args server_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&server_args, &c_tester, server_rw_handler));

    struct socket_test_args client_args;
    ASSERT_SUCCESS(s_socket_test_args_init(&client_args, &c_tester, client_rw_handler));

    struct local_server_tester local_server_tester;
    ASSERT_SUCCESS(
        s_local_server_tester_init(allocator, &local_server_tester, &server_args, &c_tester, AWS_SOCKET_LOCAL, false));

    struct aws_client_bootstrap_options client_bootstrap_options;
    AWS_ZERO_STRUCT(client_bootstrap_options);
    client_bootstrap_options.event_loop_group = c_tester.el_group;
    client_bootstrap_options.host_resolver = c_tester.resolver;

    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &client_bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_socket_channel_bootstrap_options client_channel_options;
    AWS_ZERO_STRUCT(client_channel_options);
    client_channel_options.bootstrap = client_bootstrap;
    client_channel_options.host_name = local_server_tester.endpoint.address;
    client_channel_options.port = local_server_tester.endpoint.port;
    client_channel_options.socket_options = &local_server_tester.socket_options;
    client_channel_options.creation_callback = s_creation_callback_test_channel_creation_callback;
    client_channel_options.setup_callback = s_socket_handler_test_client_setup_callback;
    client_channel_options.shutdown_callback = s_socket_handler_test_client_shutdown_callback;
    client_channel_options.user_data = &client_args;

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&client_channel_options));

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_setup_predicate, &server_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_setup_predicate, &client_args));

    ASSERT_TRUE(client_args.creation_callback_invoked);

    rw_handler_write(client_args.rw_handler, client_args.rw_slot, &msg_from_client);
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_socket_test_read_predicate, &server_rw_args));

    rw_handler_write(server_args.rw_handler, server_args.rw_slot, &msg_from_server);
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_socket_test_read_predicate, &client_rw_args));

    uint64_t ms_to_ns = aws_timestamp_convert(1, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);

    aws_atomic_store_int(&c_tester.current_time_ns, (size_t)ms_to_ns);

    struct aws_crt_statistics_handler *stats_handler = aws_atomic_load_ptr(&c_tester.stats_handler);
    struct aws_statistics_handler_test_impl *stats_impl = stats_handler->impl;

    aws_mutex_lock(&stats_impl->lock);
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &stats_impl->signal, &stats_impl->lock, TIMEOUT, s_stats_processed_predicate, stats_handler));

    ASSERT_TRUE(stats_impl->total_bytes_read == msg_from_server.len);
    ASSERT_TRUE(stats_impl->total_bytes_written == msg_from_client.len);

    aws_mutex_unlock(&stats_impl->lock);

    aws_channel_shutdown(server_args.channel, AWS_OP_SUCCESS);

    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_shutdown_predicate, &server_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_channel_shutdown_predicate, &client_args));

    aws_server_bootstrap_destroy_socket_listener(local_server_tester.server_bootstrap, local_server_tester.listener);
    ASSERT_SUCCESS(aws_condition_variable_wait_for_pred(
        &c_tester.condition_variable, &c_tester.mutex, TIMEOUT, s_listener_destroy_predicate, &server_args));

    aws_mutex_unlock(&c_tester.mutex);

    /* clean up */
    ASSERT_SUCCESS(s_local_server_tester_clean_up(&local_server_tester));

    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_socket_common_tester_clean_up(&c_tester));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(open_channel_statistics_test, s_open_channel_statistics_test)
