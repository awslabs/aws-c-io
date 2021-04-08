/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef BYO_CRYPTO

#    include <aws/io/channel_bootstrap.h>
#    include <aws/io/event_loop.h>
#    include <aws/io/file_utils.h>
#    include <aws/io/host_resolver.h>
#    include <aws/io/logging.h>
#    include <aws/io/socket.h>
#    include <aws/io/tls_channel_handler.h>

#    include <aws/common/clock.h>
#    include <aws/common/condition_variable.h>
#    include <aws/common/thread.h>

#    include <aws/testing/aws_test_harness.h>

#    include <aws/common/string.h>
#    include <read_write_test_handler.h>
#    include <statistics_handler_test.h>

#    if _MSC_VER
#        pragma warning(disable : 4996) /* sprintf */
#    endif

#    ifdef _WIN32
#        define LOCAL_SOCK_TEST_PATTERN "\\\\.\\pipe\\testsock%llu_%d"
#    else
#        define LOCAL_SOCK_TEST_PATTERN "testsock%llu_%d.sock"
#    endif

struct tls_test_args {
    struct aws_allocator *allocator;
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_tls_connection_options *tls_options;
    struct aws_channel *channel;
    struct aws_channel_handler *rw_handler;
    struct aws_channel_slot *rw_slot;
    struct aws_byte_buf negotiated_protocol;
    struct aws_byte_buf server_name;
    int last_error_code;

    uint32_t tls_levels_negotiated;
    uint32_t desired_tls_levels;

    bool listener_destroyed;
    bool error_invoked;
    bool expects_error;
    bool server;
    bool shutdown_finished;
    bool setup_callback_invoked;
    bool creation_callback_invoked;
};

/* common structure for tls options */
struct tls_opt_tester {
    struct aws_tls_ctx_options ctx_options;
    struct aws_tls_ctx *ctx;
    struct aws_tls_connection_options opt;
};

static int s_tls_server_opt_tester_init(struct aws_allocator *allocator, struct tls_opt_tester *tester) {

#    ifdef __APPLE__
    struct aws_byte_cursor pwd_cur = aws_byte_cursor_from_c_str("1234");
    ASSERT_SUCCESS(
        aws_tls_ctx_options_init_server_pkcs12_from_path(&tester->ctx_options, allocator, "unittests.p12", &pwd_cur));
#    else
    ASSERT_SUCCESS(aws_tls_ctx_options_init_default_server_from_path(
        &tester->ctx_options, allocator, "unittests.crt", "unittests.key"));
#    endif /* __APPLE__ */
    aws_tls_ctx_options_set_alpn_list(&tester->ctx_options, "h2;http/1.1");
    tester->ctx = aws_tls_server_ctx_new(allocator, &tester->ctx_options);
    ASSERT_NOT_NULL(tester->ctx);

    aws_tls_connection_options_init_from_ctx(&tester->opt, tester->ctx);
    return AWS_OP_SUCCESS;
}

static int s_tls_client_opt_tester_init(
    struct aws_allocator *allocator,
    struct tls_opt_tester *tester,
    struct aws_byte_cursor server_name) {

    aws_io_library_init(allocator);

    aws_tls_ctx_options_init_default_client(&tester->ctx_options, allocator);
    aws_tls_ctx_options_override_default_trust_store_from_path(&tester->ctx_options, NULL, "unittests.crt");

    tester->ctx = aws_tls_client_ctx_new(allocator, &tester->ctx_options);
    aws_tls_connection_options_init_from_ctx(&tester->opt, tester->ctx);
    aws_tls_connection_options_set_alpn_list(&tester->opt, allocator, "h2;http/1.1");

    aws_tls_connection_options_set_server_name(&tester->opt, allocator, &server_name);

    return AWS_OP_SUCCESS;
}

static int s_tls_opt_tester_clean_up(struct tls_opt_tester *tester) {
    aws_tls_connection_options_clean_up(&tester->opt);
    aws_tls_ctx_options_clean_up(&tester->ctx_options);
    aws_tls_ctx_release(tester->ctx);
    return AWS_OP_SUCCESS;
}

/* common structure for test */
struct tls_common_tester {
    struct aws_mutex mutex;
    struct aws_condition_variable condition_variable;
    struct aws_event_loop_group *el_group;
    struct aws_host_resolver *resolver;
    struct aws_atomic_var current_time_ns;
    struct aws_atomic_var stats_handler;
};

static struct tls_common_tester c_tester;

/* common structure for a tls local server */
struct tls_local_server_tester {
    struct aws_socket_options socket_options;
    struct tls_opt_tester server_tls_opt_tester;
    struct aws_socket_endpoint endpoint;
    struct aws_server_bootstrap *server_bootstrap;
    struct aws_socket *listener;
    uint64_t timestamp;
};

static int s_tls_test_arg_init(
    struct aws_allocator *allocator,
    struct tls_test_args *test_arg,
    bool server,
    struct tls_common_tester *tls_c_tester) {
    AWS_ZERO_STRUCT(*test_arg);
    test_arg->mutex = &tls_c_tester->mutex;
    test_arg->condition_variable = &tls_c_tester->condition_variable;
    test_arg->allocator = allocator;
    test_arg->server = server;
    test_arg->desired_tls_levels = 1;

    return AWS_OP_SUCCESS;
}

static int s_tls_common_tester_init(struct aws_allocator *allocator, struct tls_common_tester *tester) {
    AWS_ZERO_STRUCT(*tester);

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;
    tester->mutex = mutex;
    tester->condition_variable = condition_variable;
    aws_atomic_store_int(&tester->current_time_ns, 0);
    aws_atomic_store_ptr(&tester->stats_handler, NULL);

    tester->el_group = aws_event_loop_group_new_default(allocator, 0, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = tester->el_group,
        .max_entries = 1,
    };
    tester->resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    return AWS_OP_SUCCESS;
}

static int s_tls_common_tester_clean_up(struct tls_common_tester *tester) {
    aws_host_resolver_release(tester->resolver);
    aws_event_loop_group_release(tester->el_group);

    aws_io_library_clean_up();

    aws_condition_variable_clean_up(&tester->condition_variable);
    aws_mutex_clean_up(&tester->mutex);
    return AWS_OP_SUCCESS;
}

static bool s_tls_channel_shutdown_predicate(void *user_data) {
    struct tls_test_args *setup_test_args = user_data;
    return setup_test_args->shutdown_finished || setup_test_args->last_error_code == AWS_IO_SOCKET_TIMEOUT ||
           (setup_test_args->expects_error && setup_test_args->error_invoked);
}

static bool s_tls_listener_destroy_predicate(void *user_data) {
    struct tls_test_args *setup_test_args = user_data;
    return setup_test_args->listener_destroyed || setup_test_args->last_error_code == AWS_IO_SOCKET_TIMEOUT;
}

static bool s_tls_channel_setup_predicate(void *user_data) {
    struct tls_test_args *setup_test_args = user_data;
    return (setup_test_args->tls_levels_negotiated == setup_test_args->desired_tls_levels &&
            setup_test_args->setup_callback_invoked) ||
           setup_test_args->error_invoked;
}

/*
 * test args mutex must be held before calling this function
 */
static void s_aws_check_for_user_handler_setup(struct tls_test_args *setup_test_args) {
    if (setup_test_args->tls_levels_negotiated == setup_test_args->desired_tls_levels &&
        setup_test_args->setup_callback_invoked) {
        if (setup_test_args->rw_handler) {
            struct aws_channel *channel = setup_test_args->channel;
            struct aws_channel_slot *rw_slot = aws_channel_slot_new(channel);
            aws_channel_slot_insert_end(channel, rw_slot);
            aws_channel_slot_set_handler(rw_slot, setup_test_args->rw_handler);
            setup_test_args->rw_slot = rw_slot;
        }
    }
}

static int s_add_tls_handler_to_end_of_channel(struct tls_test_args *setup_test_args) {
    AWS_FATAL_ASSERT(setup_test_args->desired_tls_levels > 1);
    AWS_FATAL_ASSERT(!setup_test_args->server);

    struct aws_channel_slot *last_slot = aws_channel_get_first_slot(setup_test_args->channel);
    while (last_slot->adj_right) {
        last_slot = last_slot->adj_right;
    }

    return aws_channel_setup_client_tls(last_slot, setup_test_args->tls_options);
}

static int s_on_channel_setup_next_tls_handler(struct tls_test_args *setup_test_args) {
    if (setup_test_args->tls_levels_negotiated < setup_test_args->desired_tls_levels) {
        ASSERT_SUCCESS(s_add_tls_handler_to_end_of_channel(setup_test_args));
    }

    return AWS_OP_SUCCESS;
}

static int s_on_tls_negotiated_next_tls_handler(struct tls_test_args *setup_test_args) {
    if (!setup_test_args->setup_callback_invoked) {
        return AWS_OP_SUCCESS;
    }

    if (setup_test_args->tls_levels_negotiated < setup_test_args->desired_tls_levels) {
        ASSERT_SUCCESS(s_add_tls_handler_to_end_of_channel(setup_test_args));
    }

    return AWS_OP_SUCCESS;
}

static void s_tls_handler_test_client_setup_callback(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;

    struct tls_test_args *setup_test_args = user_data;
    aws_mutex_lock(setup_test_args->mutex);

    setup_test_args->setup_callback_invoked = true;

    if (!error_code) {
        setup_test_args->channel = channel;
        s_aws_check_for_user_handler_setup(setup_test_args);
        s_on_channel_setup_next_tls_handler(setup_test_args);
    } else {
        setup_test_args->error_invoked = true;
        setup_test_args->last_error_code = error_code;
    }

    aws_mutex_unlock(setup_test_args->mutex);
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
    setup_test_args->setup_callback_invoked = true;
    if (!error_code) {
        setup_test_args->channel = channel;
    } else {
        setup_test_args->error_invoked = true;
        setup_test_args->last_error_code = error_code;
    }

    s_aws_check_for_user_handler_setup(setup_test_args);

    aws_mutex_unlock(setup_test_args->mutex);
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
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
    aws_mutex_unlock(setup_test_args->mutex);
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
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
    aws_mutex_unlock(setup_test_args->mutex);
    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

static void s_tls_handler_test_server_listener_destroy_callback(
    struct aws_server_bootstrap *bootstrap,
    void *user_data) {
    (void)bootstrap;

    struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;
    aws_mutex_lock(setup_test_args->mutex);
    setup_test_args->listener_destroyed = true;
    aws_mutex_unlock(setup_test_args->mutex);

    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

static void s_tls_on_negotiated(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    int err_code,
    void *user_data) {

    (void)slot;
    struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;

    if (!err_code) {
        aws_mutex_lock(setup_test_args->mutex);

        if (aws_tls_is_alpn_available()) {
            setup_test_args->negotiated_protocol = aws_tls_handler_protocol(handler);
        }
        setup_test_args->server_name = aws_tls_handler_server_name(handler);
        ++setup_test_args->tls_levels_negotiated;

        s_aws_check_for_user_handler_setup(setup_test_args);
        s_on_tls_negotiated_next_tls_handler(setup_test_args);

        aws_mutex_unlock(setup_test_args->mutex);
    }

    aws_condition_variable_notify_one(setup_test_args->condition_variable);
}

static int s_tls_local_server_tester_init(
    struct aws_allocator *allocator,
    struct tls_local_server_tester *tester,
    struct tls_test_args *args,
    struct tls_common_tester *tls_c_tester,
    bool enable_back_pressure,
    int server_index) {
    AWS_ZERO_STRUCT(*tester);
    ASSERT_SUCCESS(s_tls_server_opt_tester_init(allocator, &tester->server_tls_opt_tester));
    aws_tls_connection_options_set_callbacks(&tester->server_tls_opt_tester.opt, s_tls_on_negotiated, NULL, NULL, args);
    tester->socket_options.connect_timeout_ms = 3000;
    tester->socket_options.type = AWS_SOCKET_STREAM;
    tester->socket_options.domain = AWS_SOCKET_LOCAL;
    ASSERT_SUCCESS(aws_sys_clock_get_ticks(&tester->timestamp));
    sprintf(tester->endpoint.address, LOCAL_SOCK_TEST_PATTERN, (long long unsigned)tester->timestamp, server_index);
    tester->server_bootstrap = aws_server_bootstrap_new(allocator, tls_c_tester->el_group);
    ASSERT_NOT_NULL(tester->server_bootstrap);

    struct aws_server_socket_channel_bootstrap_options bootstrap_options = {
        .bootstrap = tester->server_bootstrap,
        .enable_read_back_pressure = enable_back_pressure,
        .port = tester->endpoint.port,
        .host_name = tester->endpoint.address,
        .socket_options = &tester->socket_options,
        .incoming_callback = s_tls_handler_test_server_setup_callback,
        .shutdown_callback = s_tls_handler_test_server_shutdown_callback,
        .destroy_callback = s_tls_handler_test_server_listener_destroy_callback,
        .tls_options = &tester->server_tls_opt_tester.opt,
        .user_data = args,
    };
    tester->listener = aws_server_bootstrap_new_socket_listener(&bootstrap_options);
    ASSERT_NOT_NULL(tester->listener);

    return AWS_OP_SUCCESS;
}

static int s_tls_local_server_tester_clean_up(struct tls_local_server_tester *tester) {
    ASSERT_SUCCESS(s_tls_opt_tester_clean_up(&tester->server_tls_opt_tester));
    aws_server_bootstrap_release(tester->server_bootstrap);
    return AWS_OP_SUCCESS;
}

struct tls_test_rw_args {
    struct aws_mutex *mutex;
    struct aws_condition_variable *condition_variable;
    struct aws_byte_buf received_message;
    int read_invocations;
    bool invocation_happened;
};

static int s_tls_rw_args_init(
    struct tls_test_rw_args *args,
    struct tls_common_tester *tls_c_tester,
    struct aws_byte_buf received_message) {
    AWS_ZERO_STRUCT(*args);
    args->mutex = &tls_c_tester->mutex;
    args->condition_variable = &tls_c_tester->condition_variable;
    args->received_message = received_message;
    return AWS_OP_SUCCESS;
}

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
    aws_mutex_lock(rw_args->mutex);

    aws_byte_buf_write_from_whole_buffer(&rw_args->received_message, *data_read);
    rw_args->read_invocations += 1;
    rw_args->invocation_happened = true;

    aws_mutex_unlock(rw_args->mutex);
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

enum tls_proxy_test_state { TPTS_NONE, TPTS_CONNECTING, TPTS_CONNECTED };

struct tls_proxy_test_context {
    struct aws_mutex *lock;
    struct aws_condition_variable *signal;
    struct aws_byte_buf from_client_data;
    struct aws_byte_buf to_client_data;
    struct tls_test_args *c2p_server_test_args;
    struct aws_channel *c2p_server_channel;
    struct aws_channel *p2e_client_channel;
    struct aws_channel_handler *c2p_server_rw_handler;
    struct aws_channel_handler *proxy_server_rw_handler;
    struct aws_channel_task c2p_relay_to_client_task;
    struct aws_channel_task pe2_relay_to_endpoint_task;
    enum tls_proxy_test_state state;
    bool relay_to_client_scheduled;
    bool relay_to_endpoint_scheduled;
    bool endpoint_shutdown_finished;
    struct aws_socket_channel_bootstrap_options *to_endpoint_bootstrap_options;
};

static int s_tls_proxy_rw_args_init(
    struct tls_proxy_test_context *proxy_context,
    struct aws_allocator *allocator,
    struct tls_common_tester *tls_c_tester) {
    AWS_ZERO_STRUCT(*proxy_context);

    proxy_context->state = TPTS_NONE;
    proxy_context->lock = &tls_c_tester->mutex;
    proxy_context->signal = &tls_c_tester->condition_variable;

    ASSERT_SUCCESS(aws_byte_buf_init(&proxy_context->from_client_data, allocator, 256));
    ASSERT_SUCCESS(aws_byte_buf_init(&proxy_context->to_client_data, allocator, 256));

    return AWS_OP_SUCCESS;
}

static void s_tls_proxy_rw_args_clean_up(struct tls_proxy_test_context *args) {

    aws_byte_buf_clean_up(&args->from_client_data);
    aws_byte_buf_clean_up(&args->to_client_data);
}

static bool s_tls_proxy_channel_shutdown_predicate(void *user_data) {
    struct tls_proxy_test_context *proxy_context = (struct tls_proxy_test_context *)user_data;

    return proxy_context->endpoint_shutdown_finished;
}

static struct aws_byte_buf s_client_to_proxy_server_handle_read(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *data_read,
    void *user_data) {

    (void)handler;
    (void)slot;

    struct tls_proxy_test_context *proxy_context = (struct tls_proxy_test_context *)user_data;
    aws_mutex_lock(proxy_context->lock);

    struct aws_byte_cursor data_cursor = aws_byte_cursor_from_buf(data_read);
    aws_byte_buf_append_dynamic(&proxy_context->from_client_data, &data_cursor);

    if (proxy_context->state == TPTS_NONE) {
        /* initiate the connection to the endpoint */
        proxy_context->c2p_server_channel = proxy_context->c2p_server_test_args->channel;
        AWS_FATAL_ASSERT(proxy_context->c2p_server_channel != NULL);
        proxy_context->state = TPTS_CONNECTING;
        aws_client_bootstrap_new_socket_channel(proxy_context->to_endpoint_bootstrap_options);
    } else if (proxy_context->state == TPTS_CONNECTED && !proxy_context->endpoint_shutdown_finished) {
        /* schedule a task to send data to the endpoint */
        if (!proxy_context->relay_to_endpoint_scheduled) {
            proxy_context->relay_to_endpoint_scheduled = true;
            aws_channel_schedule_task_now(
                proxy_context->p2e_client_channel, &proxy_context->pe2_relay_to_endpoint_task);
        }
    }

    aws_mutex_unlock(proxy_context->lock);

    struct aws_byte_buf empty_buf;
    AWS_ZERO_STRUCT(empty_buf);

    return empty_buf;
}

static struct aws_byte_buf s_proxy_to_endpoint_client_handle_read(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *data_read,
    void *user_data) {

    (void)handler;
    (void)slot;

    struct tls_proxy_test_context *proxy_context = (struct tls_proxy_test_context *)user_data;
    aws_mutex_lock(proxy_context->lock);

    struct aws_byte_cursor data_cursor = aws_byte_cursor_from_buf(data_read);
    aws_byte_buf_append_dynamic(&proxy_context->to_client_data, &data_cursor);

    /* schedule a task to send the data to the client */
    if (!proxy_context->relay_to_client_scheduled) {
        proxy_context->relay_to_client_scheduled = true;
        aws_channel_schedule_task_now(proxy_context->c2p_server_channel, &proxy_context->c2p_relay_to_client_task);
    }

    aws_mutex_unlock(proxy_context->lock);

    struct aws_byte_buf empty_buf;
    AWS_ZERO_STRUCT(empty_buf);

    return empty_buf;
}

static struct aws_byte_buf s_proxy_tls_test_handle_write(
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
    aws_io_library_init(allocator);
    ASSERT_SUCCESS(s_tls_common_tester_init(allocator, &c_tester));

    struct aws_byte_buf read_tag = aws_byte_buf_from_c_str("I'm a little teapot.");
    struct aws_byte_buf write_tag = aws_byte_buf_from_c_str("I'm a big teapot");

    uint8_t incoming_received_message[128] = {0};
    uint8_t outgoing_received_message[128] = {0};

    struct tls_test_rw_args incoming_rw_args;
    ASSERT_SUCCESS(s_tls_rw_args_init(
        &incoming_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(incoming_received_message, sizeof(incoming_received_message))));

    struct tls_test_rw_args outgoing_rw_args;
    ASSERT_SUCCESS(s_tls_rw_args_init(
        &outgoing_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(outgoing_received_message, sizeof(outgoing_received_message))));

    struct tls_test_args outgoing_args;
    ASSERT_SUCCESS(s_tls_test_arg_init(allocator, &outgoing_args, false, &c_tester));

    struct tls_test_args incoming_args;
    ASSERT_SUCCESS(s_tls_test_arg_init(allocator, &incoming_args, true, &c_tester));

    struct tls_local_server_tester local_server_tester;
    ASSERT_SUCCESS(s_tls_local_server_tester_init(allocator, &local_server_tester, &incoming_args, &c_tester, true, 1));
    /* make the windows small to make sure back pressure is honored. */
    struct aws_channel_handler *outgoing_rw_handler = rw_handler_new(
        allocator, s_tls_test_handle_read, s_tls_test_handle_write, true, write_tag.len / 2, &outgoing_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_channel_handler *incoming_rw_handler = rw_handler_new(
        allocator, s_tls_test_handle_read, s_tls_test_handle_write, true, read_tag.len / 2, &incoming_rw_args);
    ASSERT_NOT_NULL(incoming_rw_handler);

    incoming_args.rw_handler = incoming_rw_handler;
    outgoing_args.rw_handler = outgoing_rw_handler;

    g_aws_channel_max_fragment_size = 4096;

    struct tls_opt_tester client_tls_opt_tester;
    struct aws_byte_cursor server_name = aws_byte_cursor_from_c_str("localhost");
    ASSERT_SUCCESS(s_tls_client_opt_tester_init(allocator, &client_tls_opt_tester, server_name));
    aws_tls_connection_options_set_callbacks(
        &client_tls_opt_tester.opt, s_tls_on_negotiated, NULL, NULL, &outgoing_args);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = c_tester.el_group,
        .host_resolver = c_tester.resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_socket_channel_bootstrap_options channel_options;
    AWS_ZERO_STRUCT(channel_options);
    channel_options.bootstrap = client_bootstrap;
    channel_options.host_name = local_server_tester.endpoint.address;
    channel_options.port = 0;
    channel_options.socket_options = &local_server_tester.socket_options;
    channel_options.tls_options = &client_tls_opt_tester.opt;
    channel_options.setup_callback = s_tls_handler_test_client_setup_callback;
    channel_options.shutdown_callback = s_tls_handler_test_client_shutdown_callback;
    channel_options.user_data = &outgoing_args;
    channel_options.enable_read_back_pressure = true;

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&channel_options));

    /* put this here to verify ownership semantics are correct. This should NOT cause a segfault. If it does, ya
     * done messed up. */
    aws_tls_connection_options_clean_up(&client_tls_opt_tester.opt);
    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_setup_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));
    ASSERT_FALSE(incoming_args.error_invoked);

/* currently it seems ALPN doesn't work in server mode. Just leaving this check out for now. */
#    ifndef __APPLE__
    struct aws_byte_buf expected_protocol = aws_byte_buf_from_c_str("h2");

    /* check ALPN and SNI was properly negotiated */
    if (aws_tls_is_alpn_available()) {
        ASSERT_BIN_ARRAYS_EQUALS(
            expected_protocol.buffer,
            expected_protocol.len,
            incoming_args.negotiated_protocol.buffer,
            incoming_args.negotiated_protocol.len);
    }
#    endif

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_setup_predicate, &outgoing_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));
    ASSERT_FALSE(outgoing_args.error_invoked);

/* currently it seems ALPN doesn't work in server mode. Just leaving this check out for now. */
#    ifndef __MACH__
    if (aws_tls_is_alpn_available()) {
        ASSERT_BIN_ARRAYS_EQUALS(
            expected_protocol.buffer,
            expected_protocol.len,
            outgoing_args.negotiated_protocol.buffer,
            outgoing_args.negotiated_protocol.len);
    }
#    endif

    ASSERT_FALSE(outgoing_args.error_invoked);

    /* Do the IO operations */
    rw_handler_write(outgoing_args.rw_handler, outgoing_args.rw_slot, &write_tag);
    rw_handler_write(incoming_args.rw_handler, incoming_args.rw_slot, &read_tag);
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_test_read_predicate, &incoming_rw_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_test_read_predicate, &outgoing_rw_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));

    incoming_rw_args.invocation_happened = false;
    outgoing_rw_args.invocation_happened = false;

    ASSERT_INT_EQUALS(1, outgoing_rw_args.read_invocations);
    ASSERT_INT_EQUALS(1, incoming_rw_args.read_invocations);

    /* Go ahead and verify back-pressure works*/
    rw_handler_trigger_increment_read_window(incoming_args.rw_handler, incoming_args.rw_slot, 100);
    rw_handler_trigger_increment_read_window(outgoing_args.rw_handler, outgoing_args.rw_slot, 100);

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_test_read_predicate, &incoming_rw_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_test_read_predicate, &outgoing_rw_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));

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
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_shutdown_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));

    /*no shutdown on the client necessary here (it should have been triggered by shutting down the other side). just
     * wait for the event to fire. */
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_shutdown_predicate, &outgoing_args));
    aws_server_bootstrap_destroy_socket_listener(local_server_tester.server_bootstrap, local_server_tester.listener);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_listener_destroy_predicate, &incoming_args));
    aws_mutex_unlock(&c_tester.mutex);
    /* clean up */
    ASSERT_SUCCESS(s_tls_opt_tester_clean_up(&client_tls_opt_tester));
    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_tls_local_server_tester_clean_up(&local_server_tester));
    ASSERT_SUCCESS(s_tls_common_tester_clean_up(&c_tester));

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

static int s_verify_negotiation_fails(struct aws_allocator *allocator, const struct aws_string *host_name) {

    aws_io_library_init(allocator);

    ASSERT_SUCCESS(s_tls_common_tester_init(allocator, &c_tester));

    struct aws_tls_ctx_options client_ctx_options;
    aws_tls_ctx_options_init_default_client(&client_ctx_options, allocator);

    struct aws_tls_ctx *client_ctx = aws_tls_client_ctx_new(allocator, &client_ctx_options);

    struct aws_tls_connection_options tls_client_conn_options;
    aws_tls_connection_options_init_from_ctx(&tls_client_conn_options, client_ctx);
    aws_tls_connection_options_set_callbacks(&tls_client_conn_options, s_tls_on_negotiated, NULL, NULL, NULL);
    struct aws_byte_cursor host_name_cur = aws_byte_cursor_from_string(host_name);
    aws_tls_connection_options_set_server_name(&tls_client_conn_options, allocator, &host_name_cur);

    struct tls_test_args outgoing_args = {
        .mutex = &c_tester.mutex,
        .allocator = allocator,
        .condition_variable = &c_tester.condition_variable,
        .error_invoked = false,
        .expects_error = true,
        .rw_handler = NULL,
        .server = false,
        .tls_levels_negotiated = 0,
        .desired_tls_levels = 1,
        .shutdown_finished = false,
    };

    tls_client_conn_options.user_data = &outgoing_args;

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    /* badssl.com is great but has occasional lags, make this timeout longer so we have a
       higher chance of actually testing something. */
    options.connect_timeout_ms = 10000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = c_tester.el_group,
        .host_resolver = c_tester.resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_socket_channel_bootstrap_options channel_options;
    AWS_ZERO_STRUCT(channel_options);
    channel_options.bootstrap = client_bootstrap;
    channel_options.host_name = aws_string_c_str(host_name);
    channel_options.port = 443;
    channel_options.socket_options = &options;
    channel_options.tls_options = &tls_client_conn_options;
    channel_options.setup_callback = s_tls_handler_test_client_setup_callback;
    channel_options.shutdown_callback = s_tls_handler_test_client_shutdown_callback;
    channel_options.user_data = &outgoing_args;

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&channel_options));

    /* put this here to verify ownership semantics are correct. This should NOT cause a segfault. If it does, ya
     * done messed up. */
    aws_tls_connection_options_clean_up(&tls_client_conn_options);
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_shutdown_predicate, &outgoing_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));

    ASSERT_TRUE(outgoing_args.error_invoked);

    /* we're talking to an external internet endpoint, yeah this sucks... we don't know for sure that
       this failed for the right reasons, but there's not much we can do about it.*/
    if (outgoing_args.last_error_code != AWS_IO_SOCKET_TIMEOUT) {
        ASSERT_INT_EQUALS(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE, outgoing_args.last_error_code);
    } else {
        fprintf(
            stderr,
            "Warning: the connection timed out and we're not completely certain"
            " that this fails for the right reasons. Maybe run the test again?\n");
    }
    aws_client_bootstrap_release(client_bootstrap);

    aws_tls_ctx_release(client_ctx);
    aws_tls_ctx_options_clean_up(&client_ctx_options);
    ASSERT_SUCCESS(s_tls_common_tester_clean_up(&c_tester));

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

/* Test that, if the channel shuts down unexpectedly during tls negotiation, that the user code is still notified.
 * We make this happen by connecting to port 80 on s3 or amazon.com and attempting TLS,
 * which gets you hung up on after a few seconds */
static int s_tls_client_channel_negotiation_error_socket_closed_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const char *host_name = "aws-crt-test-stuff.s3.amazonaws.com";
    uint16_t port = 80; /* Note: intentionally wrong and not 443 */

    aws_io_library_init(allocator);

    ASSERT_SUCCESS(s_tls_common_tester_init(allocator, &c_tester));

    struct tls_opt_tester client_tls_opt_tester;
    struct aws_byte_cursor server_name = aws_byte_cursor_from_c_str(host_name);
    ASSERT_SUCCESS(s_tls_client_opt_tester_init(allocator, &client_tls_opt_tester, server_name));
    client_tls_opt_tester.opt.timeout_ms = 0; /* disable negotiation timeout for this test */

    struct tls_test_args outgoing_args;
    ASSERT_SUCCESS(s_tls_test_arg_init(allocator, &outgoing_args, false, &c_tester));

    struct aws_socket_options options = {
        .connect_timeout_ms = 10000, .type = AWS_SOCKET_STREAM, .domain = AWS_SOCKET_IPV4};

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = c_tester.el_group,
        .host_resolver = c_tester.resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_socket_channel_bootstrap_options channel_options;
    AWS_ZERO_STRUCT(channel_options);
    channel_options.bootstrap = client_bootstrap;
    channel_options.host_name = host_name;
    channel_options.port = port;
    channel_options.socket_options = &options;
    channel_options.tls_options = &client_tls_opt_tester.opt;
    channel_options.setup_callback = s_tls_handler_test_client_setup_callback;
    channel_options.shutdown_callback = s_tls_handler_test_client_shutdown_callback;
    channel_options.user_data = &outgoing_args;

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&channel_options));

    /* Wait for setup to complete */
    aws_mutex_lock(&c_tester.mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_setup_predicate, &outgoing_args));

    /* Assert that setup failed, and that it failed for reasons unrelated to the tls-handler. */
    ASSERT_INT_EQUALS(0, outgoing_args.tls_levels_negotiated);
    ASSERT_TRUE(outgoing_args.error_invoked);
    ASSERT_INT_EQUALS(AWS_IO_SOCKET_CLOSED, outgoing_args.last_error_code);

    aws_mutex_unlock(&c_tester.mutex);

    /* Clean up */
    aws_client_bootstrap_release(client_bootstrap);

    s_tls_opt_tester_clean_up(&client_tls_opt_tester);
    ASSERT_SUCCESS(s_tls_common_tester_clean_up(&c_tester));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(
    tls_client_channel_negotiation_error_socket_closed,
    s_tls_client_channel_negotiation_error_socket_closed_fn);

static int s_verify_good_host(struct aws_allocator *allocator, const struct aws_string *host_name, bool verify) {
    aws_io_library_init(allocator);

    ASSERT_SUCCESS(s_tls_common_tester_init(allocator, &c_tester));

    struct tls_test_args outgoing_args = {
        .mutex = &c_tester.mutex,
        .allocator = allocator,
        .condition_variable = &c_tester.condition_variable,
        .error_invoked = 0,
        .rw_handler = NULL,
        .server = false,
        .tls_levels_negotiated = 0,
        .desired_tls_levels = 1,
        .shutdown_finished = false,
    };

    struct aws_tls_ctx_options client_ctx_options;
    aws_tls_ctx_options_init_default_client(&client_ctx_options, allocator);
    aws_tls_ctx_options_set_alpn_list(&client_ctx_options, "http/1.1");
    aws_tls_ctx_options_set_verify_peer(&client_ctx_options, verify);

    struct aws_tls_ctx *client_ctx = aws_tls_client_ctx_new(allocator, &client_ctx_options);

    struct aws_tls_connection_options tls_client_conn_options;
    aws_tls_connection_options_init_from_ctx(&tls_client_conn_options, client_ctx);
    aws_tls_connection_options_set_callbacks(&tls_client_conn_options, s_tls_on_negotiated, NULL, NULL, &outgoing_args);

    struct aws_byte_cursor host_name_cur = aws_byte_cursor_from_string(host_name);
    aws_tls_connection_options_set_server_name(&tls_client_conn_options, allocator, &host_name_cur);
    aws_tls_connection_options_set_alpn_list(&tls_client_conn_options, allocator, "http/1.1");

    struct aws_socket_options options;
    AWS_ZERO_STRUCT(options);
    options.connect_timeout_ms = 10000;
    options.type = AWS_SOCKET_STREAM;
    options.domain = AWS_SOCKET_IPV4;

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = c_tester.el_group,
        .host_resolver = c_tester.resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_socket_channel_bootstrap_options channel_options;
    AWS_ZERO_STRUCT(channel_options);
    channel_options.bootstrap = client_bootstrap;
    channel_options.host_name = aws_string_c_str(host_name);
    channel_options.port = 443;
    channel_options.socket_options = &options;
    channel_options.tls_options = &tls_client_conn_options;
    channel_options.setup_callback = s_tls_handler_test_client_setup_callback;
    channel_options.shutdown_callback = s_tls_handler_test_client_shutdown_callback;
    channel_options.user_data = &outgoing_args;

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&channel_options));

    /* put this here to verify ownership semantics are correct. This should NOT cause a segfault. If it does, ya
     * done messed up. */
    aws_tls_connection_options_clean_up(&tls_client_conn_options);

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_setup_predicate, &outgoing_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));

    ASSERT_FALSE(outgoing_args.error_invoked);
    struct aws_byte_buf expected_protocol = aws_byte_buf_from_c_str("http/1.1");
    /* check ALPN and SNI was properly negotiated */

    if (aws_tls_is_alpn_available() && verify) {
        ASSERT_BIN_ARRAYS_EQUALS(
            expected_protocol.buffer,
            expected_protocol.len,
            outgoing_args.negotiated_protocol.buffer,
            outgoing_args.negotiated_protocol.len);
    }

    ASSERT_BIN_ARRAYS_EQUALS(
        aws_string_bytes(host_name), host_name->len, outgoing_args.server_name.buffer, outgoing_args.server_name.len);

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    aws_channel_shutdown(outgoing_args.channel, AWS_OP_SUCCESS);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_shutdown_predicate, &outgoing_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));

    aws_client_bootstrap_release(client_bootstrap);

    aws_tls_ctx_release(client_ctx);
    aws_tls_ctx_options_clean_up(&client_ctx_options);
    ASSERT_SUCCESS(s_tls_common_tester_clean_up(&c_tester));

    return AWS_OP_SUCCESS;
}

static int s_tls_client_channel_negotiation_success_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "www.amazon.com");
    ASSERT_NOT_NULL(host_name);
    int err_code = s_verify_good_host(allocator, host_name, true);
    aws_string_destroy((void *)host_name);
    return err_code;
}

AWS_TEST_CASE(tls_client_channel_negotiation_success, s_tls_client_channel_negotiation_success_fn)

static int s_tls_client_channel_negotiation_success_ecc256_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "ecc256.badssl.com");
    ASSERT_NOT_NULL(host_name);
    int err_code = s_verify_good_host(allocator, host_name, true);
    aws_string_destroy((void *)host_name);
    return err_code;
}

AWS_TEST_CASE(tls_client_channel_negotiation_success_ecc256, s_tls_client_channel_negotiation_success_ecc256_fn)

static int s_tls_client_channel_negotiation_success_ecc384_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    const struct aws_string *host_name = aws_string_new_from_c_str(allocator, "ecc384.badssl.com");
    ASSERT_NOT_NULL(host_name);
    int err_code = s_verify_good_host(allocator, host_name, true);
    aws_string_destroy((void *)host_name);
    return err_code;
}

AWS_TEST_CASE(tls_client_channel_negotiation_success_ecc384, s_tls_client_channel_negotiation_success_ecc384_fn)

/* prove that connections complete even when verify_peer is false */
static int s_tls_client_channel_no_verify_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_string *host_name = aws_string_new_from_c_str(allocator, "s3.amazonaws.com");
    ASSERT_NOT_NULL(host_name);
    int err_code = s_verify_good_host(allocator, host_name, false);
    aws_string_destroy(host_name);
    return err_code;
}
AWS_TEST_CASE(tls_client_channel_no_verify, s_tls_client_channel_no_verify_fn)

static void s_reset_arg_state(struct tls_test_args *setup_test_args) {
    setup_test_args->tls_levels_negotiated = 0;
    setup_test_args->shutdown_finished = false;
    setup_test_args->creation_callback_invoked = false;
    setup_test_args->setup_callback_invoked = false;
}

static int s_tls_server_multiple_connections_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    ASSERT_SUCCESS(s_tls_common_tester_init(allocator, &c_tester));

    struct tls_test_args outgoing_args;
    ASSERT_SUCCESS(s_tls_test_arg_init(allocator, &outgoing_args, false, &c_tester));

    struct tls_test_args incoming_args;
    ASSERT_SUCCESS(s_tls_test_arg_init(allocator, &incoming_args, true, &c_tester));

    struct tls_local_server_tester local_server_tester;
    ASSERT_SUCCESS(
        s_tls_local_server_tester_init(allocator, &local_server_tester, &incoming_args, &c_tester, false, 1));

    struct tls_opt_tester client_tls_opt_tester;
    struct aws_byte_cursor server_name = aws_byte_cursor_from_c_str("localhost");
    ASSERT_SUCCESS(s_tls_client_opt_tester_init(allocator, &client_tls_opt_tester, server_name));
    aws_tls_connection_options_set_callbacks(
        &client_tls_opt_tester.opt, s_tls_on_negotiated, NULL, NULL, &outgoing_args);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = c_tester.el_group,
        .host_resolver = c_tester.resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_socket_channel_bootstrap_options channel_options;
    AWS_ZERO_STRUCT(channel_options);
    channel_options.bootstrap = client_bootstrap;
    channel_options.host_name = local_server_tester.endpoint.address;
    channel_options.port = 0;
    channel_options.socket_options = &local_server_tester.socket_options;
    channel_options.tls_options = &client_tls_opt_tester.opt;
    channel_options.setup_callback = s_tls_handler_test_client_setup_callback;
    channel_options.shutdown_callback = s_tls_handler_test_client_shutdown_callback;
    channel_options.user_data = &outgoing_args;

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&channel_options));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_setup_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));
    ASSERT_FALSE(incoming_args.error_invoked);

    /* shut down */
    aws_channel_shutdown(incoming_args.channel, AWS_OP_SUCCESS);
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_shutdown_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));

    /* no shutdown on the client necessary here (it should have been triggered by shutting down the other side). just
     * wait for the event to fire. */
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_shutdown_predicate, &outgoing_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));

    /* connect again! */
    s_reset_arg_state(&outgoing_args);
    s_reset_arg_state(&incoming_args);

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&channel_options));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_setup_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));
    ASSERT_FALSE(incoming_args.error_invoked);

    /* shut down */
    aws_channel_shutdown(incoming_args.channel, AWS_OP_SUCCESS);
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_shutdown_predicate, &incoming_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));

    /*no shutdown on the client necessary here (it should have been triggered by shutting down the other side). just
     * wait for the event to fire. */
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_shutdown_predicate, &outgoing_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));
    aws_server_bootstrap_destroy_socket_listener(local_server_tester.server_bootstrap, local_server_tester.listener);
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_listener_destroy_predicate, &incoming_args));
    aws_mutex_unlock(&c_tester.mutex);

    /* clean up */
    ASSERT_SUCCESS(s_tls_opt_tester_clean_up(&client_tls_opt_tester));
    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_tls_local_server_tester_clean_up(&local_server_tester));
    ASSERT_SUCCESS(s_tls_common_tester_clean_up(&c_tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(tls_server_multiple_connections, s_tls_server_multiple_connections_fn)

struct shutdown_listener_tester {
    struct aws_socket *listener;
    struct aws_server_bootstrap *server_bootstrap;
    struct tls_test_args *outgoing_args; /* client args */
    struct aws_socket client_socket;
};

static bool s_client_socket_closed_predicate(void *user_data) {
    struct tls_test_args *args = user_data;
    return args->shutdown_finished;
}

static void s_close_client_socket_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)status;
    struct shutdown_listener_tester *tester = arg;

    /* Free task memory */
    aws_mem_release(tester->outgoing_args->allocator, task);

    /* Close socket and notify  */
    AWS_FATAL_ASSERT(aws_socket_close(&tester->client_socket) == AWS_OP_SUCCESS);

    AWS_FATAL_ASSERT(aws_mutex_lock(tester->outgoing_args->mutex) == AWS_OP_SUCCESS);
    tester->outgoing_args->shutdown_finished = true;
    AWS_FATAL_ASSERT(aws_mutex_unlock(tester->outgoing_args->mutex) == AWS_OP_SUCCESS);
    AWS_FATAL_ASSERT(aws_condition_variable_notify_one(tester->outgoing_args->condition_variable) == AWS_OP_SUCCESS);
}

static void s_on_client_connected_do_hangup(struct aws_socket *socket, int error_code, void *user_data) {
    AWS_FATAL_ASSERT(error_code == 0);
    struct shutdown_listener_tester *tester = user_data;
    tester->client_socket = *socket;

    /* wait 1 sec so server side has time to setup the channel, then close the socket */
    uint64_t run_at_ns;
    aws_event_loop_current_clock_time(socket->event_loop, &run_at_ns);
    run_at_ns += aws_timestamp_convert(1, AWS_TIMESTAMP_SECS, AWS_TIMESTAMP_NANOS, NULL);
    struct aws_task *close_client_socket_task =
        aws_mem_acquire(tester->outgoing_args->allocator, sizeof(struct aws_task));
    aws_task_init(close_client_socket_task, s_close_client_socket_task, tester, "wait_close_client_socket");
    aws_event_loop_schedule_task_future(socket->event_loop, close_client_socket_task, run_at_ns);
}

/* Test that server can handle a hangup in the middle of TLS negotiation */
static int s_tls_server_hangup_during_negotiation_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);

    ASSERT_SUCCESS(s_tls_common_tester_init(allocator, &c_tester));

    struct tls_test_args outgoing_args;
    ASSERT_SUCCESS(s_tls_test_arg_init(allocator, &outgoing_args, false, &c_tester));

    struct tls_test_args incoming_args;
    ASSERT_SUCCESS(s_tls_test_arg_init(allocator, &incoming_args, true, &c_tester));

    struct tls_local_server_tester local_server_tester;
    ASSERT_SUCCESS(
        s_tls_local_server_tester_init(allocator, &local_server_tester, &incoming_args, &c_tester, false, 1));

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));

    struct shutdown_listener_tester *shutdown_tester =
        aws_mem_acquire(allocator, sizeof(struct shutdown_listener_tester));
    shutdown_tester->server_bootstrap = local_server_tester.server_bootstrap;
    shutdown_tester->listener = local_server_tester.listener;
    shutdown_tester->outgoing_args = &outgoing_args;

    /* Use a raw aws_socket for the client, instead of a full-blown TLS channel.
     * This lets us hang up on the server, instead of automatically going through with proper TLS negotiation */
    ASSERT_SUCCESS(aws_socket_init(&shutdown_tester->client_socket, allocator, &local_server_tester.socket_options));

    /* Upon connecting, immediately close the socket */
    ASSERT_SUCCESS(aws_socket_connect(
        &shutdown_tester->client_socket,
        &local_server_tester.endpoint,
        aws_event_loop_group_get_next_loop(c_tester.el_group),
        s_on_client_connected_do_hangup,
        shutdown_tester));

    /* Wait for client socket to close */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_client_socket_closed_predicate, &outgoing_args));

    /* Destroy listener socket and wait for shutdown to complete */
    aws_server_bootstrap_destroy_socket_listener(shutdown_tester->server_bootstrap, shutdown_tester->listener);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_listener_destroy_predicate, &incoming_args));

    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));
    /* clean up */
    aws_socket_clean_up(&shutdown_tester->client_socket);
    aws_mem_release(allocator, shutdown_tester);
    /* cannot double free the listener */
    ASSERT_SUCCESS(s_tls_opt_tester_clean_up(&local_server_tester.server_tls_opt_tester));
    aws_server_bootstrap_release(local_server_tester.server_bootstrap);
    ASSERT_SUCCESS(s_tls_common_tester_clean_up(&c_tester));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(tls_server_hangup_during_negotiation, s_tls_server_hangup_during_negotiation_fn)

static void s_creation_callback_test_channel_creation_callback(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;

    struct tls_test_args *setup_test_args = (struct tls_test_args *)user_data;

    setup_test_args->creation_callback_invoked = true;
    setup_test_args->channel = channel;

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

static int s_tls_common_tester_statistics_init(struct aws_allocator *allocator, struct tls_common_tester *tester) {

    aws_io_library_init(allocator);

    AWS_ZERO_STRUCT(*tester);

    struct aws_mutex mutex = AWS_MUTEX_INIT;
    struct aws_condition_variable condition_variable = AWS_CONDITION_VARIABLE_INIT;
    tester->mutex = mutex;
    tester->condition_variable = condition_variable;
    aws_atomic_store_int(&tester->current_time_ns, 0);
    aws_atomic_store_ptr(&tester->stats_handler, NULL);

    tester->el_group =
        aws_event_loop_group_new(allocator, s_statistic_test_clock_fn, 1, s_default_new_event_loop, NULL, NULL);

    struct aws_host_resolver_default_options resolver_options = {
        .el_group = tester->el_group,
        .max_entries = 1,
    };
    tester->resolver = aws_host_resolver_new_default(allocator, &resolver_options);

    return AWS_OP_SUCCESS;
}

static bool s_stats_processed_predicate(void *user_data) {
    struct aws_crt_statistics_handler *stats_handler = user_data;
    struct aws_statistics_handler_test_impl *stats_impl = stats_handler->impl;

    return stats_impl->total_bytes_read > 0 && stats_impl->total_bytes_written > 0 &&
           stats_impl->tls_status != AWS_TLS_NEGOTIATION_STATUS_NONE;
}

static int s_tls_channel_statistics_test(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_io_library_init(allocator);

    ASSERT_SUCCESS(s_tls_common_tester_statistics_init(allocator, &c_tester));

    struct aws_byte_buf read_tag = aws_byte_buf_from_c_str("This is some data.");
    struct aws_byte_buf write_tag = aws_byte_buf_from_c_str("Created from a blend of heirloom and cider apples");

    uint8_t incoming_received_message[128] = {0};
    uint8_t outgoing_received_message[128] = {0};

    struct tls_test_rw_args incoming_rw_args;
    ASSERT_SUCCESS(s_tls_rw_args_init(
        &incoming_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(incoming_received_message, sizeof(incoming_received_message))));

    struct tls_test_rw_args outgoing_rw_args;
    ASSERT_SUCCESS(s_tls_rw_args_init(
        &outgoing_rw_args,
        &c_tester,
        aws_byte_buf_from_empty_array(outgoing_received_message, sizeof(outgoing_received_message))));

    struct tls_test_args outgoing_args;
    ASSERT_SUCCESS(s_tls_test_arg_init(allocator, &outgoing_args, false, &c_tester));

    struct tls_test_args incoming_args;
    ASSERT_SUCCESS(s_tls_test_arg_init(allocator, &incoming_args, true, &c_tester));

    struct tls_local_server_tester local_server_tester;
    ASSERT_SUCCESS(
        s_tls_local_server_tester_init(allocator, &local_server_tester, &incoming_args, &c_tester, false, 1));

    struct aws_channel_handler *outgoing_rw_handler =
        rw_handler_new(allocator, s_tls_test_handle_read, s_tls_test_handle_write, true, 10000, &outgoing_rw_args);
    ASSERT_NOT_NULL(outgoing_rw_handler);

    struct aws_channel_handler *incoming_rw_handler =
        rw_handler_new(allocator, s_tls_test_handle_read, s_tls_test_handle_write, true, 10000, &incoming_rw_args);
    ASSERT_NOT_NULL(incoming_rw_handler);

    incoming_args.rw_handler = incoming_rw_handler;
    outgoing_args.rw_handler = outgoing_rw_handler;

    struct tls_opt_tester client_tls_opt_tester;
    struct aws_byte_cursor server_name = aws_byte_cursor_from_c_str("localhost");
    ASSERT_SUCCESS(s_tls_client_opt_tester_init(allocator, &client_tls_opt_tester, server_name));
    aws_tls_connection_options_set_callbacks(
        &client_tls_opt_tester.opt, s_tls_on_negotiated, NULL, NULL, &outgoing_args);

    struct aws_client_bootstrap_options bootstrap_options;
    AWS_ZERO_STRUCT(bootstrap_options);
    bootstrap_options.event_loop_group = c_tester.el_group;
    bootstrap_options.host_resolver = c_tester.resolver;

    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));

    struct aws_socket_channel_bootstrap_options channel_options;
    AWS_ZERO_STRUCT(channel_options);
    channel_options.bootstrap = client_bootstrap;
    channel_options.host_name = local_server_tester.endpoint.address;
    channel_options.port = 0;
    channel_options.socket_options = &local_server_tester.socket_options;
    channel_options.tls_options = &client_tls_opt_tester.opt;
    channel_options.creation_callback = s_creation_callback_test_channel_creation_callback;
    channel_options.setup_callback = s_tls_handler_test_client_setup_callback;
    channel_options.shutdown_callback = s_tls_handler_test_client_shutdown_callback;
    channel_options.user_data = &outgoing_args;

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&channel_options));

    /* put this here to verify ownership semantics are correct. This should NOT cause a segfault. If it does, ya
     * done messed up. */
    aws_tls_connection_options_clean_up(&client_tls_opt_tester.opt);
    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_setup_predicate, &incoming_args));
    ASSERT_FALSE(incoming_args.error_invoked);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_setup_predicate, &outgoing_args));
    ASSERT_FALSE(outgoing_args.error_invoked);

    ASSERT_TRUE(outgoing_args.creation_callback_invoked);

    /* Do the IO operations */
    rw_handler_write(outgoing_args.rw_handler, outgoing_args.rw_slot, &write_tag);
    rw_handler_write(incoming_args.rw_handler, incoming_args.rw_slot, &read_tag);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_test_read_predicate, &incoming_rw_args));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_test_read_predicate, &outgoing_rw_args));

    uint64_t ms_to_ns = aws_timestamp_convert(1, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);

    aws_atomic_store_int(&c_tester.current_time_ns, (size_t)ms_to_ns);

    struct aws_crt_statistics_handler *stats_handler = aws_atomic_load_ptr(&c_tester.stats_handler);
    struct aws_statistics_handler_test_impl *stats_impl = stats_handler->impl;

    aws_mutex_lock(&stats_impl->lock);

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &stats_impl->signal, &stats_impl->lock, s_stats_processed_predicate, stats_handler));

    ASSERT_TRUE(stats_impl->total_bytes_read >= read_tag.len);
    ASSERT_TRUE(stats_impl->total_bytes_written >= write_tag.len);
    ASSERT_TRUE(stats_impl->tls_status == AWS_TLS_NEGOTIATION_STATUS_SUCCESS);

    aws_mutex_unlock(&stats_impl->lock);

    aws_channel_shutdown(incoming_args.channel, AWS_OP_SUCCESS);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_shutdown_predicate, &incoming_args));

    /*no shutdown on the client necessary here (it should have been triggered by shutting down the other side). just
     * wait for the event to fire. */
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_shutdown_predicate, &outgoing_args));
    aws_server_bootstrap_destroy_socket_listener(local_server_tester.server_bootstrap, local_server_tester.listener);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_listener_destroy_predicate, &incoming_args));
    aws_mutex_unlock(&c_tester.mutex);
    /* clean up */
    ASSERT_SUCCESS(s_tls_opt_tester_clean_up(&client_tls_opt_tester));
    ASSERT_SUCCESS(s_tls_local_server_tester_clean_up(&local_server_tester));
    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_tls_common_tester_clean_up(&c_tester));

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(tls_channel_statistics_test, s_tls_channel_statistics_test)

///////////////////////////////////////////////////////////////

struct channel_stat_test_context {
    struct aws_allocator *allocator;
    struct tls_opt_tester *tls_tester;
    struct aws_mutex lock;
    struct aws_condition_variable signal;
    bool setup_completed;
    bool shutdown_completed;
    int error_code;
};

static void s_channel_setup_stat_test_context_init(
    struct channel_stat_test_context *context,
    struct aws_allocator *allocator,
    struct tls_opt_tester *tls_tester) {

    AWS_ZERO_STRUCT(*context);
    aws_mutex_init(&context->lock);
    aws_condition_variable_init(&context->signal);
    context->allocator = allocator;
    context->tls_tester = tls_tester;
}

static void s_channel_setup_stat_test_context_clean_up(struct channel_stat_test_context *context) {
    aws_mutex_clean_up(&context->lock);
    aws_condition_variable_clean_up(&context->signal);
}

static int s_dummy_process_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)handler;
    (void)slot;

    aws_mem_release(message->allocator, message);
    return AWS_OP_SUCCESS;
}

static int s_dummy_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {
    (void)handler;
    (void)slot;
    (void)size;

    return AWS_OP_SUCCESS;
}

static int s_dummy_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    (void)handler;
    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
}

static size_t s_dummy_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;

    return 10000;
}

static size_t s_dummy_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;

    return 0;
}

static void s_dummy_destroy(struct aws_channel_handler *handler) {
    aws_mem_release(handler->alloc, handler);
}

static struct aws_channel_handler_vtable s_dummy_handler_vtable = {
    .process_read_message = s_dummy_process_message,
    .process_write_message = s_dummy_process_message,
    .increment_read_window = s_dummy_increment_read_window,
    .shutdown = s_dummy_shutdown,
    .initial_window_size = s_dummy_initial_window_size,
    .message_overhead = s_dummy_message_overhead,
    .destroy = s_dummy_destroy,
};

static struct aws_channel_handler *aws_channel_handler_new_dummy(struct aws_allocator *allocator) {
    struct aws_channel_handler *handler = aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));
    handler->alloc = allocator;
    handler->vtable = &s_dummy_handler_vtable;
    handler->impl = NULL;

    return handler;
}

static bool s_setup_completed_predicate(void *arg) {
    struct channel_stat_test_context *context = (struct channel_stat_test_context *)arg;
    return context->setup_completed;
}

static bool s_shutdown_completed_predicate(void *arg) {
    struct channel_stat_test_context *context = (struct channel_stat_test_context *)arg;
    return context->shutdown_completed;
}

static void s_on_shutdown_completed(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    struct channel_stat_test_context *context = (struct channel_stat_test_context *)user_data;

    aws_mutex_lock(&context->lock);
    context->shutdown_completed = true;
    context->error_code = error_code;
    aws_mutex_unlock(&context->lock);

    aws_condition_variable_notify_one(&context->signal);
}

static const int s_tls_timeout_ms = 1000;

static void s_on_setup_completed(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    struct channel_stat_test_context *context = (struct channel_stat_test_context *)user_data;

    /* attach a dummy channel handler */
    struct aws_channel_slot *dummy_slot = aws_channel_slot_new(channel);

    struct aws_channel_handler *dummy_handler = aws_channel_handler_new_dummy(context->allocator);
    aws_channel_slot_set_handler(dummy_slot, dummy_handler);

    /* attach a tls channel handler and start negotiation */
    aws_channel_setup_client_tls(dummy_slot, &context->tls_tester->opt);

    aws_mutex_lock(&context->lock);
    context->error_code = error_code;
    context->setup_completed = true;
    aws_mutex_unlock(&context->lock);
    aws_condition_variable_notify_one(&context->signal);
}

static int s_test_tls_negotiation_timeout(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_io_library_init(allocator);

    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct tls_opt_tester tls_test_context;
    s_tls_client_opt_tester_init(allocator, &tls_test_context, aws_byte_cursor_from_c_str("derp.com"));
    tls_test_context.opt.timeout_ms = s_tls_timeout_ms;

    struct channel_stat_test_context channel_context;
    s_channel_setup_stat_test_context_init(&channel_context, allocator, &tls_test_context);

    struct aws_channel_options args = {
        .on_setup_completed = s_on_setup_completed,
        .setup_user_data = &channel_context,
        .on_shutdown_completed = s_on_shutdown_completed,
        .shutdown_user_data = &channel_context,
        .event_loop = event_loop,
    };

    /* set up the channel */
    ASSERT_SUCCESS(aws_mutex_lock(&channel_context.lock));
    struct aws_channel *channel = aws_channel_new(allocator, &args);
    ASSERT_NOT_NULL(channel);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &channel_context.signal, &channel_context.lock, s_setup_completed_predicate, &channel_context));
    aws_mutex_unlock(&channel_context.lock);

    /* wait for the timeout */
    aws_thread_current_sleep(aws_timestamp_convert(s_tls_timeout_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL));

    aws_mutex_lock(&channel_context.lock);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &channel_context.signal, &channel_context.lock, s_shutdown_completed_predicate, &channel_context));

    ASSERT_TRUE(channel_context.error_code == AWS_IO_TLS_NEGOTIATION_TIMEOUT);

    aws_mutex_unlock(&channel_context.lock);

    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    s_tls_opt_tester_clean_up(&tls_test_context);

    s_channel_setup_stat_test_context_clean_up(&channel_context);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_tls_negotiation_timeout, s_test_tls_negotiation_timeout)

struct import_info {
    struct aws_allocator *allocator;
    struct aws_byte_buf cert_buf;
    struct aws_byte_buf key_buf;
    struct aws_thread thread;
    struct aws_tls_ctx *tls;
};

static void s_import_cert(void *ctx) {
    (void)ctx;
#    if !defined(AWS_OS_IOS)
    struct import_info *import = ctx;
    struct aws_byte_cursor cert_cur = aws_byte_cursor_from_buf(&import->cert_buf);
    struct aws_byte_cursor key_cur = aws_byte_cursor_from_buf(&import->key_buf);
    struct aws_tls_ctx_options tls_options = {0};
    AWS_FATAL_ASSERT(
        AWS_OP_SUCCESS == aws_tls_ctx_options_init_client_mtls(&tls_options, import->allocator, &cert_cur, &key_cur));

    /* import happens in here */
    import->tls = aws_tls_client_ctx_new(import->allocator, &tls_options);
    AWS_FATAL_ASSERT(import->tls);

    aws_tls_ctx_options_clean_up(&tls_options);
#    endif /* !AWS_OS_IOS */
}

#    define NUM_PAIRS 1
static int s_test_concurrent_cert_import(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    /* temporarily disable this on apple until we can fix importing to be more robust */
    /* temporarily disable this on linux until we can make CRYPTO_zalloc behave and stop angering ASan */
#    if defined(__APPLE__) || defined(__linux__)
    return AWS_OP_SUCCESS;
#    endif

    aws_io_library_init(allocator);

    AWS_VARIABLE_LENGTH_ARRAY(struct import_info, imports, NUM_PAIRS);

    /* setup, note that all I/O should be before the threads are launched */
    for (size_t idx = 0; idx < NUM_PAIRS; ++idx) {
        struct import_info *import = &imports[idx];
        import->allocator = allocator;

        char filename[1024];
        sprintf(filename, "testcert%u.pem", (uint32_t)idx);
        ASSERT_SUCCESS(aws_byte_buf_init_from_file(&import->cert_buf, import->allocator, filename));

        sprintf(filename, "testkey.pem");
        ASSERT_SUCCESS(aws_byte_buf_init_from_file(&import->key_buf, import->allocator, filename));

        struct aws_thread *thread = &import->thread;
        ASSERT_SUCCESS(aws_thread_init(thread, allocator));
    }

    /* run threads */
    const struct aws_thread_options *options = aws_default_thread_options();
    for (size_t idx = 0; idx < NUM_PAIRS; ++idx) {
        struct import_info *import = &imports[idx];
        struct aws_thread *thread = &import->thread;
        ASSERT_SUCCESS(aws_thread_launch(thread, s_import_cert, import, options));
    }

    /* join and clean up */
    for (size_t idx = 0; idx < NUM_PAIRS; ++idx) {
        struct import_info *import = &imports[idx];
        struct aws_thread *thread = &import->thread;
        ASSERT_SUCCESS(aws_thread_join(thread));
        aws_tls_ctx_release(import->tls);
        aws_byte_buf_clean_up(&import->cert_buf);
        aws_byte_buf_clean_up(&import->key_buf);
    }

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_concurrent_cert_import, s_test_concurrent_cert_import)

static int s_tls_destroy_null_context(struct aws_allocator *allocator, void *ctx) {
    (void)allocator;
    (void)ctx;

    struct aws_tls_ctx *null_context = NULL;

    /* Verify that we don't crash. */
    aws_tls_ctx_release(null_context);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(tls_destroy_null_context, s_tls_destroy_null_context);

static void s_proxy_to_endpoint_client_setup_callback(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;

    struct tls_proxy_test_context *proxy_context = user_data;
    aws_mutex_lock(proxy_context->lock);

    AWS_FATAL_ASSERT(error_code == AWS_ERROR_SUCCESS);

    proxy_context->p2e_client_channel = channel;
    proxy_context->state = TPTS_CONNECTED;

    proxy_context->proxy_server_rw_handler = rw_handler_new(
        bootstrap->allocator,
        s_proxy_to_endpoint_client_handle_read,
        s_proxy_tls_test_handle_write,
        true,
        10000,
        proxy_context);

    struct aws_channel_slot *rw_slot = aws_channel_slot_new(channel);
    aws_channel_slot_insert_end(channel, rw_slot);
    aws_channel_slot_set_handler(rw_slot, proxy_context->proxy_server_rw_handler);

    if (!proxy_context->relay_to_endpoint_scheduled) {
        proxy_context->relay_to_endpoint_scheduled = true;
        aws_channel_schedule_task_now(proxy_context->p2e_client_channel, &proxy_context->pe2_relay_to_endpoint_task);
    }

    aws_mutex_unlock(proxy_context->lock);
    aws_condition_variable_notify_one(proxy_context->signal);
}

static void s_proxy_to_endpoint_client_shutdown_callback(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;
    (void)error_code;
    (void)channel;

    struct tls_proxy_test_context *proxy_content = user_data;

    aws_mutex_lock(proxy_content->lock);
    proxy_content->endpoint_shutdown_finished = true;
    aws_mutex_unlock(proxy_content->lock);
    aws_condition_variable_notify_one(proxy_content->signal);
}

static void s_c2p_relay_to_client(struct aws_channel_task *channel_task, void *arg, enum aws_task_status status) {
    (void)channel_task;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_io_message *message = NULL;
    struct aws_channel_slot *slot = NULL;
    struct tls_proxy_test_context *proxy_context = arg;

    aws_mutex_lock(proxy_context->lock);

    size_t amount_to_send = proxy_context->to_client_data.len;
    if (amount_to_send > 0) {
        message = aws_channel_acquire_message_from_pool(
            proxy_context->c2p_server_channel, AWS_IO_MESSAGE_APPLICATION_DATA, amount_to_send);
        AWS_FATAL_ASSERT(message);

        AWS_FATAL_ASSERT(
            aws_byte_buf_write(&message->message_data, proxy_context->to_client_data.buffer, amount_to_send));

        proxy_context->to_client_data.len = 0;

        /* send to tls handler */
        slot = aws_channel_get_first_slot(proxy_context->c2p_server_channel)->adj_right->adj_right;
    }

    proxy_context->relay_to_client_scheduled = false;
    aws_mutex_unlock(proxy_context->lock);

    if (message != NULL && slot != NULL) {
        AWS_FATAL_ASSERT(AWS_ERROR_SUCCESS == aws_channel_slot_send_message(slot, message, AWS_CHANNEL_DIR_WRITE));
    }
}

static void s_p2e_relay_to_endpoint(struct aws_channel_task *channel_task, void *arg, enum aws_task_status status) {
    (void)channel_task;

    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_io_message *message = NULL;
    struct aws_channel_slot *slot = NULL;
    struct tls_proxy_test_context *proxy_context = arg;

    aws_mutex_lock(proxy_context->lock);

    size_t amount_to_send = proxy_context->from_client_data.len;
    if (amount_to_send > 0) {
        message = aws_channel_acquire_message_from_pool(
            proxy_context->p2e_client_channel, AWS_IO_MESSAGE_APPLICATION_DATA, amount_to_send);
        AWS_FATAL_ASSERT(message);

        AWS_FATAL_ASSERT(
            aws_byte_buf_write(&message->message_data, proxy_context->from_client_data.buffer, amount_to_send));

        proxy_context->from_client_data.len = 0;

        /* socket slot */
        slot = aws_channel_get_first_slot(proxy_context->p2e_client_channel)->adj_right;
    }

    proxy_context->relay_to_endpoint_scheduled = false;
    aws_mutex_unlock(proxy_context->lock);

    if (message != NULL && slot != NULL) {
        aws_channel_slot_send_message(slot, message, AWS_CHANNEL_DIR_WRITE);
    }
}

/*
 * A variant of the basic tls test, but this time using nested tls handlers on the client.
 *
 * We use two servers, each configured with tls.  The proxy server, on handshake success, then makes a plaintext
 * (non-tls) socket connection to the endpoint server and adds a pass-through handler for data coming to and from.  In
 * this way, the client, with its nested tls handlers, will then drive tls negotiation with the endpoint server
 * directly, making for a simple proxy simulation.
 *
 * Visually:
 *
 * Client <--------------> proxy server <----------------> endpoint server
 *
 * The channel setup is a bit complex:
 *
 * c2p = client-to-proxy-server
 * p2e = proxy-server-to-endpoint-server
 *
 * (1) c2p client channel:   socket <---> client tls #1 <---> client tls #2 <---> test rw handler
 * (2) c2p server channel:   socket <---> server tls <---> to endpoint relay handler
 * (3) p2e client channel:   socket <---> to client relay handler
 * (4) p2e server channel:   socket <---> server tls <---> test rw handler
 *
 * Where the (read) relay handlers in (2) and (3) blindly forward data between one another.
 */
static int s_tls_double_channel_fn(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    aws_io_library_init(allocator);
    ASSERT_SUCCESS(s_tls_common_tester_init(allocator, &c_tester));

    struct aws_byte_buf read_tag = aws_byte_buf_from_c_str("I'm a little teapot.");
    struct aws_byte_buf write_tag = aws_byte_buf_from_c_str("I'm a big teapot");

    uint8_t incoming_received_message[128] = {0};
    uint8_t outgoing_received_message[128] = {0};

    struct tls_test_rw_args client_channel_context;
    ASSERT_SUCCESS(s_tls_rw_args_init(
        &client_channel_context,
        &c_tester,
        aws_byte_buf_from_empty_array(outgoing_received_message, sizeof(outgoing_received_message))));

    struct tls_proxy_test_context proxy_channel_context;
    ASSERT_SUCCESS(s_tls_proxy_rw_args_init(&proxy_channel_context, allocator, &c_tester));

    /* We use channel tasks to relay data across the c2p/p2e channel divide */
    aws_channel_task_init(
        &proxy_channel_context.c2p_relay_to_client_task,
        s_c2p_relay_to_client,
        &proxy_channel_context,
        "c2p_relay_to_client");
    aws_channel_task_init(
        &proxy_channel_context.pe2_relay_to_endpoint_task,
        s_p2e_relay_to_endpoint,
        &proxy_channel_context,
        "p2e_relay_to_endpoint");

    struct tls_test_rw_args endpoint_channel_context;
    ASSERT_SUCCESS(s_tls_rw_args_init(
        &endpoint_channel_context,
        &c_tester,
        aws_byte_buf_from_empty_array(incoming_received_message, sizeof(incoming_received_message))));

    struct tls_test_args client_test_state;
    ASSERT_SUCCESS(s_tls_test_arg_init(allocator, &client_test_state, false, &c_tester));
    client_test_state.desired_tls_levels = 2;

    /*
     * Configure the proxy server
     */
    struct tls_test_args proxy_server_test_state;
    ASSERT_SUCCESS(s_tls_test_arg_init(allocator, &proxy_server_test_state, true, &c_tester));
    proxy_server_test_state.desired_tls_levels = 1;

    struct tls_local_server_tester proxy_server_tester;
    ASSERT_SUCCESS(
        s_tls_local_server_tester_init(allocator, &proxy_server_tester, &proxy_server_test_state, &c_tester, false, 1));

    /*
     * Configure the endpoint server
     */
    struct tls_test_args endpoint_server_test_state;
    ASSERT_SUCCESS(s_tls_test_arg_init(allocator, &endpoint_server_test_state, true, &c_tester));
    endpoint_server_test_state.desired_tls_levels = 1;

    struct tls_local_server_tester endpoint_server_tester;
    ASSERT_SUCCESS(s_tls_local_server_tester_init(
        allocator, &endpoint_server_tester, &endpoint_server_test_state, &c_tester, false, 2));

    /* handler setup  */
    struct aws_channel_handler *client_rw_handler = rw_handler_new(
        allocator, s_tls_test_handle_read, s_tls_test_handle_write, true, 10000, &client_channel_context);
    ASSERT_NOT_NULL(client_rw_handler);
    client_test_state.rw_handler = client_rw_handler;

    struct aws_channel_handler *c2p_server_rw_handler = rw_handler_new(
        allocator, s_client_to_proxy_server_handle_read, s_tls_test_handle_write, true, 10000, &proxy_channel_context);
    ASSERT_NOT_NULL(c2p_server_rw_handler);
    proxy_server_test_state.rw_handler = c2p_server_rw_handler;

    struct aws_channel_handler *endpoint_server_rw_handler = rw_handler_new(
        allocator, s_tls_test_handle_read, s_tls_test_handle_write, true, 10000, &endpoint_channel_context);
    ASSERT_NOT_NULL(endpoint_server_rw_handler);
    endpoint_server_test_state.rw_handler = endpoint_server_rw_handler;

    struct tls_opt_tester client_tls_opt_tester;
    struct aws_byte_cursor server_name = aws_byte_cursor_from_c_str("localhost");
    ASSERT_SUCCESS(s_tls_client_opt_tester_init(allocator, &client_tls_opt_tester, server_name));
    aws_tls_connection_options_set_callbacks(
        &client_tls_opt_tester.opt, s_tls_on_negotiated, NULL, NULL, &client_test_state);

    client_test_state.tls_options = &client_tls_opt_tester.opt;
    proxy_server_test_state.tls_options = &client_tls_opt_tester.opt;
    endpoint_server_test_state.tls_options = &client_tls_opt_tester.opt;

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = c_tester.el_group,
        .host_resolver = c_tester.resolver,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);

    struct aws_socket_channel_bootstrap_options client_to_proxy_channel_options;
    AWS_ZERO_STRUCT(client_to_proxy_channel_options);
    client_to_proxy_channel_options.bootstrap = client_bootstrap;
    client_to_proxy_channel_options.host_name = proxy_server_tester.endpoint.address;
    client_to_proxy_channel_options.port = 0;
    client_to_proxy_channel_options.socket_options = &proxy_server_tester.socket_options;
    client_to_proxy_channel_options.tls_options = &client_tls_opt_tester.opt;
    client_to_proxy_channel_options.setup_callback = s_tls_handler_test_client_setup_callback;
    client_to_proxy_channel_options.shutdown_callback = s_tls_handler_test_client_shutdown_callback;
    client_to_proxy_channel_options.user_data = &client_test_state;

    struct aws_socket_channel_bootstrap_options proxy_to_endpoint_channel_options;
    AWS_ZERO_STRUCT(proxy_to_endpoint_channel_options);
    proxy_to_endpoint_channel_options.bootstrap = client_bootstrap;
    proxy_to_endpoint_channel_options.host_name = endpoint_server_tester.endpoint.address;
    proxy_to_endpoint_channel_options.port = 0;
    proxy_to_endpoint_channel_options.socket_options = &endpoint_server_tester.socket_options;
    proxy_to_endpoint_channel_options.tls_options = NULL;
    proxy_to_endpoint_channel_options.setup_callback = s_proxy_to_endpoint_client_setup_callback;
    proxy_to_endpoint_channel_options.shutdown_callback = s_proxy_to_endpoint_client_shutdown_callback;
    proxy_to_endpoint_channel_options.user_data = &proxy_channel_context;

    proxy_channel_context.to_endpoint_bootstrap_options = &proxy_to_endpoint_channel_options;
    proxy_channel_context.c2p_server_test_args = &proxy_server_test_state;

    AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "*TEST 1* starting initial connection");

    ASSERT_SUCCESS(aws_client_bootstrap_new_socket_channel(&client_to_proxy_channel_options));

    /* wait for both ends to setup */
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_setup_predicate, &endpoint_server_test_state));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));

    AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "*TEST 2* initial channel setup ");

    ASSERT_FALSE(endpoint_server_test_state.error_invoked);

/* currently it seems ALPN doesn't work in server mode. Just leaving this check out for now. */
#    ifndef __APPLE__
    struct aws_byte_buf expected_protocol = aws_byte_buf_from_c_str("h2");

    /* check ALPN and SNI was properly negotiated */
    if (aws_tls_is_alpn_available()) {
        ASSERT_BIN_ARRAYS_EQUALS(
            expected_protocol.buffer,
            expected_protocol.len,
            endpoint_server_test_state.negotiated_protocol.buffer,
            endpoint_server_test_state.negotiated_protocol.len);
    }
#    endif

    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_setup_predicate, &client_test_state));
    ASSERT_INT_EQUALS(2, client_test_state.tls_levels_negotiated);
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));
    ASSERT_FALSE(client_test_state.error_invoked);

    AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "*TEST 3* Full circuit negotiated ");

/* currently it seems ALPN doesn't work in server mode. Just leaving this check out for now. */
#    ifndef __MACH__
    if (aws_tls_is_alpn_available()) {
        ASSERT_BIN_ARRAYS_EQUALS(
            expected_protocol.buffer,
            expected_protocol.len,
            client_test_state.negotiated_protocol.buffer,
            client_test_state.negotiated_protocol.len);
    }
#    endif

    ASSERT_FALSE(client_test_state.error_invoked);

    /* Do the IO operations */
    rw_handler_write(client_test_state.rw_handler, client_test_state.rw_slot, &write_tag);
    rw_handler_write(endpoint_server_test_state.rw_handler, endpoint_server_test_state.rw_slot, &read_tag);
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_test_read_predicate, &endpoint_channel_context));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_test_read_predicate, &client_channel_context));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));

    AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "*TEST 4* App data received ");

    ASSERT_INT_EQUALS(1, client_channel_context.read_invocations);
    ASSERT_INT_EQUALS(1, endpoint_channel_context.read_invocations);

    aws_channel_shutdown(endpoint_server_test_state.channel, AWS_OP_SUCCESS);
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_shutdown_predicate, &endpoint_server_test_state));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));

    /*
     * It turns out we only need to explicitly shut down the proxy-to-endpoint server channel since that will break
     * the tls circuit all the way to client, which in turn causes both client channels to go away which in turn
     * casues the client-to-proxy server channel to go away.
     */
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_shutdown_predicate, &proxy_server_test_state));
    ASSERT_SUCCESS(aws_mutex_unlock(&c_tester.mutex));

    AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "*TEST 5* Server channel shutdowns complete ");

    /*no shutdown on the client necessary here (it should have been triggered by shutting down the other side). just
     * wait for the event to fire. */
    ASSERT_SUCCESS(aws_mutex_lock(&c_tester.mutex));

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_proxy_channel_shutdown_predicate, &proxy_channel_context));

    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_channel_shutdown_predicate, &client_test_state));

    AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "*TEST 6* Client channel shutdowns complete ");

    aws_server_bootstrap_destroy_socket_listener(
        endpoint_server_tester.server_bootstrap, endpoint_server_tester.listener);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_listener_destroy_predicate, &endpoint_server_test_state));

    aws_server_bootstrap_destroy_socket_listener(proxy_server_tester.server_bootstrap, proxy_server_tester.listener);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &c_tester.condition_variable, &c_tester.mutex, s_tls_listener_destroy_predicate, &proxy_server_test_state));

    AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "*TEST 7* Server listener shutdowns complete ");

    aws_mutex_unlock(&c_tester.mutex);

    s_tls_proxy_rw_args_clean_up(&proxy_channel_context);

    /* clean up */
    ASSERT_SUCCESS(s_tls_opt_tester_clean_up(&client_tls_opt_tester));
    aws_client_bootstrap_release(client_bootstrap);
    ASSERT_SUCCESS(s_tls_local_server_tester_clean_up(&endpoint_server_tester));
    ASSERT_SUCCESS(s_tls_local_server_tester_clean_up(&proxy_server_tester));
    ASSERT_SUCCESS(s_tls_common_tester_clean_up(&c_tester));

    AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "*TEST 8* All thread shutdowns complete ");

    aws_tls_connection_options_clean_up(&client_tls_opt_tester.opt);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(tls_double_channel, s_tls_double_channel_fn)

static int s_test_ecc_cert_import(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    (void)allocator;

#    ifndef AWS_OS_APPLE
    aws_io_library_init(allocator);

    struct aws_byte_buf cert_buf;
    struct aws_byte_buf key_buf;

    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&cert_buf, allocator, "ecc-cert.pem"));
    ASSERT_SUCCESS(aws_byte_buf_init_from_file(&key_buf, allocator, "ecc-key.pem"));

    struct aws_byte_cursor cert_cur = aws_byte_cursor_from_buf(&cert_buf);
    struct aws_byte_cursor key_cur = aws_byte_cursor_from_buf(&key_buf);
    struct aws_tls_ctx_options tls_options = {0};
    AWS_FATAL_ASSERT(
        AWS_OP_SUCCESS == aws_tls_ctx_options_init_client_mtls(&tls_options, allocator, &cert_cur, &key_cur));

    /* import happens in here */
    struct aws_tls_ctx *tls_context = aws_tls_client_ctx_new(allocator, &tls_options);
    ASSERT_NOT_NULL(tls_context);

    aws_tls_ctx_release(tls_context);

    aws_tls_ctx_options_clean_up(&tls_options);

    aws_byte_buf_clean_up(&cert_buf);
    aws_byte_buf_clean_up(&key_buf);

    aws_io_library_clean_up();
#    endif /* AWS_OS_APPLE */

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_ecc_cert_import, s_test_ecc_cert_import)

#endif /* BYO_CRYPTO */
