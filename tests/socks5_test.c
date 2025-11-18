/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/testing/aws_test_harness.h>

#include <aws/common/array_list.h>
#include <aws/common/byte_buf.h>
#include <aws/common/clock.h>
#include <aws/common/error.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/io/channel.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/socket.h>
#include <aws/io/logging.h>
#include <aws/io/socks5.h>
#include <aws/io/socks5_channel_handler.h>

typedef int(s_channel_run_fn)(struct aws_channel *channel, void *user_data);

struct channel_call_context {
    struct aws_channel *channel;
    s_channel_run_fn *fn;
    void *user_data;
    struct aws_mutex mutex;
    struct aws_condition_variable condition;
    bool completed;
    int result;
    int error_code;
    struct aws_channel_task task;
};

static bool s_channel_call_complete_predicate(void *user_data) {
    struct channel_call_context *context = user_data;
    return context->completed;
}

static void s_channel_call_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct channel_call_context *context = arg;
    int result = AWS_OP_ERR;
    int error_code = AWS_ERROR_SUCCESS;

    if (status == AWS_TASK_STATUS_CANCELED) {
        result = AWS_OP_ERR;
        error_code = AWS_ERROR_INVALID_STATE;
    } else {
        result = context->fn(context->channel, context->user_data);
        if (result != AWS_OP_SUCCESS) {
            error_code = aws_last_error();
        }
    }

    aws_mutex_lock(&context->mutex);
    context->result = result;
    context->error_code = error_code;
    context->completed = true;
    aws_mutex_unlock(&context->mutex);
    aws_condition_variable_notify_one(&context->condition);
}

static int s_channel_run_on_thread(struct aws_channel *channel, s_channel_run_fn *fn, void *user_data) {

    /* If already on the channel's thread, run directly; otherwise, schedule as a task */
    if (aws_channel_thread_is_callers_thread(channel)) {
        return fn(channel, user_data);
    }

    struct channel_call_context context;
    AWS_ZERO_STRUCT(context);

    context.channel = channel;
    context.fn = fn;
    context.user_data = user_data;
    context.result = AWS_OP_ERR;
    context.completed = false;
    context.error_code = AWS_ERROR_UNKNOWN;

    aws_mutex_init(&context.mutex);
    aws_condition_variable_init(&context.condition);
    aws_channel_task_init(&context.task, s_channel_call_task, &context, "socks5_test_channel_call");

    aws_channel_schedule_task_now(channel, &context.task);

    aws_mutex_lock(&context.mutex);
    int wait_result = aws_condition_variable_wait_pred(
        &context.condition, &context.mutex, s_channel_call_complete_predicate, &context);
    int result = context.result;
    aws_mutex_unlock(&context.mutex);

    aws_condition_variable_clean_up(&context.condition);
    aws_mutex_clean_up(&context.mutex);

    if (wait_result) {
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: s_channel_run_on_thread wait failed with error %d (%s)",
            (void *)channel,
            error_code,
            aws_error_str(error_code));
        return aws_raise_error(error_code);
    }

    if (result == AWS_OP_SUCCESS) {
        return AWS_OP_SUCCESS;
    }

    if (context.error_code != AWS_ERROR_SUCCESS && context.error_code != AWS_ERROR_UNKNOWN) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: s_channel_run_on_thread task failed with error %d (%s)",
            (void *)channel,
            context.error_code,
            aws_error_str(context.error_code));
        return aws_raise_error(context.error_code);
    }

    AWS_LOGF_ERROR(
        AWS_LS_IO_SOCKS5,
        "id=%p: s_channel_run_on_thread task failed with unknown error",
        (void *)channel);
    return aws_raise_error(AWS_ERROR_UNKNOWN);
}

struct install_handler_args {
    struct aws_channel_handler *handler;
    struct aws_channel_slot **out_slot;
};

static int s_install_handler_on_thread(struct aws_channel *channel, void *user_data) {
    struct install_handler_args *args = user_data;


    /* Create a new slot for the handler in the channel */
    struct aws_channel_slot *slot = aws_channel_slot_new(channel);
    if (!slot) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    struct aws_channel_slot *first_slot = aws_channel_get_first_slot(channel);
    if (first_slot != slot) {
        if (aws_channel_slot_insert_end(channel, slot)) {
            int error_code = aws_last_error();
            aws_mem_release(slot->alloc, slot);
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5,
                "id=%p: Failed to insert slot at end, error %d (%s)",
                (void *)channel,
                error_code,
                aws_error_str(error_code));
            return aws_raise_error(error_code);
        }
    }

    if (aws_channel_slot_set_handler(slot, args->handler)) {
        int error_code = aws_last_error();
        aws_channel_slot_remove(slot);
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=%p: Failed to set handler on slot, error %d (%s)",
            (void *)channel,
            error_code,
            aws_error_str(error_code));
        return aws_raise_error(error_code);
    }

    *args->out_slot = slot;
    return AWS_OP_SUCCESS;
}

static int s_install_handler(
    struct aws_channel *channel,
    struct aws_channel_handler *handler,
    struct aws_channel_slot **out_slot) {

    struct install_handler_args args = {
        .handler = handler,
        .out_slot = out_slot,
    };
    return s_channel_run_on_thread(channel, s_install_handler_on_thread, &args);
}

struct send_message_args {
    struct aws_allocator *allocator;
    struct aws_channel_slot *slot;
    enum aws_channel_direction direction;
    struct aws_byte_buf payload;
};

static int s_send_message_on_thread(struct aws_channel *channel, void *user_data) {
    (void)channel;

    struct send_message_args *args = user_data;


    /* Acquire a message from the pool and fill with payload */
    struct aws_io_message *message = aws_channel_acquire_message_from_pool(
        args->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, args->payload.len);
    if (!message) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor payload_cursor = aws_byte_cursor_from_buf(&args->payload);
    if (aws_byte_buf_append(&message->message_data, &payload_cursor)) {
        aws_mem_release(message->allocator, message);
        return AWS_OP_ERR;
    }

    if (aws_channel_slot_send_message(args->slot, message, args->direction)) {
        int error_code = aws_last_error();
        aws_mem_release(message->allocator, message);
        return aws_raise_error(error_code);
    }

    return AWS_OP_SUCCESS;
}

static int s_channel_send_bytes(
    struct aws_allocator *allocator,
    struct aws_channel_slot *slot,
    enum aws_channel_direction direction,
    const uint8_t *data,
    size_t len) {

    struct send_message_args args;
    AWS_ZERO_STRUCT(args);
    args.allocator = allocator;
    args.slot = slot;
    args.direction = direction;

    if (aws_byte_buf_init_copy_from_cursor(
            &args.payload, allocator, aws_byte_cursor_from_array(data, len))) {
        return AWS_OP_ERR;
    }

    int result = s_channel_run_on_thread(slot->channel, s_send_message_on_thread, &args);
    aws_byte_buf_clean_up(&args.payload);
    return result;
}

static int s_channel_send_cursor(
    struct aws_allocator *allocator,
    struct aws_channel_slot *slot,
    enum aws_channel_direction direction,
    struct aws_byte_cursor cursor) {
    return s_channel_send_bytes(allocator, slot, direction, cursor.ptr, cursor.len);
}

static int s_start_handshake_on_thread(struct aws_channel *channel, void *user_data) {
    struct aws_channel_handler *handler = user_data;
    return aws_socks5_channel_handler_start_handshake(handler);
}

static int s_socks5_proxy_options_basic(struct aws_allocator *allocator, void *ctx) {

    /* Test basic initialization and configuration of SOCKS5 proxy options */
    (void)ctx;

    struct aws_socks5_proxy_options defaults;
    ASSERT_SUCCESS(aws_socks5_proxy_options_init_default(&defaults));
    ASSERT_INT_EQUALS(1080, defaults.port);
    ASSERT_INT_EQUALS(3000, defaults.connection_timeout_ms);
    ASSERT_INT_EQUALS(AWS_SOCKS5_HOST_RESOLUTION_PROXY, defaults.host_resolution_mode);
    aws_socks5_proxy_options_clean_up(&defaults);

    struct aws_socks5_proxy_options options;
    AWS_ZERO_STRUCT(options);
    struct aws_byte_cursor proxy_host = aws_byte_cursor_from_c_str("proxy.example.com");
    ASSERT_SUCCESS(aws_socks5_proxy_options_init(&options, allocator, proxy_host, 9000));
    ASSERT_NOT_NULL(options.host);
    ASSERT_BIN_ARRAYS_EQUALS(
        proxy_host.ptr, proxy_host.len, aws_string_bytes(options.host), options.host->len);
    ASSERT_INT_EQUALS(9000, options.port);
    ASSERT_INT_EQUALS(3000, options.connection_timeout_ms);
    ASSERT_INT_EQUALS(AWS_SOCKS5_HOST_RESOLUTION_PROXY, options.host_resolution_mode);

    struct aws_byte_cursor username = aws_byte_cursor_from_c_str("user");
    struct aws_byte_cursor password = aws_byte_cursor_from_c_str("pass");
    ASSERT_SUCCESS(aws_socks5_proxy_options_set_auth(&options, allocator, username, password));
    ASSERT_NOT_NULL(options.username);
    ASSERT_NOT_NULL(options.password);
    ASSERT_BIN_ARRAYS_EQUALS(
        username.ptr, username.len, aws_string_bytes(options.username), options.username->len);
    ASSERT_BIN_ARRAYS_EQUALS(
        password.ptr, password.len, aws_string_bytes(options.password), options.password->len);

    aws_socks5_proxy_options_set_host_resolution_mode(&options, AWS_SOCKS5_HOST_RESOLUTION_CLIENT);
    ASSERT_INT_EQUALS(AWS_SOCKS5_HOST_RESOLUTION_CLIENT, aws_socks5_proxy_options_get_host_resolution_mode(&options));

    aws_socks5_proxy_options_clean_up(&options);
    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(socks5_proxy_options_basic, s_socks5_proxy_options_basic)

static int s_socks5_infer_address_type_cases(struct aws_allocator *allocator, void *ctx) {

    /* Test address type inference for various host formats */
    (void)allocator;
    (void)ctx;

    struct aws_byte_cursor ipv4_host = aws_byte_cursor_from_c_str("127.0.0.1");
    ASSERT_INT_EQUALS(
        AWS_SOCKS5_ATYP_IPV4, aws_socks5_infer_address_type(ipv4_host, AWS_SOCKS5_ATYP_DOMAIN));

    struct aws_byte_cursor ipv6_host = aws_byte_cursor_from_c_str("2001:db8::1");
    ASSERT_INT_EQUALS(
        AWS_SOCKS5_ATYP_IPV6, aws_socks5_infer_address_type(ipv6_host, AWS_SOCKS5_ATYP_DOMAIN));

    struct aws_byte_cursor bracketed_ipv6 = aws_byte_cursor_from_c_str("[fe80::1]");
    ASSERT_INT_EQUALS(
        AWS_SOCKS5_ATYP_IPV6, aws_socks5_infer_address_type(bracketed_ipv6, AWS_SOCKS5_ATYP_DOMAIN));

    struct aws_byte_cursor scoped_ipv6 = aws_byte_cursor_from_c_str("fe80::1%eth0");
    ASSERT_INT_EQUALS(
        AWS_SOCKS5_ATYP_IPV6, aws_socks5_infer_address_type(scoped_ipv6, AWS_SOCKS5_ATYP_DOMAIN));

    struct aws_byte_cursor domain_host = aws_byte_cursor_from_c_str("example.com");
    ASSERT_INT_EQUALS(
        AWS_SOCKS5_ATYP_DOMAIN, aws_socks5_infer_address_type(domain_host, AWS_SOCKS5_ATYP_DOMAIN));

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(socks5_infer_address_type_cases, s_socks5_infer_address_type_cases)

static int s_socks5_context_init_lifecycle(struct aws_allocator *allocator, void *ctx) {

    /* Test context initialization, cleanup, and error handling */
    (void)ctx;

    struct aws_socks5_proxy_options options;
    AWS_ZERO_STRUCT(options);
    struct aws_byte_cursor proxy_host = aws_byte_cursor_from_c_str("proxy.example.com");
    ASSERT_SUCCESS(aws_socks5_proxy_options_init(&options, allocator, proxy_host, 1080));

    struct aws_byte_cursor username = aws_byte_cursor_from_c_str("user");
    struct aws_byte_cursor password = aws_byte_cursor_from_c_str("pass");
    ASSERT_SUCCESS(aws_socks5_proxy_options_set_auth(&options, allocator, username, password));

    struct aws_socks5_context context;
    AWS_ZERO_STRUCT(context);
    struct aws_byte_cursor endpoint_host = aws_byte_cursor_from_c_str("destination.example.com");

    ASSERT_SUCCESS(aws_socks5_context_init(
        &context,
        allocator,
        &options,
        endpoint_host,
        443,
        AWS_SOCKS5_ATYP_DOMAIN));

    ASSERT_NOT_NULL(context.endpoint_host);
    ASSERT_BIN_ARRAYS_EQUALS(
        endpoint_host.ptr, endpoint_host.len, aws_string_bytes(context.endpoint_host), context.endpoint_host->len);
    ASSERT_INT_EQUALS(AWS_SOCKS5_STATE_INIT, context.state);
    ASSERT_INT_EQUALS(AWS_SOCKS5_ATYP_DOMAIN, context.endpoint_address_type);
    ASSERT_UINT_EQUALS(2, aws_array_list_length(&context.auth_methods));

    aws_socks5_context_clean_up(&context);
    ASSERT_NULL(context.endpoint_host);
    ASSERT_NULL(context.options.host);
    ASSERT_UINT_EQUALS(0, context.auth_methods.length);

    struct aws_socks5_context bad_context;
    AWS_ZERO_STRUCT(bad_context);
    struct aws_byte_cursor empty_host = {
        .ptr = NULL,
        .len = 0,
    };
    ASSERT_ERROR(
        AWS_ERROR_INVALID_ARGUMENT,
        aws_socks5_context_init(
            &bad_context,
            allocator,
            &options,
            empty_host,
            443,
            AWS_SOCKS5_ATYP_DOMAIN));

    aws_socks5_proxy_options_clean_up(&options);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(socks5_context_init_lifecycle, s_socks5_context_init_lifecycle)

static int s_socks5_handshake_happy_path(struct aws_allocator *allocator, void *ctx) {

    /* Simulate a successful SOCKS5 handshake sequence */
    (void)ctx;

    struct aws_socks5_proxy_options options;
    AWS_ZERO_STRUCT(options);
    struct aws_byte_cursor proxy_host = aws_byte_cursor_from_c_str("proxy.example.com");
    ASSERT_SUCCESS(aws_socks5_proxy_options_init(&options, allocator, proxy_host, 1080));
    struct aws_byte_cursor username = aws_byte_cursor_from_c_str("user");
    struct aws_byte_cursor password = aws_byte_cursor_from_c_str("pass");
    ASSERT_SUCCESS(aws_socks5_proxy_options_set_auth(&options, allocator, username, password));

    struct aws_socks5_context context;
    AWS_ZERO_STRUCT(context);
    struct aws_byte_cursor endpoint_host = aws_byte_cursor_from_c_str("destination.example.com");
    ASSERT_SUCCESS(aws_socks5_context_init(
        &context,
        allocator,
        &options,
        endpoint_host,
        443,
        AWS_SOCKS5_ATYP_DOMAIN));

    struct aws_byte_buf buffer;
    ASSERT_SUCCESS(aws_byte_buf_init(&buffer, allocator, 64));

    ASSERT_SUCCESS(aws_socks5_write_greeting(&context, &buffer));
    ASSERT_INT_EQUALS(AWS_SOCKS5_STATE_GREETING_SENT, context.state);
    ASSERT_UINT_EQUALS(4, buffer.len); /* VER + NMETHODS + 2 methods */
    ASSERT_UINT_EQUALS(AWS_SOCKS5_VERSION, buffer.buffer[0]);
    ASSERT_UINT_EQUALS(2, buffer.buffer[1]);

    uint8_t greeting_resp[] = {AWS_SOCKS5_VERSION, AWS_SOCKS5_AUTH_USERNAME_PASSWORD};
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(greeting_resp, sizeof(greeting_resp));
    ASSERT_SUCCESS(aws_socks5_read_greeting_response(&context, &cursor));
    ASSERT_INT_EQUALS(AWS_SOCKS5_STATE_GREETING_RECEIVED, context.state);
    ASSERT_INT_EQUALS(AWS_SOCKS5_AUTH_USERNAME_PASSWORD, context.selected_auth);

    aws_byte_buf_reset(&buffer, false);
    ASSERT_SUCCESS(aws_socks5_write_auth_request(&context, &buffer));
    ASSERT_INT_EQUALS(AWS_SOCKS5_STATE_AUTH_STARTED, context.state);
    ASSERT_UINT_EQUALS(3 + username.len + password.len, buffer.len);
    ASSERT_UINT_EQUALS(AWS_SOCKS5_AUTH_VERSION, buffer.buffer[0]);
    ASSERT_UINT_EQUALS(username.len, buffer.buffer[1]);
    ASSERT_UINT_EQUALS(password.len, buffer.buffer[1 + 1 + username.len]);

    uint8_t auth_resp[] = {AWS_SOCKS5_AUTH_VERSION, 0};
    cursor = aws_byte_cursor_from_array(auth_resp, sizeof(auth_resp));
    ASSERT_SUCCESS(aws_socks5_read_auth_response(&context, &cursor));
    ASSERT_INT_EQUALS(AWS_SOCKS5_STATE_AUTH_COMPLETED, context.state);

    aws_byte_buf_reset(&buffer, false);
    ASSERT_SUCCESS(aws_socks5_write_connect_request(&context, &buffer));
    ASSERT_TRUE(buffer.len > AWS_SOCKS5_CONN_REQ_MIN_SIZE);
    ASSERT_INT_EQUALS(AWS_SOCKS5_STATE_REQUEST_SENT, context.state);

    uint8_t connect_resp[] = {
        AWS_SOCKS5_VERSION,
        AWS_SOCKS5_STATUS_SUCCESS,
        AWS_SOCKS5_RESERVED,
        AWS_SOCKS5_ATYP_IPV4,
        10,
        0,
        0,
        1,
        0,
        80};
    cursor = aws_byte_cursor_from_array(connect_resp, sizeof(connect_resp));
    ASSERT_SUCCESS(aws_socks5_read_connect_response(&context, &cursor));
    ASSERT_INT_EQUALS(AWS_SOCKS5_STATE_CONNECTED, context.state);

    aws_byte_buf_clean_up(&buffer);
    aws_socks5_context_clean_up(&context);
    aws_socks5_proxy_options_clean_up(&options);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(socks5_handshake_happy_path, s_socks5_handshake_happy_path)

static int s_socks5_handshake_error_paths(struct aws_allocator *allocator, void *ctx) {

    /* Test error handling for handshake failures (greeting, auth, connect) */
    (void)ctx;

    /* Greeting rejection */
    struct aws_socks5_proxy_options options_default;
    AWS_ZERO_STRUCT(options_default);
    struct aws_byte_cursor proxy_host = aws_byte_cursor_from_c_str("proxy.example.com");
    ASSERT_SUCCESS(aws_socks5_proxy_options_init(&options_default, allocator, proxy_host, 1080));

    struct aws_socks5_context context_default;
    AWS_ZERO_STRUCT(context_default);
    struct aws_byte_cursor endpoint_host = aws_byte_cursor_from_c_str("endpoint.example.com");
    ASSERT_SUCCESS(aws_socks5_context_init(
        &context_default,
        allocator,
        &options_default,
        endpoint_host,
        80,
        AWS_SOCKS5_ATYP_DOMAIN));

    struct aws_byte_buf buffer;
    ASSERT_SUCCESS(aws_byte_buf_init(&buffer, allocator, 32));
    ASSERT_SUCCESS(aws_socks5_write_greeting(&context_default, &buffer));

    uint8_t reject_resp[] = {AWS_SOCKS5_VERSION, AWS_SOCKS5_AUTH_NO_ACCEPTABLE};
    struct aws_byte_cursor cursor = aws_byte_cursor_from_array(reject_resp, sizeof(reject_resp));
    ASSERT_ERROR(
        AWS_IO_SOCKS5_PROXY_ERROR_UNSUPPORTED_AUTH_METHOD,
        aws_socks5_read_greeting_response(&context_default, &cursor));
    ASSERT_INT_EQUALS(AWS_SOCKS5_STATE_ERROR, context_default.state);

    aws_byte_buf_clean_up(&buffer);
    aws_socks5_context_clean_up(&context_default);
    aws_socks5_proxy_options_clean_up(&options_default);

    /* Auth failure */
    struct aws_socks5_proxy_options auth_options;
    AWS_ZERO_STRUCT(auth_options);
    ASSERT_SUCCESS(aws_socks5_proxy_options_init(&auth_options, allocator, proxy_host, 1080));
    struct aws_byte_cursor username = aws_byte_cursor_from_c_str("user");
    struct aws_byte_cursor password = aws_byte_cursor_from_c_str("pass");
    ASSERT_SUCCESS(aws_socks5_proxy_options_set_auth(&auth_options, allocator, username, password));

    struct aws_socks5_context auth_context;
    AWS_ZERO_STRUCT(auth_context);
    ASSERT_SUCCESS(aws_socks5_context_init(
        &auth_context,
        allocator,
        &auth_options,
        endpoint_host,
        443,
        AWS_SOCKS5_ATYP_DOMAIN));

    ASSERT_SUCCESS(aws_byte_buf_init(&buffer, allocator, 32));
    ASSERT_SUCCESS(aws_socks5_write_greeting(&auth_context, &buffer));
    uint8_t greeting_resp[] = {AWS_SOCKS5_VERSION, AWS_SOCKS5_AUTH_USERNAME_PASSWORD};
    cursor = aws_byte_cursor_from_array(greeting_resp, sizeof(greeting_resp));
    ASSERT_SUCCESS(aws_socks5_read_greeting_response(&auth_context, &cursor));
    aws_byte_buf_reset(&buffer, false);
    ASSERT_SUCCESS(aws_socks5_write_auth_request(&auth_context, &buffer));
    uint8_t auth_fail_resp[] = {AWS_SOCKS5_AUTH_VERSION, 1};
    cursor = aws_byte_cursor_from_array(auth_fail_resp, sizeof(auth_fail_resp));
    ASSERT_ERROR(AWS_IO_SOCKS5_PROXY_ERROR_AUTH_FAILED, aws_socks5_read_auth_response(&auth_context, &cursor));
    ASSERT_INT_EQUALS(AWS_SOCKS5_STATE_ERROR, auth_context.state);

    aws_byte_buf_clean_up(&buffer);
    aws_socks5_context_clean_up(&auth_context);
    aws_socks5_proxy_options_clean_up(&auth_options);

    /* Connect failure */
    struct aws_socks5_proxy_options connect_options;
    AWS_ZERO_STRUCT(connect_options);
    ASSERT_SUCCESS(aws_socks5_proxy_options_init(&connect_options, allocator, proxy_host, 1080));
    ASSERT_SUCCESS(aws_socks5_proxy_options_set_auth(&connect_options, allocator, username, password));

    struct aws_socks5_context connect_context;
    AWS_ZERO_STRUCT(connect_context);
    ASSERT_SUCCESS(aws_socks5_context_init(
        &connect_context,
        allocator,
        &connect_options,
        endpoint_host,
        443,
        AWS_SOCKS5_ATYP_DOMAIN));

    ASSERT_SUCCESS(aws_byte_buf_init(&buffer, allocator, 32));
    ASSERT_SUCCESS(aws_socks5_write_greeting(&connect_context, &buffer));
    cursor = aws_byte_cursor_from_array(greeting_resp, sizeof(greeting_resp));
    ASSERT_SUCCESS(aws_socks5_read_greeting_response(&connect_context, &cursor));
    aws_byte_buf_reset(&buffer, false);
    ASSERT_SUCCESS(aws_socks5_write_auth_request(&connect_context, &buffer));
    uint8_t auth_ok_resp[] = {AWS_SOCKS5_AUTH_VERSION, 0};
    cursor = aws_byte_cursor_from_array(auth_ok_resp, sizeof(auth_ok_resp));
    ASSERT_SUCCESS(aws_socks5_read_auth_response(&connect_context, &cursor));
    aws_byte_buf_reset(&buffer, false);
    ASSERT_SUCCESS(aws_socks5_write_connect_request(&connect_context, &buffer));
    uint8_t connect_fail_resp[] = {
        AWS_SOCKS5_VERSION,
        AWS_SOCKS5_STATUS_CONNECTION_REFUSED,
        AWS_SOCKS5_RESERVED,
        AWS_SOCKS5_ATYP_IPV4,
        10,
        0,
        0,
        1,
        0,
        80};
    cursor = aws_byte_cursor_from_array(connect_fail_resp, sizeof(connect_fail_resp));
    ASSERT_ERROR(AWS_IO_SOCKET_CONNECTION_REFUSED, aws_socks5_read_connect_response(&connect_context, &cursor));
    ASSERT_INT_EQUALS(AWS_SOCKS5_STATE_ERROR, connect_context.state);

    aws_byte_buf_clean_up(&buffer);
    aws_socks5_context_clean_up(&connect_context);
    aws_socks5_proxy_options_clean_up(&connect_options);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(socks5_handshake_error_paths, s_socks5_handshake_error_paths)

struct socks5_peer_impl {
    struct aws_allocator *allocator;
    struct aws_mutex mutex;
    struct aws_condition_variable condition;
    struct aws_byte_buf last_write;
    bool has_write;
    size_t write_count;
    struct aws_channel_slot *slot;
};

static bool s_peer_has_write_predicate(void *user_data) {
    struct socks5_peer_impl *impl = user_data;
    return impl->has_write;
}

static int s_peer_wait_for_write(struct socks5_peer_impl *impl, struct aws_byte_buf *out_buf) {
    int result = AWS_OP_SUCCESS;


    /* Wait until the peer handler has written data */
    aws_mutex_lock(&impl->mutex);
    if (aws_condition_variable_wait_pred(&impl->condition, &impl->mutex, s_peer_has_write_predicate, impl)) {
        result = AWS_OP_ERR;
        goto done;
    }

    result = aws_byte_buf_init_copy_from_cursor(
        out_buf,
        impl->allocator,
        aws_byte_cursor_from_buf(&impl->last_write));
    impl->has_write = false;
    aws_byte_buf_clean_up(&impl->last_write);
    AWS_ZERO_STRUCT(impl->last_write);

done:
    aws_mutex_unlock(&impl->mutex);
    return result;
}

static int s_peer_send(struct socks5_peer_impl *impl, const uint8_t *data, size_t len) {
    struct aws_channel_slot *slot = NULL;


    /* Send data to the peer's slot (simulates network input) */
    aws_mutex_lock(&impl->mutex);
    slot = impl->slot;
    aws_mutex_unlock(&impl->mutex);

    if (!slot) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    return s_channel_send_bytes(impl->allocator, slot, AWS_CHANNEL_DIR_READ, data, len);
}

static int s_peer_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct socks5_peer_impl *impl = handler->impl;
    struct aws_byte_cursor payload = aws_byte_cursor_from_buf(&message->message_data);

    /* Store the written message so the test can inspect it */
    aws_mutex_lock(&impl->mutex);

    if (impl->last_write.buffer) {
        aws_byte_buf_clean_up(&impl->last_write);
        AWS_ZERO_STRUCT(impl->last_write);
    }

    if (aws_byte_buf_init_copy_from_cursor(&impl->last_write, impl->allocator, payload)) {
        aws_mutex_unlock(&impl->mutex);
        aws_mem_release(message->allocator, message);
        return AWS_OP_ERR;
    }

    impl->has_write = true;
    impl->write_count++;
    impl->slot = slot;
    aws_condition_variable_notify_one(&impl->condition);

    aws_mutex_unlock(&impl->mutex);

    aws_mem_release(message->allocator, message);
    return AWS_OP_SUCCESS;
}

static int s_peer_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)handler;
    (void)slot;

    aws_mem_release(message->allocator, message);
    return AWS_OP_SUCCESS;
}

static int s_peer_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {
    (void)handler;
    (void)slot;
    (void)size;
    return AWS_OP_SUCCESS;
}

static int s_peer_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool abort_immediately) {
    (void)handler;

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, abort_immediately);
}

static size_t s_peer_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;
    return SIZE_MAX;
}

static size_t s_peer_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;
    return 0;
}

static void s_peer_destroy(struct aws_channel_handler *handler) {
    struct socks5_peer_impl *impl = handler->impl;
    if (!impl) {
        return;
    }

    aws_byte_buf_clean_up(&impl->last_write);
    aws_condition_variable_clean_up(&impl->condition);
    aws_mutex_clean_up(&impl->mutex);
    aws_mem_release(handler->alloc, impl);
    aws_mem_release(handler->alloc, handler);
}

static struct aws_channel_handler_vtable s_peer_handler_vtable = {
    .process_read_message = s_peer_process_read_message,
    .process_write_message = s_peer_process_write_message,
    .increment_read_window = s_peer_increment_read_window,
    .shutdown = s_peer_shutdown,
    .initial_window_size = s_peer_initial_window_size,
    .message_overhead = s_peer_message_overhead,
    .destroy = s_peer_destroy,
};

static struct aws_channel_handler *s_peer_handler_new(
    struct aws_allocator *allocator,
    struct socks5_peer_impl **out_impl) {
    struct aws_channel_handler *handler = aws_mem_calloc(allocator, 1, sizeof(struct aws_channel_handler));
    if (!handler) {
        return NULL;
    }

    struct socks5_peer_impl *impl = aws_mem_calloc(allocator, 1, sizeof(struct socks5_peer_impl));
    if (!impl) {
        aws_mem_release(allocator, handler);
        return NULL;
    }

    impl->allocator = allocator;
    if (aws_mutex_init(&impl->mutex)) {
        aws_mem_release(allocator, impl);
        aws_mem_release(allocator, handler);
        return NULL;
    }
    if (aws_condition_variable_init(&impl->condition)) {
        aws_mutex_clean_up(&impl->mutex);
        aws_mem_release(allocator, impl);
        aws_mem_release(allocator, handler);
        return NULL;
    }

    handler->alloc = allocator;
    handler->impl = impl;
    handler->vtable = &s_peer_handler_vtable;

    *out_impl = impl;
    return handler;
}

struct socks5_channel_fixture {
    struct aws_mutex mutex;
    struct aws_condition_variable condition;
    bool setup_completed;
    int setup_error;
    bool shutdown_completed;
    int shutdown_error;
};

static void s_socks5_channel_on_setup_completed(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    struct socks5_channel_fixture *fixture = user_data;

    aws_mutex_lock(&fixture->mutex);
    fixture->setup_completed = true;
    fixture->setup_error = error_code;
    aws_condition_variable_notify_one(&fixture->condition);
    aws_mutex_unlock(&fixture->mutex);
}

static void s_socks5_channel_on_shutdown_completed(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    struct socks5_channel_fixture *fixture = user_data;

    aws_mutex_lock(&fixture->mutex);
    fixture->shutdown_completed = true;
    fixture->shutdown_error = error_code;
    aws_condition_variable_notify_one(&fixture->condition);
    aws_mutex_unlock(&fixture->mutex);
}

static bool s_socks5_channel_setup_predicate(void *user_data) {
    struct socks5_channel_fixture *fixture = user_data;
    return fixture->setup_completed;
}

static bool s_socks5_channel_shutdown_predicate(void *user_data) {
    struct socks5_channel_fixture *fixture = user_data;
    return fixture->shutdown_completed;
}

struct socks5_handler_context {
    struct aws_mutex mutex;
    struct aws_condition_variable condition;
    bool invoked;
    int error_code;
};

static void s_socks5_handler_on_setup_completed(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    struct socks5_handler_context *context = user_data;

    aws_mutex_lock(&context->mutex);
    context->invoked = true;
    context->error_code = error_code;
    aws_condition_variable_notify_one(&context->condition);
    aws_mutex_unlock(&context->mutex);
}

static bool s_socks5_handler_invoked_predicate(void *user_data) {
    struct socks5_handler_context *context = user_data;
    return context->invoked;
}

static int s_socks5_channel_handler_happy_path(struct aws_allocator *allocator, void *ctx) {

    /* Test full channel handler flow and data forwarding */
    (void)ctx;

    /* Set up event loop and channel for handler integration test */
    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);
    ASSERT_NOT_NULL(event_loop);
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct socks5_channel_fixture channel_fixture = {
        .mutex = AWS_MUTEX_INIT,
        .condition = AWS_CONDITION_VARIABLE_INIT,
        .setup_completed = false,
        .setup_error = AWS_ERROR_SUCCESS,
        .shutdown_completed = false,
        .shutdown_error = AWS_ERROR_SUCCESS,
    };

    struct aws_channel_options channel_options = {
        .on_setup_completed = s_socks5_channel_on_setup_completed,
        .setup_user_data = &channel_fixture,
        .on_shutdown_completed = s_socks5_channel_on_shutdown_completed,
        .shutdown_user_data = &channel_fixture,
        .event_loop = event_loop,
    };

    struct aws_channel *channel = aws_channel_new(allocator, &channel_options);
    ASSERT_NOT_NULL(channel);

    aws_mutex_lock(&channel_fixture.mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &channel_fixture.condition, &channel_fixture.mutex, s_socks5_channel_setup_predicate, &channel_fixture));
    aws_mutex_unlock(&channel_fixture.mutex);
    ASSERT_INT_EQUALS(0, channel_fixture.setup_error);

    /* Install a peer handler to simulate the remote SOCKS5 server */
    struct socks5_peer_impl *peer_impl = NULL;
    struct aws_channel_handler *peer_handler = s_peer_handler_new(allocator, &peer_impl);
    ASSERT_NOT_NULL(peer_handler);

    struct aws_channel_slot *peer_slot = NULL;
    ASSERT_SUCCESS(s_install_handler(channel, peer_handler, &peer_slot));
    aws_mutex_lock(&peer_impl->mutex);
    peer_impl->slot = peer_slot;
    aws_mutex_unlock(&peer_impl->mutex);

    struct aws_channel_slot *socks5_slot = NULL;

    struct aws_socks5_proxy_options proxy_options;
    ASSERT_SUCCESS(aws_socks5_proxy_options_init(
        &proxy_options, allocator, aws_byte_cursor_from_c_str("proxy.example.com"), 1080));
    ASSERT_SUCCESS(aws_socks5_proxy_options_set_auth(
        &proxy_options, allocator, aws_byte_cursor_from_c_str("user"), aws_byte_cursor_from_c_str("pass")));

    struct socks5_handler_context handler_context = {
        .mutex = AWS_MUTEX_INIT,
        .condition = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .error_code = AWS_ERROR_SUCCESS,
    };

    struct aws_channel_handler *socks5_handler = aws_socks5_channel_handler_new(
        allocator,
        &proxy_options,
        aws_byte_cursor_from_c_str("destination.example.com"),
        443,
        AWS_SOCKS5_ATYP_DOMAIN,
        s_socks5_handler_on_setup_completed,
        &handler_context);
    ASSERT_NOT_NULL(socks5_handler);
    ASSERT_SUCCESS(s_install_handler(channel, socks5_handler, &socks5_slot));

    ASSERT_SUCCESS(s_channel_run_on_thread(channel, s_start_handshake_on_thread, socks5_handler));

    struct aws_byte_buf greeting;
    ASSERT_SUCCESS(s_peer_wait_for_write(peer_impl, &greeting));
    ASSERT_TRUE(greeting.len >= AWS_SOCKS5_GREETING_MIN_SIZE);
    ASSERT_UINT_EQUALS(AWS_SOCKS5_VERSION, greeting.buffer[0]);
    ASSERT_UINT_EQUALS(2, greeting.buffer[1]);
    aws_byte_buf_clean_up(&greeting);

    uint8_t greeting_response[] = {AWS_SOCKS5_VERSION, AWS_SOCKS5_AUTH_USERNAME_PASSWORD};
    ASSERT_SUCCESS(s_peer_send(peer_impl, greeting_response, sizeof(greeting_response)));

    struct aws_byte_buf auth_request;
    ASSERT_SUCCESS(s_peer_wait_for_write(peer_impl, &auth_request));
    ASSERT_UINT_EQUALS(3 + 4 + 4, auth_request.len);
    aws_byte_buf_clean_up(&auth_request);

    uint8_t auth_response[] = {AWS_SOCKS5_AUTH_VERSION, 0};
    ASSERT_SUCCESS(s_peer_send(peer_impl, auth_response, sizeof(auth_response)));

    struct aws_byte_buf connect_request;
    ASSERT_SUCCESS(s_peer_wait_for_write(peer_impl, &connect_request));
    ASSERT_TRUE(connect_request.len > AWS_SOCKS5_CONN_REQ_MIN_SIZE);
    aws_byte_buf_clean_up(&connect_request);

    uint8_t connect_success[] = {
        AWS_SOCKS5_VERSION,
        AWS_SOCKS5_STATUS_SUCCESS,
        AWS_SOCKS5_RESERVED,
        AWS_SOCKS5_ATYP_IPV4,
        1,
        1,
        1,
        1,
        0,
        80};
    ASSERT_SUCCESS(s_peer_send(peer_impl, connect_success, sizeof(connect_success)));

    aws_mutex_lock(&handler_context.mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &handler_context.condition, &handler_context.mutex, s_socks5_handler_invoked_predicate, &handler_context));
    int handshake_error = handler_context.error_code;
    aws_mutex_unlock(&handler_context.mutex);
    ASSERT_INT_EQUALS(AWS_ERROR_SUCCESS, handshake_error);

    struct aws_byte_cursor ping_cur = aws_byte_cursor_from_c_str("ping");
    ASSERT_SUCCESS(s_channel_send_cursor(allocator, socks5_slot, AWS_CHANNEL_DIR_WRITE, ping_cur));

    struct aws_byte_buf forwarded_ping;
    ASSERT_SUCCESS(s_peer_wait_for_write(peer_impl, &forwarded_ping));
    ASSERT_UINT_EQUALS(4, forwarded_ping.len);
    ASSERT_BIN_ARRAYS_EQUALS("ping", 4, forwarded_ping.buffer, forwarded_ping.len);
    aws_byte_buf_clean_up(&forwarded_ping);

    struct aws_byte_cursor pong_cur = aws_byte_cursor_from_c_str("pong");
    ASSERT_SUCCESS(s_channel_send_cursor(allocator, socks5_slot, AWS_CHANNEL_DIR_WRITE, pong_cur));

    struct aws_byte_buf forwarded_pong;
    ASSERT_SUCCESS(s_peer_wait_for_write(peer_impl, &forwarded_pong));
    ASSERT_UINT_EQUALS(4, forwarded_pong.len);
    ASSERT_BIN_ARRAYS_EQUALS("pong", 4, forwarded_pong.buffer, forwarded_pong.len);
    aws_byte_buf_clean_up(&forwarded_pong);

    aws_channel_shutdown(channel, AWS_OP_SUCCESS);
    aws_mutex_lock(&channel_fixture.mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &channel_fixture.condition, &channel_fixture.mutex, s_socks5_channel_shutdown_predicate, &channel_fixture));
    aws_mutex_unlock(&channel_fixture.mutex);
    if (channel_fixture.shutdown_error != AWS_ERROR_SUCCESS) {
        ASSERT_INT_EQUALS(AWS_IO_SOCKET_CLOSED, channel_fixture.shutdown_error);
    }

    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);
    aws_mutex_clean_up(&handler_context.mutex);
    aws_condition_variable_clean_up(&handler_context.condition);
    aws_mutex_clean_up(&channel_fixture.mutex);
    aws_condition_variable_clean_up(&channel_fixture.condition);
    aws_socks5_proxy_options_clean_up(&proxy_options);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(socks5_channel_handler_happy_path, s_socks5_channel_handler_happy_path)

static int s_socks5_channel_handler_greeting_failure(struct aws_allocator *allocator, void *ctx) {

    /* Test handler behavior on malformed greeting response */
    (void)ctx;

    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);
    ASSERT_NOT_NULL(event_loop);
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct socks5_channel_fixture channel_fixture = {
        .mutex = AWS_MUTEX_INIT,
        .condition = AWS_CONDITION_VARIABLE_INIT,
        .setup_completed = false,
        .setup_error = AWS_ERROR_SUCCESS,
        .shutdown_completed = false,
        .shutdown_error = AWS_ERROR_SUCCESS,
    };

    struct aws_channel_options channel_options = {
        .on_setup_completed = s_socks5_channel_on_setup_completed,
        .setup_user_data = &channel_fixture,
        .on_shutdown_completed = s_socks5_channel_on_shutdown_completed,
        .shutdown_user_data = &channel_fixture,
        .event_loop = event_loop,
    };

    struct aws_channel *channel = aws_channel_new(allocator, &channel_options);
    ASSERT_NOT_NULL(channel);

    aws_mutex_lock(&channel_fixture.mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &channel_fixture.condition, &channel_fixture.mutex, s_socks5_channel_setup_predicate, &channel_fixture));
    aws_mutex_unlock(&channel_fixture.mutex);
    ASSERT_INT_EQUALS(0, channel_fixture.setup_error);

    struct socks5_peer_impl *peer_impl = NULL;
    struct aws_channel_handler *peer_handler = s_peer_handler_new(allocator, &peer_impl);
    ASSERT_NOT_NULL(peer_handler);
    struct aws_channel_slot *peer_slot = NULL;
    ASSERT_SUCCESS(s_install_handler(channel, peer_handler, &peer_slot));
    aws_mutex_lock(&peer_impl->mutex);
    peer_impl->slot = peer_slot;
    aws_mutex_unlock(&peer_impl->mutex);

    struct aws_channel_slot *socks5_slot = NULL;

    struct aws_socks5_proxy_options proxy_options;
    ASSERT_SUCCESS(aws_socks5_proxy_options_init(
        &proxy_options, allocator, aws_byte_cursor_from_c_str("proxy.example.com"), 1080));

    struct socks5_handler_context handler_context = {
        .mutex = AWS_MUTEX_INIT,
        .condition = AWS_CONDITION_VARIABLE_INIT,
        .invoked = false,
        .error_code = AWS_ERROR_SUCCESS,
    };

    struct aws_channel_handler *socks5_handler = aws_socks5_channel_handler_new(
        allocator,
        &proxy_options,
        aws_byte_cursor_from_c_str("destination.example.com"),
        80,
        AWS_SOCKS5_ATYP_DOMAIN,
        s_socks5_handler_on_setup_completed,
        &handler_context);
    ASSERT_NOT_NULL(socks5_handler);
    ASSERT_SUCCESS(s_install_handler(channel, socks5_handler, &socks5_slot));

    ASSERT_SUCCESS(s_channel_run_on_thread(channel, s_start_handshake_on_thread, socks5_handler));

    struct aws_byte_buf greeting;
    ASSERT_SUCCESS(s_peer_wait_for_write(peer_impl, &greeting));
    ASSERT_TRUE(greeting.len >= AWS_SOCKS5_GREETING_MIN_SIZE);
    aws_byte_buf_clean_up(&greeting);

    uint8_t invalid_greeting[] = {0x04, AWS_SOCKS5_AUTH_NO_ACCEPTABLE};
    ASSERT_SUCCESS(s_peer_send(peer_impl, invalid_greeting, sizeof(invalid_greeting)));

    aws_mutex_lock(&handler_context.mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &handler_context.condition, &handler_context.mutex, s_socks5_handler_invoked_predicate, &handler_context));
    int failure_code = handler_context.error_code;
    aws_mutex_unlock(&handler_context.mutex);
    ASSERT_INT_EQUALS(AWS_IO_SOCKS5_PROXY_ERROR_MALFORMED_RESPONSE, failure_code);
    ASSERT_INT_EQUALS(1, (int)peer_impl->write_count);

    aws_channel_shutdown(channel, AWS_OP_SUCCESS);
    aws_mutex_lock(&channel_fixture.mutex);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &channel_fixture.condition, &channel_fixture.mutex, s_socks5_channel_shutdown_predicate, &channel_fixture));
    aws_mutex_unlock(&channel_fixture.mutex);

    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);
    aws_mutex_clean_up(&handler_context.mutex);
    aws_condition_variable_clean_up(&handler_context.condition);
    aws_mutex_clean_up(&channel_fixture.mutex);
    aws_condition_variable_clean_up(&channel_fixture.condition);
    aws_socks5_proxy_options_clean_up(&proxy_options);

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(socks5_channel_handler_greeting_failure, s_socks5_channel_handler_greeting_failure)

struct socks5_bootstrap_stub_context {
    bool invoked;
    const char *host_name;
    uint16_t port;
    void *user_data;
    const struct aws_tls_connection_options *tls_options;
};

static struct socks5_bootstrap_stub_context *s_stub_context = NULL;

/* Stub function for simulating an error on a new socket channel creation */
static int s_stub_bootstrap_new_socket_channel(struct aws_socket_channel_bootstrap_options *options) {
    if (s_stub_context) {
        s_stub_context->invoked = true;
        s_stub_context->host_name = options->host_name;
        s_stub_context->port = options->port;
        s_stub_context->user_data = options->user_data;
        s_stub_context->tls_options = options->tls_options;
    }
    aws_raise_error(AWS_ERROR_UNKNOWN);
    return AWS_OP_ERR;
}

static int s_socks5_bootstrap_system_vtable_failure(struct aws_allocator *allocator, void *ctx) {

    // Test socket creation error via vtable during bootstrap
    (void)ctx;

        aws_io_library_init(allocator);

    struct aws_event_loop_group *el_group = aws_event_loop_group_new_default(allocator, 1, NULL);
    ASSERT_NOT_NULL(el_group);

    struct aws_client_bootstrap_options bootstrap_options = {
        .event_loop_group = el_group,
        .host_resolver = NULL,
    };
    struct aws_client_bootstrap *client_bootstrap = aws_client_bootstrap_new(allocator, &bootstrap_options);
    ASSERT_NOT_NULL(client_bootstrap);

    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .connect_timeout_ms = 1000,
    };

    struct aws_socket_channel_bootstrap_options channel_options;
    AWS_ZERO_STRUCT(channel_options);
    channel_options.bootstrap = client_bootstrap;
    channel_options.host_name = "target.example.com";
    channel_options.port = 443;
    channel_options.socket_options = &socket_options;

    struct aws_socks5_proxy_options proxy_options;
    ASSERT_SUCCESS(aws_socks5_proxy_options_init(
        &proxy_options, allocator, aws_byte_cursor_from_c_str("proxy.local"), 1080));

    struct socks5_bootstrap_stub_context stub_context;
    AWS_ZERO_STRUCT(stub_context);
    s_stub_context = &stub_context;

    struct aws_socks5_system_vtable stub_vtable = {
        .aws_client_bootstrap_new_socket_channel = s_stub_bootstrap_new_socket_channel,
    };
    aws_socks5_channel_handler_set_system_vtable(&stub_vtable);

    ASSERT_ERROR(
        AWS_ERROR_UNKNOWN,
        aws_client_bootstrap_new_socket_channel_with_socks5(allocator, &channel_options, &proxy_options));

    ASSERT_TRUE(stub_context.invoked);
    ASSERT_STR_EQUALS("proxy.local", stub_context.host_name);
    ASSERT_INT_EQUALS(1080, stub_context.port);
    ASSERT_NOT_NULL(stub_context.user_data);
    ASSERT_NULL(stub_context.tls_options);

    aws_socks5_channel_handler_set_system_vtable(NULL);
    s_stub_context = NULL;

    channel_options.host_name = "target.example.com";
    aws_socks5_proxy_options_clean_up(&proxy_options);
    aws_client_bootstrap_release(client_bootstrap);
    aws_event_loop_group_release(el_group);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}
AWS_TEST_CASE(socks5_bootstrap_system_vtable_failure, s_socks5_bootstrap_system_vtable_failure)
