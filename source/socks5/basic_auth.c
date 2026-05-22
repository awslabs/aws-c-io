/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/socks5.h>

#include <aws/common/allocator.h>
#include <aws/common/byte_buf.h>
#include <aws/common/logging.h>
#include <aws/common/ref_count.h>
#include <aws/io/logging.h>
#include <aws/io/private/socks5_impl.h>

#define BASIC_AUTH_SUBNEGOTIATION_VERSION 1
#define BASIC_AUTH_METHOD_ID 2

struct aws_socks5_proxy_negotiation_strategy_basic_auth {
    struct aws_socks5_proxy_negotiation_strategy base;

    struct aws_byte_buf username;
    struct aws_byte_buf password;
};

static void s_aws_socks5_proxy_negotiation_strategy_basic_auth_final_release(void *value) {
    if (value == NULL) {
        return;
    }

    struct aws_socks5_proxy_negotiation_strategy *base = value;
    struct aws_socks5_proxy_negotiation_strategy_basic_auth *strategy = base->impl;

    aws_byte_buf_clean_up(&strategy->username);
    aws_byte_buf_clean_up(&strategy->password);

    aws_mem_release(strategy->base.allocator, strategy);
}

enum aws_socks5_basic_auth_negotiation_state {
    AWS_S5BANS_INVALID = -1,
    AWS_S5BANS_PENDING_METHOD_SELECTION, // method selection not yet fully received
    AWS_S5BANS_PENDING_REQUEST,          // basic auth request built but not fully written to socket
    AWS_S5BANS_PENDING_RESPONSE,         // server response not fully read
    AWS_S5BANS_COMPLETE_SUCCESS,         // negotiation completed successfully, terminal
    AWS_S5BANS_COMPLETE_FAILURE,         // negotiation failed, terminal

    AWS_S5BANS_COUNT,
};

static const char *s_aws_socks5_basic_auth_negotiation_state_strings[AWS_S5BANS_COUNT] = {
    "PendingMethodSelection",
    "PendingRequest",
    "PendingResponse",
    "CompleteSuccess",
    "CompleteFailure",
};

struct aws_socks5_proxy_negotiation_strategy_instance_basic_auth {
    struct aws_socks5_proxy_negotiation_strategy_instance base;

    struct aws_socks5_proxy_negotiation_strategy *strategy;

    enum aws_socks5_basic_auth_negotiation_state state;
    int final_error_code;

    struct aws_byte_buf inbound_buffer;
    struct aws_byte_buf outbound_buffer;
    struct aws_byte_cursor remaining_outbound_cursor;
};

static void s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_destroy(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance) {
    if (instance == NULL) {
        return;
    }

    struct aws_socks5_proxy_negotiation_strategy_instance_basic_auth *basic_auth_instance = instance->impl;

    aws_socks5_proxy_negotiation_strategy_release(basic_auth_instance->strategy);

    aws_byte_buf_clean_up(&basic_auth_instance->inbound_buffer);
    aws_byte_buf_clean_up(&basic_auth_instance->outbound_buffer);

    aws_mem_release(basic_auth_instance->base.allocator, basic_auth_instance);
}

static void s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_change_state(
    struct aws_socks5_proxy_negotiation_strategy_instance_basic_auth *instance,
    enum aws_socks5_basic_auth_negotiation_state new_state) {
    if (instance->state != new_state) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "(%p) Changing basic auth negotiation state from %d(%s) to %d(%s)",
            (void *)instance,
            (int)instance->state,
            s_aws_socks5_basic_auth_negotiation_state_strings[instance->state],
            (int)new_state,
            s_aws_socks5_basic_auth_negotiation_state_strings[new_state]);

        instance->state = new_state;
        aws_byte_buf_reset(&instance->inbound_buffer, false);
        aws_byte_buf_reset(&instance->outbound_buffer, false);
        AWS_ZERO_STRUCT(instance->remaining_outbound_cursor);
    }
}

static void s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_fail(
    struct aws_socks5_proxy_negotiation_strategy_instance_basic_auth *instance,
    struct aws_socks5_negotiation_context *context,
    int error_code) {
    if (instance->state != AWS_S5BANS_COMPLETE_FAILURE) {
        AWS_LOGF_WARN(
            AWS_LS_IO_SOCKS5,
            "(%p) Basic auth negotiation failed with error code %d(%s)",
            (void *)instance,
            error_code,
            aws_error_debug_str(error_code));
        s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_change_state(instance, AWS_S5BANS_COMPLETE_FAILURE);
        instance->final_error_code = error_code;
    }

    context->error_code = instance->final_error_code;
}

static int s_build_basic_auth_request(struct aws_socks5_proxy_negotiation_strategy_instance_basic_auth *instance) {
    AWS_FATAL_ASSERT(instance->outbound_buffer.len == 0);

    struct aws_socks5_proxy_negotiation_strategy_basic_auth *strategy = instance->strategy->impl;

    if (aws_byte_buf_append_byte_dynamic(&instance->outbound_buffer, BASIC_AUTH_SUBNEGOTIATION_VERSION)) {
        return AWS_OP_ERR;
    }

    // safe cast since we validate username length <= 255
    if (aws_byte_buf_append_byte_dynamic(&instance->outbound_buffer, (uint8_t)strategy->username.len)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor username_cursor = aws_byte_cursor_from_buf(&strategy->username);
    if (aws_byte_buf_append_dynamic(&instance->outbound_buffer, &username_cursor)) {
        return AWS_OP_ERR;
    }

    // safe cast since we validate password length <= 255
    if (aws_byte_buf_append_byte_dynamic(&instance->outbound_buffer, (uint8_t)strategy->password.len)) {
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor password_cursor = aws_byte_cursor_from_buf(&strategy->password);
    if (aws_byte_buf_append_dynamic(&instance->outbound_buffer, &password_cursor)) {
        return AWS_OP_ERR;
    }

    instance->remaining_outbound_cursor = aws_byte_cursor_from_buf(&instance->outbound_buffer);

    return AWS_OP_SUCCESS;
}

static void s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_service_pending_method_selection(
    struct aws_socks5_proxy_negotiation_strategy_instance_basic_auth *instance,
    struct aws_socks5_negotiation_context *context) {
    size_t bytes_needed = METHOD_SELECTION_LENGTH - aws_min_size(instance->inbound_buffer.len, METHOD_SELECTION_LENGTH);
    size_t bytes_available = aws_min_size(bytes_needed, (context->data) ? context->data->len : 0);

    if (bytes_available > 0) {
        struct aws_byte_cursor to_append = aws_byte_cursor_advance(context->data, bytes_available);
        if (aws_byte_buf_append_dynamic(&instance->inbound_buffer, &to_append)) {
            s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_fail(instance, context, aws_last_error());
            return;
        }
    }

    if (instance->inbound_buffer.len < METHOD_SELECTION_LENGTH) {
        return;
    }

    if (instance->inbound_buffer.buffer[0] != SOCKS_VERSION) {
        s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_fail(
            instance, context, AWS_IO_SOCKS5_PROTOCOL_VERSION_MISMATCH);
        return;
    }

    uint8_t selected_method = instance->inbound_buffer.buffer[1];
    if (selected_method != BASIC_AUTH_METHOD_ID) {
        s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_fail(
            instance,
            context,
            (selected_method == NO_ACCEPTABLE_METHODS_ID) ? AWS_IO_SOCKS5_NO_ACCEPTABLE_METHODS
                                                          : AWS_IO_SOCKS5_UNEXPECTED_METHOD_ID);
        return;
    }

    s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_change_state(instance, AWS_S5BANS_PENDING_REQUEST);

    if (s_build_basic_auth_request(instance)) {
        s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_fail(instance, context, aws_last_error());
    }
}

static void s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_service_pending_request(
    struct aws_socks5_proxy_negotiation_strategy_instance_basic_auth *instance,
    struct aws_socks5_negotiation_context *context) {
    size_t write_length =
        aws_min_size(context->to_write->capacity - context->to_write->len, instance->remaining_outbound_cursor.len);
    if (write_length > 0) {
        struct aws_byte_cursor to_copy = aws_byte_cursor_advance(&instance->remaining_outbound_cursor, write_length);
        aws_byte_buf_append(context->to_write, &to_copy);
    }

    if (instance->remaining_outbound_cursor.len == 0) {
        s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_change_state(instance, AWS_S5BANS_PENDING_RESPONSE);
    }
}

static void s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_service_pending_response(
    struct aws_socks5_proxy_negotiation_strategy_instance_basic_auth *instance,
    struct aws_socks5_negotiation_context *context) {
    size_t bytes_needed = METHOD_RESPONSE_LENGTH - aws_min_size(instance->inbound_buffer.len, METHOD_RESPONSE_LENGTH);
    size_t bytes_available = (context->data) ? (context->data->len) : 0;
    if (bytes_available == 0) {
        return;
    }

    bytes_needed = aws_min_size(bytes_needed, bytes_available);

    struct aws_byte_cursor to_append = aws_byte_cursor_advance(context->data, bytes_needed);
    if (aws_byte_buf_append_dynamic(&instance->inbound_buffer, &to_append)) {
        s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_fail(instance, context, aws_last_error());
        return;
    }

    if (instance->inbound_buffer.len < METHOD_RESPONSE_LENGTH) {
        return;
    }

    if (instance->inbound_buffer.buffer[0] != BASIC_AUTH_SUBNEGOTIATION_VERSION) {
        s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_fail(
            instance, context, AWS_IO_SOCKS5_SUBNEGOTIATION_VERSION_MISMATCH);
        return;
    }

    if (instance->inbound_buffer.buffer[1] != 0) {
        s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_fail(
            instance, context, AWS_IO_SOCKS5_SUBNEGOTIATION_REJECTED);
        return;
    }

    s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_change_state(instance, AWS_S5BANS_COMPLETE_SUCCESS);
}

static void s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_drive_negotiation(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_socks5_negotiation_context *context) {
    struct aws_socks5_proxy_negotiation_strategy_instance_basic_auth *basic_auth_instance = instance->impl;

    context->status = AWS_S5PS_IN_PROGRESS;
    enum aws_socks5_basic_auth_negotiation_state last_state = AWS_S5BANS_INVALID;
    while (last_state != basic_auth_instance->state) {
        last_state = basic_auth_instance->state;

        switch (basic_auth_instance->state) {
            case AWS_S5BANS_PENDING_METHOD_SELECTION:
                s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_service_pending_method_selection(
                    basic_auth_instance, context);
                break;

            case AWS_S5BANS_PENDING_REQUEST:
                s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_service_pending_request(
                    basic_auth_instance, context);
                break;

            case AWS_S5BANS_PENDING_RESPONSE:
                s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_service_pending_response(
                    basic_auth_instance, context);
                break;

            case AWS_S5BANS_COMPLETE_SUCCESS:
                context->status = AWS_S5PS_SUCCESS;
                return;

            default:
                break;
        }

        if (basic_auth_instance->state == AWS_S5BANS_COMPLETE_FAILURE) {
            context->status = AWS_S5PS_FAILURE;
        }
    }
}

static int a_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_get_auth_methods(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_array_list *methods) {
    (void)instance;

    uint8_t method = BASIC_AUTH_METHOD_ID;
    return aws_array_list_push_back(methods, &method);
}

static struct aws_socks5_proxy_negotiation_strategy_instance_vtable s_basic_auth_strategy_instance_vtable = {
    .destroy = s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_destroy,
    .drive_negotiation = s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_drive_negotiation,
    .get_auth_methods = a_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_get_auth_methods};

static struct aws_socks5_proxy_negotiation_strategy_instance *
    s_aws_socks5_proxy_negotiation_strategy_basic_auth_new_instance(
        struct aws_socks5_proxy_negotiation_strategy *strategy) {
    struct aws_socks5_proxy_negotiation_strategy_instance_basic_auth *instance = aws_mem_calloc(
        strategy->allocator, 1, sizeof(struct aws_socks5_proxy_negotiation_strategy_instance_basic_auth));
    instance->base.allocator = strategy->allocator;
    instance->base.vtable = &s_basic_auth_strategy_instance_vtable;
    instance->base.impl = instance;
    instance->strategy = aws_socks5_proxy_negotiation_strategy_acquire(strategy);

    struct aws_socks5_proxy_negotiation_strategy_basic_auth *basic_auth_strategy = strategy->impl;
    size_t inbound_buffer_length = aws_max_size(METHOD_SELECTION_LENGTH, METHOD_RESPONSE_LENGTH);
    size_t outbound_buffer_length = 3 + basic_auth_strategy->username.len + basic_auth_strategy->password.len;
    if (aws_byte_buf_init(&instance->inbound_buffer, strategy->allocator, inbound_buffer_length) ||
        aws_byte_buf_init(&instance->outbound_buffer, strategy->allocator, outbound_buffer_length)) {
        goto error;
    }

    return &instance->base;

error:

    s_aws_socks5_proxy_negotiation_strategy_instance_basic_auth_destroy(&instance->base);

    return NULL;
}

static struct aws_socks5_proxy_negotiation_strategy_vtable s_basic_auth_strategy_vtable = {
    .new_instance = s_aws_socks5_proxy_negotiation_strategy_basic_auth_new_instance,
};

struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_new_basic_auth(
    struct aws_allocator *allocator,
    struct aws_socks5_proxy_negotiation_basic_auth_options *options) {
    if (options->username.len > UINT8_MAX || options->password.len > UINT8_MAX) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "Invalid socks5 basic auth configuration - username/password too long");
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        return NULL;
    }

    struct aws_socks5_proxy_negotiation_strategy_basic_auth *strategy =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_proxy_negotiation_strategy_basic_auth));

    strategy->base.allocator = allocator;
    strategy->base.vtable = &s_basic_auth_strategy_vtable;
    strategy->base.impl = strategy;
    aws_ref_count_init(
        &strategy->base.ref_count, &strategy->base, s_aws_socks5_proxy_negotiation_strategy_basic_auth_final_release);

    if (aws_byte_buf_init_copy_from_cursor(&strategy->username, allocator, options->username) ||
        aws_byte_buf_init_copy_from_cursor(&strategy->password, allocator, options->password)) {
        goto error;
    }

    return &strategy->base;

error:

    aws_socks5_proxy_negotiation_strategy_release(&strategy->base);

    return NULL;
}
