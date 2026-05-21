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

#define NO_AUTH_METHOD_ID 0

struct aws_socks5_proxy_negotiation_strategy_no_auth {
    struct aws_socks5_proxy_negotiation_strategy base;
};

static void s_aws_socks5_proxy_negotiation_strategy_no_auth_final_release(void *value) {
    if (value == NULL) {
        return;
    }

    struct aws_socks5_proxy_negotiation_strategy *base = value;
    struct aws_socks5_proxy_negotiation_strategy_no_auth *strategy = base->impl;

    aws_mem_release(strategy->base.allocator, strategy);
}

enum aws_socks5_no_auth_negotiation_state {
    AWS_S5NANS_INVALID = -1,
    AWS_S5NANS_PENDING_METHOD_SELECTION, // method selection not yet fully received
    AWS_S5NANS_COMPLETE_SUCCESS,
    AWS_S5NANS_COMPLETE_FAILURE,

    AWS_S5NANS_COUNT,
};

static const char *s_aws_socks5_no_auth_negotiation_state_strings[AWS_S5NANS_COUNT] = {
    "PendingMethodSelection",
    "CompleteSuccess",
    "CompleteFailure"};

struct aws_socks5_proxy_negotiation_strategy_instance_no_auth {
    struct aws_socks5_proxy_negotiation_strategy_instance base;

    struct aws_byte_buf inbound_buffer;

    enum aws_socks5_no_auth_negotiation_state state;
    int final_error_code;
};

static void s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_destroy(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance) {
    if (instance == NULL) {
        return;
    }

    struct aws_socks5_proxy_negotiation_strategy_instance_no_auth *no_auth_instance = instance->impl;

    aws_byte_buf_clean_up(&no_auth_instance->inbound_buffer);

    aws_mem_release(no_auth_instance->base.allocator, no_auth_instance);
}

static void s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_change_state(
    struct aws_socks5_proxy_negotiation_strategy_instance_no_auth *instance,
    enum aws_socks5_no_auth_negotiation_state new_state) {
    if (instance->state != new_state) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5,
            "(%p) Changing no auth negotiation state from %d(%s) to %d(%s)",
            (void *)instance,
            (int)instance->state,
            s_aws_socks5_no_auth_negotiation_state_strings[instance->state],
            (int)new_state,
            s_aws_socks5_no_auth_negotiation_state_strings[new_state]);
        aws_byte_buf_reset(&instance->inbound_buffer, false);
        instance->state = new_state;
    }
}

static void s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_fail(
    struct aws_socks5_proxy_negotiation_strategy_instance_no_auth *instance,
    struct aws_socks5_negotiation_context *context,
    int error_code) {
    if (instance->state != AWS_S5NANS_COMPLETE_FAILURE) {
        AWS_LOGF_WARN(
            AWS_LS_IO_SOCKS5,
            "(%p) No auth negotiation failed with error code %d(%s)",
            (void *)instance,
            error_code,
            aws_error_debug_str(error_code));
        s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_change_state(instance, AWS_S5NANS_COMPLETE_FAILURE);
        instance->final_error_code = error_code;
    }

    context->error_code = instance->final_error_code;
}

static void s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_service_pending_method_selection(
    struct aws_socks5_proxy_negotiation_strategy_instance_no_auth *instance,
    struct aws_socks5_negotiation_context *context) {
    size_t bytes_needed = METHOD_SELECTION_LENGTH - aws_min_size(instance->inbound_buffer.len, METHOD_SELECTION_LENGTH);
    size_t bytes_available = aws_min_size(bytes_needed, (context->data) ? context->data->len : 0);

    if (bytes_available > 0) {
        struct aws_byte_cursor to_append = aws_byte_cursor_advance(context->data, bytes_available);
        if (aws_byte_buf_append_dynamic(&instance->inbound_buffer, &to_append)) {
            s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_fail(instance, context, aws_last_error());
            return;
        }
    }

    if (instance->inbound_buffer.len < METHOD_SELECTION_LENGTH) {
        return;
    }

    AWS_FATAL_ASSERT(instance->inbound_buffer.len == METHOD_SELECTION_LENGTH);

    if (instance->inbound_buffer.buffer[0] != SOCKS_VERSION) {
        s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_fail(
            instance, context, AWS_IO_SOCKS5_PROTOCOL_VERSION_MISMATCH);
        return;
    }

    uint8_t selected_method = instance->inbound_buffer.buffer[1];
    if (selected_method != NO_AUTH_METHOD_ID) {
        s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_fail(
            instance,
            context,
            (selected_method == NO_ACCEPTABLE_METHODS_ID) ? AWS_IO_SOCKS5_NO_ACCEPTABLE_METHODS
                                                          : AWS_IO_SOCKS5_UNEXPECTED_METHOD_ID);
        return;
    }

    s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_change_state(instance, AWS_S5NANS_COMPLETE_SUCCESS);
}

static void s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_drive_negotiation(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_socks5_negotiation_context *context) {
    struct aws_socks5_proxy_negotiation_strategy_instance_no_auth *no_auth_instance = instance->impl;

    context->status = AWS_S5PS_IN_PROGRESS;
    context->error_code = AWS_ERROR_SUCCESS;

    enum aws_socks5_no_auth_negotiation_state last_state = AWS_S5NANS_INVALID;
    while (last_state != no_auth_instance->state) {
        last_state = no_auth_instance->state;
        switch (no_auth_instance->state) {
            case AWS_S5NANS_PENDING_METHOD_SELECTION:
                s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_service_pending_method_selection(
                    no_auth_instance, context);
                break;

            case AWS_S5NANS_COMPLETE_SUCCESS:
                context->status = AWS_S5PS_SUCCESS;
                return;

            default:
                break;
        }
    }

    if (no_auth_instance->state == AWS_S5NANS_COMPLETE_FAILURE) {
        context->status = AWS_S5PS_FAILURE;
    }
}

static int s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_get_auth_methods(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_array_list *methods) {
    (void)instance;

    uint8_t method = NO_AUTH_METHOD_ID;
    return aws_array_list_push_back(methods, &method);
}

static struct aws_socks5_proxy_negotiation_strategy_instance_vtable s_no_auth_strategy_instance_vtable = {
    .destroy = s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_destroy,
    .drive_negotiation = s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_drive_negotiation,
    .get_auth_methods = s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_get_auth_methods,
};

static struct aws_socks5_proxy_negotiation_strategy_instance *
    s_aws_socks5_proxy_negotiation_strategy_no_auth_new_instance(
        struct aws_socks5_proxy_negotiation_strategy *strategy) {
    struct aws_socks5_proxy_negotiation_strategy_instance_no_auth *instance =
        aws_mem_calloc(strategy->allocator, 1, sizeof(struct aws_socks5_proxy_negotiation_strategy_instance_no_auth));
    instance->base.allocator = strategy->allocator;
    instance->base.vtable = &s_no_auth_strategy_instance_vtable;
    instance->base.impl = instance;

    if (aws_byte_buf_init(&instance->inbound_buffer, strategy->allocator, METHOD_SELECTION_LENGTH)) {
        goto error;
    }

    return &instance->base;

error:

    s_aws_socks5_proxy_negotiation_strategy_instance_no_auth_destroy(&instance->base);

    return NULL;
}

static struct aws_socks5_proxy_negotiation_strategy_vtable s_no_auth_strategy_vtable = {
    .new_instance = s_aws_socks5_proxy_negotiation_strategy_no_auth_new_instance};

struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_new_no_auth(
    struct aws_allocator *allocator) {
    struct aws_socks5_proxy_negotiation_strategy_no_auth *strategy =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_proxy_negotiation_strategy_no_auth));

    strategy->base.allocator = allocator;
    strategy->base.vtable = &s_no_auth_strategy_vtable;
    strategy->base.impl = strategy;
    aws_ref_count_init(
        &strategy->base.ref_count, &strategy->base, s_aws_socks5_proxy_negotiation_strategy_no_auth_final_release);

    return &strategy->base;
}
