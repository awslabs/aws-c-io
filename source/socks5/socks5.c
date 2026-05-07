/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/socks5.h>

#include <aws/common/allocator.h>
#include <aws/common/byte_buf.h>
#include <aws/common/ref_count.h>
#include <aws/io/private/socks5_impl.h>

struct aws_socks5_proxy_config *aws_socks5_proxy_config_new(
    struct aws_allocator *allocator,
    struct aws_socks5_proxy_options *options) {
    struct aws_socks5_proxy_config *config = aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_proxy_config));

    if (aws_byte_buf_init_copy_from_cursor(&config->proxy_host, allocator, options->proxy_host)) {
        goto on_error;
    }

    config->allocator = allocator;
    config->proxy_port = options->proxy_port;

    /* ensure we always have a strategy */
    if (options->negotiation_strategy) {
        config->negotiation_strategy = aws_socks5_proxy_negotiation_strategy_acquire(options->negotiation_strategy);
    } else {
        config->negotiation_strategy = aws_socks5_proxy_negotiation_strategy_new_no_auth(allocator);
    }

    config->negotiation_timeout_ms = options->negotiation_timeout_ms;
    config->skip_name_resolution = options->skip_name_resolution;

    return config;

on_error:

    aws_socks5_proxy_config_destroy(config);

    return NULL;
}

void aws_socks5_proxy_config_destroy(struct aws_socks5_proxy_config *config) {
    if (!config) {
        return;
    }

    aws_byte_buf_clean_up(&config->proxy_host);
    aws_socks5_proxy_negotiation_strategy_release(config->negotiation_strategy);

    aws_mem_release(config->allocator, config);
}

// general negotiation strategy

struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_acquire(
    struct aws_socks5_proxy_negotiation_strategy *strategy) {
    if (strategy != NULL) {
        aws_ref_count_acquire(&strategy->ref_count);
    }

    return strategy;
}

struct aws_socks5_proxy_negotiation_strategy *aws_socks5_proxy_negotiation_strategy_release(
    struct aws_socks5_proxy_negotiation_strategy *strategy) {
    if (strategy != NULL) {
        aws_ref_count_release(&strategy->ref_count);
    }

    return NULL;
}

struct aws_socks5_proxy_negotiation_strategy_instance *aws_socks5_proxy_negotiation_strategy_new_instance(
    struct aws_socks5_proxy_negotiation_strategy *strategy) {
    return strategy->vtable->new_instance(strategy);
}

void aws_socks5_proxy_negotiation_strategy_instance_destroy(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance) {
    if (instance != NULL) {
        instance->vtable->destroy(instance);
    }
}

void aws_socks5_proxy_negotiation_strategy_instance_drive_negotiation(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_socks5_negotiation_context *context) {
    instance->vtable->drive_negotiation(instance, context);
}

int aws_socks5_proxy_negotiation_strategy_instance_get_auth_methods(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_array_list *methods) {
    return instance->vtable->get_auth_methods(instance, methods);
}

/////

enum aws_socks5_proxy_impl_state {
    AWS_S5PIS_INVALID = -1,
    AWS_S5PIS_START = 0,
    AWS_S5PIS_PENDING_METHOD_REQUEST,
    AWS_S5PIS_PENDING_AUTH_SUBNEGOTIATION,
    AWS_S5PIS_PENDING_REQUEST,
    AWS_S5PIS_PENDING_RESPONSE,
    AWS_S5PIS_SUCCESS,
    AWS_S5PIS_FAILURE,
};

struct aws_socks5_proxy_impl {
    struct aws_allocator *allocator;

    struct aws_socks5_proxy_negotiation_strategy_instance *auth_instance;

    enum aws_socks5_proxy_impl_state state;

    struct aws_byte_buf write_buffer;
    struct aws_byte_cursor pending_write_data;

    struct aws_byte_buf read_buffer;

    struct aws_byte_buf connect_host;
    uint32_t connect_port;

    int final_error_code;
};

void aws_socks5_proxy_impl_destroy(struct aws_socks5_proxy_impl *impl) {
    if (impl == NULL) {
        return;
    }

    aws_socks5_proxy_negotiation_strategy_instance_destroy(impl->auth_instance);

    aws_byte_buf_clean_up(&impl->write_buffer);
    aws_byte_buf_clean_up(&impl->read_buffer);
    aws_byte_buf_clean_up(&impl->connect_host);

    aws_mem_release(impl->allocator, impl);
}

static const size_t DEFAULT_SOCKS5_PROTOCOL_BUFFER_SIZE = 512;

struct aws_socks5_proxy_impl *aws_socks5_proxy_impl_new(
    struct aws_allocator *allocator,
    struct aws_socks5_proxy_config *config) {

    struct aws_socks5_proxy_impl *impl = aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_proxy_impl));
    impl->allocator = allocator;
    impl->auth_instance = aws_socks5_proxy_negotiation_strategy_new_instance(config->negotiation_strategy);
    impl->state = AWS_S5PIS_INVALID;
    if (aws_byte_buf_init(&impl->write_buffer, allocator, DEFAULT_SOCKS5_PROTOCOL_BUFFER_SIZE) ||
        aws_byte_buf_init(&impl->read_buffer, allocator, DEFAULT_SOCKS5_PROTOCOL_BUFFER_SIZE)) {
        goto failure;
    }

    if (aws_byte_buf_init_copy_from_cursor(
            &impl->connect_host, allocator, aws_byte_cursor_from_buf(&config->proxy_host))) {
        goto failure;
    }

    impl->connect_host = config->proxy_host;

    return impl;

failure:

    aws_socks5_proxy_impl_destroy(impl);

    return NULL;
}

static void s_handle_socks5_impl_state_start(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context) {}

static void s_handle_socks5_impl_state_pending_method_request(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context) {}

static void s_handle_socks5_impl_state_pending_auth_subnegotiation(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context) {}

static void s_handle_socks5_impl_state_pending_request(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context) {}

static void s_handle_socks5_impl_state_pending_response(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context) {}

void aws_socks5_proxy_impl_drive_negotiation(
    struct aws_socks5_proxy_impl *impl,
    struct aws_socks5_negotiation_context *context) {
    context->status = AWS_S5PS_IN_PROGRESS;

    enum aws_socks5_proxy_impl_state last_state = AWS_S5PIS_INVALID;
    while (last_state != impl->state) {
        last_state = impl->state;
        switch (impl->state) {
            case AWS_S5PIS_START:
                s_handle_socks5_impl_state_start(impl, context);
                break;

            case AWS_S5PIS_PENDING_METHOD_REQUEST:
                s_handle_socks5_impl_state_pending_method_request(impl, context);
                break;

            case AWS_S5PIS_PENDING_AUTH_SUBNEGOTIATION:
                s_handle_socks5_impl_state_pending_auth_subnegotiation(impl, context);
                break;

            case AWS_S5PIS_PENDING_REQUEST:
                s_handle_socks5_impl_state_pending_request(impl, context);
                break;

            case AWS_S5PIS_PENDING_RESPONSE:
                s_handle_socks5_impl_state_pending_response(impl, context);
                break;

            case AWS_S5PIS_SUCCESS:
                context->status = AWS_S5PS_SUCCESS;
                break;

            default:
                context->status = AWS_S5PS_FAILURE;
                context->error_code = impl->final_error_code;
                break;
        }
    }
}