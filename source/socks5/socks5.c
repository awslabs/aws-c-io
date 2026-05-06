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
