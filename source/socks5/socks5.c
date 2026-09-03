/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/common/allocator.h>
#include <aws/common/byte_buf.h>
#include <aws/common/ref_count.h>
#include <aws/io/logging.h>
#include <aws/io/private/l4_proxy_impl.h>
#include <aws/io/private/socks5_impl.h>
#include <aws/io/socks5.h>

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
    struct aws_l4_proxy_negotiation_context *context) {
    instance->vtable->drive_negotiation(instance, context);
}

int aws_socks5_proxy_negotiation_strategy_instance_get_auth_methods(
    struct aws_socks5_proxy_negotiation_strategy_instance *instance,
    struct aws_array_list *methods) {
    return instance->vtable->get_auth_methods(instance, methods);
}
