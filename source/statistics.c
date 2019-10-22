/*
 * Copyright 2010-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include <aws/io/statistics.h>

int aws_crt_statistics_socket_init(struct aws_crt_statistics_socket *stats) {
    AWS_ZERO_STRUCT(*stats);
    stats->category = AWSCRT_STAT_CAT_SOCKET;

    return AWS_OP_SUCCESS;
}

void aws_crt_statistics_socket_cleanup(struct aws_crt_statistics_socket *stats) {
    (void)stats;
}

void aws_crt_statistics_socket_reset(struct aws_crt_statistics_socket *stats) {
    stats->bytes_read = 0;
    stats->bytes_written = 0;
}

int aws_crt_statistics_tls_init(struct aws_crt_statistics_tls *stats) {
    AWS_ZERO_STRUCT(*stats);
    stats->category = AWSCRT_STAT_CAT_TLS;
    stats->handshake_status = AWS_MTLS_STATUS_NONE;

    return AWS_OP_SUCCESS;
}

void aws_crt_statistics_tls_cleanup(struct aws_crt_statistics_tls *stats) {
    (void)stats;
}

void aws_crt_statistics_tls_reset(struct aws_crt_statistics_tls *stats) {
    (void)stats;
}

struct aws_crt_statistics_handler_chain_impl {
    struct aws_array_list handlers;
    uint64_t report_interval_ms;
};

static void s_chain_process_statistics(
    struct aws_crt_statistics_handler *handler,
    struct aws_crt_statistics_sample_interval *interval,
    struct aws_array_list *stats_list,
    void *context) {

    struct aws_crt_statistics_handler_chain_impl *impl = handler->impl;

    uint64_t handler_count = aws_array_list_length(&impl->handlers);
    for (size_t i = 0; i < handler_count; ++i) {
        struct aws_crt_statistics_handler *handler = NULL;
        if (aws_array_list_get_at(&impl->handlers, &handler, i)) {
            continue;
        }

        aws_crt_statistics_handler_process_statistics(handler, interval, stats_list, context);
    }
}

static void s_chain_destroy(struct aws_crt_statistics_handler *handler) {
    if (handler == NULL) {
        return;
    }

    struct aws_crt_statistics_handler_chain_impl *impl = handler->impl;
    if (impl != NULL) {

        uint64_t handler_count = aws_array_list_length(&impl->handlers);
        for (size_t i = 0; i < handler_count; ++i) {
            struct aws_crt_statistics_handler *sub_handler = NULL;
            if (aws_array_list_get_at(&impl->handlers, &sub_handler, i)) {
                continue;
            }

            aws_crt_statistics_handler_destroy(sub_handler);
        }

        aws_array_list_clean_up(&impl->handlers);
    }

    aws_mem_release(handler->allocator, handler);
}

static uint64_t s_chain_get_report_interval_ms(struct aws_crt_statistics_handler *handler) {
    struct aws_crt_statistics_handler_chain_impl *impl = handler->impl;
    return impl->report_interval_ms;
}

static struct aws_crt_statistics_handler_vtable s_statistics_handler_chain_vtable = {
    .process_statistics = s_chain_process_statistics,
    .destroy = s_chain_destroy,
    .get_report_interval_ms = s_chain_get_report_interval_ms,
};

struct aws_crt_statistics_handler *aws_statistics_handler_new_chain(
    struct aws_allocator *allocator,
    struct aws_crt_statistics_handler **handlers,
    size_t handler_count) {
    struct aws_crt_statistics_handler *handler = NULL;
    struct aws_crt_statistics_handler_chain_impl *impl = NULL;

    if (!aws_mem_acquire_many(
            allocator,
            2,
            &handler,
            sizeof(struct aws_crt_statistics_handler),
            &impl,
            sizeof(struct aws_crt_statistics_handler_chain_impl))) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*handler);
    AWS_ZERO_STRUCT(*impl);
    if (aws_array_list_init_dynamic(
            &impl->handlers, allocator, handler_count, sizeof(struct aws_crt_statistics_handler *))) {
        goto on_error;
    }

    uint64_t min_report_interval_ms = UINT64_MAX;
    for (size_t i = 0; i < handler_count; ++i) {
        aws_array_list_push_back(&impl->handlers, &handlers[i]);

        uint64_t report_interval_ms = aws_crt_statistics_handler_get_report_interval_ms(handlers[i]);
        if (report_interval_ms < min_report_interval_ms) {
            min_report_interval_ms = report_interval_ms;
        }
    }

    impl->report_interval_ms = min_report_interval_ms;

    handler->vtable = &s_statistics_handler_chain_vtable;
    handler->allocator = allocator;
    handler->impl = impl;

    return handler;

on_error:

    s_chain_destroy(handler);

    return NULL;
}
