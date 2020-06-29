/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "statistics_handler_test.h"

#include <aws/common/clock.h>
#include <aws/common/thread.h>
#include <aws/io/channel.h>
#include <aws/io/event_loop.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/testing/aws_test_harness.h>

static void s_process_statistics(
    struct aws_crt_statistics_handler *handler,
    struct aws_crt_statistics_sample_interval *interval,
    struct aws_array_list *stats_list,
    void *context) {

    (void)context;

    struct aws_statistics_handler_test_impl *impl = handler->impl;

    aws_mutex_lock(&impl->lock);

    if (impl->start_time_ns == 0) {
        impl->start_time_ns =
            aws_timestamp_convert(interval->begin_time_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    }

    size_t stats_count = aws_array_list_length(stats_list);
    for (size_t i = 0; i < stats_count; ++i) {
        struct aws_crt_statistics_base *stats_base = NULL;
        if (aws_array_list_get_at(stats_list, &stats_base, i)) {
            continue;
        }

        switch (stats_base->category) {
            case AWSCRT_STAT_CAT_SOCKET: {
                struct aws_crt_statistics_socket *socket_stats = (struct aws_crt_statistics_socket *)stats_base;
                impl->total_bytes_read += socket_stats->bytes_read;
                impl->total_bytes_written += socket_stats->bytes_written;
                break;
            }

            case AWSCRT_STAT_CAT_TLS: {
                struct aws_crt_statistics_tls *tls_stats = (struct aws_crt_statistics_tls *)stats_base;
                impl->tls_status = tls_stats->handshake_status;
                break;
            }

            default:
                break;
        }
    }

    aws_mutex_unlock(&impl->lock);
    aws_condition_variable_notify_one(&impl->signal);
}

static void s_destroy_handler(struct aws_crt_statistics_handler *handler) {
    struct aws_statistics_handler_test_impl *impl = handler->impl;

    aws_mutex_clean_up(&impl->lock);
    aws_condition_variable_clean_up(&impl->signal);

    /* impl and handler allocated via acquire_many */
    aws_mem_release(handler->allocator, handler);
}

static uint64_t s_get_report_interval_ms(struct aws_crt_statistics_handler *handler) {
    (void)handler;

    /*
     * Making this a very small number means the stat task will be in the very near future and thus a very
     * short wait.
     */
    return 1;
}

static struct aws_crt_statistics_handler_vtable s_test_statistics_handler_vtable = {
    .process_statistics = s_process_statistics,
    .destroy = s_destroy_handler,
    .get_report_interval_ms = s_get_report_interval_ms};

struct aws_crt_statistics_handler *aws_statistics_handler_new_test(struct aws_allocator *allocator) {
    struct aws_crt_statistics_handler *handler = NULL;
    struct aws_statistics_handler_test_impl *impl = NULL;

    if (!aws_mem_acquire_many(
            allocator,
            2,
            &handler,
            sizeof(struct aws_crt_statistics_handler),
            &impl,
            sizeof(struct aws_statistics_handler_test_impl))) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*handler);
    AWS_ZERO_STRUCT(*impl);

    aws_mutex_init(&impl->lock);
    aws_condition_variable_init(&impl->signal);

    handler->vtable = &s_test_statistics_handler_vtable;
    handler->allocator = allocator;
    handler->impl = impl;

    return handler;
}
