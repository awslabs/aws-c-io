/*
 * Copyright 2010-2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

#include "statistics_handler_test.h"

#include <aws/common/clock.h>
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

/* mock handler to let us test the chain implementation */

struct aws_statistics_handler_mock_impl {
    uint32_t process_call_count;
    uint32_t get_report_interval_call_count;
};

static void s_mock_process_statistics(
    struct aws_crt_statistics_handler *handler,
    struct aws_crt_statistics_sample_interval *interval,
    struct aws_array_list *stats_list,
    void *context) {

    (void)context;
    (void)stats_list;
    (void)interval;

    struct aws_statistics_handler_mock_impl *impl = handler->impl;

    ++impl->process_call_count;
}

static void s_mock_destroy_handler(struct aws_crt_statistics_handler *handler) {

    /* impl and handler allocated via acquire_many */
    aws_mem_release(handler->allocator, handler);
}

static uint64_t s_mock_get_report_interval_ms(struct aws_crt_statistics_handler *handler) {
    (void)handler;

    struct aws_statistics_handler_mock_impl *impl = handler->impl;
    ++impl->get_report_interval_call_count;

    return 1;
}

static struct aws_crt_statistics_handler_vtable s_mock_statistics_handler_vtable = {
    .process_statistics = s_mock_process_statistics,
    .destroy = s_mock_destroy_handler,
    .get_report_interval_ms = s_mock_get_report_interval_ms};

struct aws_crt_statistics_handler *aws_crt_statistics_handler_new_mock(struct aws_allocator *allocator) {
    struct aws_crt_statistics_handler *handler = NULL;
    struct aws_statistics_handler_mock_impl *impl = NULL;

    if (!aws_mem_acquire_many(
            allocator,
            2,
            &handler,
            sizeof(struct aws_crt_statistics_handler),
            &impl,
            sizeof(struct aws_statistics_handler_mock_impl))) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*handler);
    AWS_ZERO_STRUCT(*impl);

    handler->vtable = &s_mock_statistics_handler_vtable;
    handler->allocator = allocator;
    handler->impl = impl;

    return handler;
}

static int s_test_statistics_handler_chain(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;

    struct aws_crt_statistics_handler *handler1 = aws_crt_statistics_handler_new_mock(allocator);
    struct aws_statistics_handler_mock_impl *impl1 = handler1->impl;

    struct aws_crt_statistics_handler *handler2 = aws_crt_statistics_handler_new_mock(allocator);
    struct aws_statistics_handler_mock_impl *impl2 = handler2->impl;

    struct aws_crt_statistics_handler *handler3 = aws_crt_statistics_handler_new_mock(allocator);
    struct aws_statistics_handler_mock_impl *impl3 = handler3->impl;

    struct aws_crt_statistics_handler *handlers[3] = {handler1, handler2, handler3};

    struct aws_crt_statistics_handler *handler_chain = aws_statistics_handler_new_chain(allocator, handlers, 3);

    aws_crt_statistics_handler_get_report_interval_ms(handler_chain);
    ASSERT_TRUE(impl1->get_report_interval_call_count == 1);
    ASSERT_TRUE(impl2->get_report_interval_call_count == 1);
    ASSERT_TRUE(impl3->get_report_interval_call_count == 1);

    aws_crt_statistics_handler_process_statistics(handler_chain, NULL, NULL, NULL);
    aws_crt_statistics_handler_process_statistics(handler_chain, NULL, NULL, NULL);
    ASSERT_TRUE(impl1->process_call_count == 2);
    ASSERT_TRUE(impl2->process_call_count == 2);
    ASSERT_TRUE(impl3->process_call_count == 2);

    aws_crt_statistics_handler_destroy(handler_chain);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_statistics_handler_chain, s_test_statistics_handler_chain);