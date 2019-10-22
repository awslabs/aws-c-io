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
#include <aws/common/thread.h>
#include <aws/io/channel.h>
#include <aws/io/event_loop.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/testing/aws_test_harness.h>

#include "tls_handler_test.h"

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

/*
 * Tls monitor test - verify exceeding the timeout shuts down the channel
 *
 * Create a real channel and a real tls handler adjacent to a dummy handler that pretends to be a socket but does
 * nothing.  Then wait for the timeout and verify the channel was shutdown with the correct error code.
 */

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

static struct aws_channel_handler_vtable s_dummy_handler_vtable = {.process_read_message = s_dummy_process_message,
                                                                   .process_write_message = s_dummy_process_message,
                                                                   .increment_read_window =
                                                                       s_dummy_increment_read_window,
                                                                   .shutdown = s_dummy_shutdown,
                                                                   .initial_window_size = s_dummy_initial_window_size,
                                                                   .message_overhead = s_dummy_message_overhead,
                                                                   .destroy = s_dummy_destroy};

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

    context->shutdown_completed = true;
    context->error_code = error_code;

    aws_condition_variable_notify_one(&context->signal);
}

static const int s_tls_timeout_ms = 1000;

static void s_on_setup_completed(struct aws_channel *channel, int error_code, void *user_data) {
    (void)channel;
    struct channel_stat_test_context *context = (struct channel_stat_test_context *)user_data;

    /* attach a tls timeout monitor */
    struct aws_tls_monitor_options options = {.tls_timeout_ms = s_tls_timeout_ms};

    struct aws_crt_statistics_handler *tls_monitor =
        aws_crt_statistics_handler_new_tls_monitor(context->allocator, &options);
    aws_channel_set_statistics_handler(channel, tls_monitor);

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

static int s_test_tls_monitor_timeout(struct aws_allocator *allocator, void *ctx) {
    (void)ctx;
    aws_io_library_init(allocator);

    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_SUCCESS(aws_event_loop_run(event_loop));

    struct tls_opt_tester tls_test_context;
    tls_client_opt_tester_init(allocator, &tls_test_context, aws_byte_cursor_from_c_str("derp.com"));

    struct channel_stat_test_context channel_context;
    s_channel_setup_stat_test_context_init(&channel_context, allocator, &tls_test_context);

    struct aws_channel_creation_callbacks callbacks = {
        .on_setup_completed = s_on_setup_completed,
        .setup_user_data = &channel_context,
        .on_shutdown_completed = s_on_shutdown_completed,
        .shutdown_user_data = &channel_context,
    };

    /* set up the channel */
    ASSERT_SUCCESS(aws_mutex_lock(&channel_context.lock));
    struct aws_channel *channel = aws_channel_new(allocator, event_loop, &callbacks);
    ASSERT_NOT_NULL(channel);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &channel_context.signal, &channel_context.lock, s_setup_completed_predicate, &channel_context));
    aws_mutex_unlock(&channel_context.lock);

    /* wait for the timeout */
    aws_thread_current_sleep(aws_timestamp_convert(s_tls_timeout_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL));

    aws_mutex_lock(&channel_context.lock);
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &channel_context.signal, &channel_context.lock, s_shutdown_completed_predicate, &channel_context));

    ASSERT_TRUE(channel_context.error_code == AWS_IO_CHANNEL_TLS_TIMEOUT);

    aws_mutex_unlock(&channel_context.lock);

    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    tls_opt_tester_clean_up(&tls_test_context);

    s_channel_setup_stat_test_context_clean_up(&channel_context);

    aws_io_library_clean_up();

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(test_tls_monitor_timeout, s_test_tls_monitor_timeout)
