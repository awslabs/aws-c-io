/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/channel.h>
#include <aws/io/event_loop.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/testing/aws_test_harness.h>

#include <aws/common/clock.h>
#include <aws/common/condition_variable.h>

struct alpn_channel_setup_test_args {
    struct aws_condition_variable condition_variable;
    struct aws_mutex mutex;
    int error_code;
    bool shutdown_finished;
    bool setup_completed;
};

static void s_alpn_channel_setup_test_on_setup_completed(struct aws_channel *channel, int error_code, void *ctx) {
    (void)channel;

    struct alpn_channel_setup_test_args *setup_test_args = (struct alpn_channel_setup_test_args *)ctx;
    aws_mutex_lock(&setup_test_args->mutex);
    setup_test_args->setup_completed = true;
    setup_test_args->error_code |= error_code;
    aws_mutex_unlock(&setup_test_args->mutex);
    aws_condition_variable_notify_one(&setup_test_args->condition_variable);
}

static bool s_alpn_test_setup_completed_predicate(void *arg) {
    struct alpn_channel_setup_test_args *setup_test_args = (struct alpn_channel_setup_test_args *)arg;
    return setup_test_args->setup_completed;
}

struct alpn_test_on_negotiation_args {
    struct aws_allocator *allocator;
    struct aws_channel_slot *new_slot;
    struct aws_channel_handler *new_handler;
    struct aws_byte_buf protocol;
};

static int s_alpn_test_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool abort_immediately) {
    (void)handler;

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, abort_immediately);
}

static size_t s_alpn_test_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;

    return 0;
}

static size_t s_alpn_test_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;

    return SIZE_MAX;
}

static void s_alpn_test_destroy(struct aws_channel_handler *handler) {
    aws_mem_release(handler->alloc, (void *)handler);
}

struct aws_channel_handler_vtable s_alpn_test_vtable = {
    .destroy = s_alpn_test_destroy,
    .shutdown = s_alpn_test_shutdown,
    .initial_window_size = s_alpn_test_initial_window_size,
    .message_overhead = s_alpn_test_message_overhead,
};

static struct aws_channel_handler *s_alpn_tls_successful_negotiation(
    struct aws_channel_slot *new_slot,
    struct aws_byte_buf *protocol,
    void *ctx) {
    struct alpn_test_on_negotiation_args *negotiation_args = (struct alpn_test_on_negotiation_args *)ctx;

    struct aws_channel_handler *handler =
        aws_mem_calloc(negotiation_args->allocator, 1, sizeof(struct aws_channel_handler));

    negotiation_args->new_handler = handler;
    negotiation_args->protocol = *protocol;
    negotiation_args->new_slot = new_slot;

    handler->vtable = &s_alpn_test_vtable;
    handler->alloc = negotiation_args->allocator;

    return handler;
}

static bool s_alpn_test_shutdown_predicate(void *arg) {
    struct alpn_channel_setup_test_args *test_args = (struct alpn_channel_setup_test_args *)arg;
    return test_args->shutdown_finished;
}

static void s_on_server_channel_on_shutdown(struct aws_channel *channel, int error_code, void *user_data) {

    (void)channel;
    (void)error_code;

    struct alpn_channel_setup_test_args *test_args = (struct alpn_channel_setup_test_args *)user_data;

    aws_mutex_lock(&test_args->mutex);
    test_args->shutdown_finished = true;
    aws_mutex_unlock(&test_args->mutex);

    aws_condition_variable_notify_one(&test_args->condition_variable);
}

static int s_test_alpn_successfully_negotiates(struct aws_allocator *allocator, void *ctx) {

    (void)ctx;

    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));
    struct aws_channel *channel;

    struct alpn_channel_setup_test_args test_args = {.error_code = 0,
                                                     .condition_variable = AWS_CONDITION_VARIABLE_INIT,
                                                     .mutex = AWS_MUTEX_INIT,
                                                     .setup_completed = false,
                                                     .shutdown_finished = false};

    struct aws_channel_options args = {
        .on_setup_completed = s_alpn_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = s_on_server_channel_on_shutdown,
        .shutdown_user_data = &test_args,
        .event_loop = event_loop,
    };

    channel = aws_channel_new(allocator, &args);
    ASSERT_NOT_NULL(channel);
    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &test_args.condition_variable, &test_args.mutex, s_alpn_test_setup_completed_predicate, &test_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&test_args.mutex));

    struct aws_channel_slot *slot = aws_channel_slot_new(channel);
    ASSERT_NOT_NULL(slot);

    struct alpn_test_on_negotiation_args on_negotiation_args = {
        .new_slot = NULL, .protocol = {0}, .new_handler = NULL, .allocator = allocator};

    struct aws_channel_handler *handler =
        aws_tls_alpn_handler_new(allocator, s_alpn_tls_successful_negotiation, &on_negotiation_args);
    ASSERT_NOT_NULL(handler);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, handler));

    struct aws_tls_negotiated_protocol_message protocol_message = {.protocol = aws_byte_buf_from_c_str("h2")};

    struct aws_io_message message = {
        .allocator = NULL,
        .user_data = NULL,
        .message_tag = AWS_TLS_NEGOTIATED_PROTOCOL_MESSAGE,
        .message_data = aws_byte_buf_from_array(
            (const uint8_t *)&protocol_message, sizeof(struct aws_tls_negotiated_protocol_message)),
        .copy_mark = 0,
        .on_completion = NULL,
        .message_type = AWS_IO_MESSAGE_APPLICATION_DATA};

    ASSERT_SUCCESS(aws_channel_handler_process_read_message(handler, slot, &message));
    ASSERT_BIN_ARRAYS_EQUALS(
        protocol_message.protocol.buffer,
        protocol_message.protocol.len,
        on_negotiation_args.protocol.buffer,
        on_negotiation_args.protocol.len);

    aws_channel_shutdown(channel, AWS_OP_SUCCESS);
    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &test_args.condition_variable, &test_args.mutex, s_alpn_test_shutdown_predicate, &test_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&test_args.mutex));

    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(alpn_successfully_negotiates, s_test_alpn_successfully_negotiates)

static int s_test_alpn_no_protocol_message(struct aws_allocator *allocator, void *ctx) {

    (void)ctx;

    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));
    struct aws_channel *channel;

    struct alpn_channel_setup_test_args test_args = {.error_code = 0,
                                                     .condition_variable = AWS_CONDITION_VARIABLE_INIT,
                                                     .mutex = AWS_MUTEX_INIT,
                                                     .shutdown_finished = false};

    struct aws_channel_options args = {
        .on_setup_completed = s_alpn_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = s_on_server_channel_on_shutdown,
        .shutdown_user_data = &test_args,
        .event_loop = event_loop,
    };

    channel = aws_channel_new(allocator, &args);
    ASSERT_NOT_NULL(channel);
    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &test_args.condition_variable, &test_args.mutex, s_alpn_test_setup_completed_predicate, &test_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&test_args.mutex));

    struct aws_channel_slot *slot = aws_channel_slot_new(channel);
    ASSERT_NOT_NULL(slot);

    struct alpn_test_on_negotiation_args on_negotiation_args = {
        .new_slot = NULL, .protocol = {0}, .new_handler = NULL, .allocator = allocator};

    struct aws_channel_handler *handler =
        aws_tls_alpn_handler_new(allocator, s_alpn_tls_successful_negotiation, &on_negotiation_args);
    ASSERT_NOT_NULL(handler);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, handler));

    /*this is just for the test since it's the only slot in the channel */
    handler->vtable->shutdown = s_alpn_test_shutdown;

    struct aws_io_message message = {
        .allocator = NULL,
        .user_data = NULL,
        .message_tag = 0,
        .copy_mark = 0,
        .on_completion = NULL,
        .message_type = AWS_IO_MESSAGE_APPLICATION_DATA,
    };

    ASSERT_ERROR(AWS_IO_MISSING_ALPN_MESSAGE, aws_channel_handler_process_read_message(handler, slot, &message));

    aws_channel_shutdown(channel, AWS_OP_SUCCESS);
    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &test_args.condition_variable, &test_args.mutex, s_alpn_test_shutdown_predicate, &test_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&test_args.mutex));
    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(alpn_no_protocol_message, s_test_alpn_no_protocol_message)

static struct aws_channel_handler *s_alpn_tls_failed_negotiation(
    struct aws_channel_slot *new_slot,
    struct aws_byte_buf *protocol,
    void *ctx) {

    (void)new_slot;
    (void)protocol;
    (void)ctx;

    return NULL;
}

static int s_test_alpn_error_creating_handler(struct aws_allocator *allocator, void *ctx) {

    (void)ctx;

    struct aws_event_loop *event_loop = aws_event_loop_new_default(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));
    struct aws_channel *channel;

    struct alpn_channel_setup_test_args test_args = {.error_code = 0,
                                                     .condition_variable = AWS_CONDITION_VARIABLE_INIT,
                                                     .mutex = AWS_MUTEX_INIT,
                                                     .shutdown_finished = false};

    struct aws_channel_options args = {
        .on_setup_completed = s_alpn_channel_setup_test_on_setup_completed,
        .setup_user_data = &test_args,
        .on_shutdown_completed = s_on_server_channel_on_shutdown,
        .shutdown_user_data = &test_args,
        .event_loop = event_loop,
    };

    channel = aws_channel_new(allocator, &args);
    ASSERT_NOT_NULL(channel);
    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &test_args.condition_variable, &test_args.mutex, s_alpn_test_setup_completed_predicate, &test_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&test_args.mutex));

    struct aws_channel_slot *slot = aws_channel_slot_new(channel);
    ASSERT_NOT_NULL(slot);

    struct aws_tls_negotiated_protocol_message protocol_message = {.protocol = aws_byte_buf_from_c_str("h2")};

    struct aws_io_message message = {
        .allocator = NULL,
        .user_data = NULL,
        .message_tag = AWS_TLS_NEGOTIATED_PROTOCOL_MESSAGE,
        .message_data = aws_byte_buf_from_array(
            (const uint8_t *)&protocol_message, sizeof(struct aws_tls_negotiated_protocol_message)),
        .copy_mark = 0,
        .on_completion = NULL,
        .message_type = AWS_IO_MESSAGE_APPLICATION_DATA};

    struct alpn_test_on_negotiation_args on_negotiation_args = {
        .new_slot = NULL, .protocol = {0}, .new_handler = NULL, .allocator = allocator};

    struct aws_channel_handler *handler =
        aws_tls_alpn_handler_new(allocator, s_alpn_tls_failed_negotiation, &on_negotiation_args);
    ASSERT_NOT_NULL(handler);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, handler));

    /*this is just for the test since it's the only slot in the channel */
    handler->vtable->shutdown = s_alpn_test_shutdown;

    ASSERT_ERROR(
        AWS_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE, aws_channel_handler_process_read_message(handler, slot, &message));

    aws_channel_shutdown(channel, AWS_OP_SUCCESS);
    ASSERT_SUCCESS(aws_mutex_lock(&test_args.mutex));
    ASSERT_SUCCESS(aws_condition_variable_wait_pred(
        &test_args.condition_variable, &test_args.mutex, s_alpn_test_shutdown_predicate, &test_args));
    ASSERT_SUCCESS(aws_mutex_unlock(&test_args.mutex));
    aws_channel_destroy(channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(alpn_error_creating_handler, s_test_alpn_error_creating_handler)
