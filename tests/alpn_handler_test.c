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

#include <aws/testing/aws_test_harness.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/io/channel.h>

struct alpn_channel_setup_test_args {
    struct aws_condition_variable condition_variable;
    int error_code;
};

static void alpn_channel_setup_test_on_setup_completed(struct aws_channel *channel, int error_code, void *ctx) {
    struct alpn_channel_setup_test_args *setup_test_args = (struct alpn_channel_setup_test_args *)ctx;

    setup_test_args->error_code |= error_code;
    aws_condition_variable_notify_one(&setup_test_args->condition_variable);
}

struct alpn_test_on_negotiation_args {
    struct aws_allocator *allocator;
    struct aws_channel_slot *new_slot;
    struct aws_channel_handler *new_handler;
    struct aws_byte_buf protocol;
};

int alpn_test_shutdown (struct aws_channel_handler *handler, struct aws_channel_slot *slot, int error_code, bool abort_immediately) {
    return aws_channel_slot_shutdown_notify(slot, AWS_CHANNEL_DIR_READ, error_code);
}

int alpn_test_on_shutdown (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                           enum aws_channel_direction dir, int error_code) {
    return aws_channel_slot_shutdown_notify(slot, dir, error_code);
}

size_t alpn_test_get_current_window_size (struct aws_channel_handler *handler) {
    return SIZE_MAX;
}

void alpn_test_destroy(struct aws_channel_handler *handler) {
    aws_mem_release(handler->alloc, (void *)handler);
}

struct aws_channel_handler *alpn_tls_successful_negotiation(struct aws_channel_slot *new_slot, struct aws_byte_buf *protocol,
                                                              void *ctx) {
    struct alpn_test_on_negotiation_args *negotiation_args = (struct alpn_test_on_negotiation_args *)ctx;

    struct aws_channel_handler *handler = (struct aws_channel_handler *)
            aws_mem_acquire(negotiation_args->allocator, sizeof(struct aws_channel_handler));

    negotiation_args->new_handler = handler;
    negotiation_args->protocol = *protocol;
    negotiation_args->new_slot = new_slot;

    handler->vtable.destroy = alpn_test_destroy;
    handler->vtable.on_shutdown_notify = alpn_test_on_shutdown;
    handler->vtable.shutdown = alpn_test_shutdown;
    handler->vtable.get_current_window_size = alpn_test_get_current_window_size;
    handler->alloc = negotiation_args->allocator;

    return handler;
}

static int test_alpn_successfully_negotiates (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));
    struct aws_channel channel;

    struct alpn_channel_setup_test_args test_args = {
            .error_code = 0,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    struct aws_channel_creation_callbacks callbacks = {
            .on_setup_completed = alpn_channel_setup_test_on_setup_completed,
            .setup_user_data = &test_args,
            .on_shutdown_completed = NULL,
            .shutdown_user_data = NULL,
    };

    struct aws_mutex mutex = AWS_MUTEX_INIT;

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_channel_init(&channel, allocator, event_loop, &callbacks));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &mutex));

    struct aws_channel_slot *slot = aws_channel_slot_new(&channel);
    ASSERT_NOT_NULL(slot);

    struct alpn_test_on_negotiation_args on_negotiation_args = {
            .new_slot = NULL,
            .protocol = {0},
            .new_handler = NULL,
            .allocator = allocator
    };

    struct aws_channel_handler *handler = aws_tls_alpn_handler_new(allocator, alpn_tls_successful_negotiation, &on_negotiation_args);
    ASSERT_NOT_NULL(handler);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, handler));

    struct aws_tls_negotiated_protocol_message protocol_message = {
        .protocol = aws_byte_buf_from_literal("h2")
    };

    struct aws_io_message message = {
        .allocator = NULL,
            .user_data = NULL,
            .message_tag = AWS_TLS_NEGOTIATED_PROTOCOL_MESSAGE,
            .message_data = aws_byte_buf_from_array((const uint8_t *)&protocol_message, sizeof(struct aws_tls_negotiated_protocol_message)),
            .copy_mark = 0,
            .on_completion = NULL,
            .message_type =AWS_IO_MESSAGE_APPLICATION_DATA
    };

    ASSERT_SUCCESS(aws_channel_handler_process_read_message(handler, slot, &message));
    ASSERT_INT_EQUALS(on_negotiation_args.new_slot, channel.first);
    ASSERT_INT_EQUALS(on_negotiation_args.new_handler, channel.first->handler);
    ASSERT_NULL(channel.first->adj_right);
    ASSERT_BIN_ARRAYS_EQUALS(protocol_message.protocol.buffer, protocol_message.protocol.len,
                             on_negotiation_args.protocol.buffer, on_negotiation_args.protocol.len);

    aws_channel_clean_up(&channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(alpn_successfully_negotiates, test_alpn_successfully_negotiates)

static int test_alpn_no_protocol_message (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));
    struct aws_channel channel;

    struct alpn_channel_setup_test_args test_args = {
            .error_code = 0,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    struct aws_channel_creation_callbacks callbacks = {
            .on_setup_completed = alpn_channel_setup_test_on_setup_completed,
            .setup_user_data = &test_args,
            .on_shutdown_completed = NULL,
            .shutdown_user_data = NULL,
    };

    struct aws_mutex mutex = AWS_MUTEX_INIT;

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_channel_init(&channel, allocator, event_loop, &callbacks));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &mutex));

    struct aws_channel_slot *slot = aws_channel_slot_new(&channel);
    ASSERT_NOT_NULL(slot);

    struct alpn_test_on_negotiation_args on_negotiation_args = {
            .new_slot = NULL,
            .protocol = {0},
            .new_handler = NULL,
            .allocator = allocator
    };

    struct aws_channel_handler *handler = aws_tls_alpn_handler_new(allocator, alpn_tls_successful_negotiation, &on_negotiation_args);
    ASSERT_NOT_NULL(handler);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, handler));

    /*this is just for the test since it's the only slot in the channel */
    handler->vtable.shutdown = alpn_test_shutdown;

    struct aws_io_message message = {
            .allocator = NULL,
            .user_data = NULL,
            .message_tag = 0,
            .copy_mark = 0,
            .on_completion = NULL,
            .message_type =AWS_IO_MESSAGE_APPLICATION_DATA
    };

    ASSERT_ERROR(AWS_IO_MISSING_ALPN_MESSAGE, aws_channel_handler_process_read_message(handler, slot, &message));

    aws_channel_clean_up(&channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(alpn_no_protocol_message, test_alpn_no_protocol_message)

struct aws_channel_handler *alpn_tls_failed_negotiation(struct aws_channel_slot *new_slot, struct aws_byte_buf *protocol,
                                                            void *ctx) {
    aws_raise_error(AWS_ERROR_OOM);
    return NULL;
}

static int test_alpn_error_creating_handler (struct aws_allocator *allocator, void *ctx) {

    struct aws_event_loop *event_loop = aws_event_loop_default_new(allocator, aws_high_res_clock_get_ticks);

    ASSERT_NOT_NULL(event_loop, "Event loop creation failed with error: %s", aws_error_debug_str(aws_last_error()));
    ASSERT_SUCCESS(aws_event_loop_run(event_loop));
    struct aws_channel channel;

    struct alpn_channel_setup_test_args test_args = {
            .error_code = 0,
            .condition_variable = AWS_CONDITION_VARIABLE_INIT
    };

    struct aws_channel_creation_callbacks callbacks = {
            .on_setup_completed = alpn_channel_setup_test_on_setup_completed,
            .setup_user_data = &test_args,
            .on_shutdown_completed = NULL,
            .shutdown_user_data = NULL,
    };

    struct aws_mutex mutex = AWS_MUTEX_INIT;

    ASSERT_SUCCESS(aws_mutex_lock(&mutex));
    ASSERT_SUCCESS(aws_channel_init(&channel, allocator, event_loop, &callbacks));
    ASSERT_SUCCESS(aws_condition_variable_wait(&test_args.condition_variable, &mutex));

    struct aws_channel_slot *slot = aws_channel_slot_new(&channel);
    ASSERT_NOT_NULL(slot);

    struct aws_tls_negotiated_protocol_message protocol_message = {
            .protocol = aws_byte_buf_from_literal("h2")
    };

    struct aws_io_message message = {
            .allocator = NULL,
            .user_data = NULL,
            .message_tag = AWS_TLS_NEGOTIATED_PROTOCOL_MESSAGE,
            .message_data = aws_byte_buf_from_array((const uint8_t *)&protocol_message, sizeof(struct aws_tls_negotiated_protocol_message)),
            .copy_mark = 0,
            .on_completion = NULL,
            .message_type =AWS_IO_MESSAGE_APPLICATION_DATA
    };

    struct alpn_test_on_negotiation_args on_negotiation_args = {
            .new_slot = NULL,
            .protocol = {0},
            .new_handler = NULL,
            .allocator = allocator
    };

    struct aws_channel_handler *handler = aws_tls_alpn_handler_new(allocator, alpn_tls_failed_negotiation, &on_negotiation_args);
    ASSERT_NOT_NULL(handler);
    ASSERT_SUCCESS(aws_channel_slot_set_handler(slot, handler));

    /*this is just for the test since it's the only slot in the channel */
    handler->vtable.shutdown = alpn_test_shutdown;

    ASSERT_ERROR(AWS_ERROR_OOM, aws_channel_handler_process_read_message(handler, slot, &message));

    aws_channel_clean_up(&channel);
    aws_event_loop_destroy(event_loop);

    return AWS_OP_SUCCESS;
}

AWS_TEST_CASE(alpn_error_creating_handler, test_alpn_error_creating_handler)