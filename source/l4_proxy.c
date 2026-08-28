/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/l4_proxy.h>

#include "aws/common/clock.h"
#include "aws/io/event_loop.h"
#include <aws/io/logging.h>
#include <aws/io/private/l4_proxy_impl.h>

void aws_l4_proxy_config_clean_up(struct aws_l4_proxy_config *config) {
    aws_byte_buf_clean_up(&config->proxy_host);
}

struct aws_l4_proxy_config *aws_l4_proxy_config_release(struct aws_l4_proxy_config *config) {
    if (config) {
        aws_ref_count_release(&config->ref_count);
    }

    return NULL;
}

struct aws_l4_proxy_config *aws_l4_proxy_config_acquire(struct aws_l4_proxy_config *config) {
    if (config) {
        aws_ref_count_acquire(&config->ref_count);
    }

    return config;
}

struct aws_l4_proxy_channel_handler *aws_l4_proxy_config_new_channel_handler(
    struct aws_l4_proxy_config *config,
    struct aws_l4_proxy_channel_handler_options *options) {
    return config->vtable->new_channel_handler(config, options);
}

void aws_l4_proxy_config_get_proxy_address(
    struct aws_l4_proxy_config *config,
    struct aws_connection_remote *new_remote) {
    AWS_ZERO_STRUCT(*new_remote);

    new_remote->host = aws_byte_cursor_from_buf(&config->proxy_host);
    new_remote->port = config->proxy_port;
}

////////////////////////////////////////////////

static const size_t AWS_L4_PROXY_IO_MESSAGE_DEFAULT_LENGTH = 1024;
static const size_t DEFAULT_L4_PROXY_WINDOW_SIZE = 1024;

static void s_aws_l4_proxy_cancel_timeout_task(struct aws_l4_proxy_channel_handler *handler) {
    if (handler->timeout_task) {
        struct aws_channel *channel = handler->channel_handler.slot->channel;
        struct aws_event_loop *loop = aws_channel_get_event_loop(channel);

        aws_event_loop_cancel_task(loop, handler->timeout_task);
        aws_mem_release(handler->allocator, handler->timeout_task);
        handler->timeout_task = NULL;
    }
}

static void s_aws_l4_proxy_on_socket_write_completion(
    struct aws_channel *channel,
    struct aws_io_message *message,
    int err_code,
    void *user_data) {

    (void)channel;
    (void)message;

    struct aws_l4_proxy_channel_handler *handler = user_data;
    if (err_code != AWS_ERROR_SUCCESS) {
        handler->status = AWS_L4PPS_FAILURE;
        aws_channel_shutdown(channel, err_code);
    }
}

static int s_drive_negotiation_l4_proxy(
    struct aws_l4_proxy_channel_handler *handler,
    struct aws_l4_proxy_negotiation_context *context) {
    struct aws_channel_slot *slot = handler->channel_handler.slot;
    struct aws_channel *channel = slot->channel;

    AWS_FATAL_ASSERT(aws_channel_thread_is_callers_thread(channel));

    if (handler->status != AWS_L4PPS_IN_PROGRESS) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    return (handler->vtable->drive_negotiation)(handler, context);
}

static void s_service_l4_proxy_negotiation(
    struct aws_l4_proxy_channel_handler *handler,
    struct aws_io_message *message) {

    struct aws_channel *channel = handler->channel_handler.slot->channel;

    // we may or may not use this; if we don't use, we release before exiting
    struct aws_io_message *output_message = aws_channel_acquire_message_from_pool(
        channel, AWS_IO_MESSAGE_APPLICATION_DATA, AWS_L4_PROXY_IO_MESSAGE_DEFAULT_LENGTH);
    output_message->user_data = handler;
    output_message->on_completion = s_aws_l4_proxy_on_socket_write_completion;

    struct aws_l4_proxy_negotiation_context context;
    AWS_ZERO_STRUCT(context);

    struct aws_byte_cursor fragment_cursor;
    AWS_ZERO_STRUCT(fragment_cursor);

    // we may or may not have input data
    if (message != NULL) {
        fragment_cursor = aws_byte_cursor_from_buf(&message->message_data);
        aws_byte_cursor_advance(&fragment_cursor, message->copy_mark);
        if (fragment_cursor.len > 0) {
            context.data = &fragment_cursor;
        }
    }

    context.status = handler->status;
    context.to_write = &output_message->message_data;

    // the handler tells us how many bytes they used, use that for window updates
    size_t pre_consumed_bytes = fragment_cursor.len;
    int negotiation_result = s_drive_negotiation_l4_proxy(handler, &context);
    size_t consumed_bytes = pre_consumed_bytes - fragment_cursor.len;
    aws_channel_slot_increment_read_window(handler->channel_handler.slot, consumed_bytes);

    if (message) {
        aws_mem_release(message->allocator, message);
    }

    if (negotiation_result == AWS_OP_SUCCESS) {
        handler->status = context.status;

        // is there anything to write?
        if (output_message->message_data.len > 0) {
            if (aws_channel_slot_send_message(handler->channel_handler.slot, output_message, AWS_CHANNEL_DIR_WRITE)) {
                negotiation_result = AWS_OP_ERR;
            } else {
                // successful send means we shouldn't release
                output_message = NULL;
            }
        }
    }

    bool invoke_completion_callback = false;
    int callback_error_code = AWS_ERROR_SUCCESS;

    if (negotiation_result == AWS_OP_ERR || context.status == AWS_L4PPS_FAILURE) {
        handler->status = AWS_L4PPS_FAILURE;

        callback_error_code = aws_error_or_last_error_or_unknown_error(context.error_code);
        invoke_completion_callback = true;
    }

    if (handler->status == AWS_L4PPS_SUCCESS) {
        invoke_completion_callback = true;
    }

    if (invoke_completion_callback) {
        if (handler->negotiation_complete_callback) {
            (*handler->negotiation_complete_callback)(
                channel, callback_error_code, handler->negotiation_complete_user_data);
        }

        s_aws_l4_proxy_cancel_timeout_task(handler);
    }

    if (output_message != NULL) {
        aws_mem_release(output_message->allocator, output_message);
    }
}

static int s_process_read_message_l4_proxy(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct aws_channel *channel = handler->slot->channel;
    AWS_FATAL_ASSERT(aws_channel_thread_is_callers_thread(channel));

    struct aws_l4_proxy_channel_handler *l4_proxy_handler = handler->impl;

    switch (l4_proxy_handler->status) {
        case AWS_L4PPS_SUCCESS:
            // if we're in pass-through mode then just pass it on
            return aws_channel_slot_send_message(slot, message, AWS_CHANNEL_DIR_READ);

        case AWS_L4PPS_IN_PROGRESS:
            s_service_l4_proxy_negotiation(l4_proxy_handler, message);
            return AWS_OP_SUCCESS;

        default:
            return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }
}

static int s_process_write_message_l4_proxy(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct aws_l4_proxy_channel_handler *l4_proxy_handler = handler->impl;
    if (l4_proxy_handler->status != AWS_L4PPS_SUCCESS) {
        aws_raise_error(AWS_ERROR_INVALID_STATE);
        goto error;
    }

    if (aws_channel_slot_send_message(slot, message, AWS_CHANNEL_DIR_WRITE)) {
        goto error;
    }

    return AWS_OP_SUCCESS;

error:

    ; // should never reach here
    int error_code = aws_last_error();
    AWS_LOGF_ERROR(
        AWS_LS_IO_SOCKS5,
        "id=%p: Destroying write message without passing it along, error %d (%s)",
        (void *)l4_proxy_handler,
        error_code,
        aws_error_name(error_code));

    if (message->on_completion) {
        message->on_completion(handler->slot->channel, message, error_code, message->user_data);
    }
    aws_mem_release(message->allocator, message);
    aws_channel_shutdown(slot->channel, error_code);

    // we cleaned up the message, so return success despite failing to send
    return AWS_OP_SUCCESS;
}

static int s_increment_read_window_l4_proxy(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {

    struct aws_l4_proxy_channel_handler *l4_proxy_handler = handler->impl;

    if (l4_proxy_handler->last_seen_right_slot == NULL && handler->slot->adj_right != NULL) {
        l4_proxy_handler->last_seen_right_slot = handler->slot->adj_right;
        if (size < slot->window_size) {
            return aws_raise_error(AWS_ERROR_INVALID_STATE);
        }

        // by syncing ourselves to the new downstream, anything that works for us will work for our downstream
        size -= slot->window_size;
        if (slot->current_window_update_batch_size > size) {
            slot->current_window_update_batch_size = size;
            size = 0;
        } else {
            size -= slot->current_window_update_batch_size;
        }
    }

    uint64_t new_size = aws_add_size_saturating(size, slot->window_size);
    uint64_t increment = new_size - slot->window_size;

    if (increment > 0) {
        aws_channel_slot_increment_read_window(slot, increment);
    }

    return AWS_OP_SUCCESS;
}

static int s_shutdown_l4_proxy(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    (void)handler;

    // get this early before there's a chance the channel structure gets torn down
    s_aws_l4_proxy_cancel_timeout_task(handler->impl);

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
}

static size_t s_initial_window_size_l4_proxy(struct aws_channel_handler *handler) {
    (void)handler;

    return DEFAULT_L4_PROXY_WINDOW_SIZE;
}

static void s_destroy_l4_proxy(struct aws_channel_handler *handler) {
    struct aws_l4_proxy_channel_handler *l4_proxy_handler = handler->impl;
    aws_l4_proxy_channel_handler_clean_up(l4_proxy_handler);

    (l4_proxy_handler->vtable->destroy)(l4_proxy_handler);
}

static size_t s_message_overhead_l4_proxy(struct aws_channel_handler *handler) {
    (void)handler;

    return 0;
}

static struct aws_channel_handler_vtable s_l4_proxy_channel_handle_vtable = {
    .process_read_message = &s_process_read_message_l4_proxy,
    .process_write_message = &s_process_write_message_l4_proxy,
    .increment_read_window = &s_increment_read_window_l4_proxy,
    .shutdown = &s_shutdown_l4_proxy,
    .initial_window_size = &s_initial_window_size_l4_proxy,
    .message_overhead = &s_message_overhead_l4_proxy,
    .destroy = &s_destroy_l4_proxy,
    .reset_statistics = NULL,
    .gather_statistics = NULL,
    .trigger_read = NULL,
};

void aws_l4_proxy_channel_handler_clean_up(struct aws_l4_proxy_channel_handler *handler) {
    s_aws_l4_proxy_cancel_timeout_task(handler);

    handler->config = aws_l4_proxy_config_release(handler->config);
}

void aws_l4_proxy_channel_handler_init(
    struct aws_l4_proxy_channel_handler *handler,
    struct aws_allocator *allocator,
    struct aws_l4_proxy_config *config,
    struct aws_l4_proxy_channel_handler_options *options) {
    handler->status = AWS_L4PPS_IN_PROGRESS;

    handler->allocator = allocator;
    handler->config = aws_l4_proxy_config_acquire(config);

    handler->negotiation_complete_callback = options->negotiation_complete_callback;
    handler->negotiation_complete_user_data = options->negotiation_complete_user_data;

    struct aws_channel_handler *base_handler = &handler->channel_handler;
    base_handler->vtable = &s_l4_proxy_channel_handle_vtable;
    base_handler->alloc = allocator;
    base_handler->slot = NULL;
    base_handler->impl = handler;
}

void s_l4_proxy_negotiation_timeout_task_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct aws_l4_proxy_channel_handler *handler = arg;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_channel *channel = handler->channel_handler.slot->channel;
        aws_channel_shutdown(channel, AWS_IO_SOCKS5_NEGOTIATION_TIMEOUT);
    }

    aws_mem_release(handler->allocator, task);
    handler->timeout_task = NULL;
}

static void s_l4_proxy_schedule_timeout_task(struct aws_l4_proxy_channel_handler *handler) {
    uint64_t timeout_millis = handler->config->negotiation_timeout_ms;
    if (timeout_millis == 0) {
        return;
    }

    uint64_t now = 0;
    if (aws_high_res_clock_get_ticks(&now)) {
        return;
    }

    uint64_t timeout_delay_nanos =
        aws_timestamp_convert(timeout_millis, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    uint64_t timeout_timepoint = aws_add_u64_saturating(timeout_delay_nanos, now);

    struct aws_allocator *allocator = handler->allocator;
    handler->timeout_task = aws_mem_calloc(allocator, 1, sizeof(struct aws_task));
    aws_task_init(handler->timeout_task, s_l4_proxy_negotiation_timeout_task_fn, handler, "socks5_negotiation_timeout");

    struct aws_channel *channel = handler->channel_handler.slot->channel;
    struct aws_event_loop *loop = aws_channel_get_event_loop(channel);
    aws_event_loop_schedule_task_future(loop, handler->timeout_task, timeout_timepoint);
}

void aws_l4_proxy_channel_handler_start_negotiation(struct aws_l4_proxy_channel_handler *handler) {
    s_l4_proxy_schedule_timeout_task(handler);

    s_service_l4_proxy_negotiation(handler, NULL);
}