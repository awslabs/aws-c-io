/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/l4_proxy.h>
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
static const size_t DEFAULT_L4_PROXY_WINDOW_SIZE = 8096;

static void s_schedule_l4_proxy_service(struct aws_l4_proxy_channel_handler *handler) {
    struct aws_channel *channel = handler->channel_handler.slot->channel;
    AWS_FATAL_ASSERT(aws_channel_thread_is_callers_thread(channel));

    if (handler->is_service_scheduled) {
        return;
    }

    handler->is_service_scheduled = true;
    aws_channel_schedule_task_now(channel, &handler->service_task);
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
    }

    s_schedule_l4_proxy_service(handler);
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

    return (handler->vtable->drive_negotiation)(handler->impl, context);
}

static struct aws_byte_cursor s_aws_byte_buf_get_downstream_data(
    struct aws_io_message *source_message,
    size_t downstream_window) {
    size_t remaining_bytes = aws_sub_size_saturating(source_message->message_data.len, source_message->copy_mark);
    size_t fragment_size = aws_min_size(downstream_window, remaining_bytes);
    struct aws_byte_cursor fragment_cursor = {
        .ptr = source_message->message_data.buffer + source_message->copy_mark,
        .len = fragment_size,
    };

    return fragment_cursor;
}

static struct aws_io_message *s_aws_io_message_new_downstream(
    struct aws_l4_proxy_channel_handler *handler,
    struct aws_io_message *source_message,
    size_t downstream_window) {
    struct aws_byte_cursor fragment_cursor = s_aws_byte_buf_get_downstream_data(source_message, downstream_window);
    if (fragment_cursor.len == 0) {
        return NULL;
    }

    struct aws_io_message *downstream_message = aws_channel_acquire_message_from_pool(
        handler->channel_handler.slot->channel, source_message->message_type, fragment_cursor.len);
    if (downstream_message == NULL) {
        return NULL;
    }

    if (aws_byte_buf_append(&downstream_message->message_data, &fragment_cursor)) {
        aws_mem_release(downstream_message->allocator, downstream_message);
        return NULL;
    }

    return downstream_message;
}

static void s_service_l4_proxy_negotiation(struct aws_l4_proxy_channel_handler *handler) {

    struct aws_io_message *output_message = aws_channel_acquire_message_from_pool(
        handler->channel_handler.slot->channel,
        AWS_IO_MESSAGE_APPLICATION_DATA,
        AWS_L4_PROXY_IO_MESSAGE_DEFAULT_LENGTH);
    output_message->user_data = handler;
    output_message->on_completion = s_aws_l4_proxy_on_socket_write_completion;

    bool done = false;
    while (!done) {
        struct aws_l4_proxy_negotiation_context context;
        AWS_ZERO_STRUCT(context);

        size_t fragment_length = 0;
        struct aws_byte_cursor fragment_cursor;
        AWS_ZERO_STRUCT(fragment_cursor);

        struct aws_io_message *head_message = NULL;
        if (!aws_linked_list_empty(&handler->pending_read_bytes)) {
            struct aws_linked_list_node *head_node = aws_linked_list_front(&handler->pending_read_bytes);
            head_message = AWS_CONTAINER_OF(head_node, struct aws_io_message, queueing_handle);

            fragment_cursor = s_aws_byte_buf_get_downstream_data(head_message, SIZE_MAX);
            fragment_length = fragment_cursor.len;
        }

        context.status = handler->status;
        if (fragment_cursor.len > 0) {
            context.data = &fragment_cursor;
        }
        context.to_write = &output_message->message_data;

        if (s_drive_negotiation_l4_proxy(handler, &context) || context.status == AWS_L4PPS_FAILURE) {
            int error_code = context.error_code;
            if (error_code == AWS_ERROR_SUCCESS) {
                error_code = aws_last_error();
            }
            handler->status = AWS_L4PPS_FAILURE;
            aws_mem_release(output_message->allocator, output_message);
            aws_channel_shutdown(handler->channel_handler.slot->channel, error_code);
            return;
        }

        handler->status = context.status;
        if (context.data != NULL) {
            head_message->copy_mark += fragment_length - context.data->len;
        }

        if (output_message->message_data.len > 0) {
            if (aws_channel_slot_send_message(handler->channel_handler.slot, output_message, AWS_CHANNEL_DIR_WRITE)) {
                aws_mem_release(output_message->allocator, output_message);
                aws_channel_shutdown(handler->channel_handler.slot->channel, aws_last_error());
            }
            return;
        }

        done = aws_linked_list_empty(&handler->pending_read_bytes) || context.status != AWS_L4PPS_IN_PROGRESS;
    }

    aws_mem_release(output_message->allocator, output_message);
}

static void s_service_downstream_handler(struct aws_l4_proxy_channel_handler *handler) {
    AWS_FATAL_ASSERT(handler->status == AWS_L4PPS_SUCCESS);

    struct aws_channel_slot *slot = handler->channel_handler.slot;
    bool done = slot->adj_right == NULL || slot->adj_right->window_size == 0 ||
                aws_linked_list_empty(&handler->pending_read_bytes);

    while (!done) {
        struct aws_channel_handler *downstream_handler = slot->adj_right->handler;
        struct aws_linked_list_node *head_node = aws_linked_list_front(&handler->pending_read_bytes);
        struct aws_io_message *head_message = AWS_CONTAINER_OF(head_node, struct aws_io_message, queueing_handle);

        size_t downstream_window = slot->adj_right->window_size;
        struct aws_io_message *downstream_message =
            s_aws_io_message_new_downstream(handler, head_message, downstream_window);
        if (downstream_message == NULL) {
            return;
        }

        if (aws_channel_handler_process_read_message(downstream_handler, slot->adj_right, downstream_message)) {
            aws_mem_release(downstream_message->allocator, downstream_message);
            aws_channel_shutdown(handler->channel_handler.slot->channel, aws_last_error());
            break;
        }

        size_t bytes_consumed = downstream_message->message_data.len;
        head_message->copy_mark += bytes_consumed;
        handler->num_pending_read_bytes -= bytes_consumed;

        if (head_message->copy_mark >= head_message->message_data.len) {
            aws_linked_list_pop_front(&handler->pending_read_bytes);
            aws_mem_release(head_message->allocator, head_message);
        }

        done = slot->adj_right == NULL || slot->adj_right->window_size == 0 ||
               aws_linked_list_empty(&handler->pending_read_bytes);
    }
}

static size_t s_compute_l4_proxy_window_size(struct aws_l4_proxy_channel_handler *handler) {
    switch (handler->status) {
        case AWS_L4PPS_IN_PROGRESS:
            return SIZE_MAX;

        case AWS_L4PPS_SUCCESS: {
            struct aws_channel_slot *slot = handler->channel_handler.slot;
            if (slot->adj_right) {
                return slot->adj_right->window_size;
            }

            return 0;
        }

        default:
            return 0;
    }
}

static void s_service_l4_proxy(struct aws_channel_task *channel_task, void *arg, enum aws_task_status status) {
    (void)channel_task;

    if (status == AWS_TASK_STATUS_CANCELED) {
        return;
    }

    struct aws_l4_proxy_channel_handler *handler = arg;
    // technically we should do this even if cancelled, but it's unclear if it's possible for the handler
    // to be deleted before the cancelled task is run, invalidating the memory access.  Given that cancellation
    // only happens on channel destruction, it doesn't matter if this flag doesn't get cleared in that case.
    handler->is_service_scheduled = false;

    size_t downstream_window = s_compute_l4_proxy_window_size(handler);
    bool should_iterate =
        (handler->status == AWS_L4PPS_IN_PROGRESS) ||
        (handler->status == AWS_L4PPS_SUCCESS && downstream_window > 0 && handler->num_pending_read_bytes > 0);

    while (should_iterate) {
        if (handler->status == AWS_L4PPS_IN_PROGRESS) {
            s_service_l4_proxy_negotiation(handler);
        } else {
            s_service_downstream_handler(handler);
        }

        downstream_window = s_compute_l4_proxy_window_size(handler);
        should_iterate =
            handler->status == AWS_L4PPS_SUCCESS && downstream_window > 0 && handler->num_pending_read_bytes > 0;
    }
}

static int s_process_read_message_l4_proxy(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct aws_channel *channel = handler->slot->channel;
    AWS_FATAL_ASSERT(aws_channel_thread_is_callers_thread(channel));

    struct aws_l4_proxy_channel_handler *l4_proxy_handler = handler->impl;

    size_t message_size = message->message_data.len - message->copy_mark;

    // if we're in pass-through mode and the message respects the down stream handle's window then just pass it on
    if (l4_proxy_handler->status == AWS_L4PPS_SUCCESS &&
        message_size <= s_compute_l4_proxy_window_size(l4_proxy_handler) &&
        l4_proxy_handler->num_pending_read_bytes == 0) {
        return aws_channel_slot_send_message(slot, message, AWS_CHANNEL_DIR_READ);
    }

    l4_proxy_handler->num_pending_read_bytes += message_size;
    aws_linked_list_push_back(&l4_proxy_handler->pending_read_bytes, &message->queueing_handle);
    s_schedule_l4_proxy_service(l4_proxy_handler);

    return AWS_OP_SUCCESS;
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

    ;
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
    (void)slot;
    (void)size;

    struct aws_l4_proxy_channel_handler *l4_proxy_handler = handler->impl;

    if (l4_proxy_handler->num_pending_read_bytes > 0) {
        s_schedule_l4_proxy_service(l4_proxy_handler);
    }

    return AWS_OP_SUCCESS;
    ;
}

static int s_shutdown_l4_proxy(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    (void)handler;

    // TBI, maybe we delay because we now buffer?
    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
}

static size_t s_initial_window_size_l4_proxy(struct aws_channel_handler *handler) {
    (void)handler;

    return DEFAULT_L4_PROXY_WINDOW_SIZE;
}

static void s_destroy_l4_proxy(struct aws_channel_handler *handler) {
    struct aws_l4_proxy_channel_handler *l4_proxy_handler = handler->impl;
    aws_l4_proxy_channel_handler_clean_up(l4_proxy_handler);

    (l4_proxy_handler->vtable->destroy)(l4_proxy_handler->impl);
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
    handler->config = aws_l4_proxy_config_release(handler->config);
    aws_byte_buf_clean_up(&handler->remote_host);

    while (!aws_linked_list_empty(&handler->pending_read_bytes)) {
        struct aws_linked_list_node *head_node = aws_linked_list_pop_front(&handler->pending_read_bytes);
        struct aws_io_message *head_message = AWS_CONTAINER_OF(head_node, struct aws_io_message, queueing_handle);
        aws_mem_release(head_message->allocator, head_message);
    }
}

void aws_l4_proxy_channel_handler_init(
    struct aws_l4_proxy_channel_handler *handler,
    struct aws_allocator *allocator,
    struct aws_l4_proxy_config *config,
    struct aws_l4_proxy_channel_handler_options *options) {
    handler->status = AWS_L4PPS_IN_PROGRESS;
    handler->is_service_scheduled = false;
    handler->num_pending_read_bytes = 0;

    aws_linked_list_init(&handler->pending_read_bytes);
    aws_channel_task_init(&handler->service_task, s_service_l4_proxy, handler, "l4_proxy_service");

    handler->allocator = allocator;
    handler->config = aws_l4_proxy_config_acquire(config);

    aws_byte_buf_init_copy_from_cursor(&handler->remote_host, allocator, options->remote->host);
    handler->remote_port = options->remote->port;

    handler->negotiation_complete_callback = options->negotiation_complete_callback;
    handler->negotiation_complete_user_data = options->negotiation_complete_user_data;

    struct aws_channel_handler *base_handler = &handler->channel_handler;
    base_handler->vtable = &s_l4_proxy_channel_handle_vtable;
    base_handler->alloc = allocator;
    base_handler->slot = NULL;
    base_handler->impl = handler;
}

void aws_l4_proxy_channel_handler_start_negotiation(struct aws_l4_proxy_channel_handler *handler) {
    s_schedule_l4_proxy_service(handler);
}