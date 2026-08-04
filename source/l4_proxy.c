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

struct aws_l4_proxy_channel_handler *aws_l4_proxy_config_new_channel_handler(struct aws_l4_proxy_config *config, struct aws_l4_proxy_channel_handler_options *options) {
    return config->vtable->new_channel_handler(config, options);
}

void aws_l4_proxy_config_get_proxy_address(struct aws_l4_proxy_config *config, struct aws_connection_remote *new_remote) {
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

/*
*    struct aws_io_message *io_message = aws_channel_acquire_message_from_pool(channel, AWS_IO_MESSAGE_APPLICATION_DATA, AWS_SOCKS5_IO_MESSAGE_DEFAULT_LENGTH);
    if (io_message == NULL) {
        return AWS_OP_ERR;
    }

handler->status = negotiation_context.status;

if (io_message->message_data.len == 0 || negotiation_context.status == AWS_L4PPS_FAILURE) {
aws_mem_release(io_message->allocator, io_message);
if (negotiation_context.status == AWS_L4PPS_FAILURE) {
AWS_FATAL_ASSERT(negotiation_context.error_code != AWS_ERROR_SUCCESS);
return aws_raise_error(negotiation_context.error_code);
}
}

io_message->on_completion = s_aws_socks5_on_socket_write_completion;
io_message->user_data = handler;

if (aws_channel_slot_send_message(slot, io_message, AWS_CHANNEL_DIR_WRITE)) {
aws_mem_release(io_message->allocator, io_message);
return AWS_OP_ERR;
}

if (handler->status == AWS_L4PPS_SUCCESS) {
//
??;
}
??;

return AWS_OP_SUCCESS;
*/

static int s_drive_negotiation_l4_proxy(struct aws_l4_proxy_channel_handler *handler,  struct aws_l4_proxy_negotiation_context *context) {
    struct aws_channel_slot *slot = handler->channel_handler.slot;
    struct aws_channel *channel = slot->channel;

    AWS_FATAL_ASSERT(aws_channel_thread_is_callers_thread(channel));

    if (handler->status != AWS_L4PPS_IN_PROGRESS) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    return (handler->vtable->drive_negotiation)(handler->impl, context);
}

static void s_aws_l4_proxy_negotiation_context_init(struct aws_l4_proxy_negotiation_context *context) {
    if (??) {
        ??
    } else {
        context->data = NULL;
    }

    context->status = ??;
    context->error_code = AWS_ERROR_SUCCESS;
    ??;
}

static void s_aws_l4_proxy_negotiation_context_clean_up(struct aws_l4_proxy_negotiation_context *context) {

}

/*

struct aws_l4_proxy_negotiation_context {
    struct aws_byte_cursor *data;
    enum aws_l4_proxy_protocol_status status;
    struct aws_byte_buf *to_write;
    int error_code;
};
 */

static void s_service_l4_proxy_negotiation(struct aws_l4_proxy_channel_handler *handler) {
    (void)handler;
    // TBI
}

static void s_service_downstream_handler(struct aws_l4_proxy_channel_handler *handler) {
    (void)handler;
    // TBI
}

static size_t s_compute_l4_proxy_window_size(struct aws_l4_proxy_channel_handler *handler) {
    switch (handler->status) {
        case AWS_L4PPS_IN_PROGRESS:
            return SIZE_MAX;

        case AWS_L4PPS_SUCCESS: {
            struct aws_channel_slot *slot= handler->channel_handler.slot;
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
    handler->in_service = true;

    size_t downstream_window = s_compute_l4_proxy_window_size(handler);
    bool should_iterate = (handler->status == AWS_L4PPS_IN_PROGRESS) ||
        (handler->status == AWS_L4PPS_SUCCESS && downstream_window > 0 && handler->num_pending_read_bytes > 0);

    while (should_iterate) {
        if (handler->status == AWS_L4PPS_IN_PROGRESS) {
            s_service_l4_proxy_negotiation(handler);
        } else {
            s_service_downstream_handler(handler);
        }

        downstream_window = s_compute_l4_proxy_window_size(handler);
        should_iterate = handler->status == AWS_L4PPS_SUCCESS && downstream_window > 0 && handler->num_pending_read_bytes > 0;
    }

    handler->in_service = false;
}

static int s_process_read_message_l4_proxy(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    (void)slot;

    struct aws_channel *channel = handler->slot->channel;
    AWS_FATAL_ASSERT(aws_channel_thread_is_callers_thread(channel));

    struct aws_l4_proxy_channel_handler *l4_proxy_handler = handler->impl;

    size_t message_size = message->message_data.len; // TBD copy mark?
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

    AWS_LOGF_ERROR(
        AWS_LS_IO_SOCKS5,
        "id=%p: Destroying write message without passing it along, error %d (%s)",
        (void *)l4_proxy_handler,
        aws_last_error(),
        aws_error_name(aws_last_error()));

    if (message->on_completion) {
        message->on_completion(handler->slot->channel, message, aws_last_error(), message->user_data);
    }
    aws_mem_release(message->allocator, message);
    // TBI
    //s_shutdown_due_to_error(connection, aws_last_error());

    return AWS_OP_SUCCESS;
}

static int s_increment_read_window_l4_proxy(struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size) {
    (void)handler;
    (void)slot;
    (void)size;

    // TBI
    return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
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

    // purge all pending read (which should be empty)
    // TBI
}

void aws_l4_proxy_channel_handler_init(struct aws_l4_proxy_channel_handler *handler, struct aws_allocator *allocator, struct aws_l4_proxy_config *config, struct aws_l4_proxy_channel_handler_options *options) {
    handler->status = AWS_L4PPS_IN_PROGRESS;
    handler->in_service = false;
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