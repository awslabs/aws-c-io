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

#include <aws/io/tls_channel_handler.h>
#include <aws/io/channel.h>

struct alpn_handler {
    aws_tls_on_protocol_negotiated on_protocol_negotiated;
    void *ctx;
};

int alpn_process_read_message ( struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                              struct aws_io_message *message ) {

    if (message->message_tag != AWS_TLS_NEGOTIATED_PROTOCOL_MESSAGE) {
        return aws_raise_error(AWS_IO_MISSING_ALPN_MESSAGE);
    }

    struct aws_tls_negotiated_protocol_message *protocol_message =
            (struct aws_tls_negotiated_protocol_message *)message->message_data.buffer;

    struct aws_channel_slot *new_slot = aws_channel_slot_new(slot->channel);

    struct alpn_handler *alpn_handler = (struct alpn_handler *)handler->impl;

    if (!new_slot) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    struct aws_channel_handler *new_handler = alpn_handler->on_protocol_negotiated(new_slot,
                                                                                   &protocol_message->protocol, alpn_handler->ctx);

    if (!new_handler) {
        aws_mem_release(handler->alloc, (void *)new_slot);
        return AWS_OP_ERR;
    }

    aws_channel_slot_replace(slot, new_slot);
    aws_channel_slot_set_handler(new_slot, new_handler);
    return AWS_OP_SUCCESS;
}

int alpn_on_shutdown_notify (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                           enum aws_channel_direction dir, int error_code) {
    return aws_channel_slot_shutdown_notify(slot, dir, error_code);
}

size_t alpn_get_current_window_size (struct aws_channel_handler *handler) {
    return SIZE_MAX;
}

void alpn_destroy(struct aws_channel_handler *handler) {
    struct alpn_handler *alpn_handler = (struct alpn_handler *)handler->impl;
    aws_mem_release(handler->alloc, alpn_handler);
    aws_mem_release(handler->alloc, handler);
}

struct aws_channel_handler *aws_tls_alpn_handler_new(struct aws_allocator *allocator,
                                                     aws_tls_on_protocol_negotiated on_protocol_negotiated, void *ctx) {
    struct aws_channel_handler *channel_handler = (struct aws_channel_handler *)aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));

    if (!channel_handler) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    struct alpn_handler *alpn_handler = (struct alpn_handler *)aws_mem_acquire(allocator, sizeof(struct alpn_handler));

    if (!alpn_handler) {
        aws_mem_release(allocator, (void *)channel_handler);
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    alpn_handler->on_protocol_negotiated = on_protocol_negotiated;
    alpn_handler->ctx = ctx;
    channel_handler->impl = alpn_handler;
    channel_handler->alloc = allocator;

    channel_handler->vtable = (struct aws_channel_handler_vtable){
            .shutdown = NULL,
            .get_current_window_size = alpn_get_current_window_size,
            .on_window_update = NULL,
            .on_shutdown_notify = alpn_on_shutdown_notify,
            .process_write_message = NULL,
            .process_read_message = alpn_process_read_message,
            .destroy = alpn_destroy
    };

    return channel_handler;
}