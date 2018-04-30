#ifndef READ_WRITE_TEST_HANDLER
#define READ_WRITE_TEST_HANDLER
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
#include <aws/io/channel.h>

struct rw_test_handler_impl {
    struct aws_byte_buf read_tag;
    struct aws_byte_buf write_tag;
    struct aws_byte_buf final_message;
    bool shutdown_notify_called;
    bool window_update_called;
};

static int rw_handler_process_read (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                         struct aws_io_message *message) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;

    if (slot->adj_right) {
        struct aws_io_message *msg =
                aws_channel_aquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA,
                                                 message->message_data.len +
                                                 handler_impl->read_tag.len);

        memcpy(msg->message_data.buffer, message->message_data.buffer, message->message_data.len);
        memcpy(msg->message_data.buffer + message->message_data.len, handler_impl->read_tag.buffer,
                  handler_impl->read_tag.len);

        aws_channel_release_message_to_pool(slot->channel, message);

        return aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_READ);
    }

    struct aws_io_message *msg =
            aws_channel_aquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA,
                                                 message->message_data.len + handler_impl->read_tag.len
                                                 + handler_impl->write_tag.len);

    memcpy(msg->message_data.buffer, message->message_data.buffer, message->message_data.len);
    memcpy(msg->message_data.buffer + message->message_data.len, handler_impl->read_tag.buffer, handler_impl->read_tag.len);
    memcpy(msg->message_data.buffer + message->message_data.len + handler_impl->read_tag.len,
           handler_impl->write_tag.buffer, handler_impl->write_tag.len);


    aws_channel_release_message_to_pool(slot->channel, message);

    return aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_WRITE);
}

static int rw_handler_process_write_message ( struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                               struct aws_io_message *message ) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;

    if (slot->adj_left) {
        struct aws_io_message *msg =
                aws_channel_aquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA,
                                                     message->message_data.len +
                                                     handler_impl->write_tag.len);

        memcpy(msg->message_data.buffer, message->message_data.buffer, message->message_data.len);
        memcpy(msg->message_data.buffer + message->message_data.len, handler_impl->write_tag.buffer,
               handler_impl->write_tag.len);

        aws_channel_release_message_to_pool(slot->channel, message);

        return aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_WRITE);
    }

    aws_byte_buf_alloc(handler->alloc, &handler_impl->final_message, message->message_data.len + handler_impl->write_tag.len);
    memcpy(handler_impl->final_message.buffer, message->message_data.buffer, message->message_data.len);
    memcpy(handler_impl->final_message.buffer + message->message_data.len, handler_impl->write_tag.buffer, handler_impl->write_tag.len);

    aws_channel_release_message_to_pool(slot->channel, message);

    return AWS_OP_SUCCESS;
}

static int rw_handler_on_window_update(struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    handler_impl->window_update_called = true;

    aws_channel_slot_update_window(slot, size);
    return AWS_OP_SUCCESS;
}

static int rw_handler_on_shutdown_notify(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                           enum aws_channel_direction dir, int error_code) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    handler_impl->shutdown_notify_called = true;

    return AWS_OP_SUCCESS;
}

static int rw_handler_shutdown_direction (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                           enum aws_channel_direction dir) {
    return aws_channel_slot_shutdown_notify(slot, dir, 0);
}

static size_t rw_handler_get_current_window_size (struct aws_channel_handler *handler) {
    return 10000;
}

static void rw_handler_destroy(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    aws_byte_buf_free(handler->alloc, &handler_impl->final_message);
    aws_mem_release(handler->alloc, handler_impl);
    aws_mem_release(handler->alloc, handler);
}

struct aws_channel_handler *rw_test_handler_new(struct aws_allocator *allocator, struct aws_byte_buf read_tag,
                                                struct aws_byte_buf write_tag) {
    struct aws_channel_handler *handler = (struct aws_channel_handler *)aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));
    handler->alloc = allocator;
    handler->vtable = (struct aws_channel_handler_vtable){
            .shutdown_direction = rw_handler_shutdown_direction,
            .on_shutdown_notify = rw_handler_on_shutdown_notify,
            .on_window_update = rw_handler_on_window_update,
            .get_current_window_size = rw_handler_get_current_window_size,
            .process_read_message = rw_handler_process_read,
            .process_write_message = rw_handler_process_write_message,
            .destroy = rw_handler_destroy
    };

    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)aws_mem_acquire(allocator, sizeof(struct rw_test_handler_impl));
    handler_impl->shutdown_notify_called = false;
    handler_impl->write_tag = write_tag;
    handler_impl->read_tag = read_tag;
    handler_impl->window_update_called = false;
    handler->impl = handler_impl;

    return handler;
}

static void rw_handler_trigger_read(struct aws_channel_handler *handler, struct aws_channel_slot *slot) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;

    struct aws_io_message *msg =
            aws_channel_aquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA,
                                                 handler_impl->read_tag.len);

    memcpy(msg->message_data.buffer, handler_impl->read_tag.buffer, handler_impl->read_tag.len);
    aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_READ);
}

static struct aws_byte_buf rw_handler_get_final_message(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    return handler_impl->final_message;
}

static bool rw_handler_shutdown_notify_called(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    return handler_impl->shutdown_notify_called;
}

static bool rw_handler_window_update_called(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    return handler_impl->window_update_called;
}

#endif /*READ_WRITE_TEST_HANDLER*/
