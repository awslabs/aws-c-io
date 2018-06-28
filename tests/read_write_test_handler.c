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
#include <aws/common/condition_variable.h>

typedef struct aws_byte_buf(*rw_test_handler_driver)(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                                     struct aws_byte_buf *data_read, void *ctx);

struct rw_test_handler_impl {
    bool shutdown_called;
    bool increment_read_window_called;
    rw_test_handler_driver on_read;
    rw_test_handler_driver on_write;
    bool event_loop_driven;
    size_t window;
    struct aws_condition_variable condition_variable;
    struct aws_mutex mutex;
    int shutdown_error;
    void *ctx;
};

static int rw_handler_process_read (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                         struct aws_io_message *message) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;

    struct aws_byte_buf next_data = handler_impl->on_read(handler, slot, &message->message_data, handler_impl->ctx);
    aws_channel_release_message_to_pool(slot->channel, message);

    if (slot->adj_right) {

        struct aws_io_message *msg =
                aws_channel_acquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, next_data.len);

        struct aws_byte_cursor next_data_cursor = aws_byte_cursor_from_buf(&next_data);
        aws_byte_buf_append(&msg->message_data, &next_data_cursor);

        return aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_READ);
    }

    return AWS_OP_SUCCESS;
}

static int rw_handler_process_write_message ( struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                               struct aws_io_message *message ) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;

    struct aws_byte_buf next_data = handler_impl->on_write(handler, slot, &message->message_data, handler_impl->ctx);
    aws_channel_release_message_to_pool(slot->channel, message);

    if (slot->adj_left) {
        struct aws_io_message *msg =
                aws_channel_acquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA,
                                                     next_data.len);

        struct aws_byte_cursor next_data_cursor = aws_byte_cursor_from_buf(&next_data);
        aws_byte_buf_append(&msg->message_data, &next_data_cursor);
        return aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_WRITE);
    }

    return AWS_OP_SUCCESS;
}

static int rw_handler_increment_read_window(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                            size_t size) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    handler_impl->increment_read_window_called = true;
    aws_channel_slot_increment_read_window(slot, size);
    return AWS_OP_SUCCESS;
}

static int rw_handler_shutdown(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                           enum aws_channel_direction dir, int error_code, bool abort_immediately) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    handler_impl->shutdown_called = true;
    handler_impl->shutdown_error = error_code;
    aws_condition_variable_notify_one(&handler_impl->condition_variable);
    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, abort_immediately);
}

static size_t rw_handler_get_current_window_size (struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    return handler_impl->window;
}

static void rw_handler_destroy(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    aws_mem_release(handler->alloc, handler_impl);
    aws_mem_release(handler->alloc, handler);
}

struct aws_channel_handler *rw_test_handler_new(struct aws_allocator *allocator, rw_test_handler_driver on_read,
                                                rw_test_handler_driver on_write, bool event_loop_driven, size_t window, void *ctx) {
    struct aws_channel_handler *handler = (struct aws_channel_handler *)aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));
    handler->alloc = allocator;
    handler->vtable = (struct aws_channel_handler_vtable){
            .shutdown = rw_handler_shutdown,
            .increment_read_window = rw_handler_increment_read_window,
            .initial_window_size = rw_handler_get_current_window_size,
            .process_read_message = rw_handler_process_read,
            .process_write_message = rw_handler_process_write_message,
            .destroy = rw_handler_destroy
    };

    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)aws_mem_acquire(allocator, sizeof(struct rw_test_handler_impl));
    handler_impl->shutdown_called = false;
    handler_impl->increment_read_window_called = false;

    handler_impl->on_read = on_read;
    handler_impl->on_write = on_write;
    handler_impl->ctx = ctx;
    handler_impl->event_loop_driven = event_loop_driven;
    handler_impl->shutdown_error = 0;
    handler_impl->window = window;
    handler_impl->condition_variable = (struct aws_condition_variable)AWS_CONDITION_VARIABLE_INIT;
    handler_impl->mutex = (struct aws_mutex)AWS_MUTEX_INIT;

    handler->impl = handler_impl;

    return handler;
}

static void rw_handler_trigger_read(struct aws_channel_handler *handler, struct aws_channel_slot *slot) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;

    struct aws_byte_buf next_data = handler_impl->on_read(handler, slot, NULL, handler_impl->ctx);

    struct aws_io_message *msg =
            aws_channel_acquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, next_data.len);

    struct aws_byte_cursor next_data_cursor = aws_byte_cursor_from_buf(&next_data);
    aws_byte_buf_append(&msg->message_data, &next_data_cursor);

    aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_READ);
}

struct rw_handler_write_task_args {
    struct aws_channel_handler *handler;
    struct aws_channel_slot *slot;
    struct aws_byte_buf *buffer;
};

static void rw_handler_write_task(void *arg, aws_task_status task_status) {
    struct rw_handler_write_task_args *write_task_args = (struct rw_handler_write_task_args *)arg;

    struct aws_io_message *msg =
            aws_channel_acquire_message_from_pool(write_task_args->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA,
                                                 write_task_args->buffer->len);

    struct aws_byte_cursor write_buffer = aws_byte_cursor_from_buf(write_task_args->buffer);
    aws_byte_buf_append(&msg->message_data, &write_buffer);

    aws_channel_slot_send_message(write_task_args->slot, msg, AWS_CHANNEL_DIR_WRITE);

    aws_mem_release(write_task_args->handler->alloc, write_task_args);
}

static void rw_handler_write(struct aws_channel_handler *handler, struct aws_channel_slot *slot, struct aws_byte_buf *buffer) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;

    if (!handler_impl->event_loop_driven || aws_channel_thread_is_callers_thread(slot->channel)) {
        struct aws_io_message *msg =
                aws_channel_acquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA,
                                                     buffer->len);

        struct aws_byte_cursor write_buffer = aws_byte_cursor_from_buf(buffer);
        aws_byte_buf_append(&msg->message_data, &write_buffer);

        aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_WRITE);
    }
    else {
        struct rw_handler_write_task_args *write_task_args = (struct rw_handler_write_task_args *) aws_mem_acquire(
                handler->alloc,
                sizeof(struct rw_handler_write_task_args));
        write_task_args->handler = handler;
        write_task_args->buffer = buffer;
        write_task_args->slot = slot;

        struct aws_task task = {
                .fn = rw_handler_write_task,
                .arg = write_task_args
        };

        uint64_t now = 0;
        aws_channel_current_clock_time(slot->channel, &now);
        aws_channel_schedule_task(slot->channel, &task, now);
    }
}

struct increment_read_window_task_args {
    size_t window_update;
    struct aws_channel_handler *handler;
    struct aws_channel_slot *slot;
};

static void increment_read_window_task(void *arg, aws_task_status task_status) {
    struct increment_read_window_task_args *increment_read_window_task_args = (struct increment_read_window_task_args *)arg;
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)increment_read_window_task_args->handler->impl;

    handler_impl->window += increment_read_window_task_args->window_update;
    aws_channel_slot_increment_read_window(increment_read_window_task_args->slot, increment_read_window_task_args->window_update);

    aws_mem_release(increment_read_window_task_args->handler->alloc, increment_read_window_task_args);
}

static void rw_handler_trigger_increment_read_window(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                 size_t window_update) {

    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;

    if (!handler_impl->event_loop_driven || aws_channel_thread_is_callers_thread(slot->channel)) {
        handler_impl->window += window_update;
        aws_channel_slot_increment_read_window(slot, window_update);
    }
    else {
        struct increment_read_window_task_args *increment_read_window_task_args = (struct increment_read_window_task_args *) aws_mem_acquire(
                handler->alloc,
                sizeof(struct increment_read_window_task_args));
        increment_read_window_task_args->handler = handler;
        increment_read_window_task_args->window_update = window_update;
        increment_read_window_task_args->slot = slot;

        struct aws_task task = {
                .fn = increment_read_window_task,
                .arg = increment_read_window_task_args
        };

        uint64_t now = 0;
        aws_channel_current_clock_time(slot->channel, &now);
        aws_channel_schedule_task(slot->channel, &task, now);
    }
}

static bool rw_handler_shutdown_called(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    return handler_impl->shutdown_called;
}

static bool rw_handler_increment_read_window_called(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    return handler_impl->increment_read_window_called;

}

static int rw_handler_last_error_code(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    return handler_impl->shutdown_error;
}

static bool rw_test_handler_shutdown_predicate(void *arg) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)arg;
    return handler_impl->shutdown_called;
}

static int rw_handler_wait_on_shutdown(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = (struct rw_test_handler_impl *)handler->impl;
    return aws_condition_variable_wait_pred(&handler_impl->condition_variable, &handler_impl->mutex,
                                            rw_test_handler_shutdown_predicate, handler_impl);
}

#endif /*READ_WRITE_TEST_HANDLER*/
