/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "read_write_test_handler.h"

#include <aws/common/atomics.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/task_scheduler.h>
#include <aws/io/channel.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#    pragma warning(disable : 4267) /* size_t to int conversion */
#endif

struct rw_test_handler_impl {
    struct aws_atomic_var shutdown_called;
    bool increment_read_window_called;
    struct aws_atomic_var *destroy_called;
    struct aws_condition_variable *destroy_condition_variable;
    rw_handler_driver_fn *on_read;
    rw_handler_driver_fn *on_write;
    bool event_loop_driven;
    size_t window;
    struct aws_condition_variable condition_variable;
    struct aws_mutex mutex;
    struct aws_atomic_var shutdown_error;
    void *ctx;
};

static int s_rw_handler_process_read(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct rw_test_handler_impl *handler_impl = handler->impl;

    struct aws_byte_buf next_data = handler_impl->on_read(handler, slot, &message->message_data, handler_impl->ctx);
    aws_mem_release(message->allocator, message);

    if (slot->adj_right) {

        struct aws_io_message *msg =
            aws_channel_acquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, next_data.len);

        struct aws_byte_cursor next_data_cursor = aws_byte_cursor_from_buf(&next_data);
        aws_byte_buf_append(&msg->message_data, &next_data_cursor);

        return aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_READ);
    }

    return AWS_OP_SUCCESS;
}

static int s_rw_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct rw_test_handler_impl *handler_impl = handler->impl;

    struct aws_byte_buf next_data = handler_impl->on_write(handler, slot, &message->message_data, handler_impl->ctx);
    aws_mem_release(message->allocator, message);

    if (slot->adj_left) {
        struct aws_io_message *msg =
            aws_channel_acquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, next_data.len);

        struct aws_byte_cursor next_data_cursor = aws_byte_cursor_from_buf(&next_data);
        aws_byte_buf_append(&msg->message_data, &next_data_cursor);
        return aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_WRITE);
    }

    return AWS_OP_SUCCESS;
}

static int s_rw_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {

    struct rw_test_handler_impl *handler_impl = handler->impl;
    handler_impl->increment_read_window_called = true;
    aws_channel_slot_increment_read_window(slot, size);
    return AWS_OP_SUCCESS;
}

static int s_rw_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool abort_immediately) {

    struct rw_test_handler_impl *handler_impl = handler->impl;
    aws_atomic_store_int(&handler_impl->shutdown_called, true);
    aws_atomic_store_int(&handler_impl->shutdown_error, error_code);
    aws_condition_variable_notify_one(&handler_impl->condition_variable);
    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, abort_immediately);
}

static size_t s_rw_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;
    return 0;
}

static size_t s_rw_handler_get_current_window_size(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = handler->impl;
    return handler_impl->window;
}

static void s_rw_handler_destroy(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = handler->impl;

    if (handler_impl->destroy_called) {
        aws_atomic_store_int(handler_impl->destroy_called, 1);
        aws_condition_variable_notify_one(handler_impl->destroy_condition_variable);
    }

    aws_mem_release(handler->alloc, handler_impl);
    aws_mem_release(handler->alloc, handler);
}

struct aws_channel_handler_vtable s_rw_test_vtable = {
    .shutdown = s_rw_handler_shutdown,
    .increment_read_window = s_rw_handler_increment_read_window,
    .initial_window_size = s_rw_handler_get_current_window_size,
    .process_read_message = s_rw_handler_process_read,
    .process_write_message = s_rw_handler_process_write_message,
    .destroy = s_rw_handler_destroy,
    .message_overhead = s_rw_handler_message_overhead,
};

struct aws_channel_handler *rw_handler_new(
    struct aws_allocator *allocator,
    rw_handler_driver_fn *on_read,
    rw_handler_driver_fn *on_write,
    bool event_loop_driven,
    size_t window,
    void *ctx) {

    struct aws_channel_handler *handler = aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));
    handler->alloc = allocator;
    handler->vtable = &s_rw_test_vtable;

    struct rw_test_handler_impl *handler_impl = aws_mem_acquire(allocator, sizeof(struct rw_test_handler_impl));
    AWS_ZERO_STRUCT(*handler_impl);
    handler_impl->on_read = on_read;
    handler_impl->on_write = on_write;
    handler_impl->ctx = ctx;
    handler_impl->event_loop_driven = event_loop_driven;
    handler_impl->window = window;
    handler_impl->condition_variable = (struct aws_condition_variable)AWS_CONDITION_VARIABLE_INIT;
    handler_impl->mutex = (struct aws_mutex)AWS_MUTEX_INIT;

    handler->impl = handler_impl;

    return handler;
}

void rw_handler_enable_wait_on_destroy(
    struct aws_channel_handler *handler,
    struct aws_atomic_var *destroy_called,
    struct aws_condition_variable *condition_variable) {

    struct rw_test_handler_impl *handler_impl = handler->impl;
    handler_impl->destroy_called = destroy_called;
    handler_impl->destroy_condition_variable = condition_variable;
}

void rw_handler_trigger_read(struct aws_channel_handler *handler, struct aws_channel_slot *slot) {
    struct rw_test_handler_impl *handler_impl = handler->impl;

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
    struct aws_channel_task task;
};

static void s_rw_handler_write_task(struct aws_channel_task *task, void *arg, enum aws_task_status task_status) {
    (void)task;
    (void)task_status;
    struct rw_handler_write_task_args *write_task_args = arg;

    struct aws_io_message *msg = aws_channel_acquire_message_from_pool(
        write_task_args->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, write_task_args->buffer->len);

    struct aws_byte_cursor write_buffer = aws_byte_cursor_from_buf(write_task_args->buffer);
    aws_byte_buf_append(&msg->message_data, &write_buffer);

    aws_channel_slot_send_message(write_task_args->slot, msg, AWS_CHANNEL_DIR_WRITE);

    aws_mem_release(write_task_args->handler->alloc, write_task_args);
}

void rw_handler_write(struct aws_channel_handler *handler, struct aws_channel_slot *slot, struct aws_byte_buf *buffer) {

    struct rw_test_handler_impl *handler_impl = handler->impl;

    if (!handler_impl->event_loop_driven || aws_channel_thread_is_callers_thread(slot->channel)) {
        struct aws_io_message *msg =
            aws_channel_acquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, buffer->len);

        struct aws_byte_cursor write_buffer = aws_byte_cursor_from_buf(buffer);
        aws_byte_buf_append(&msg->message_data, &write_buffer);

        aws_channel_slot_send_message(slot, msg, AWS_CHANNEL_DIR_WRITE);
    } else {
        struct rw_handler_write_task_args *write_task_args =
            aws_mem_acquire(handler->alloc, sizeof(struct rw_handler_write_task_args));
        write_task_args->handler = handler;
        write_task_args->buffer = buffer;
        write_task_args->slot = slot;
        aws_channel_task_init(&write_task_args->task, s_rw_handler_write_task, write_task_args, "rw_handler_write");

        aws_channel_schedule_task_now(slot->channel, &write_task_args->task);
    }
}

struct increment_read_window_task_args {
    size_t window_update;
    struct aws_channel_handler *handler;
    struct aws_channel_slot *slot;
    struct aws_channel_task task;
};

static void s_increment_read_window_task(struct aws_channel_task *task, void *arg, enum aws_task_status task_status) {
    (void)task;
    (void)task_status;
    struct increment_read_window_task_args *increment_read_window_task_args = arg;
    struct rw_test_handler_impl *handler_impl = increment_read_window_task_args->handler->impl;

    handler_impl->window += increment_read_window_task_args->window_update;
    aws_channel_slot_increment_read_window(
        increment_read_window_task_args->slot, increment_read_window_task_args->window_update);

    aws_mem_release(increment_read_window_task_args->handler->alloc, increment_read_window_task_args);
}

void rw_handler_trigger_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t window_update) {

    struct rw_test_handler_impl *handler_impl = handler->impl;

    if (!handler_impl->event_loop_driven || aws_channel_thread_is_callers_thread(slot->channel)) {
        handler_impl->window += window_update;
        aws_channel_slot_increment_read_window(slot, window_update);
    } else {
        struct increment_read_window_task_args *increment_read_window_task_args =
            aws_mem_acquire(handler->alloc, sizeof(struct increment_read_window_task_args));
        increment_read_window_task_args->handler = handler;
        increment_read_window_task_args->window_update = window_update;
        increment_read_window_task_args->slot = slot;
        aws_channel_task_init(
            &increment_read_window_task_args->task,
            s_increment_read_window_task,
            increment_read_window_task_args,
            "increment_read_window_task");

        aws_channel_schedule_task_now(slot->channel, &increment_read_window_task_args->task);
    }
}

bool rw_handler_shutdown_called(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = handler->impl;
    return aws_atomic_load_int(&handler_impl->shutdown_called);
}

bool rw_handler_increment_read_window_called(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = handler->impl;
    return handler_impl->increment_read_window_called;
}

int rw_handler_last_error_code(struct aws_channel_handler *handler) {
    struct rw_test_handler_impl *handler_impl = handler->impl;
    return aws_atomic_load_int(&handler_impl->shutdown_error);
}
