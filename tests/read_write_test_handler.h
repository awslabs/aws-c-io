#ifndef AWS_READ_WRITE_TEST_HANDLER
#define AWS_READ_WRITE_TEST_HANDLER
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/io.h>

#include <aws/common/task_scheduler.h>

struct aws_atomic_var;
struct aws_byte_buf;
struct aws_channel_handler;
struct aws_channel_slot;
struct aws_condition_variable;

typedef struct aws_byte_buf(rw_handler_driver_fn)(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *data_read,
    void *ctx);

struct aws_channel_handler *rw_handler_new(
    struct aws_allocator *allocator,
    rw_handler_driver_fn *on_read,
    rw_handler_driver_fn *on_write,
    bool event_loop_driven,
    size_t window,
    void *ctx);

void rw_handler_enable_wait_on_destroy(
    struct aws_channel_handler *handler,
    struct aws_atomic_var *destroy_called,
    struct aws_condition_variable *condition_variable);

void rw_handler_write(struct aws_channel_handler *handler, struct aws_channel_slot *slot, struct aws_byte_buf *buffer);

void rw_handler_write_with_callback(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *buffer,
    aws_channel_on_message_write_completed_fn *on_completion,
    void *user_data);

void rw_handler_trigger_read(struct aws_channel_handler *handler, struct aws_channel_slot *slot);

bool rw_handler_shutdown_called(struct aws_channel_handler *handler);

bool rw_handler_increment_read_window_called(struct aws_channel_handler *handler);

void rw_handler_trigger_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t window_update);

void increment_read_window_task(void *arg, enum aws_task_status task_status);

int rw_handler_last_error_code(struct aws_channel_handler *handler);

#endif /* AWS_READ_WRITE_TEST_HANDLER */
