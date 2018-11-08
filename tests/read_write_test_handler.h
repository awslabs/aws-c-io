#ifndef AWS_READ_WRITE_TEST_HANDLER
#define AWS_READ_WRITE_TEST_HANDLER
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

void rw_handler_trigger_read(struct aws_channel_handler *handler, struct aws_channel_slot *slot);

bool rw_handler_shutdown_called(struct aws_channel_handler *handler);

bool rw_handler_increment_read_window_called(struct aws_channel_handler *handler);

void rw_handler_trigger_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t window_update);

void increment_read_window_task(void *arg, enum aws_task_status task_status);

int rw_handler_last_error_code(struct aws_channel_handler *handler);

int rw_handler_wait_on_shutdown(struct aws_channel_handler *handler);

#endif /* AWS_READ_WRITE_TEST_HANDLER */
