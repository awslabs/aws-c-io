/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "./tcp_client.h"

#include <aws/common/byte_buf.h>
#include <aws/common/ref_count.h>
#include <aws/io/channel.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/l4_proxy.h>

#include "aws/common/string.h"
#include "aws/io/event_loop.h"

struct aws_tcp_client_config {
    struct aws_allocator *allocator;

    struct aws_string *remote_host_name;
    uint16_t remote_port;

    struct aws_l4_proxy_config *proxy_config;

    struct aws_client_bootstrap *bootstrap;
    struct aws_socket_options socket_options;

    aws_tcp_client_on_connection_result_callback on_connection_result_callback;
    aws_tcp_client_on_disconnection_callback on_disconnection_callback;
    aws_tcp_client_on_data_callback on_data_callback;
    aws_tcp_client_on_destroyed_callback on_destroyed_callback;
    void *user_data;
};

static struct aws_tcp_client_config *s_aws_tcp_client_config_new(
    struct aws_allocator *allocator,
    struct aws_tcp_client_options *options) {
    struct aws_tcp_client_config *config = aws_mem_calloc(allocator, 1, sizeof(struct aws_tcp_client_config));

    config->allocator = allocator;
    config->remote_host_name = aws_string_new_from_cursor(allocator, &options->remote_host_name);
    config->remote_port = options->remote_port;
    config->proxy_config = aws_l4_proxy_config_acquire(options->proxy_config);
    config->bootstrap = aws_client_bootstrap_acquire(options->bootstrap);
    config->socket_options = options->socket_options;
    config->on_connection_result_callback = options->on_connection_result_callback;
    config->on_disconnection_callback = options->on_disconnection_callback;
    config->on_data_callback = options->on_data_callback;
    config->on_destroyed_callback = options->on_destroyed_callback;
    config->user_data = options->user_data;

    return config;
}

static void s_aws_tcp_client_config_destroy(struct aws_tcp_client_config *config) {
    if (!config) {
        return;
    }

    aws_string_destroy(config->remote_host_name);
    aws_client_bootstrap_release(config->bootstrap);

    aws_l4_proxy_config_release(config->proxy_config);

    aws_mem_release(config->allocator, config);
}

enum aws_tcp_client_state {
    AWS_TCS_CONNECTING,
    AWS_TCS_CONNECTED,
    AWS_TCS_DISCONNECTING,
    AWS_TCS_DISCONNECTED,
};

struct aws_tcp_client {
    struct aws_allocator *allocator;

    struct aws_ref_count internal_ref_count;
    struct aws_ref_count external_ref_count;

    struct aws_tcp_client_config *config;

    struct aws_event_loop *loop;

    struct aws_channel *channel;
    struct aws_channel_handler channel_handler;

    enum aws_tcp_client_state state;
    int shutdown_error_code;
};

static void s_aws_tcp_client_update_error_code(struct aws_tcp_client *client, int error_code) {
    if (client->shutdown_error_code == AWS_ERROR_SUCCESS) {
        client->shutdown_error_code = error_code;
    }
}

static void s_aws_tcp_client_on_internal_ref_count_zero(void *data) {
    struct aws_tcp_client *client = data;

    AWS_FATAL_ASSERT(client->state == AWS_TCS_DISCONNECTED);

    aws_tcp_client_on_destroyed_callback on_destroyed_callback = client->config->on_destroyed_callback;
    void *user_data = client->config->user_data;

    s_aws_tcp_client_config_destroy(client->config);

    aws_mem_release(client->allocator, client);

    if (on_destroyed_callback) {
        (*on_destroyed_callback)(user_data);
    }
}

struct aws_tcp_client_task {
    struct aws_allocator *allocator;

    struct aws_tcp_client *client;

    struct aws_task task;
};

static void s_aws_tcp_client_task_destroy(struct aws_tcp_client_task *task) {
    aws_ref_count_release(&task->client->internal_ref_count);

    aws_mem_release(task->allocator, task);
}

static struct aws_tcp_client_task *s_aws_tcp_client_task_new(
    struct aws_allocator *allocator,
    struct aws_tcp_client *client,
    aws_task_fn *task_fn) {
    struct aws_tcp_client_task *task =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_tcp_client_task));

    task->allocator = allocator;
    task->client = client;
    aws_ref_count_acquire(&client->internal_ref_count);
    aws_task_init(&task->task, task_fn, task, "tcpclient");

    return task;
}


static void s_on_external_ref_count_zero_task_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct aws_tcp_client_task *client_task = arg;
    struct aws_tcp_client *client = client_task->client;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        switch (client->state) {
            case AWS_TCS_CONNECTING:
                client->state = AWS_TCS_DISCONNECTING;
                break;

            case AWS_TCS_CONNECTED:
                aws_channel_shutdown(client->channel, AWS_ERROR_EXTERNAL_REQUEST_SHUTDOWN);
                client->state = AWS_TCS_DISCONNECTING;
                break;

            default:
                break;
        }

        aws_ref_count_release(&client->internal_ref_count);
    }

    s_aws_tcp_client_task_destroy(client_task);
}

static void s_aws_tcp_client_on_external_ref_count_zero(void *data) {
    struct aws_tcp_client *client = data;

    struct aws_tcp_client_task *task = s_aws_tcp_client_task_new(client->allocator, client, s_on_external_ref_count_zero_task_fn);
    aws_event_loop_schedule_task_now_serialized(client->loop, &task->task);
}

struct aws_tcp_client *aws_tcp_client_new(struct aws_allocator *allocator, struct aws_tcp_client_options *options) {
    struct aws_tcp_client *client = aws_mem_calloc(allocator, 1, sizeof(struct aws_tcp_client));

    client->allocator = allocator;
    aws_ref_count_init(&client->internal_ref_count, client, s_aws_tcp_client_on_internal_ref_count_zero);
    aws_ref_count_init(&client->external_ref_count, client, s_aws_tcp_client_on_external_ref_count_zero);
    client->config = s_aws_tcp_client_config_new(allocator, options);

    client->loop = aws_event_loop_group_get_next_loop(client->config->bootstrap->event_loop_group);
    client->state = AWS_TCS_DISCONNECTED;

    return client;
}

struct aws_tcp_client *aws_tcp_client_acquire(struct aws_tcp_client *client) {
    if (client != NULL) {
        aws_ref_count_acquire(&client->external_ref_count);
    }

    return client;
}

struct aws_tcp_client *aws_tcp_client_release(struct aws_tcp_client *client) {
    if (client != NULL) {
        aws_ref_count_release(&client->external_ref_count);
    }

    return NULL;
}

static void s_aws_tcp_client_do_connection_result_callback(struct aws_tcp_client *client, int error_code) {
    if (client->config->on_connection_result_callback) {
        (*client->config->on_connection_result_callback)(error_code, client->config->user_data);
    }
}

static int s_tcp_client_channel_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)slot;

    struct aws_tcp_client *client = handler->impl;
    if (client->state != AWS_TCS_CONNECTED) {
        // not necessarily invalid, but we don't want to handle it (during shut down)
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    if (client->config->on_data_callback) {
        struct aws_byte_cursor data = aws_byte_cursor_from_buf(&message->message_data);
        aws_byte_cursor_advance(&data, message->copy_mark);

        (*client->config->on_data_callback)(data, client->config->user_data);
    }

    aws_mem_release(message->allocator, message);

    return AWS_OP_SUCCESS;
}

static int s_tcp_client_channel_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    struct aws_tcp_client *client = handler->impl;
    s_aws_tcp_client_update_error_code(client, error_code);

    if (client->state == AWS_TCS_CONNECTED) {
        client->state = AWS_TCS_DISCONNECTING;
    }

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
}

static size_t s_tcp_client_channel_handler_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;

    return SIZE_MAX;
}

static size_t s_tcp_client_channel_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;

    return 0;
}

static void s_tcp_client_channel_handler_destroy(struct aws_channel_handler *handler) {
    (void)handler;
}

static struct aws_channel_handler_vtable s_tcp_client_channel_handler_vtable = {
    .process_read_message = s_tcp_client_channel_handler_process_read_message,
    .process_write_message = NULL,
    .increment_read_window = NULL,
    .shutdown = s_tcp_client_channel_handler_shutdown,
    .initial_window_size = s_tcp_client_channel_handler_initial_window_size,
    .message_overhead = s_tcp_client_channel_handler_message_overhead,
    .destroy = s_tcp_client_channel_handler_destroy,
    .reset_statistics = NULL,
    .gather_statistics = NULL,
    .trigger_read = NULL,
};

static void s_aws_tcp_client_on_channel_setup_fn(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;

    struct aws_tcp_client *client = user_data;

    AWS_FATAL_ASSERT(aws_event_loop_thread_is_callers_thread(client->loop));

    if (error_code != AWS_ERROR_SUCCESS) {
        s_aws_tcp_client_do_connection_result_callback(client, error_code);
        client->state = AWS_TCS_DISCONNECTED;
        aws_ref_count_release(&client->internal_ref_count);
        return;
    }

    struct aws_channel_slot *slot = aws_channel_slot_new(channel);
    client->channel = channel;

    client->channel_handler.alloc = client->allocator;
    client->channel_handler.impl = client;
    client->channel_handler.slot = slot;
    client->channel_handler.vtable = &s_tcp_client_channel_handler_vtable;

    aws_channel_slot_insert_end(channel, slot);

    aws_channel_slot_set_handler(slot, &client->channel_handler);

    if (client->state == AWS_TCS_CONNECTING) {
        client->state = AWS_TCS_CONNECTED;
    }

    s_aws_tcp_client_do_connection_result_callback(client, AWS_ERROR_SUCCESS);

    if (client->state != AWS_TCS_CONNECTED) {
        aws_channel_shutdown(channel, AWS_ERROR_EXTERNAL_REQUEST_SHUTDOWN);
    }
}

static void s_aws_tcp_client_on_channel_shutdown_fn(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    struct aws_tcp_client *client = user_data;

    AWS_FATAL_ASSERT(aws_event_loop_thread_is_callers_thread(client->loop));

    s_aws_tcp_client_update_error_code(client, error_code);

    client->channel = NULL;
    client->state = AWS_TCS_DISCONNECTED;

    if (client->config->on_disconnection_callback) {
        (*client->config->on_disconnection_callback)(client->shutdown_error_code, client->config->user_data);
    }

    aws_ref_count_release(&client->internal_ref_count);
}

static void s_aws_tcp_client_connect(struct aws_tcp_client *client) {
    AWS_FATAL_ASSERT(aws_event_loop_thread_is_callers_thread(client->loop));

    if (client->state != AWS_TCS_DISCONNECTED) {
        s_aws_tcp_client_do_connection_result_callback(client, AWS_ERROR_INVALID_STATE);
        return;
    }

    struct aws_socket_channel_bootstrap_options channel_options = {
        .bootstrap = client->config->bootstrap,
        .host_name = aws_string_c_str(client->config->remote_host_name),
        .port = client->config->remote_port,
        .socket_options = &client->config->socket_options,
        .tls_options = NULL, // TODO: support this
        .creation_callback = NULL,
        .setup_callback = s_aws_tcp_client_on_channel_setup_fn,
        .shutdown_callback = s_aws_tcp_client_on_channel_shutdown_fn,
        .enable_read_back_pressure = false,
        .user_data = client,
        .requested_event_loop = client->loop,
        .host_resolution_override_config = NULL,
        .l4_proxy_config = client->config->proxy_config,
    };

    aws_ref_count_acquire(&client->internal_ref_count);

    if (aws_client_bootstrap_new_socket_channel(&channel_options)) {
        s_aws_tcp_client_do_connection_result_callback(client, aws_last_error());
        aws_ref_count_release(&client->internal_ref_count);
        return;
    }

    client->state = AWS_TCS_CONNECTING;
}

static void s_aws_tcp_client_connect_task_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct aws_tcp_client_task *client_task = arg;
    if (status == AWS_TASK_STATUS_RUN_READY) {
        s_aws_tcp_client_connect(client_task->client);
    }

    s_aws_tcp_client_task_destroy(client_task);
}



void aws_tcp_client_connect(struct aws_tcp_client *client) {
    struct aws_tcp_client_task *task = s_aws_tcp_client_task_new(client->allocator, client, s_aws_tcp_client_connect_task_fn);

    aws_event_loop_schedule_task_now_serialized(client->loop, &task->task);
}

static void s_aws_tcp_client_disconnect(struct aws_tcp_client *client) {
    switch (client->state) {
        case AWS_TCS_CONNECTING:
            client->state = AWS_TCS_DISCONNECTING;
            break;

        case AWS_TCS_CONNECTED:
            client->state = AWS_TCS_DISCONNECTING;
            aws_channel_shutdown(client->channel, AWS_ERROR_EXTERNAL_REQUEST_SHUTDOWN);
            break;

        default:
            break;
    }
}

static void s_aws_tcp_client_disconnect_task_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct aws_tcp_client_task *client_task = arg;
    if (status == AWS_TASK_STATUS_RUN_READY) {
        s_aws_tcp_client_disconnect(client_task->client);
    }

    s_aws_tcp_client_task_destroy(client_task);
}

void aws_tcp_client_disconnect(struct aws_tcp_client *client) {
    struct aws_tcp_client_task *task = s_aws_tcp_client_task_new(client->allocator, client, s_aws_tcp_client_disconnect_task_fn);

    aws_event_loop_schedule_task_now_serialized(client->loop, &task->task);
}

struct aws_tcp_client_send_task {
    struct aws_allocator *allocator;

    struct aws_tcp_client *client;
    struct aws_byte_buf data;

    struct aws_task task;
};

static void s_aws_tcp_client_send_task_destroy(struct aws_tcp_client_send_task *task) {
    aws_tcp_client_release(task->client);
    aws_byte_buf_clean_up(&task->data);

    aws_mem_release(task->allocator, task);
}

static void s_aws_tcp_client_send(struct aws_tcp_client *client, struct aws_byte_cursor data) {
    if (client->state != AWS_TCS_CONNECTED) {
        return;
    }

    struct aws_io_message *message =
        aws_channel_acquire_message_from_pool(client->channel, AWS_IO_MESSAGE_APPLICATION_DATA, data.len);
    aws_byte_buf_append(&message->message_data, &data);

    if (aws_channel_slot_send_message(client->channel_handler.slot, message, AWS_CHANNEL_DIR_WRITE)) {
        aws_mem_release(message->allocator, message);
    }
}

static void s_aws_tcp_client_send_task_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct aws_tcp_client_send_task *send_task = arg;
    if (status == AWS_TASK_STATUS_RUN_READY) {
        s_aws_tcp_client_send(send_task->client, aws_byte_cursor_from_buf(&send_task->data));
    }

    s_aws_tcp_client_send_task_destroy(send_task);
}

static struct aws_tcp_client_send_task *s_aws_tcp_client_send_task_new(
    struct aws_allocator *allocator,
    struct aws_tcp_client *client,
    struct aws_byte_cursor data) {
    struct aws_tcp_client_send_task *task = aws_mem_calloc(allocator, 1, sizeof(struct aws_tcp_client_send_task));

    task->allocator = allocator;
    task->client = aws_tcp_client_acquire(client);
    aws_byte_buf_init_copy_from_cursor(&task->data, allocator, data);
    aws_task_init(&task->task, s_aws_tcp_client_send_task_fn, task, "tcpclientconnect");

    return task;
}

void aws_tcp_client_send(struct aws_tcp_client *client, struct aws_byte_cursor data) {
    struct aws_tcp_client_send_task *task = s_aws_tcp_client_send_task_new(client->allocator, client, data);

    aws_event_loop_schedule_task_now_serialized(client->loop, &task->task);
}

static void s_aws_tcp_client_test_context_on_connection_result_callback(int error_code, void *user_data) {
    struct aws_tcp_client_test_context *context = user_data;

    aws_mutex_lock(&context->lock);

    context->sync.connection_attempt_completed = true;
    context->sync.connection_error_code = error_code;

    aws_mutex_unlock(&context->lock);

    aws_condition_variable_notify_all(&context->signal);
}

static void s_aws_tcp_client_test_context_on_disconnection_callback(int error_code, void *user_data) {
    struct aws_tcp_client_test_context *context = user_data;

    aws_mutex_lock(&context->lock);

    context->sync.disconnection_completed = true;
    context->sync.disconnection_error_code = error_code;

    aws_mutex_unlock(&context->lock);

    aws_condition_variable_notify_all(&context->signal);
}

static void s_aws_tcp_client_test_context_on_data_callback(struct aws_byte_cursor data, void *user_data) {
    struct aws_tcp_client_test_context *context = user_data;

    aws_mutex_lock(&context->lock);

    aws_byte_buf_append_dynamic(&context->sync.received_data, &data);

    aws_mutex_unlock(&context->lock);

    aws_condition_variable_notify_all(&context->signal);
}

static void s_aws_tcp_client_test_context_on_destroyed_callback(void *user_data) {
    struct aws_tcp_client_test_context *context = user_data;

    aws_mutex_lock(&context->lock);

    context->sync.destruction_completed = true;

    aws_mutex_unlock(&context->lock);

    aws_condition_variable_notify_all(&context->signal);
}

void aws_tcp_client_test_context_init(
    struct aws_tcp_client_test_context *context,
    struct aws_allocator *allocator,
    struct aws_tcp_client_test_context_options *options) {

    AWS_ZERO_STRUCT(*context);

    context->allocator = allocator;

    aws_mutex_init(&context->lock);
    aws_condition_variable_init(&context->signal);

    aws_byte_buf_init(&context->sync.sent_data, allocator, 128 * 1024);
    aws_byte_buf_init(&context->sync.received_data, allocator, 128 * 1024);

    if (options->elg != NULL) {
        context->elg = aws_event_loop_group_acquire(options->elg);
    } else {
        struct aws_event_loop_group_options elg_options = {};
        context->elg = aws_event_loop_group_new(allocator, &elg_options);
    }

    struct aws_host_resolver_default_options hr_options = {
        .el_group = context->elg,
        .max_entries = 32,

    };
    context->resolver = aws_host_resolver_new_default(allocator, &hr_options);

    struct aws_client_bootstrap_options client_bootstrap_options = {
        .event_loop_group = context->elg,
        .host_resolver = context->resolver,
    };
    context->bootstrap = aws_client_bootstrap_new(context->allocator, &client_bootstrap_options);

    struct aws_tcp_client_options client_options = {
        .remote_host_name = options->remote_host_name,
        .remote_port = options->remote_port,
        .proxy_config = options->proxy_config,
        .bootstrap = context->bootstrap,
        .socket_options = {
            .type = AWS_SOCKET_STREAM,
            .domain = AWS_SOCKET_IPV4,
        },
        .on_connection_result_callback = s_aws_tcp_client_test_context_on_connection_result_callback,
        .on_disconnection_callback = s_aws_tcp_client_test_context_on_disconnection_callback,
        .on_data_callback = s_aws_tcp_client_test_context_on_data_callback,
        .on_destroyed_callback = s_aws_tcp_client_test_context_on_destroyed_callback,
        .user_data = context,
    };

    context->client = aws_tcp_client_new(allocator, &client_options);
}

static bool s_aws_tcp_client_test_context_is_destroyed(void *user_data) {
    struct aws_tcp_client_test_context *context = user_data;

    return context->sync.destruction_completed;
}

static void s_aws_tcp_client_test_context_wait_on_destroyed(struct aws_tcp_client_test_context *context) {
    aws_mutex_lock(&context->lock);
    aws_condition_variable_wait_pred(&context->signal, &context->lock, s_aws_tcp_client_test_context_is_destroyed, context);
    aws_mutex_unlock(&context->lock);
}

void aws_tcp_client_test_context_clean_up(struct aws_tcp_client_test_context *context) {

    aws_tcp_client_release(context->client);

    s_aws_tcp_client_test_context_wait_on_destroyed(context);

    aws_host_resolver_release(context->resolver);
    aws_client_bootstrap_release(context->bootstrap);
    aws_event_loop_group_release(context->elg);

    aws_mutex_clean_up(&context->lock);
    aws_condition_variable_clean_up(&context->signal);

    aws_byte_buf_clean_up(&context->sync.sent_data);
    aws_byte_buf_clean_up(&context->sync.received_data);
}

static bool s_aws_tcp_client_test_context_has_connection_result(void *user_data) {
    struct aws_tcp_client_test_context *context = user_data;

    return context->sync.connection_attempt_completed;
}

int aws_tcp_client_test_context_wait_on_connection_result(struct aws_tcp_client_test_context *context) {
    aws_mutex_lock(&context->lock);
    aws_condition_variable_wait_pred(&context->signal, &context->lock, s_aws_tcp_client_test_context_has_connection_result, context);
    int error_code = context->sync.connection_error_code;
    aws_mutex_unlock(&context->lock);

    return error_code;
}

static bool s_aws_tcp_client_test_context_has_disconnection_result(void *user_data) {
    struct aws_tcp_client_test_context *context = user_data;

    return context->sync.disconnection_completed;
}

int aws_tcp_client_test_context_wait_on_disconnection_result(struct aws_tcp_client_test_context *context) {
    aws_mutex_lock(&context->lock);
    aws_condition_variable_wait_pred(&context->signal, &context->lock, s_aws_tcp_client_test_context_has_disconnection_result, context);
    int error_code = context->sync.disconnection_error_code;
    aws_mutex_unlock(&context->lock);

    return error_code;
}

void aws_tcp_client_test_context_send_data(struct aws_tcp_client_test_context *context, struct aws_byte_cursor data) {
    aws_mutex_lock(&context->lock);
    aws_byte_buf_append_dynamic(&context->sync.sent_data, &data);
    aws_mutex_unlock(&context->lock);

   aws_tcp_client_send(context->client, data);
}

struct aws_tcp_client_test_received_bytes_context {
    struct aws_tcp_client_test_context *context;
    size_t received_bytes;
};

static bool s_aws_tcp_client_test_context_has_received_bytes(void *user_data) {
    struct aws_tcp_client_test_received_bytes_context *context = user_data;

    return context->context->sync.received_data.len == context->received_bytes;
}

void aws_tcp_client_test_context_wait_on_received_bytes(struct aws_tcp_client_test_context *context, size_t received_bytes) {
    aws_mutex_lock(&context->lock);

    struct aws_tcp_client_test_received_bytes_context received_bytes_context = {
        .context = context,
        .received_bytes = received_bytes,
    };

    aws_condition_variable_wait_pred(&context->signal, &context->lock, s_aws_tcp_client_test_context_has_received_bytes, &received_bytes_context);
    aws_mutex_unlock(&context->lock);
}

void aws_tcp_client_test_context_get_sent_bytes(struct aws_tcp_client_test_context *context, struct aws_byte_buf *bytes) {
    aws_mutex_lock(&context->lock);
    struct aws_byte_cursor sent_data = aws_byte_cursor_from_buf(&context->sync.sent_data);
    aws_byte_buf_append_dynamic(bytes, &sent_data);
    aws_mutex_unlock(&context->lock);
}

void aws_tcp_client_test_context_get_received_bytes(struct aws_tcp_client_test_context *context, struct aws_byte_buf *bytes) {
    aws_mutex_lock(&context->lock);
    struct aws_byte_cursor received_data = aws_byte_cursor_from_buf(&context->sync.received_data);
    aws_byte_buf_append_dynamic(bytes, &received_data);
    aws_mutex_unlock(&context->lock);
}
