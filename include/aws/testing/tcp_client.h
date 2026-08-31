/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef TCP_CLIENT_H
#define TCP_CLIENT_H

#include <aws/io/io.h>

#include <aws/common/byte_buf.h>
#include <aws/common/condition_variable.h>
#include <aws/common/mutex.h>
#include <aws/common/ref_count.h>
#include <aws/common/string.h>
#include <aws/io/channel.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>
#include <aws/io/l4_proxy.h>
#include <aws/io/socket.h>

#ifndef AWS_UNSTABLE_TESTING_API
#    error This code is designed for use by AWS owned libraries for the AWS C99 SDK. \
You are welcome to use it, but we make no promises on the stability of this API. \
To enable use of this code, set the AWS_UNSTABLE_TESTING_API compiler flag.
#endif

struct aws_tcp_client;

/* Public types */

typedef void (*aws_tcp_client_on_connection_result_callback)(int error_code, void *user_data);
typedef void (*aws_tcp_client_on_disconnection_callback)(int error_code, void *user_data);
typedef void (*aws_tcp_client_on_data_callback)(struct aws_byte_cursor data, void *user_data);
typedef void (*aws_tcp_client_on_destroyed_callback)(void *user_data);

/**
 * Configuration options for TCP client construction
 */
struct aws_tcp_client_options {

    /** Host to connect to */
    struct aws_byte_cursor remote_host_name;

    /** Port to connect to */
    uint32_t remote_port;

    /** L4 proxy to connect through.  This type was created to test l4 proxy tunneling.  */
    struct aws_l4_proxy_config *proxy_config;

    /** Client bootstrap to use to create the connection channel */
    struct aws_client_bootstrap *bootstrap;

    /** Socket options to use when establishing the connection.  Some options won't necessarily work here */
    struct aws_socket_options socket_options;

    /** Callback to invoke when a connection attempt resolves */
    aws_tcp_client_on_connection_result_callback on_connection_result_callback;

    /** Callback to invoke on disconnection.  Only invoked if a successful connection was previously established. */
    aws_tcp_client_on_disconnection_callback on_disconnection_callback;

    /** Callback invoked when the client receives data */
    aws_tcp_client_on_data_callback on_data_callback;

    /** Callback invoked when the client has been fully destroyed.  Denotes a time point when no other callbacks can
     * be invoked and the client can safely be forgotten.
     */
    aws_tcp_client_on_destroyed_callback on_destroyed_callback;

    /** Opaque data to inject into callbacks */
    void *user_data;

    /** Channel window size to use.  A value of zero disables window management and read backpressure */
    size_t window_size;
};

/**
 * Configuration options for a tcp client test context
 */
struct aws_tcp_client_test_context_options {

    /** Host to connect to */
    struct aws_byte_cursor remote_host_name;

    /** Port to connect to */
    uint32_t remote_port;

    /** L4 proxy to connect through.  */
    struct aws_l4_proxy_config *proxy_config;

    /** Event loop group to seat channels on */
    struct aws_event_loop_group *elg;

    /** Channel window size to use.  A value of zero disables window management and read backpressure */
    size_t window_size;
};

/**
 * Wraps a tcp client with test-related functionality for waiting on async events like connection, disconnection, and
 * incoming data.
 */
struct aws_tcp_client_test_context {
    struct aws_allocator *allocator;

    struct aws_event_loop_group *elg;
    struct aws_client_bootstrap *bootstrap;
    struct aws_host_resolver *resolver;

    struct aws_mutex lock;
    struct aws_condition_variable signal;
    struct {
        bool connection_attempt_completed;
        int connection_error_code;
        bool disconnection_completed;
        int disconnection_error_code;
        bool destruction_completed;
        struct aws_byte_buf sent_data;
        struct aws_byte_buf received_data;
    } sync;

    struct aws_tcp_client *client;
};

/****** Public API ******/

/**
 * Creates a new TCP client
 *
 * @param allocator - allocator to use
 * @param options - client options to use
 */
static struct aws_tcp_client *aws_tcp_client_new(
    struct aws_allocator *allocator,
    struct aws_tcp_client_options *options);

/**
 * Increments the reference count of a client
 *
 * @param client client to add a reference to
 * @return the input client value
 */
static struct aws_tcp_client *aws_tcp_client_acquire(struct aws_tcp_client *client);

/**
 * Decrements the reference count of a client
 *
 * @param client client to remove a reference from
 * @return NULL
 */
static struct aws_tcp_client *aws_tcp_client_release(struct aws_tcp_client *client);

/**
 * Starts the client's async connection process to the configured remote.
 *
 * @param client client to connect with
 */
static void aws_tcp_client_connect(struct aws_tcp_client *client);

/**
 * Starts the client's async disconnect (if currently connected) process
 *
 * @param client client to disconnect
 */
static void aws_tcp_client_disconnect(struct aws_tcp_client *client);

/**
 * Queues data to be sent to the remote host
 *
 * @param client client to send data through
 * @param data data to send
 */
static void aws_tcp_client_send(struct aws_tcp_client *client, struct aws_byte_cursor data);

/**
 * Initializes the test wrapper around a tcp client
 *
 * @param context test context to initialize
 * @param allocator allocator to use
 * @param options test context configuration options to use
 */
static void aws_tcp_client_test_context_init(
    struct aws_tcp_client_test_context *context,
    struct aws_allocator *allocator,
    struct aws_tcp_client_test_context_options *options);

/**
 * Cleans up a tcp client test wrapper.  This includes blocking on disconnection and async destruction.
 *
 * @param context test context to clean up
 */
static void aws_tcp_client_test_context_clean_up(struct aws_tcp_client_test_context *context);

/**
 * Blocks on a client's connection attempt resolving.
 *
 * @param context client test context to wait on
 * @return the error code associated with the connection attempt
 */
static int aws_tcp_client_test_context_wait_on_connection_result(struct aws_tcp_client_test_context *context);

/**
 * Blocks on a client's disconnection event.
 *
 * @param context client test context to wait on
 * @return the error code associated with the disconnection
 */
static int aws_tcp_client_test_context_wait_on_disconnection_result(struct aws_tcp_client_test_context *context);

/**
 * Sends data through the client associated with a test context
 *
 * @param context context whose client will be used to send data
 * @param data data to send
 */
static void aws_tcp_client_test_context_send_data(
    struct aws_tcp_client_test_context *context,
    struct aws_byte_cursor data);

/**
 * Blocks on receiving a specific amount of bytes from the remote host connected to by the context's client
 *
 * @param context context whose client must receive an amount of data
 * @param received_bytes amount of data to wait for
 */
static void aws_tcp_client_test_context_wait_on_received_bytes(
    struct aws_tcp_client_test_context *context,
    size_t received_bytes);

/**
 * Copies all data sent by the client into a buffer
 *
 * @param context context to retrieve the sent data from
 * @param bytes output parameter to place the sent data into
 */
static void aws_tcp_client_test_context_get_sent_bytes(
    struct aws_tcp_client_test_context *context,
    struct aws_byte_buf *bytes);

/**
 * Copies all data received by the client into a buffer
 *
 * @param context context to retrieve the received data from
 * @param bytes output parameter to place the received data into
 */
static void aws_tcp_client_test_context_get_received_bytes(
    struct aws_tcp_client_test_context *context,
    struct aws_byte_buf *bytes);

/**
 * Resets the sent and received data to empty buffers.
 *
 * @param context context to reset the send/received data for
 */
static void aws_tcp_client_test_context_reset_data(struct aws_tcp_client_test_context *context);

/****** Static implementation ******/

struct aws_tcp_client_config {
    struct aws_allocator *allocator;

    struct aws_string *remote_host_name;
    uint32_t remote_port;

    struct aws_l4_proxy_config *proxy_config;

    struct aws_client_bootstrap *bootstrap;
    struct aws_socket_options socket_options;

    aws_tcp_client_on_connection_result_callback on_connection_result_callback;
    aws_tcp_client_on_disconnection_callback on_disconnection_callback;
    aws_tcp_client_on_data_callback on_data_callback;
    aws_tcp_client_on_destroyed_callback on_destroyed_callback;
    void *user_data;

    size_t window_size;
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
    config->window_size = options->window_size;

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

struct aws_tcp_client_outbound_data {
    struct aws_allocator *allocator;
    struct aws_linked_list_node node;
    struct aws_byte_buf data;
    struct aws_byte_cursor remaining;
};

// extra copy but who cares atm
static struct aws_tcp_client_outbound_data *s_aws_tcp_client_outbound_data_new(
    struct aws_allocator *allocator,
    struct aws_byte_cursor data) {
    struct aws_tcp_client_outbound_data *data_node =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_tcp_client_outbound_data));

    data_node->allocator = allocator;
    aws_byte_buf_init_copy_from_cursor(&data_node->data, allocator, data);
    data_node->remaining = aws_byte_cursor_from_buf(&data_node->data);

    return data_node;
}

static void s_aws_tcp_client_outbound_data_destroy(struct aws_tcp_client_outbound_data *data) {
    if (data == NULL) {
        return;
    }

    // assumes already removed from list

    aws_byte_buf_clean_up(&data->data);
    aws_mem_release(data->allocator, data);
}

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

    struct aws_linked_list outbound_data_queue;
    struct aws_channel_task write_task;
    bool is_write_scheduled;
};

static void s_aws_tcp_client_schedule_write_if_needed(struct aws_tcp_client *client) {
    AWS_FATAL_ASSERT(aws_event_loop_thread_is_callers_thread(client->loop));

    if (client->is_write_scheduled) {
        return;
    }

    if (client->state != AWS_TCS_CONNECTED || client->channel == NULL) {
        return;
    }

    if (aws_linked_list_empty(&client->outbound_data_queue)) {
        return;
    }

    client->is_write_scheduled = true;
    aws_channel_schedule_task_now(client->channel, &client->write_task);
}

static void s_aws_tcp_client_on_message_write_completed(
    struct aws_channel *channel,
    struct aws_io_message *message,
    int error_code,
    void *user_data) {
    (void)channel;
    (void)message;
    (void)error_code;

    struct aws_tcp_client *client = user_data;

    s_aws_tcp_client_schedule_write_if_needed(client);
}

static void s_aws_tcp_client_write_task_fn(
    struct aws_channel_task *channel_task,
    void *arg,
    enum aws_task_status status) {
    (void)channel_task;

    struct aws_tcp_client *client = arg;

    client->is_write_scheduled = false;

    if (aws_linked_list_empty(&client->outbound_data_queue)) {
        return;
    }

    if (status != AWS_TASK_STATUS_RUN_READY) {
        return;
    }

    struct aws_io_message *message =
        aws_channel_acquire_message_from_pool(client->channel, AWS_IO_MESSAGE_APPLICATION_DATA, 16 * 1024);

    struct aws_linked_list_node *node = aws_linked_list_front(&client->outbound_data_queue);
    struct aws_tcp_client_outbound_data *data_entry = AWS_CONTAINER_OF(node, struct aws_tcp_client_outbound_data, node);

    size_t advance = aws_min_size(message->message_data.capacity, data_entry->remaining.len);
    struct aws_byte_cursor to_write = aws_byte_cursor_advance(&data_entry->remaining, advance);

    aws_byte_buf_append(&message->message_data, &to_write);
    message->on_completion = s_aws_tcp_client_on_message_write_completed;
    message->user_data = client;

    if (aws_channel_slot_send_message(client->channel_handler.slot, message, AWS_CHANNEL_DIR_WRITE)) {
        aws_mem_release(message->allocator, message);
    }

    if (data_entry->remaining.len == 0) {
        aws_linked_list_pop_front(&client->outbound_data_queue);
        s_aws_tcp_client_outbound_data_destroy(data_entry);
    }
}

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

    while (!aws_linked_list_empty(&client->outbound_data_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&client->outbound_data_queue);
        struct aws_tcp_client_outbound_data *data_entry =
            AWS_CONTAINER_OF(node, struct aws_tcp_client_outbound_data, node);

        s_aws_tcp_client_outbound_data_destroy(data_entry);
    }

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
    struct aws_tcp_client_task *task = aws_mem_calloc(allocator, 1, sizeof(struct aws_tcp_client_task));

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

    struct aws_tcp_client_task *task =
        s_aws_tcp_client_task_new(client->allocator, client, s_on_external_ref_count_zero_task_fn);
    aws_event_loop_schedule_task_now_serialized(client->loop, &task->task);
}

static struct aws_tcp_client *aws_tcp_client_new(
    struct aws_allocator *allocator,
    struct aws_tcp_client_options *options) {
    struct aws_tcp_client *client = aws_mem_calloc(allocator, 1, sizeof(struct aws_tcp_client));

    client->allocator = allocator;
    aws_ref_count_init(&client->internal_ref_count, client, s_aws_tcp_client_on_internal_ref_count_zero);
    aws_ref_count_init(&client->external_ref_count, client, s_aws_tcp_client_on_external_ref_count_zero);
    client->config = s_aws_tcp_client_config_new(allocator, options);

    client->loop = aws_event_loop_group_get_next_loop(client->config->bootstrap->event_loop_group);
    client->state = AWS_TCS_DISCONNECTED;

    aws_linked_list_init(&client->outbound_data_queue);

    aws_channel_task_init(&client->write_task, s_aws_tcp_client_write_task_fn, client, "tcpclientwrite");

    return client;
}

static struct aws_tcp_client *aws_tcp_client_acquire(struct aws_tcp_client *client) {
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

    struct aws_byte_cursor data = aws_byte_cursor_from_buf(&message->message_data);
    aws_byte_cursor_advance(&data, message->copy_mark);

    if (client->config->on_data_callback) {
        (*client->config->on_data_callback)(data, client->config->user_data);
    }

    aws_channel_slot_increment_read_window(slot, data.len);

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

static int s_tcp_client_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {
    (void)handler;

    uint64_t new_size = aws_add_size_saturating(size, slot->window_size);
    uint64_t increment = new_size - slot->window_size;

    if (increment > 0) {
        aws_channel_slot_increment_read_window(slot, increment);
    }

    return AWS_OP_SUCCESS;
}

static size_t s_tcp_client_channel_handler_initial_window_size(struct aws_channel_handler *handler) {
    struct aws_tcp_client *client = handler->impl;

    if (client->config->window_size > 0) {
        return client->config->window_size;
    }

    return SIZE_MAX;
}

static size_t s_tcp_client_channel_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;

    return 0;
}

static void s_tcp_client_channel_handler_destroy(struct aws_channel_handler *handler) {
    struct aws_tcp_client *client = handler->impl;

    aws_ref_count_release(&client->internal_ref_count);
}

static struct aws_channel_handler_vtable s_tcp_client_channel_handler_vtable = {
    .process_read_message = s_tcp_client_channel_handler_process_read_message,
    .process_write_message = NULL,
    .increment_read_window = s_tcp_client_increment_read_window,
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
    (void)bootstrap;
    (void)channel;

    struct aws_tcp_client *client = user_data;

    AWS_FATAL_ASSERT(aws_event_loop_thread_is_callers_thread(client->loop));

    s_aws_tcp_client_update_error_code(client, error_code);

    client->channel = NULL;
    client->state = AWS_TCS_DISCONNECTED;

    if (client->config->on_disconnection_callback) {
        (*client->config->on_disconnection_callback)(client->shutdown_error_code, client->config->user_data);
    }
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
        .enable_read_back_pressure = client->config->window_size > 0,
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

static void aws_tcp_client_connect(struct aws_tcp_client *client) {
    struct aws_tcp_client_task *task =
        s_aws_tcp_client_task_new(client->allocator, client, s_aws_tcp_client_connect_task_fn);

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

static void aws_tcp_client_disconnect(struct aws_tcp_client *client) {
    struct aws_tcp_client_task *task =
        s_aws_tcp_client_task_new(client->allocator, client, s_aws_tcp_client_disconnect_task_fn);

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

    struct aws_tcp_client_outbound_data *data_entry = s_aws_tcp_client_outbound_data_new(client->allocator, data);
    aws_linked_list_push_back(&client->outbound_data_queue, &data_entry->node);

    s_aws_tcp_client_schedule_write_if_needed(client);
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

static void aws_tcp_client_send(struct aws_tcp_client *client, struct aws_byte_cursor data) {
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

static void aws_tcp_client_test_context_init(
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
        .socket_options =
            {
                .type = AWS_SOCKET_STREAM,
                .domain = AWS_SOCKET_IPV4,
                .connect_timeout_ms = 10000,
            },
        .on_connection_result_callback = s_aws_tcp_client_test_context_on_connection_result_callback,
        .on_disconnection_callback = s_aws_tcp_client_test_context_on_disconnection_callback,
        .on_data_callback = s_aws_tcp_client_test_context_on_data_callback,
        .on_destroyed_callback = s_aws_tcp_client_test_context_on_destroyed_callback,
        .user_data = context,
    };

    if (options->window_size > 0) {
        client_options.window_size = options->window_size;
    }

    context->client = aws_tcp_client_new(allocator, &client_options);
}

static bool s_aws_tcp_client_test_context_is_destroyed(void *user_data) {
    struct aws_tcp_client_test_context *context = user_data;

    return context->sync.destruction_completed;
}

static void s_aws_tcp_client_test_context_wait_on_destroyed(struct aws_tcp_client_test_context *context) {
    aws_mutex_lock(&context->lock);
    aws_condition_variable_wait_pred(
        &context->signal, &context->lock, s_aws_tcp_client_test_context_is_destroyed, context);
    aws_mutex_unlock(&context->lock);
}

static void aws_tcp_client_test_context_clean_up(struct aws_tcp_client_test_context *context) {

    aws_tcp_client_disconnect(context->client); // not needed but avoids unreferenced function
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

static int aws_tcp_client_test_context_wait_on_connection_result(struct aws_tcp_client_test_context *context) {
    aws_mutex_lock(&context->lock);
    aws_condition_variable_wait_pred(
        &context->signal, &context->lock, s_aws_tcp_client_test_context_has_connection_result, context);
    int error_code = context->sync.connection_error_code;
    aws_mutex_unlock(&context->lock);

    return error_code;
}

static bool s_aws_tcp_client_test_context_has_disconnection_result(void *user_data) {
    struct aws_tcp_client_test_context *context = user_data;

    return context->sync.disconnection_completed;
}

static int aws_tcp_client_test_context_wait_on_disconnection_result(struct aws_tcp_client_test_context *context) {
    aws_mutex_lock(&context->lock);
    aws_condition_variable_wait_pred(
        &context->signal, &context->lock, s_aws_tcp_client_test_context_has_disconnection_result, context);
    int error_code = context->sync.disconnection_error_code;
    aws_mutex_unlock(&context->lock);

    return error_code;
}

static void aws_tcp_client_test_context_send_data(
    struct aws_tcp_client_test_context *context,
    struct aws_byte_cursor data) {
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

static void aws_tcp_client_test_context_wait_on_received_bytes(
    struct aws_tcp_client_test_context *context,
    size_t received_bytes) {
    aws_mutex_lock(&context->lock);

    struct aws_tcp_client_test_received_bytes_context received_bytes_context = {
        .context = context,
        .received_bytes = received_bytes,
    };

    aws_condition_variable_wait_pred(
        &context->signal, &context->lock, s_aws_tcp_client_test_context_has_received_bytes, &received_bytes_context);
    aws_mutex_unlock(&context->lock);
}

static void aws_tcp_client_test_context_get_sent_bytes(
    struct aws_tcp_client_test_context *context,
    struct aws_byte_buf *bytes) {
    aws_mutex_lock(&context->lock);
    struct aws_byte_cursor sent_data = aws_byte_cursor_from_buf(&context->sync.sent_data);
    aws_byte_buf_append_dynamic(bytes, &sent_data);
    aws_mutex_unlock(&context->lock);
}

static void aws_tcp_client_test_context_get_received_bytes(
    struct aws_tcp_client_test_context *context,
    struct aws_byte_buf *bytes) {
    aws_mutex_lock(&context->lock);
    struct aws_byte_cursor received_data = aws_byte_cursor_from_buf(&context->sync.received_data);
    aws_byte_buf_append_dynamic(bytes, &received_data);
    aws_mutex_unlock(&context->lock);
}

static void aws_tcp_client_test_context_reset_data(struct aws_tcp_client_test_context *context) {
    aws_mutex_lock(&context->lock);
    aws_byte_buf_reset(&context->sync.sent_data, false);
    aws_byte_buf_reset(&context->sync.received_data, false);
    aws_mutex_unlock(&context->lock);
}

#endif /* TCP_CLIENT_H */
