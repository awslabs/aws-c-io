/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "echo_server.h"

#include <aws/common/hash_table.h>
#include <aws/common/mutex.h>
#include <aws/common/ref_count.h>
#include <aws/common/string.h>
#include <aws/io/channel.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>

struct aws_echo_server_config {
    struct aws_allocator *allocator;

    struct aws_event_loop_group *elg;
    struct aws_server_bootstrap *listener_bootstrap;

    struct aws_string *host_name;
    uint16_t port;

    struct aws_socket_options socket_options;

    void (*on_setup)(struct aws_echo_server *server, int error_code, void *user_data);
    void *on_setup_user_data;

    void (*on_destroy)(struct aws_echo_server *server, void *user_data);
    void *on_destroy_user_data;
};

enum aws_echo_server_state {
    AWS_ECHO_SS_INITIAL,
    AWS_ECHO_SS_PENDING_LISTENER,
    AWS_ECHO_SS_LISTENING,
    AWS_ECHO_SS_SHUTTING_DOWN,
    AWS_ECHO_SS_SHUTDOWN,
};

struct aws_echo_server {
    struct aws_allocator *allocator;

    struct aws_ref_count external_ref_count;

    /*
     * Internal Ref Cases:
     *  1. External ref count holds one internal ref while non-zero
     *  2. The listener socket holds a ref while alive
     *  3. Each connection holds an internal ref
     */
    struct aws_ref_count internal_ref_count;

    struct aws_echo_server_config *config;

    struct aws_mutex lock;

    struct {
        enum aws_echo_server_state state;
        uint64_t next_id;
        struct aws_hash_table connections_by_id;
        struct aws_socket *listener_socket;
    } sync;
};

enum aws_echo_connection_state {
    AWS_ECHO_CS_ACTIVE,
    AWS_ECHO_CS_SHUTTING_DOWN,
    AWS_ECHO_CS_SHUTDOWN,
};

struct aws_echo_connection {
    struct aws_allocator *allocator;

    struct aws_ref_count ref_count;

    uint64_t id;

    struct aws_echo_server *server;

    enum aws_echo_connection_state state;

    struct aws_event_loop *event_loop;

    struct aws_channel *channel;
    struct aws_channel_handler channel_handler;

    int shutdown_error_code;

    void (*on_shutdown)(struct aws_echo_connection *tunnel, int error_code, void *user_data);
    void *on_shutdown_user_data;
};

static struct aws_echo_server_config *s_aws_echo_server_config_new(
    struct aws_allocator *allocator,
    struct aws_echo_server_options *options) {

    struct aws_echo_server_config *config = aws_mem_calloc(allocator, 1, sizeof(struct aws_echo_server_config));

    config->allocator = allocator;
    config->elg = aws_event_loop_group_acquire(options->elg);
    config->listener_bootstrap = aws_server_bootstrap_acquire(options->listener_bootstrap);
    config->host_name = aws_string_new_from_c_str(allocator, options->host_name);
    config->port = options->port;
    config->socket_options = options->socket_options;
    config->on_setup = options->on_setup;
    config->on_setup_user_data = options->on_setup_user_data;
    config->on_destroy = options->on_destroy;
    config->on_destroy_user_data = options->on_destroy_user_data;

    return config;
}

static void s_aws_echo_server_config_destroy(struct aws_echo_server_config *config) {
    if (config == NULL) {
        return;
    }

    aws_string_destroy(config->host_name);

    aws_event_loop_group_release(config->elg);
    aws_server_bootstrap_release(config->listener_bootstrap);

    aws_mem_release(config->allocator, config);
}


static void s_aws_echo_connection_update_error_code(struct aws_echo_connection *connection, int error_code) {
    if (connection->shutdown_error_code == AWS_ERROR_SUCCESS) {
        connection->shutdown_error_code = error_code;
    }
}

static void s_aws_echo_connection_on_channel_destroyed(struct aws_echo_connection *connection) {
    AWS_FATAL_ASSERT(aws_event_loop_thread_is_callers_thread(connection->event_loop));

    connection->channel = NULL;
    connection->state = AWS_ECHO_CS_SHUTDOWN;
    (*connection->on_shutdown)(connection, connection->shutdown_error_code, connection->on_shutdown_user_data);
}

struct aws_echo_connection_shutdown_task {
    struct aws_allocator *allocator;

    struct aws_task task;

    struct aws_echo_connection *connection;
    int error_code;
};

static void s_aws_echo_connection_shutdown_task_destroy(struct aws_echo_connection_shutdown_task *task) {
    aws_ref_count_release(&task->connection->ref_count);
    aws_mem_release(task->allocator, task);
}

static void s_aws_echo_connection_shutdown_task_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct aws_echo_connection_shutdown_task *shutdown_task = arg;

    if (status == AWS_TASK_STATUS_CANCELED) {
        goto done;
    }

    struct aws_echo_connection *connection = shutdown_task->connection;
    AWS_FATAL_ASSERT(aws_event_loop_thread_is_callers_thread(connection->event_loop));

    if (connection->state == AWS_ECHO_CS_SHUTTING_DOWN || connection->state == AWS_ECHO_CS_SHUTDOWN) {
        goto done;
    }

    connection->state = AWS_ECHO_CS_SHUTTING_DOWN;

    s_aws_echo_connection_update_error_code(connection, shutdown_task->error_code);

    if (connection->channel) {
        aws_channel_shutdown(connection->channel, connection->shutdown_error_code);
    } else {
        s_aws_echo_connection_on_channel_destroyed(connection);
    }

done:

    s_aws_echo_connection_shutdown_task_destroy(shutdown_task);
}

static struct aws_echo_connection_shutdown_task *s_aws_echo_connection_shutdown_task_new(
    struct aws_allocator *allocator,
    struct aws_echo_connection *connection,
    int error_code) {

    struct aws_echo_connection_shutdown_task *task =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_echo_connection_shutdown_task));
    task->allocator = allocator;
    task->connection = connection;
    aws_ref_count_acquire(&connection->ref_count);
    task->error_code = error_code;

    aws_task_init(&task->task, s_aws_echo_connection_shutdown_task_fn, task, "echoconnectionshutdown");

    return task;
}

static void s_aws_echo_connection_shutdown(struct aws_echo_connection *connection, int error_code) {
    struct aws_echo_connection_shutdown_task *task =
        s_aws_echo_connection_shutdown_task_new(connection->allocator, connection, error_code);

    aws_event_loop_schedule_task_now_serialized(connection->event_loop, &task->task);
}

// Server Reference Semantics
//
// External ref count - starts at 1 (the caller of _new(...)), external holders only
//
// Internal ref count - starts at 1 (the external ref count being non zero)
//    Listener start to final destruction - holds 1
//    Every tunnel - holds 1
//
// Don't dec the internal ref count while holding the lock

static void s_shut_down_echo_server(struct aws_echo_server *server) {

    struct aws_socket *listener = NULL;

    aws_mutex_lock(&server->lock);

    // shut down listener, wait for shutdown callback
    switch (server->sync.state) {
        case AWS_ECHO_SS_PENDING_LISTENER:
            server->sync.state = AWS_ECHO_SS_SHUTTING_DOWN;
            // can't do anything, have to wait for async listener to complete and then shut it down in the callback
            break;

        case AWS_ECHO_SS_LISTENING:
            server->sync.state = AWS_ECHO_SS_SHUTTING_DOWN;
            listener = server->sync.listener_socket;
            server->sync.listener_socket = NULL;
            break;

        case AWS_ECHO_SS_INITIAL:
            server->sync.state = AWS_ECHO_SS_SHUTDOWN;
            break;

        default:
            // do nothing (shutting down, shut down)
            break;
    }

    struct aws_array_list connections;
    aws_array_list_init_dynamic(
        &connections,
        server->allocator,
        aws_hash_table_get_entry_count(&server->sync.connections_by_id),
        sizeof(struct aws_echo_connection *));

    for (struct aws_hash_iter iter = aws_hash_iter_begin(&server->sync.connections_by_id); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        struct aws_echo_connection *connection = iter.element.value;

        aws_array_list_push_back(&connections, &connection);
        aws_ref_count_acquire(&connection->ref_count);
    }

    aws_mutex_unlock(&server->lock);

    for (size_t i = 0; i < aws_array_list_length(&connections); i++) {
        struct aws_echo_connection *connection = NULL;
        aws_array_list_get_at(&connections, &connection, i);

        s_aws_echo_connection_shutdown(connection, AWS_ERROR_EXTERNAL_REQUEST_SHUTDOWN);
        aws_ref_count_release(&connection->ref_count);
    }

    aws_array_list_clean_up(&connections);

    if (listener) {
        aws_server_bootstrap_destroy_socket_listener(server->config->listener_bootstrap, listener);
    }
}

static void s_on_echo_server_external_ref_count_zero(void *user_data) {
    struct aws_echo_server *server = user_data;

    s_shut_down_echo_server(server);

    // External ref count holds one internal ref
    aws_ref_count_release(&server->internal_ref_count); // Internal Ref Case 1
}

static void s_on_echo_server_internal_ref_count_zero(void *user_data) {

    struct aws_echo_server *server = user_data;

    aws_mutex_clean_up(&server->lock);

    AWS_FATAL_ASSERT(aws_hash_table_get_entry_count(&server->sync.connections_by_id) == 0);

    aws_hash_table_clean_up(&server->sync.connections_by_id);

    if (server->config->on_destroy) {
        (*server->config->on_destroy)(server, server->config->on_destroy_user_data);
    }

    s_aws_echo_server_config_destroy(server->config);

    aws_mem_release(server->allocator, server);
}

struct aws_echo_server *aws_echo_server_new(struct aws_allocator *allocator, struct aws_echo_server_options *options) {

    struct aws_echo_server *server = aws_mem_calloc(allocator, 1, sizeof(struct aws_echo_server));

    server->allocator = allocator;

    aws_ref_count_init(&server->external_ref_count, server, s_on_echo_server_external_ref_count_zero);
    aws_ref_count_init(
        &server->internal_ref_count, server, s_on_echo_server_internal_ref_count_zero); // Internal Ref Case 1

    server->config = s_aws_echo_server_config_new(allocator, options);

    aws_mutex_init(&server->lock);

    server->sync.state = AWS_ECHO_SS_INITIAL;
    server->sync.next_id = 1;
    aws_hash_table_init(
        &server->sync.connections_by_id,
        allocator,
        4,
        aws_hash_uint64_t_by_identity,
        aws_hash_compare_uint64_t_eq,
        NULL,
        NULL);

    return server;
}

struct aws_echo_server *aws_echo_server_acquire(struct aws_echo_server *server) {
    if (server) {
        aws_ref_count_acquire(&server->external_ref_count);
    }

    return server;
}

void aws_echo_server_release(struct aws_echo_server *server) {
    aws_ref_count_release(&server->external_ref_count);
}

static void s_aws_echo_server_bootstrap_on_listener_setup_fn(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    void *user_data) {
    (void)bootstrap;

    struct aws_echo_server *server = user_data;
    bool should_shutdown = false;

    aws_mutex_lock(&server->lock);

    if (error_code != AWS_ERROR_SUCCESS) {
        server->sync.state = AWS_ECHO_SS_SHUTDOWN;
    } else {
        should_shutdown = server->sync.state == AWS_ECHO_SS_SHUTTING_DOWN;
        server->sync.state = AWS_ECHO_SS_LISTENING;
    }

    aws_mutex_unlock(&server->lock);

    if (server->config->on_setup) {
        (*server->config->on_setup)(server, error_code, server->config->on_setup_user_data);
    }

    if (error_code != AWS_ERROR_SUCCESS) {
        aws_ref_count_release(&server->internal_ref_count); // Internal Ref Case 2
    }

    if (should_shutdown) {
        s_shut_down_echo_server(server);
    }
}

struct aws_echo_connection_options {
    struct aws_echo_server *server;

    struct aws_channel *channel;

    uint64_t id;
};

static void s_aws_echo_server_on_connection_shutdown(
    struct aws_echo_connection *connection,
    int error_code,
    void *user_data) {
    struct aws_echo_server *server = user_data;

    aws_mutex_lock(&server->lock);

    int was_present = false;
    aws_hash_table_remove(&server->sync.connections_by_id, &connection->id, NULL, &was_present);

    aws_mutex_unlock(&server->lock);

    if (was_present) {
        aws_ref_count_release(&connection->ref_count);
        ;
    }
}

static void s_aws_echo_connection_destroy(void *user_data) {
    struct aws_echo_connection *connection = user_data;

    aws_ref_count_release(&connection->server->internal_ref_count); // Internal Ref Case 3

    aws_mem_release(connection->allocator, connection);
}

static struct aws_echo_connection *s_aws_echo_connection_new(
    struct aws_allocator *allocator,
    struct aws_echo_connection_options *options) {
    struct aws_echo_connection *connection = aws_mem_calloc(allocator, 1, sizeof(struct aws_echo_connection));

    connection->allocator = allocator;
    aws_ref_count_init(&connection->ref_count, connection, s_aws_echo_connection_destroy);
    connection->id = options->id;
    connection->server = options->server;
    aws_ref_count_acquire(&connection->server->internal_ref_count); // Internal Ref Case 3

    connection->state = AWS_ECHO_CS_ACTIVE;
    connection->event_loop = aws_channel_get_event_loop(options->channel);
    connection->channel = options->channel;

    connection->on_shutdown = s_aws_echo_server_on_connection_shutdown;
    connection->on_shutdown_user_data = options->server;

    return connection;
}

static int s_echo_connection_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)slot;

    struct aws_echo_connection *connection = handler->impl;
    if (connection->state != AWS_ECHO_CS_ACTIVE) {
        // not necessarily invalid, but we don't want to handle it (during shut down)
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    // reflect it
    if (aws_channel_slot_send_message(slot, message, AWS_CHANNEL_DIR_WRITE)) {
        s_aws_echo_connection_shutdown(connection, aws_last_error());
        aws_mem_release(message->allocator, message);
    }

    return AWS_OP_SUCCESS;
}

static int s_echo_connection_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    struct aws_echo_connection *connection = handler->impl;
    s_aws_echo_connection_update_error_code(connection, error_code);

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
}

static size_t s_echo_connection_handler_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;

    return SIZE_MAX;
}

static size_t s_echo_connection_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;

    return 0;
}

static void s_echo_connection_handler_destroy(struct aws_channel_handler *handler) {
    struct aws_echo_connection *connection = handler->impl;
    s_aws_echo_connection_on_channel_destroyed(connection);
}

static struct aws_channel_handler_vtable s_echo_connection_handler_vtable = {
    .process_read_message = s_echo_connection_handler_process_read_message,
    .process_write_message = NULL,
    .increment_read_window = NULL,
    .shutdown = s_echo_connection_handler_shutdown,
    .initial_window_size = s_echo_connection_handler_initial_window_size,
    .message_overhead = s_echo_connection_handler_message_overhead,
    .destroy = s_echo_connection_handler_destroy,
    .reset_statistics = NULL,
    .gather_statistics = NULL,
    .trigger_read = NULL,
};

static void s_aws_echo_server_bootstrap_on_accept_channel_setup_fn(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;

    if (error_code != AWS_ERROR_SUCCESS) {
        return; // Nothing to do
    }

    struct aws_echo_server *server = user_data;

    struct aws_echo_connection_options connection_options = {
        .server = server,
        .id = 0,
        .channel = channel,
    };

    aws_mutex_lock(&server->lock);

    connection_options.id = server->sync.next_id++;
    struct aws_echo_connection *connection = s_aws_echo_connection_new(server->allocator, &connection_options);
    aws_hash_table_put(&server->sync.connections_by_id, &connection->id, connection, NULL);

    aws_mutex_unlock(&server->lock);

    struct aws_channel_slot *slot = aws_channel_slot_new(channel);

    struct aws_channel_handler *channel_handler = &connection->channel_handler;
    channel_handler->vtable = &s_echo_connection_handler_vtable;
    channel_handler->alloc = server->allocator;
    channel_handler->impl = connection;
    channel_handler->slot = slot;

    aws_channel_slot_insert_end(channel, slot);

    aws_channel_slot_set_handler(slot, &connection->channel_handler);
}

static void s_aws_echo_server_bootstrap_on_accept_channel_shutdown_fn(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    (void)channel;

    struct aws_echo_connection *connection = user_data;
    s_aws_echo_connection_update_error_code(connection, error_code);
}

static void s_aws_echo_server_bootstrap_on_server_listener_destroy_fn(
    struct aws_server_bootstrap *bootstrap,
    void *user_data) {
    (void)bootstrap;

    struct aws_echo_server *server = user_data;

    aws_ref_count_release(&server->internal_ref_count); // Internal Ref Case 2
}

int aws_echo_server_begin_accept(struct aws_echo_server *server) {
    if (!server) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    bool can_proceed = false;
    aws_mutex_lock(&server->lock);
    can_proceed = server->sync.state == AWS_ECHO_SS_INITIAL;
    if (can_proceed) {
        server->sync.state = AWS_ECHO_SS_PENDING_LISTENER;
    }
    aws_mutex_unlock(&server->lock);

    if (!can_proceed) {
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    aws_ref_count_acquire(&server->internal_ref_count); // Internal Ref Case 2

    struct aws_server_socket_channel_bootstrap_options listener_options = {
        .bootstrap = server->config->listener_bootstrap,
        .host_name = aws_string_c_str(server->config->host_name),
        .port = server->config->port,
        .socket_options = &server->config->socket_options,
        .tls_options = NULL,
        .setup_callback = s_aws_echo_server_bootstrap_on_listener_setup_fn,
        .incoming_callback = s_aws_echo_server_bootstrap_on_accept_channel_setup_fn,
        .shutdown_callback = s_aws_echo_server_bootstrap_on_accept_channel_shutdown_fn,
        .destroy_callback = s_aws_echo_server_bootstrap_on_server_listener_destroy_fn,
        .enable_read_back_pressure = false,
        .user_data = server,
    };

    struct aws_socket *listener = aws_server_bootstrap_new_socket_listener(&listener_options);
    if (!listener) {
        goto error;
    }

    aws_mutex_lock(&server->lock);
    server->sync.listener_socket = listener;
    aws_mutex_unlock(&server->lock);

    return AWS_OP_SUCCESS;

error:

    aws_ref_count_release(&server->internal_ref_count); // Internal Ref Case 2

    return AWS_OP_ERR;
}

uint16_t aws_echo_server_get_listener_port(struct aws_echo_server *server) {
    uint16_t port = 0;

    aws_mutex_lock(&server->lock);
    port = server->sync.listener_socket->local_endpoint.port;
    aws_mutex_unlock(&server->lock);

    return port;
}

static void s_aws_echo_server_test_context_on_server_setup(
    struct aws_echo_server *server,
    int error_code,
    void *user_data) {
    (void)server;
    (void)error_code;

    struct aws_echo_server_test_context *context = user_data;

    aws_mutex_lock(&context->lock);
    context->sync.server_setup = true;
    context->sync.setup_error_code = error_code;
    if (error_code != AWS_ERROR_SUCCESS) {
        context->sync.server_shutdown = true;
    }
    aws_mutex_unlock(&context->lock);

    aws_condition_variable_notify_all(&context->signal);
}

static void s_aws_echo_server_test_context_on_server_destroy(struct aws_echo_server *server, void *user_data) {
    (void)server;

    struct aws_echo_server_test_context *context = user_data;

    aws_mutex_lock(&context->lock);
    context->sync.server_shutdown = true;
    aws_mutex_unlock(&context->lock);

    aws_condition_variable_notify_all(&context->signal);
}

void aws_echo_server_test_context_init(struct aws_echo_server_test_context *context, struct aws_allocator *allocator, struct aws_event_loop_group *elg) {
    AWS_ZERO_STRUCT(*context);

    context->allocator = allocator;

    if (elg != NULL) {
        context->elg = aws_event_loop_group_acquire(elg);
    } else {
        struct aws_event_loop_group_options elg_options = {};
        context->elg = aws_event_loop_group_new(allocator, &elg_options);
    }

    context->server_bootstrap = aws_server_bootstrap_new(context->allocator, context->elg);

    aws_mutex_init(&context->lock);
    aws_condition_variable_init(&context->signal);

    struct aws_echo_server_options server_options = {
        .elg = context->elg,
        .listener_bootstrap = context->server_bootstrap,
        .host_name = "127.0.0.1",
        .port = 0,
        .socket_options =
            {
                .type = AWS_SOCKET_STREAM,
                .domain = AWS_SOCKET_IPV4,
            },
        .on_setup = s_aws_echo_server_test_context_on_server_setup,
        .on_setup_user_data = context,
        .on_destroy = s_aws_echo_server_test_context_on_server_destroy,
        .on_destroy_user_data = context,
    };

    context->server = aws_echo_server_new(allocator, &server_options);

    aws_echo_server_begin_accept(context->server);
}

static bool s_check_echo_server_setup(void *user_data) {
    struct aws_echo_server_test_context *context = user_data;

    return context->sync.server_setup;
}

void aws_echo_server_test_context_wait_on_server_setup(struct aws_echo_server_test_context *context) {
    aws_mutex_lock(&context->lock);
    aws_condition_variable_wait_pred(&context->signal, &context->lock, s_check_echo_server_setup, context);
    aws_mutex_unlock(&context->lock);
}

static bool s_check_echo_server_destroyed(void *user_data) {
    struct aws_echo_server_test_context *context = user_data;

    return context->sync.server_shutdown;
}

static void s_aws_echo_server_test_context_wait_on_server_shutdown(struct aws_echo_server_test_context *context) {
    aws_mutex_lock(&context->lock);
    aws_condition_variable_wait_pred(&context->signal, &context->lock, s_check_echo_server_destroyed, context);
    aws_mutex_unlock(&context->lock);
}

void aws_echo_server_test_context_clean_up(struct aws_echo_server_test_context *context) {

    aws_echo_server_release(context->server);

    s_aws_echo_server_test_context_wait_on_server_shutdown(context);

    aws_server_bootstrap_release(context->server_bootstrap);
    aws_event_loop_group_release(context->elg);

    aws_condition_variable_clean_up(&context->signal);
    aws_mutex_clean_up(&context->lock);
}