/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include "./socks5_server.h"

#include <aws/common/byte_buf.h>
#include <aws/common/hash_table.h>
#include <aws/common/mutex.h>
#include <aws/common/ref_count.h>
#include <aws/common/string.h>
#include <aws/io/channel.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/io/event_loop.h>

struct aws_socks5_server_auth_config {
    struct aws_allocator *allocator;

    bool allow_no_auth;
    bool allow_basic_auth;
    struct aws_byte_buf basic_username;
    struct aws_byte_buf basic_password;
};

struct aws_socks5_server_config {
    struct aws_allocator *allocator;

    struct aws_event_loop_group *elg;
    struct aws_client_bootstrap *to_remote_bootstrap;
    struct aws_server_bootstrap *listener_bootstrap;

    struct aws_string *host_name;
    uint16_t port;

    struct aws_socket_options socket_options;

    struct aws_socks5_server_auth_config *auth_config;

    void (*on_setup)(struct aws_socks5_server *server, int error_code, void *user_data);
    void *on_setup_user_data;

    void (*on_destroy)(struct aws_socks5_server *server, void *user_data);
    void *on_destroy_user_data;
};

enum aws_socks5_server_state {
    AWS_SOCKS5_SS_INITIAL,
    AWS_SOCKS5_SS_PENDING_LISTENER,
    AWS_SOCKS5_SS_LISTENING,
    AWS_SOCKS5_SS_SHUTTING_DOWN,
    AWS_SOCKS5_SS_SHUTDOWN,
};

struct aws_socks5_server {
    struct aws_allocator *allocator;

    struct aws_ref_count external_ref_count;

    /*
     * Internal Ref Cases:
     *  1. External ref count holds one internal ref while non-zero
     *  2. The listener socket holds a ref while alive
     *  3. Each tunnel holds an internal ref
     */
    struct aws_ref_count internal_ref_count;

    struct aws_socks5_server_config *config;

    struct aws_mutex lock;

    struct {
        enum aws_socks5_server_state state;
        uint64_t next_id;
        struct aws_hash_table tunnels_by_id;
        struct aws_socket *listener_socket;
    } sync;
};

enum aws_socks5_tunnel_state {
    AWS_SOCKS5_TS_PENDING_METHOD_LIST,
    AWS_SOCKS5_TS_PENDING_BASIC_AUTH_RECORD,
    AWS_SOCKS5_TS_PENDING_COMMAND,
    AWS_SOCKS5_TS_PENDING_REMOTE_CONNECTION,
    AWS_SOCKS5_TS_PASS_THROUGH,
    AWS_SOCKS5_TS_SHUTTING_DOWN,
    AWS_SOCKS5_TS_SHUTDOWN,
};

enum aws_socks5_auth_method_ids {
    AWS_SOCKS5_AMI_NONE = 0x00,
    AWS_SOCKS5_AMI_BASIC = 0x02,
    AWS_SOCSK5_AMI_NO_ACCEPTABLE = 0xFF
};

enum aws_socks5_command_ids {
    AWS_SOCKS5_COMMAND_CONNECT = 0x01,
    AWS_SOCKS5_COMMAND_BIND = 0x02,
    AWS_SOCKS5_COMMAND_ASSOCIATE = 0x03,
};

enum aws_socks5_address_type {
    AWS_SOCKS5_AT_IPV4 = 0x01,
    AWS_SOCKS5_AT_DOMAIN_NAME = 0x03,
    AWS_SOCKS5_AT_IPV6 = 0x04,
};

struct aws_socks5_tunnel {
    struct aws_allocator *allocator;

    struct aws_ref_count ref_count;

    uint64_t id;

    struct aws_socks5_server *server;

    enum aws_socks5_tunnel_state state;

    enum aws_socks5_auth_method_ids selected_auth_method;

    struct aws_string *remote_host_name;
    uint16_t remote_port;

    struct aws_event_loop *event_loop;

    struct aws_channel *to_client;
    struct aws_channel_handler to_client_handler;

    struct aws_channel *to_remote;
    struct aws_channel_handler to_remote_handler;

    struct aws_byte_buf handshake_data;

    int shutdown_error_code;

    bool pending_remote;
    void (*on_shutdown)(struct aws_socks5_tunnel *tunnel, int error_code, void *user_data);
    void *on_shutdown_user_data;
};

static struct aws_socks5_server_auth_config *s_aws_socks5_server_auth_config_new(
    struct aws_allocator *allocator,
    struct aws_socks5_server_auth_options *options) {

    struct aws_socks5_server_auth_config *config =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_server_auth_config));

    config->allocator = allocator;

    if (options != NULL) {
        config->allow_no_auth = options->allow_no_auth;
        config->allow_basic_auth = options->allow_basic_auth;

        if (options->allow_basic_auth) {
            if (options->basic_username) {
                aws_byte_buf_init_copy_from_cursor(&config->basic_username, allocator, *options->basic_username);
            }

            if (options->basic_password) {
                aws_byte_buf_init_copy_from_cursor(&config->basic_password, allocator, *options->basic_password);
            }
        }
    }

    return config;
}

static void s_aws_socks5_server_auth_config_destroy(struct aws_socks5_server_auth_config *config) {
    if (config == NULL) {
        return;
    }

    aws_byte_buf_clean_up(&config->basic_username);
    aws_byte_buf_clean_up(&config->basic_password);

    aws_mem_release(config->allocator, config);
}

static struct aws_socks5_server_config *s_aws_socks5_server_config_new(
    struct aws_allocator *allocator,
    struct aws_socks5_server_options *options) {

    struct aws_socks5_server_config *config = aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_server_config));

    config->allocator = allocator;
    config->elg = aws_event_loop_group_acquire(options->elg);
    config->to_remote_bootstrap = aws_client_bootstrap_acquire(options->to_remote_bootstrap);
    config->listener_bootstrap = aws_server_bootstrap_acquire(options->listener_bootstrap);
    config->host_name = aws_string_new_from_c_str(allocator, options->host_name);
    config->port = options->port;
    config->socket_options = options->socket_options;
    config->auth_config = s_aws_socks5_server_auth_config_new(allocator, &options->auth_options);
    config->on_setup = options->on_setup;
    config->on_setup_user_data = options->on_setup_user_data;
    config->on_destroy = options->on_destroy;
    config->on_destroy_user_data = options->on_destroy_user_data;

    return config;
}

static void s_aws_socks5_server_config_destroy(struct aws_socks5_server_config *config) {
    if (config == NULL) {
        return;
    }

    s_aws_socks5_server_auth_config_destroy(config->auth_config);

    aws_string_destroy(config->host_name);

    aws_event_loop_group_release(config->elg);
    aws_client_bootstrap_release(config->to_remote_bootstrap);
    aws_server_bootstrap_release(config->listener_bootstrap);

    aws_mem_release(config->allocator, config);
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

static void s_shut_down_server(struct aws_socks5_server *server) {

    struct aws_socket *listener = NULL;

    aws_mutex_lock(&server->lock);

    // shut down listener, wait for shutdown callback
    switch (server->sync.state) {
        case AWS_SOCKS5_SS_PENDING_LISTENER:
            server->sync.state = AWS_SOCKS5_SS_SHUTTING_DOWN;
            // can't do anything, have to wait for async listener to complete and then shut it down in the callback
            break;

        case AWS_SOCKS5_SS_LISTENING:
            server->sync.state = AWS_SOCKS5_SS_SHUTTING_DOWN;
            listener = server->sync.listener_socket;
            server->sync.listener_socket = NULL;
            break;

        case AWS_SOCKS5_SS_INITIAL:
            server->sync.state = AWS_SOCKS5_SS_SHUTDOWN;
            break;

        default:
            // do nothing (shutting down, shut down)
            break;
    }

    aws_mutex_unlock(&server->lock);

    if (listener) {
        aws_server_bootstrap_destroy_socket_listener(server->config->listener_bootstrap, listener);
    }
}

static void s_on_server_external_ref_count_zero(void *user_data) {
    struct aws_socks5_server *server = user_data;

    s_shut_down_server(server);

    // External ref count holds one internal ref
    aws_ref_count_release(&server->internal_ref_count); // Internal Ref Case 1
}

static void s_on_server_internal_ref_count_zero(void *user_data) {

    struct aws_socks5_server *server = user_data;

    aws_mutex_clean_up(&server->lock);

    AWS_FATAL_ASSERT(aws_hash_table_get_entry_count(&server->sync.tunnels_by_id) == 0);

    aws_hash_table_clean_up(&server->sync.tunnels_by_id);

    if (server->config->on_destroy) {
        (*server->config->on_destroy)(server, server->config->on_destroy_user_data);
    }

    s_aws_socks5_server_config_destroy(server->config);

    aws_mem_release(server->allocator, server);
}

struct aws_socks5_server *aws_socks5_server_new(
    struct aws_allocator *allocator,
    struct aws_socks5_server_options *options) {

    struct aws_socks5_server *server = aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_server));

    server->allocator = allocator;

    aws_ref_count_init(&server->external_ref_count, server, s_on_server_external_ref_count_zero);
    aws_ref_count_init(&server->internal_ref_count, server, s_on_server_internal_ref_count_zero); // Internal Ref Case 1

    server->config = s_aws_socks5_server_config_new(allocator, options);

    aws_mutex_init(&server->lock);

    server->sync.state = AWS_SOCKS5_SS_INITIAL;
    server->sync.next_id = 1;
    aws_hash_table_init(
        &server->sync.tunnels_by_id,
        allocator,
        4,
        aws_hash_uint64_t_by_identity,
        aws_hash_compare_uint64_t_eq,
        NULL,
        NULL);

    return server;
}

struct aws_socks5_server *aws_socks5_server_acquire(struct aws_socks5_server *server) {
    if (server) {
        aws_ref_count_acquire(&server->external_ref_count);
    }

    return server;
}

void aws_socks5_server_release(struct aws_socks5_server *server) {
    aws_ref_count_release(&server->external_ref_count);
}

static void s_aws_socks5_server_bootstrap_on_listener_setup_fn(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    void *user_data) {
    (void)bootstrap;

    struct aws_socks5_server *server = user_data;
    bool should_shutdown = false;

    aws_mutex_lock(&server->lock);

    if (error_code != AWS_ERROR_SUCCESS) {
        server->sync.state = AWS_SOCKS5_SS_SHUTDOWN;
    } else {
        should_shutdown = server->sync.state == AWS_SOCKS5_SS_SHUTTING_DOWN;
        server->sync.state = AWS_SOCKS5_SS_LISTENING;
    }

    aws_mutex_unlock(&server->lock);

    if (server->config->on_setup) {
        (*server->config->on_setup)(server, error_code, server->config->on_setup_user_data);
    }

    if (error_code != AWS_ERROR_SUCCESS) {
        aws_ref_count_release(&server->internal_ref_count); // Internal Ref Case 2
    }

    if (should_shutdown) {
        s_shut_down_server(server);
    }
}

struct aws_socks5_tunnel_options {
    struct aws_socks5_server *server;

    struct aws_channel *to_client_channel;

    uint64_t id;
};

static void s_aws_socks5_server_on_tunnel_shutdown(struct aws_socks5_tunnel *tunnel, int error_code, void *user_data) {
    struct aws_socks5_server *server = user_data;

    aws_mutex_lock(&server->lock);

    int was_present = false;
    aws_hash_table_remove(&server->sync.tunnels_by_id, &tunnel->id, NULL, &was_present);

    aws_mutex_unlock(&server->lock);

    if (was_present) {
        aws_ref_count_release(&tunnel->ref_count);
        ;
    }
}

static void s_aws_socks5_tunnel_destroy(void *user_data) {
    struct aws_socks5_tunnel *tunnel = user_data;

    aws_string_destroy(tunnel->remote_host_name);
    aws_byte_buf_clean_up(&tunnel->handshake_data);
    aws_ref_count_release(&tunnel->server->internal_ref_count); // Internal Ref Case 3

    aws_mem_release(tunnel->allocator, tunnel);
}

static struct aws_socks5_tunnel *s_aws_socks5_tunnel_new(
    struct aws_allocator *allocator,
    struct aws_socks5_tunnel_options *options) {
    struct aws_socks5_tunnel *tunnel = aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_tunnel));

    tunnel->allocator = allocator;
    aws_ref_count_init(&tunnel->ref_count, tunnel, s_aws_socks5_tunnel_destroy);
    tunnel->id = options->id;
    tunnel->server = options->server;
    aws_ref_count_acquire(&tunnel->server->internal_ref_count); // Internal Ref Case 3

    tunnel->state = AWS_SOCKS5_TS_PENDING_METHOD_LIST;
    tunnel->selected_auth_method = AWS_SOCSK5_AMI_NO_ACCEPTABLE;
    tunnel->event_loop = aws_channel_get_event_loop(options->to_client_channel);
    tunnel->to_client = options->to_client_channel;

    aws_byte_buf_init(&tunnel->handshake_data, allocator, 512);

    tunnel->on_shutdown = s_aws_socks5_server_on_tunnel_shutdown;
    tunnel->on_shutdown_user_data = options->server;

    return tunnel;
}

static void s_aws_socks5_tunnel_update_error_code(struct aws_socks5_tunnel *tunnel, int error_code) {
    if (tunnel->shutdown_error_code == AWS_ERROR_SUCCESS) {
        tunnel->shutdown_error_code = error_code;
    }
}

static void s_aws_socks5_tunnel_change_state(struct aws_socks5_tunnel *tunnel, enum aws_socks5_tunnel_state new_state) {
    tunnel->state = new_state;
    aws_byte_buf_reset(&tunnel->handshake_data, false);
}

static void s_aws_socks5_tunnel_on_channel_destroyed(struct aws_socks5_tunnel *tunnel, struct aws_channel *channel) {
    AWS_FATAL_ASSERT(aws_event_loop_thread_is_callers_thread(tunnel->event_loop));

    if (tunnel->to_remote == channel) {
        tunnel->to_remote = NULL;
    }

    if (tunnel->to_client == channel) {
        tunnel->to_client = NULL;
    }

    if (tunnel->to_remote == NULL && tunnel->to_client == NULL && !tunnel->pending_remote) {
        s_aws_socks5_tunnel_change_state(tunnel, AWS_SOCKS5_TS_SHUTDOWN);
        (*tunnel->on_shutdown)(tunnel, tunnel->shutdown_error_code, tunnel->on_shutdown_user_data);
    }
}

struct aws_socks5_tunnel_shutdown_task {
    struct aws_allocator *allocator;

    struct aws_task task;

    struct aws_socks5_tunnel *tunnel;
    int error_code;
};

static void s_aws_socks5_tunnel_shutdown_task_destroy(struct aws_socks5_tunnel_shutdown_task *task) {
    aws_ref_count_release(&task->tunnel->ref_count);
    aws_mem_release(task->allocator, task);
}

static void s_aws_socks5_tunnel_shutdown_task_fn(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct aws_socks5_tunnel_shutdown_task *shutdown_task = arg;

    if (status == AWS_TASK_STATUS_CANCELED) {
        goto done;
    }

    struct aws_socks5_tunnel *tunnel = shutdown_task->tunnel;
    AWS_FATAL_ASSERT(aws_event_loop_thread_is_callers_thread(tunnel->event_loop));

    if (tunnel->state == AWS_SOCKS5_TS_SHUTTING_DOWN || tunnel->state == AWS_SOCKS5_TS_SHUTDOWN) {
        goto done;
    }

    tunnel->state = AWS_SOCKS5_TS_SHUTTING_DOWN;

    s_aws_socks5_tunnel_update_error_code(tunnel, shutdown_task->error_code);

    if (tunnel->to_remote) {
        aws_channel_shutdown(tunnel->to_remote, tunnel->shutdown_error_code);
    }

    if (tunnel->to_client) {
        aws_channel_shutdown(tunnel->to_client, tunnel->shutdown_error_code);
    }

    s_aws_socks5_tunnel_on_channel_destroyed(tunnel, NULL);

done:

    s_aws_socks5_tunnel_shutdown_task_destroy(shutdown_task);
}

static struct aws_socks5_tunnel_shutdown_task *s_aws_socks5_tunnel_shutdown_task_new(
    struct aws_allocator *allocator,
    struct aws_socks5_tunnel *tunnel,
    int error_code) {

    struct aws_socks5_tunnel_shutdown_task *task =
        aws_mem_calloc(allocator, 1, sizeof(struct aws_socks5_tunnel_shutdown_task));
    task->allocator = allocator;
    task->tunnel = tunnel;
    aws_ref_count_acquire(&tunnel->ref_count);
    task->error_code = error_code;

    aws_task_init(&task->task, s_aws_socks5_tunnel_shutdown_task_fn, task, "socks5tunnelshutdown");

    return task;
}

static void s_aws_socks5_tunnel_shutdown(struct aws_socks5_tunnel *tunnel, int error_code) {
    struct aws_socks5_tunnel_shutdown_task *task =
        s_aws_socks5_tunnel_shutdown_task_new(tunnel->allocator, tunnel, error_code);

    aws_event_loop_schedule_task_now_serialized(tunnel->event_loop, &task->task);
}

static bool s_methods_contains(struct aws_byte_cursor methods, uint8_t method) {
    uint8_t *method_ptr = methods.ptr;
    for (size_t i = 0; i < methods.len; ++i, ++method_ptr) {
        if (*method_ptr == method) {
            return true;
        }
    }

    return false;
}

static int s_send_method_selection(struct aws_socks5_tunnel *tunnel, enum aws_socks5_auth_method_ids method) {
    tunnel->selected_auth_method = method;

    struct aws_io_message *message =
        aws_channel_acquire_message_from_pool(tunnel->to_client, AWS_IO_MESSAGE_APPLICATION_DATA, 2);

    uint8_t method_selection_data[2] = {0x05, method};

    struct aws_byte_cursor method_selection_data_cursor =
        aws_byte_cursor_from_array(method_selection_data, AWS_ARRAY_SIZE(method_selection_data));
    aws_byte_buf_append(&message->message_data, &method_selection_data_cursor);

    if (aws_channel_slot_send_message(tunnel->to_client_handler.slot, message, AWS_CHANNEL_DIR_WRITE)) {
        aws_mem_release(message->allocator, message);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static int s_handle_pending_method_list(struct aws_socks5_tunnel *tunnel, struct aws_io_message *message) {
    struct aws_byte_cursor message_data = {
        .ptr = message->message_data.buffer + message->copy_mark,
        .len = message->message_data.len - message->copy_mark,
    };

    aws_byte_buf_append_dynamic(&tunnel->handshake_data, &message_data);

    size_t handshake_data_len = tunnel->handshake_data.len;
    if (handshake_data_len < 2) {
        return AWS_OP_SUCCESS;
    }

    uint8_t num_methods = *(tunnel->handshake_data.buffer + 1);
    if (handshake_data_len < num_methods + 2) {
        return AWS_OP_SUCCESS;
    }

    if (handshake_data_len != num_methods + 2) {
        return aws_raise_error(AWS_IO_SOCKS5_PROTOCOL_FAILURE);
    }

    struct aws_byte_cursor methods = aws_byte_cursor_from_buf(&tunnel->handshake_data);
    methods = aws_byte_cursor_advance(&methods, 2);

    enum aws_socks5_auth_method_ids selected_method = AWS_SOCSK5_AMI_NO_ACCEPTABLE;
    struct aws_socks5_server_auth_config *auth_config = tunnel->server->config->auth_config;
    if (auth_config->allow_basic_auth) {
        if (s_methods_contains(methods, AWS_SOCKS5_AMI_BASIC)) {
            selected_method = AWS_SOCKS5_AMI_BASIC;
        }
    }

    if (auth_config->allow_no_auth) {
        if (s_methods_contains(methods, AWS_SOCKS5_AMI_NONE)) {
            selected_method = AWS_SOCKS5_AMI_NONE;
        }
    }

    if (s_send_method_selection(tunnel, selected_method)) {
        return AWS_OP_ERR;
    }

    enum aws_socks5_tunnel_state new_state = (selected_method == AWS_SOCKS5_AMI_BASIC)
                                                 ? AWS_SOCKS5_TS_PENDING_BASIC_AUTH_RECORD
                                                 : AWS_SOCKS5_TS_PENDING_COMMAND;
    s_aws_socks5_tunnel_change_state(tunnel, new_state);

    return AWS_OP_SUCCESS;
}

static int s_handle_basic_auth_record(struct aws_socks5_tunnel *tunnel, struct aws_io_message *message) {
    struct aws_byte_cursor message_data = {
        .ptr = message->message_data.buffer + message->copy_mark,
        .len = message->message_data.len - message->copy_mark,
    };

    aws_byte_buf_append_dynamic(&tunnel->handshake_data, &message_data);

    size_t handshake_data_len = tunnel->handshake_data.len;
    if (handshake_data_len < 2) {
        return AWS_OP_SUCCESS;
    }

    size_t username_length = tunnel->handshake_data.buffer[1];
    if (handshake_data_len < username_length + 3) {
        return AWS_OP_SUCCESS;
    }

    size_t password_length = tunnel->handshake_data.buffer[username_length + 2];
    size_t required_record_length = username_length + password_length + 3;
    if (handshake_data_len < required_record_length) {
        return AWS_OP_SUCCESS;
    }

    if (handshake_data_len > required_record_length) {
        return aws_raise_error(AWS_IO_SOCKS5_PROTOCOL_FAILURE);
    }

    struct aws_byte_cursor username_cursor =
        aws_byte_cursor_from_array(tunnel->handshake_data.buffer + 2, username_length);
    struct aws_byte_cursor password_cursor =
        aws_byte_cursor_from_array(tunnel->handshake_data.buffer + username_length + 3, password_length);
    struct aws_byte_cursor expected_username_cursor =
        aws_byte_cursor_from_buf(&tunnel->server->config->auth_config->basic_username);
    struct aws_byte_cursor expected_password_cursor =
        aws_byte_cursor_from_buf(&tunnel->server->config->auth_config->basic_password);
    uint8_t response_byte = 0x01;

    if (aws_byte_cursor_eq(&username_cursor, &expected_username_cursor) &&
        aws_byte_cursor_eq(&password_cursor, &expected_password_cursor)) {
        response_byte = 0x00;
    }

    struct aws_io_message *result_message =
        aws_channel_acquire_message_from_pool(tunnel->to_client, AWS_IO_MESSAGE_APPLICATION_DATA, 2);

    uint8_t auth_result_data[2] = {0x01, response_byte};

    struct aws_byte_cursor auth_result_data_cursor =
        aws_byte_cursor_from_array(auth_result_data, AWS_ARRAY_SIZE(auth_result_data));
    aws_byte_buf_append(&result_message->message_data, &auth_result_data_cursor);

    if (aws_channel_slot_send_message(tunnel->to_client_handler.slot, result_message, AWS_CHANNEL_DIR_WRITE)) {
        aws_mem_release(result_message->allocator, result_message);
        return AWS_OP_ERR;
    }

    s_aws_socks5_tunnel_change_state(tunnel, AWS_SOCKS5_TS_PENDING_COMMAND);

    return AWS_OP_SUCCESS;
}

static int s_socks5_tunnel_to_remote_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)slot;

    struct aws_socks5_tunnel *tunnel = handler->impl;
    if (tunnel->state != AWS_SOCKS5_TS_PASS_THROUGH) {
        // not necessarily invalid, but we don't want to handle it (during shut down)
        return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    // write it to the client channel
    if (aws_channel_slot_send_message(tunnel->to_client_handler.slot, message, AWS_CHANNEL_DIR_WRITE)) {
        s_aws_socks5_tunnel_shutdown(tunnel, aws_last_error());
        aws_mem_release(message->allocator, message);
    }

    return AWS_OP_SUCCESS;
}

static int s_socks5_tunnel_to_remote_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    struct aws_socks5_tunnel *tunnel = handler->impl;
    s_aws_socks5_tunnel_update_error_code(tunnel, error_code);

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
}

static size_t s_socks5_tunnel_to_remote_handler_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;

    return SIZE_MAX;
}

static size_t s_socks5_tunnel_to_remote_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;

    return 0;
}

static void s_socks5_tunnel_to_remote_handler_destroy(struct aws_channel_handler *handler) {
    struct aws_socks5_tunnel *tunnel = handler->impl;
    s_aws_socks5_tunnel_on_channel_destroyed(tunnel, tunnel->to_remote);
}

static struct aws_channel_handler_vtable s_socks5_tunnel_to_remote_handler_vtable = {
    .process_read_message = s_socks5_tunnel_to_remote_handler_process_read_message,
    .process_write_message = NULL,
    .increment_read_window = NULL,
    .shutdown = s_socks5_tunnel_to_remote_handler_shutdown,
    .initial_window_size = s_socks5_tunnel_to_remote_handler_initial_window_size,
    .message_overhead = s_socks5_tunnel_to_remote_handler_message_overhead,
    .destroy = s_socks5_tunnel_to_remote_handler_destroy,
    .reset_statistics = NULL,
    .gather_statistics = NULL,
    .trigger_read = NULL,
};

static void s_aws_socks5_tunnel_on_remote_channel_setup_fn(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    struct aws_socks5_tunnel *tunnel = user_data;
    tunnel->pending_remote = false;

    if (error_code != AWS_OP_SUCCESS) {
        s_aws_socks5_tunnel_shutdown(tunnel, error_code);
        return;
    }

    tunnel->to_remote = channel;

    struct aws_channel_slot *slot = aws_channel_slot_new(channel);

    struct aws_channel_handler *to_remote_handler = &tunnel->to_remote_handler;
    to_remote_handler->vtable = &s_socks5_tunnel_to_remote_handler_vtable;
    to_remote_handler->alloc = tunnel->allocator;
    to_remote_handler->impl = tunnel;
    to_remote_handler->slot = slot;

    aws_channel_slot_insert_end(channel, slot);

    aws_channel_slot_set_handler(slot, &tunnel->to_remote_handler);

    if (tunnel->state == AWS_SOCKS5_TS_SHUTTING_DOWN) {
        aws_channel_shutdown(channel, AWS_IO_SOCKS5_INTERNAL_FAILURE);
    } else {
        s_aws_socks5_tunnel_change_state(tunnel, AWS_SOCKS5_TS_PASS_THROUGH);
    }
}

static void s_aws_client_bootstrap_on_channel_shutdown_fn(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    (void)channel;

    struct aws_socks5_tunnel *tunnel = user_data;
    s_aws_socks5_tunnel_update_error_code(tunnel, error_code);
}

static int s_aws_socks5_tunnel_connect_to_remote(struct aws_socks5_tunnel *tunnel) {
    struct aws_socket_options socket_options = {
        .type = AWS_SOCKET_STREAM,
        .domain = AWS_SOCKET_IPV4,
        .connect_timeout_ms = 10000,
    };

    struct aws_socket_channel_bootstrap_options connect_options = {
        .bootstrap = tunnel->server->config->to_remote_bootstrap,
        .host_name = aws_string_c_str(tunnel->remote_host_name),
        .port = tunnel->remote_port,
        .socket_options = &socket_options,
        .tls_options = NULL,
        .creation_callback = NULL,
        .setup_callback = s_aws_socks5_tunnel_on_remote_channel_setup_fn,
        .shutdown_callback = s_aws_client_bootstrap_on_channel_shutdown_fn,
        .enable_read_back_pressure = false,
        .user_data = tunnel,
        .requested_event_loop = tunnel->event_loop,
    };

    tunnel->pending_remote = true;
    if (aws_client_bootstrap_new_socket_channel(&connect_options)) {
        tunnel->pending_remote = false;
        return AWS_OP_ERR;
    }

    s_aws_socks5_tunnel_change_state(tunnel, AWS_SOCKS5_TS_PENDING_REMOTE_CONNECTION);

    return AWS_OP_SUCCESS;
}

static int s_handle_command(struct aws_socks5_tunnel *tunnel, struct aws_io_message *message) {
    struct aws_byte_cursor message_data = {
        .ptr = message->message_data.buffer + message->copy_mark,
        .len = message->message_data.len - message->copy_mark,
    };

    aws_byte_buf_append_dynamic(&tunnel->handshake_data, &message_data);

    size_t handshake_data_len = tunnel->handshake_data.len;
    if (handshake_data_len < 5) {
        return AWS_OP_SUCCESS;
    }

    uint8_t command = tunnel->handshake_data.buffer[1];
    if (command != AWS_SOCKS5_COMMAND_CONNECT) {
        return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
    }

    uint8_t address_type = tunnel->handshake_data.buffer[3];
    if (address_type != AWS_SOCKS5_AT_DOMAIN_NAME) {
        return aws_raise_error(AWS_ERROR_UNIMPLEMENTED);
    }

    uint8_t address_length = tunnel->handshake_data.buffer[4];
    size_t expected_command_length = address_length + 7;
    if (handshake_data_len < expected_command_length) {
        return AWS_OP_SUCCESS;
    }

    if (handshake_data_len > expected_command_length) {
        return aws_raise_error(AWS_IO_SOCKS5_PROTOCOL_FAILURE);
    }

    struct aws_byte_cursor remote_host_name =
        aws_byte_cursor_from_array(tunnel->handshake_data.buffer + 5, address_length);
    tunnel->remote_host_name = aws_string_new_from_cursor(tunnel->allocator, &remote_host_name);

    struct aws_byte_cursor port_cursor =
        aws_byte_cursor_from_array(tunnel->handshake_data.buffer + 5 + address_length, 2);
    aws_byte_cursor_read_be16(&port_cursor, &tunnel->remote_port);

    return s_aws_socks5_tunnel_connect_to_remote(tunnel);
}

static int s_handle_pass_through(struct aws_socks5_tunnel *tunnel, struct aws_io_message *message) {
    return aws_channel_slot_send_message(tunnel->to_remote_handler.slot, message, AWS_CHANNEL_DIR_WRITE);
}

static int s_socks5_tunnel_to_client_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)slot;

    struct aws_socks5_tunnel *tunnel = handler->impl;
    int result = AWS_OP_SUCCESS;
    switch (tunnel->state) {
        case AWS_SOCKS5_TS_PENDING_METHOD_LIST:
            result = s_handle_pending_method_list(tunnel, message);
            break;

        case AWS_SOCKS5_TS_PENDING_BASIC_AUTH_RECORD:
            result = s_handle_basic_auth_record(tunnel, message);
            break;

        case AWS_SOCKS5_TS_PENDING_COMMAND:
            result = s_handle_command(tunnel, message);
            break;

        case AWS_SOCKS5_TS_PENDING_REMOTE_CONNECTION:
            // should never happen
            return aws_raise_error(AWS_ERROR_INVALID_STATE);

        case AWS_SOCKS5_TS_PASS_THROUGH:
            // write it to the remote channel
            result = s_handle_pass_through(tunnel, message);
            break;

        default:
            // not necessarily invalid, but we don't want to handle it (during shut down)
            return aws_raise_error(AWS_ERROR_INVALID_STATE);
    }

    if (result != AWS_OP_SUCCESS) {
        s_aws_socks5_tunnel_shutdown(tunnel, aws_last_error());
    }

    aws_mem_release(message->allocator, message);

    return AWS_OP_SUCCESS;
}

static int s_socks5_tunnel_to_client_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    struct aws_socks5_tunnel *tunnel = handler->impl;
    s_aws_socks5_tunnel_update_error_code(tunnel, error_code);

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, free_scarce_resources_immediately);
}

static size_t s_socks5_tunnel_to_client_handler_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;

    return SIZE_MAX;
}

static size_t s_socks5_tunnel_to_client_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;

    return 0;
}

static void s_socks5_tunnel_to_client_handler_destroy(struct aws_channel_handler *handler) {
    struct aws_socks5_tunnel *tunnel = handler->impl;
    s_aws_socks5_tunnel_on_channel_destroyed(tunnel, tunnel->to_client);
}

static struct aws_channel_handler_vtable s_socks5_tunnel_to_client_handler_vtable = {
    .process_read_message = s_socks5_tunnel_to_client_handler_process_read_message,
    .process_write_message = NULL,
    .increment_read_window = NULL,
    .shutdown = s_socks5_tunnel_to_client_handler_shutdown,
    .initial_window_size = s_socks5_tunnel_to_client_handler_initial_window_size,
    .message_overhead = s_socks5_tunnel_to_client_handler_message_overhead,
    .destroy = s_socks5_tunnel_to_client_handler_destroy,
    .reset_statistics = NULL,
    .gather_statistics = NULL,
    .trigger_read = NULL,
};

static void s_aws_socks5_server_bootstrap_on_accept_channel_setup_fn(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {

    (void)bootstrap;

    if (error_code != AWS_ERROR_SUCCESS) {
        return; // Nothing to do
    }

    struct aws_socks5_server *server = user_data;

    struct aws_socks5_tunnel_options tunnel_options = {
        .server = server,
        .id = 0,
        .to_client_channel = channel,
    };

    aws_mutex_lock(&server->lock);

    tunnel_options.id = server->sync.next_id++;
    struct aws_socks5_tunnel *tunnel = s_aws_socks5_tunnel_new(server->allocator, &tunnel_options);
    aws_hash_table_put(&server->sync.tunnels_by_id, &tunnel->id, tunnel, NULL);

    aws_mutex_unlock(&server->lock);

    struct aws_channel_slot *slot = aws_channel_slot_new(channel);

    struct aws_channel_handler *to_client_handler = &tunnel->to_client_handler;
    to_client_handler->vtable = &s_socks5_tunnel_to_client_handler_vtable;
    to_client_handler->alloc = server->allocator;
    to_client_handler->impl = tunnel;
    to_client_handler->slot = slot;

    aws_channel_slot_insert_end(channel, slot);

    aws_channel_slot_set_handler(slot, &tunnel->to_client_handler);
}

static void s_aws_socks5_server_bootstrap_on_accept_channel_shutdown_fn(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data) {
    (void)bootstrap;
    (void)channel;

    struct aws_socks5_tunnel *tunnel = user_data;
    s_aws_socks5_tunnel_update_error_code(tunnel, error_code);
}

static void s_aws_socks5_server_bootstrap_on_server_listener_destroy_fn(
    struct aws_server_bootstrap *bootstrap,
    void *user_data) {
    (void)bootstrap;

    struct aws_socks5_server *server = user_data;

    // with the listener destroyed, there should be no further connections
    // go through them all and shut them down
    // when all have been fully destroyed, our internal ref count will drop to zero, allowing the server to
    // self-destruct

    aws_mutex_lock(&server->lock);

    struct aws_array_list tunnels;
    aws_array_list_init_dynamic(
        &tunnels,
        server->allocator,
        aws_hash_table_get_entry_count(&server->sync.tunnels_by_id),
        sizeof(struct aws_socks5_tunnel *));

    for (struct aws_hash_iter iter = aws_hash_iter_begin(&server->sync.tunnels_by_id); !aws_hash_iter_done(&iter);
         aws_hash_iter_next(&iter)) {
        struct aws_socks5_tunnel *tunnel = iter.element.value;

        aws_array_list_push_back(&tunnels, &tunnel);
        aws_ref_count_acquire(&tunnel->ref_count);
    }

    aws_mutex_unlock(&server->lock);

    for (size_t i = 0; i < aws_array_list_length(&tunnels); i++) {
        struct aws_socks5_tunnel *tunnel = NULL;
        aws_array_list_get_at(&tunnels, &tunnel, i);

        s_aws_socks5_tunnel_shutdown(tunnel, AWS_ERROR_EXTERNAL_REQUEST_SHUTDOWN);
        aws_ref_count_release(&tunnel->ref_count);
    }

    aws_array_list_clean_up(&tunnels);

    aws_ref_count_release(&server->internal_ref_count); // Internal Ref Case 2
}

int aws_socks5_server_begin_accept(struct aws_socks5_server *server) {
    if (!server) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    bool can_proceed = false;
    aws_mutex_lock(&server->lock);
    can_proceed = server->sync.state == AWS_SOCKS5_SS_INITIAL;
    if (can_proceed) {
        server->sync.state = AWS_SOCKS5_SS_PENDING_LISTENER;
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
        .setup_callback = s_aws_socks5_server_bootstrap_on_listener_setup_fn,
        .incoming_callback = s_aws_socks5_server_bootstrap_on_accept_channel_setup_fn,
        .shutdown_callback = s_aws_socks5_server_bootstrap_on_accept_channel_shutdown_fn,
        .destroy_callback = s_aws_socks5_server_bootstrap_on_server_listener_destroy_fn,
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

uint16_t aws_socks5_server_get_listener_port(struct aws_socks5_server *server) {
    uint16_t port = 0;

    aws_mutex_lock(&server->lock);
    port = server->sync.listener_socket->local_endpoint.port;
    aws_mutex_unlock(&server->lock);

    return port;
}

static void s_aws_socks5_server_test_context_on_server_setup(
    struct aws_socks5_server *server,
    int error_code,
    void *user_data) {
    (void)server;
    (void)error_code;

    struct aws_socks5_server_test_context *context = user_data;

    aws_mutex_lock(&context->lock);
    context->sync.server_setup = true;
    context->sync.setup_error_code = error_code;
    if (error_code != AWS_ERROR_SUCCESS) {
        context->sync.server_shutdown = true;
    }
    aws_mutex_unlock(&context->lock);

    aws_condition_variable_notify_all(&context->signal);
}

static void s_aws_socks5_server_test_context_on_server_destroy(struct aws_socks5_server *server, void *user_data) {
    (void)server;

    struct aws_socks5_server_test_context *context = user_data;

    aws_mutex_lock(&context->lock);
    context->sync.server_shutdown = true;
    aws_mutex_unlock(&context->lock);

    aws_condition_variable_notify_all(&context->signal);
}

void aws_socks5_server_test_context_init(
    struct aws_socks5_server_test_context *context,
    struct aws_allocator *allocator,
    struct aws_socks5_server_auth_options *override_auth_options) {
    AWS_ZERO_STRUCT(*context);

    context->allocator = allocator;

    struct aws_event_loop_group_options elg_options = {};
    context->elg = aws_event_loop_group_new(allocator, &elg_options);

    struct aws_host_resolver_default_options hr_options = {
        .el_group = context->elg,
        .max_entries = 32,

    };
    context->resolver = aws_host_resolver_new_default(allocator, &hr_options);

    struct aws_client_bootstrap_options client_bootstrap_options = {
        .event_loop_group = context->elg,
        .host_resolver = context->resolver,
    };
    context->client_bootstrap = aws_client_bootstrap_new(context->allocator, &client_bootstrap_options);

    context->server_bootstrap = aws_server_bootstrap_new(context->allocator, context->elg);

    aws_mutex_init(&context->lock);
    aws_condition_variable_init(&context->signal);

    struct aws_socks5_server_options server_options = {
        .elg = context->elg,
        .to_remote_bootstrap = context->client_bootstrap,
        .listener_bootstrap = context->server_bootstrap,
        .host_name = "127.0.0.1",
        .port = 0,
        .socket_options =
            {
                .type = AWS_SOCKET_STREAM,
                .domain = AWS_SOCKET_IPV4,
            },
        .auth_options =
            {
                .allow_no_auth = true,
                .allow_basic_auth = false,
            },
        .on_setup = s_aws_socks5_server_test_context_on_server_setup,
        .on_setup_user_data = context,
        .on_destroy = s_aws_socks5_server_test_context_on_server_destroy,
        .on_destroy_user_data = context,
    };

    if (override_auth_options) {
        server_options.auth_options = *override_auth_options;
    }

    context->server = aws_socks5_server_new(allocator, &server_options);

    aws_socks5_server_begin_accept(context->server);
}

static bool s_check_server_setup(void *user_data) {
    struct aws_socks5_server_test_context *context = user_data;

    return context->sync.server_setup;
}

void aws_socks5_server_test_context_wait_on_server_setup(struct aws_socks5_server_test_context *context) {
    aws_mutex_lock(&context->lock);
    aws_condition_variable_wait_pred(&context->signal, &context->lock, s_check_server_setup, context);
    aws_mutex_unlock(&context->lock);
}

static bool s_check_server_destroyed(void *user_data) {
    struct aws_socks5_server_test_context *context = user_data;

    return context->sync.server_shutdown;
}

static void s_aws_socks5_server_test_context_wait_on_server_shutdown(struct aws_socks5_server_test_context *context) {
    aws_mutex_lock(&context->lock);
    aws_condition_variable_wait_pred(&context->signal, &context->lock, s_check_server_destroyed, context);
    aws_mutex_unlock(&context->lock);
}

void aws_socks5_server_test_context_clean_up(struct aws_socks5_server_test_context *context) {

    aws_socks5_server_release(context->server);

    s_aws_socks5_server_test_context_wait_on_server_shutdown(context);

    aws_server_bootstrap_release(context->server_bootstrap);
    aws_client_bootstrap_release(context->client_bootstrap);
    aws_host_resolver_release(context->resolver);
    aws_event_loop_group_release(context->elg);

    aws_condition_variable_clean_up(&context->signal);
    aws_mutex_clean_up(&context->lock);
}