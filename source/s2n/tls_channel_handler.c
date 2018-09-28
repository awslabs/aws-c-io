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
#include <aws/io/pki_utils.h>

#include <aws/common/task_scheduler.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <s2n.h>
#include <stdio.h>
#include <stdlib.h>

static const size_t EST_TLS_RECORD_OVERHEAD = 53; /* 5 byte header + 32 + 16 bytes for padding */

struct s2n_handler {
    struct s2n_connection *connection;
    struct aws_channel_slot *slot;
    struct aws_linked_list input_queue;
    struct aws_byte_buf protocol;
    struct aws_byte_buf server_name;
    struct aws_tls_connection_options options;
    aws_channel_on_message_write_completed_fn *latest_message_on_completion;
    struct aws_task sequential_tasks;
    void *latest_message_completion_user_data;
    bool negotiation_finished;
};

struct s2n_ctx {
    struct s2n_config *s2n_config;
};

void aws_tls_init_static_state(struct aws_allocator *alloc) {

    (void)alloc;

    setenv("S2N_ENABLE_CLIENT_MODE", "1", 1);
    setenv("S2N_DONT_MLOCK", "1", 1);
    s2n_init();
}

void aws_tls_clean_up_tl_state(void) {
    /* if you're wondering why this function exists, this is why.... s2n_cleanup() cleans up some allocated
     * memory in thread local state (sigh.....). */
    s2n_cleanup();
}

void aws_tls_clean_up_static_state(void) {
    s2n_cleanup();
}

bool aws_tls_is_alpn_available(void) {
    return true;
}

static int s_generic_read(struct s2n_handler *handler, struct aws_byte_buf *buf) {

    size_t written = 0;

    while (!aws_linked_list_empty(&handler->input_queue) && written < buf->len) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&handler->input_queue);
        struct aws_io_message *message = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);

        size_t remaining_message_len = message->message_data.len - message->copy_mark;
        size_t remaining_buf_len = buf->len - written;

        size_t to_write = remaining_message_len < remaining_buf_len ? remaining_message_len : remaining_buf_len;

        struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&message->message_data);
        aws_byte_cursor_advance(&message_cursor, message->copy_mark);
        aws_byte_cursor_read(&message_cursor, buf->buffer + written, to_write);

        written += to_write;

        message->copy_mark += to_write;

        if (message->copy_mark == message->message_data.len) {
            /* note: value is the first member of the allocated struct */
            aws_channel_release_message_to_pool(handler->slot->channel, message);
        } else {
            aws_linked_list_push_front(&handler->input_queue, &message->queueing_handle);
        }
    }

    if (written) {
        return (int)written;
    }

    errno = EAGAIN;
    return -1;
}

static int s_s2n_handler_recv(void *io_context, uint8_t *buf, uint32_t len) {
    struct s2n_handler *handler = (struct s2n_handler *)io_context;

    struct aws_byte_buf read_buffer = aws_byte_buf_from_array(buf, len);
    return s_generic_read(handler, &read_buffer);
}

static int s_generic_send(struct s2n_handler *handler, struct aws_byte_buf *buf) {
    size_t processed = 0;
    while (processed < buf->len) {
        struct aws_io_message *message = aws_channel_acquire_message_from_pool(
            handler->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, buf->len - processed);

        if (!message) {
            errno = ENOMEM;
            return AWS_OP_ERR;
        }

        struct aws_byte_cursor buffer_cursor = aws_byte_cursor_from_buf(buf);
        aws_byte_buf_append(&message->message_data, &buffer_cursor);
        processed += message->message_data.len;

        if (processed == buf->len) {
            message->on_completion = handler->latest_message_on_completion;
            message->user_data = handler->latest_message_completion_user_data;
            handler->latest_message_on_completion = NULL;
            handler->latest_message_completion_user_data = NULL;
        }

        aws_channel_slot_send_message(handler->slot, message, AWS_CHANNEL_DIR_WRITE);
    }

    if (processed) {
        return (int)processed;
    }

    errno = EAGAIN;
    return -1;
}

static int s_s2n_handler_send(void *io_context, const uint8_t *buf, uint32_t len) {
    struct s2n_handler *handler = (struct s2n_handler *)io_context;
    struct aws_byte_buf send_buf = aws_byte_buf_from_array(buf, len);

    return s_generic_send(handler, &send_buf);
}

static void s_s2n_handler_destroy(struct aws_channel_handler *handler) {
    if (handler) {
        struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;
        s2n_connection_free(s2n_handler->connection);
        aws_mem_release(handler->alloc, (void *)s2n_handler);
        aws_mem_release(handler->alloc, (void *)handler);
    }
}

static int s_drive_negotiation(struct aws_channel_handler *handler) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    do {
        int negotiation_code = s2n_negotiate(s2n_handler->connection, &blocked);

        int s2n_error = s2n_errno;
        if (negotiation_code == S2N_ERR_T_OK) {
            s2n_handler->negotiation_finished = true;

            const char *protocol = s2n_get_application_protocol(s2n_handler->connection);
            if (protocol) {
                s2n_handler->protocol = aws_byte_buf_from_c_str(protocol);
            }

            const char *server_name = s2n_get_server_name(s2n_handler->connection);

            if (server_name) {
                s2n_handler->server_name = aws_byte_buf_from_c_str(server_name);
            }

            if (s2n_handler->slot->adj_right && s2n_handler->options.advertise_alpn_message && protocol) {
                struct aws_io_message *message = aws_channel_acquire_message_from_pool(
                    s2n_handler->slot->channel,
                    AWS_IO_MESSAGE_APPLICATION_DATA,
                    sizeof(struct aws_tls_negotiated_protocol_message));
                message->message_tag = AWS_TLS_NEGOTIATED_PROTOCOL_MESSAGE;
                struct aws_tls_negotiated_protocol_message *protocol_message =
                    (struct aws_tls_negotiated_protocol_message *)message->message_data.buffer;

                protocol_message->protocol = s2n_handler->protocol;
                message->message_data.len = sizeof(struct aws_tls_negotiated_protocol_message);
                if (aws_channel_slot_send_message(s2n_handler->slot, message, AWS_CHANNEL_DIR_READ)) {
                    aws_channel_release_message_to_pool(s2n_handler->slot->channel, message);
                    aws_channel_shutdown(s2n_handler->slot->channel, aws_last_error());
                    return AWS_OP_SUCCESS;
                }
            }

            if (s2n_handler->options.on_negotiation_result) {
                s2n_handler->options.on_negotiation_result(
                    handler, s2n_handler->slot, AWS_OP_SUCCESS, s2n_handler->options.user_data);
            }

            break;
        }
        if (s2n_error_get_type(s2n_error) != S2N_ERR_T_BLOCKED) {
            const char *err_str = s2n_strerror_debug(s2n_error, NULL);
            (void)err_str;
            s2n_handler->negotiation_finished = false;

            aws_raise_error(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);

            if (s2n_handler->options.on_negotiation_result) {
                s2n_handler->options.on_negotiation_result(
                    handler, s2n_handler->slot, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE, s2n_handler->options.user_data);
            }

            return AWS_OP_ERR;
        }
    } while (blocked == S2N_NOT_BLOCKED);

    return AWS_OP_SUCCESS;
}

static void s_negotiation_task(struct aws_task *task, void *arg, aws_task_status status) {
    task->fn = NULL;
    task->arg = NULL;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_channel_handler *handler = (struct aws_channel_handler *)arg;
        s_drive_negotiation(handler);
    }
}

int aws_tls_client_handler_start_negotiation(struct aws_channel_handler *handler) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;

    if (aws_channel_thread_is_callers_thread(s2n_handler->slot->channel)) {
        return s_drive_negotiation(handler);
    }

    s2n_handler->sequential_tasks.fn = s_negotiation_task;
    s2n_handler->sequential_tasks.arg = handler;
    aws_channel_schedule_task_now(s2n_handler->slot->channel, &s2n_handler->sequential_tasks);

    return AWS_OP_SUCCESS;
}

static int s_s2n_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;

    if (message) {
        aws_linked_list_push_back(&s2n_handler->input_queue, &message->queueing_handle);

        if (!s2n_handler->negotiation_finished) {
            size_t message_len = message->message_data.len;
            if (!s_drive_negotiation(handler)) {
                aws_channel_slot_increment_read_window(slot, message_len);
            } else {
                aws_channel_shutdown(s2n_handler->slot->channel, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
            }
            return AWS_OP_SUCCESS;
        }
    }

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    size_t downstream_window = SIZE_MAX;
    if (slot->adj_right) {
        downstream_window = aws_channel_slot_downstream_read_window(slot);
    }

    size_t processed = 0;

    while (processed < downstream_window && blocked == S2N_NOT_BLOCKED) {

        struct aws_io_message *outgoing_read_message =
            aws_channel_acquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, downstream_window);
        if (!outgoing_read_message) {
            return AWS_OP_ERR;
        }

        ssize_t read = s2n_recv(
            s2n_handler->connection,
            outgoing_read_message->message_data.buffer,
            outgoing_read_message->message_data.capacity,
            &blocked);

        if (read <= 0) {
            aws_channel_release_message_to_pool(slot->channel, outgoing_read_message);
            continue;
        };

        processed += read;
        outgoing_read_message->message_data.len = (size_t)read;

        if (s2n_handler->options.on_data_read) {
            s2n_handler->options.on_data_read(
                handler, slot, &outgoing_read_message->message_data, s2n_handler->options.user_data);
        }

        if (slot->adj_right) {
            aws_channel_slot_send_message(slot, outgoing_read_message, AWS_CHANNEL_DIR_READ);
        } else {
            aws_channel_release_message_to_pool(slot->channel, outgoing_read_message);
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_s2n_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;

    if (AWS_UNLIKELY(!s2n_handler->negotiation_finished)) {
        return aws_raise_error(AWS_IO_TLS_ERROR_NOT_NEGOTIATED);
    }

    s2n_handler->latest_message_on_completion = message->on_completion;
    s2n_handler->latest_message_completion_user_data = message->user_data;

    s2n_blocked_status blocked;
    ssize_t write_code =
        s2n_send(s2n_handler->connection, message->message_data.buffer, (ssize_t)message->message_data.len, &blocked);

    ssize_t message_len = (ssize_t)message->message_data.len;
    aws_channel_release_message_to_pool(slot->channel, message);

    if (write_code < message_len) {
        return aws_raise_error(AWS_IO_TLS_ERROR_WRITE_FAILURE);
    }

    return AWS_OP_SUCCESS;
}

static int s_s2n_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool abort_immediately) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;

    if (dir == AWS_CHANNEL_DIR_WRITE && !error_code) {
        s2n_blocked_status blocked;
        /* make a best effort, but the channel is going away after this run, so.... you only get one shot anyways */
        s2n_shutdown(s2n_handler->connection, &blocked);
    } else {
        while (!aws_linked_list_empty(&s2n_handler->input_queue)) {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&s2n_handler->input_queue);
            struct aws_io_message *message = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);
            aws_channel_release_message_to_pool(s2n_handler->slot->channel, message);
        }
    }

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, abort_immediately);
}

static void s_run_read(struct aws_task *task, void *arg, aws_task_status status) {
    task->fn = NULL;
    task->arg = NULL;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_channel_handler *handler = (struct aws_channel_handler *)arg;
        struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;
        s_s2n_handler_process_read_message(handler, s2n_handler->slot, NULL);
    }
}

static int s_s2n_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {
    aws_channel_slot_increment_read_window(slot, size + EST_TLS_RECORD_OVERHEAD);

    struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;

    if (s2n_handler->negotiation_finished) {
        /* we have messages in a queue and they need to be run after the socket has popped (even if it didn't have data
         * to read). Alternatively, s2n reads entire records at a time, so we'll need to grab whatever we can and we
         * have no idea what's going on inside there. So we need to attempt another read.*/
        s2n_handler->sequential_tasks.fn = s_run_read;
        s2n_handler->sequential_tasks.arg = handler;
        aws_channel_schedule_task_now(slot->channel, &s2n_handler->sequential_tasks);
    }

    return AWS_OP_SUCCESS;
}

static size_t s_s2n_handler_get_current_window_size(struct aws_channel_handler *handler) {
    (void)handler;

    /* This is going to end up getting reset as soon as an downstream handler is added to the channel, but
     * we don't actually care about our window, we just want to honor the downstream handler's window. Start off
     * with it large, and then take the downstream window when it notifies us.*/
    return SIZE_MAX;
}

struct aws_byte_buf aws_tls_handler_protocol(struct aws_channel_handler *handler) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;
    return s2n_handler->protocol;
}

struct aws_byte_buf aws_tls_handler_server_name(struct aws_channel_handler *handler) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;
    return s2n_handler->server_name;
}

static struct aws_channel_handler_vtable s_handler_vtable = {
    .destroy = s_s2n_handler_destroy,
    .process_read_message = s_s2n_handler_process_read_message,
    .process_write_message = s_s2n_handler_process_write_message,
    .shutdown = s_s2n_handler_shutdown,
    .increment_read_window = s_s2n_handler_increment_read_window,
    .initial_window_size = s_s2n_handler_get_current_window_size,
};

static int s_parse_protocol_preferences(
    const char *alpn_list_str,
    const char protocol_output[4][128],
    size_t *protocol_count) {
    size_t max_count = *protocol_count;
    *protocol_count = 0;

    struct aws_byte_cursor alpn_list_buffer[4];
    AWS_ZERO_ARRAY(alpn_list_buffer);
    struct aws_array_list alpn_list;
    struct aws_byte_buf user_alpn_str = aws_byte_buf_from_c_str(alpn_list_str);

    aws_array_list_init_static(&alpn_list, alpn_list_buffer, 4, sizeof(struct aws_byte_cursor));

    if (aws_byte_buf_split_on_char(&user_alpn_str, ';', &alpn_list)) {
        aws_raise_error(AWS_IO_TLS_CTX_ERROR);
        return AWS_OP_ERR;
    }

    size_t protocols_list_len = aws_array_list_length(&alpn_list);
    if (protocols_list_len < 1) {
        aws_raise_error(AWS_IO_TLS_CTX_ERROR);
        return AWS_OP_ERR;
    }

    for (size_t i = 0; i < protocols_list_len && i < max_count; ++i) {
        struct aws_byte_cursor cursor;
        AWS_ZERO_STRUCT(cursor);
        if (aws_array_list_get_at(&alpn_list, (void *)&cursor, (size_t)i)) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            return AWS_OP_ERR;
        }

        memcpy((void *)protocol_output[i], cursor.ptr, cursor.len);
        *protocol_count += 1;
    }

    return AWS_OP_SUCCESS;
}

struct aws_channel_handler *s_new_tls_handler(
    struct aws_allocator *allocator,
    struct aws_tls_ctx *ctx,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot,
    s2n_mode mode) {
    struct aws_channel_handler *handler =
        (struct aws_channel_handler *)aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));

    if (!handler) {
        return NULL;
    }

    struct s2n_handler *s2n_handler = (struct s2n_handler *)aws_mem_acquire(allocator, sizeof(struct s2n_handler));

    if (!s2n_handler) {
        goto cleanup_handler;
    }

    AWS_ZERO_STRUCT(*s2n_handler);
    struct s2n_ctx *s2n_ctx = (struct s2n_ctx *)ctx->impl;
    s2n_handler->connection = s2n_connection_new(mode);

    if (!s2n_handler->connection) {
        goto cleanup_s2n_handler;
    }

    handler->impl = s2n_handler;
    handler->alloc = allocator;
    handler->vtable = s_handler_vtable;

    s2n_handler->options = *options;
    s2n_handler->latest_message_completion_user_data = NULL;
    s2n_handler->latest_message_on_completion = NULL;
    s2n_handler->slot = slot;
    aws_linked_list_init(&s2n_handler->input_queue);

    s2n_handler->protocol = aws_byte_buf_from_array(NULL, 0);

    if (options->server_name) {
        s2n_handler->server_name = aws_byte_buf_from_c_str(options->server_name);
        if (s2n_set_server_name(s2n_handler->connection, options->server_name)) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_conn;
        }
    }

    s2n_handler->negotiation_finished = false;

    s2n_connection_set_recv_cb(s2n_handler->connection, s_s2n_handler_recv);
    s2n_connection_set_recv_ctx(s2n_handler->connection, s2n_handler);
    s2n_connection_set_send_cb(s2n_handler->connection, s_s2n_handler_send);
    s2n_connection_set_send_ctx(s2n_handler->connection, s2n_handler);
    s2n_connection_set_blinding(s2n_handler->connection, S2N_SELF_SERVICE_BLINDING);

    if (options->alpn_list) {
        const char protocols_cpy[4][128];
        AWS_ZERO_ARRAY(protocols_cpy);
        size_t protocols_size = 4;
        if (s_parse_protocol_preferences(options->alpn_list, protocols_cpy, &protocols_size)) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_conn;
        }

        const char *protocols[4];
        AWS_ZERO_ARRAY(protocols);
        for (size_t i = 0; i < protocols_size; ++i) {
            protocols[i] = protocols_cpy[i];
        }

        if (s2n_connection_set_protocol_preferences(
                s2n_handler->connection, (const char *const *)protocols, (int)protocols_size)) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_conn;
        }
    }

    if (s2n_connection_set_config(s2n_handler->connection, s2n_ctx->s2n_config)) {
        aws_raise_error(AWS_IO_TLS_CTX_ERROR);
        goto cleanup_conn;
    }

    return handler;

cleanup_conn:
    s2n_connection_free(s2n_handler->connection);

cleanup_s2n_handler:
    aws_mem_release(allocator, s2n_handler);

cleanup_handler:
    aws_mem_release(allocator, handler);

    return NULL;
}

struct aws_channel_handler *aws_tls_client_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_ctx *ctx,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {

    return s_new_tls_handler(allocator, ctx, options, slot, S2N_CLIENT);
}

struct aws_channel_handler *aws_tls_server_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_ctx *ctx,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {

    return s_new_tls_handler(allocator, ctx, options, slot, S2N_SERVER);
}

void aws_tls_ctx_destroy(struct aws_tls_ctx *ctx) {
    struct s2n_ctx *s2n_ctx = (struct s2n_ctx *)ctx->impl;

    if (s2n_ctx) {
        s2n_config_free(s2n_ctx->s2n_config);
        aws_mem_release(ctx->alloc, (void *)s2n_ctx);
    }

    aws_mem_release(ctx->alloc, ctx);
}

struct aws_tls_ctx *aws_tls_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options, s2n_mode mode) {
    struct aws_tls_ctx *ctx = (struct aws_tls_ctx *)aws_mem_acquire(alloc, sizeof(struct aws_tls_ctx));

    if (!ctx) {
        return NULL;
    }

    struct s2n_ctx *s2n_ctx = (struct s2n_ctx *)aws_mem_acquire(alloc, sizeof(struct s2n_ctx));

    if (!s2n_ctx) {
        goto cleanup_ctx;
    }

    ctx->alloc = alloc;
    ctx->impl = s2n_ctx;
    s2n_ctx->s2n_config = s2n_config_new();

    if (!s2n_ctx->s2n_config) {
        goto cleanup_s2n_ctx;
    }

    s2n_config_set_cipher_preferences(s2n_ctx->s2n_config, "default");

    if (options->certificate_path && options->private_key_path) {

        struct aws_byte_buf certificate_chain, private_key;

        if (aws_byte_buf_init_from_file(&certificate_chain, alloc, options->certificate_path)) {
            goto cleanup_s2n_config;
        }

        if (aws_byte_buf_init_from_file(&private_key, alloc, options->private_key_path)) {
            aws_secure_zero(certificate_chain.buffer, certificate_chain.len);
            aws_byte_buf_clean_up(&certificate_chain);
            goto cleanup_s2n_config;
        }

        int err_code = s2n_config_add_cert_chain_and_key(
            s2n_ctx->s2n_config, (const char *)certificate_chain.buffer, (const char *)private_key.buffer);

        if (mode == S2N_CLIENT) {
            s2n_config_set_client_auth_type(s2n_ctx->s2n_config, S2N_CERT_AUTH_REQUIRED);
        }

        aws_secure_zero(certificate_chain.buffer, certificate_chain.len);
        aws_byte_buf_clean_up(&certificate_chain);
        aws_secure_zero(private_key.buffer, private_key.len);
        aws_byte_buf_clean_up(&private_key);

        if (err_code != S2N_ERR_T_OK) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_s2n_config;
        }
    }

    if (options->verify_peer) {
        if (s2n_config_set_check_stapled_ocsp_response(s2n_ctx->s2n_config, 1) ||
            s2n_config_set_status_request_type(s2n_ctx->s2n_config, S2N_STATUS_REQUEST_OCSP)) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_s2n_config;
        }

        if (options->ca_path || options->ca_file) {
            if (s2n_config_set_verification_ca_location(s2n_ctx->s2n_config, options->ca_file, options->ca_path)) {
                aws_raise_error(AWS_IO_TLS_CTX_ERROR);
                goto cleanup_s2n_config;
            }
        }

        if (mode == S2N_SERVER && s2n_config_set_client_auth_type(s2n_ctx->s2n_config, S2N_CERT_AUTH_REQUIRED)) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_s2n_config;
        }
    } else {
        if (s2n_config_disable_x509_verification(s2n_ctx->s2n_config)) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_s2n_config;
        }
    }

    if (options->alpn_list) {
        const char protocols_cpy[4][128];
        AWS_ZERO_ARRAY(protocols_cpy);
        size_t protocols_size = 4;
        if (s_parse_protocol_preferences(options->alpn_list, protocols_cpy, &protocols_size)) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_s2n_config;
        }

        const char *protocols[4];
        AWS_ZERO_ARRAY(protocols);
        for (size_t i = 0; i < protocols_size; ++i) {
            protocols[i] = protocols_cpy[i];
        }

        if (s2n_config_set_protocol_preferences(s2n_ctx->s2n_config, protocols, (int)protocols_size)) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_s2n_config;
        }
    }

    return ctx;

cleanup_s2n_config:
    s2n_config_free(s2n_ctx->s2n_config);

cleanup_s2n_ctx:
    aws_mem_release(alloc, s2n_ctx);

cleanup_ctx:
    aws_mem_release(alloc, ctx);

    return NULL;
}

struct aws_tls_ctx *aws_tls_server_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    return aws_tls_ctx_new(alloc, options, S2N_SERVER);
}

struct aws_tls_ctx *aws_tls_client_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    return aws_tls_ctx_new(alloc, options, S2N_CLIENT);
}
