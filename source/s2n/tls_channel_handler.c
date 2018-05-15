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

#include <aws/common/task_scheduler.h>

#include <s2n.h>
#include <stdlib.h>
#include <errno.h>

static const size_t EST_TLS_RECORD_OVERHEAD = 53; /* 5 byte header + 32 + 16 bytes for padding */

struct s2n_handler {
    struct s2n_connection *connection;
    struct aws_channel_slot *slot;
    struct aws_linked_list_node input_queue;
    struct aws_byte_buf protocol;
    struct aws_byte_buf server_name;
    struct aws_tls_connection_options options;
    aws_channel_on_message_write_completed latest_message_on_completion;
    void *latest_message_completion_ctx;
    bool read_shutdown;
    bool write_shutdown;
    bool negotiation_finished;
};

struct s2n_ctx {
    struct s2n_config *s2n_config;
};

void aws_tls_init_static_state(struct aws_allocator *alloc) {
    setenv("S2N_ENABLE_CLIENT_MODE", "1", 1);
    setenv("S2N_DONT_MLOCK", "1", 1);
    s2n_init();
}

void aws_tls_clean_up_static_state(struct aws_allocator *alloc) {
    s2n_cleanup();
}

static int generic_read(struct s2n_handler *handler, struct aws_byte_buf *buf) {

    size_t written = 0;

    while (!aws_linked_list_empty(&handler->input_queue) && written < buf->len) {
        struct aws_linked_list_node *head = aws_linked_list_remove(&handler->input_queue);
        struct aws_io_message *message = aws_container_of(head, struct aws_io_message, queueing_handle);

        size_t remaining_message_len = message->message_data.len - message->copy_mark;
        size_t remaining_buf_len = buf->len - written;

        size_t to_write = remaining_message_len < remaining_buf_len ? remaining_message_len : remaining_buf_len;

        struct aws_byte_buf message_buf_cpy = message->message_data;
        message_buf_cpy.len = message->copy_mark + to_write;

        aws_byte_buf_copy(buf, written, &message_buf_cpy, message->copy_mark);
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
        return (int) written;
    }

    errno = EAGAIN;
    return -1;
}

static int s2n_handler_recv(void *io_context, uint8_t *buf, uint32_t len) {
    struct s2n_handler *handler = (struct s2n_handler *) io_context;

    struct aws_byte_buf read_buffer = aws_byte_buf_from_array(buf, len);
    return generic_read(handler, &read_buffer);
}

static int generic_send(struct s2n_handler *handler, struct aws_byte_buf *buf) {
    int processed = 0;
    while (processed < buf->len) {
        struct aws_io_message *message = aws_channel_aquire_message_from_pool(handler->slot->channel,
                                                                              AWS_IO_MESSAGE_APPLICATION_DATA,
                                                                              buf->len - processed);

        if (!message) {
            errno = ENOMEM;
            return aws_raise_error(AWS_ERROR_OOM);
        }

        if (processed + message->message_data.len == buf->len) {
            message->on_completion = handler->latest_message_on_completion;
            message->ctx = handler->latest_message_completion_ctx;
            handler->latest_message_on_completion = NULL;
            handler->latest_message_completion_ctx = NULL;
        }

        aws_byte_buf_copy(&message->message_data, 0, buf, (size_t)processed);
        processed += message->message_data.len;

        aws_channel_slot_send_message(handler->slot, message, AWS_CHANNEL_DIR_WRITE);
    }

    if (processed) {
        return processed;
    }

    errno = EAGAIN;
    return -1;
}

static int s2n_handler_send(void *io_context, const uint8_t *buf, uint32_t len) {
    struct s2n_handler *handler = (struct s2n_handler *) io_context;
    struct aws_byte_buf send_buf = aws_byte_buf_from_array(buf, len);

    return generic_send(handler, &send_buf);
}

static void s2n_handler_destroy(struct aws_channel_handler *handler) {
    if (handler) {
        struct s2n_handler *s2n_handler = (struct s2n_handler *) handler->impl;
        s2n_connection_free(s2n_handler->connection);
        aws_mem_release(handler->alloc, (void *) s2n_handler);
        aws_mem_release(handler->alloc, (void *) handler);
    }
}

static int drive_negotiation(struct aws_channel_handler *handler) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    do {
        int negotiation_code = s2n_negotiate(s2n_handler->connection, &blocked);
        int s2n_error = s2n_errno;
        if (negotiation_code == S2N_ERR_T_OK) {
            s2n_handler->negotiation_finished = true;

            /*now lets match the upstream window now that negotiation is finished. */
            size_t upstream_window = aws_channel_slot_upstream_read_window(s2n_handler->slot);
            s2n_handler->slot->window_size = upstream_window + EST_TLS_RECORD_OVERHEAD;

            const char *protocol = s2n_get_application_protocol(s2n_handler->connection);
            if (protocol) {
                s2n_handler->protocol = aws_byte_buf_from_literal(protocol);
            }

            const char *server_name = s2n_get_server_name(s2n_handler->connection);

            if (server_name) {
                s2n_handler->server_name = aws_byte_buf_from_literal(server_name);
            }

            if (s2n_handler->slot->adj_right && protocol) {
                struct aws_io_message *message = aws_channel_aquire_message_from_pool(s2n_handler->slot->channel,
                                                                                      AWS_IO_MESSAGE_APPLICATION_DATA,
                                                                                      sizeof(struct aws_tls_negotiated_protocol_message));
                message->message_tag = AWS_TLS_NEGOTIATED_PROTOCOL_MESSAGE;
                struct aws_tls_negotiated_protocol_message *protocol_message =
                    (struct aws_tls_negotiated_protocol_message *)message->message_data.buffer;

                protocol_message->protocol = s2n_handler->protocol;
                aws_channel_slot_send_message(s2n_handler->slot, message, AWS_CHANNEL_DIR_READ);
            }

            if (s2n_handler->options.on_negotiation_result) {
                s2n_handler->options.on_negotiation_result(handler, s2n_handler->slot, AWS_OP_SUCCESS, s2n_handler->options.ctx);
            }

            break;
        } else if (s2n_error_get_type(s2n_error) != S2N_ERR_T_BLOCKED) {
            s2n_handler->negotiation_finished = false;

            aws_raise_error(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);

            if (s2n_handler->options.on_negotiation_result) {
                s2n_handler->options.on_negotiation_result(handler, s2n_handler->slot,
                                                           AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE,
                                                           s2n_handler->options.ctx);
            }

            aws_channel_slot_shutdown_notify(s2n_handler->slot, AWS_CHANNEL_DIR_READ, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
            aws_channel_slot_shutdown_notify(s2n_handler->slot, AWS_CHANNEL_DIR_WRITE, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);

            return AWS_OP_ERR;
         }
    } while (blocked == S2N_NOT_BLOCKED);

   return AWS_OP_SUCCESS;
}

static void negotiation_task(void *arg, aws_task_status status) {
    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_channel_handler *handler = (struct aws_channel_handler *) arg;
        drive_negotiation(handler);
    }
}

int aws_tls_client_handler_start_negotiation(struct aws_channel_handler *handler) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *) handler->impl;

    if (aws_channel_is_on_callers_thread(s2n_handler->slot->channel)) {
        return drive_negotiation(handler);
    }

    struct aws_task task = {
        .fn = negotiation_task,
        .arg = handler,
    };

    uint64_t now = 0;
    aws_channel_current_clock_time(s2n_handler->slot->channel, &now);
    return aws_channel_schedule_task(s2n_handler->slot->channel, &task, now);
}

static int s2n_handler_process_read_message(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                              struct aws_io_message *message) {

    struct s2n_handler *s2n_handler = (struct s2n_handler *) handler->impl;

    if (message) {
        aws_linked_list_push_back(&s2n_handler->input_queue, &message->queueing_handle);

        if (!s2n_handler->negotiation_finished) {
            size_t message_len = message->message_data.len;
            int neg_err = drive_negotiation(handler);
            aws_channel_slot_update_window(slot, message_len);
            return neg_err;
        }
    }

    s2n_blocked_status blocked = S2N_NOT_BLOCKED;
    size_t upstream_window = aws_channel_slot_upstream_read_window(slot);
    size_t processed = 0;

    while (processed < upstream_window && blocked == S2N_NOT_BLOCKED) {

        struct aws_io_message *outgoing_read_message = aws_channel_aquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA,
                                                                                            upstream_window);
        if (!outgoing_read_message) {
            return aws_raise_error(AWS_ERROR_OOM);
        }

        ssize_t read = s2n_recv(s2n_handler->connection, outgoing_read_message->message_data.buffer,
                                outgoing_read_message->message_data.len, &blocked);

        if (read <= 0) {
            aws_channel_release_message_to_pool(slot->channel, outgoing_read_message);
            continue;
        };

        processed += read;
        outgoing_read_message->message_data.len = (size_t)read;

        if (s2n_handler->options.on_data_read) {
            s2n_handler->options.on_data_read(handler, slot, &outgoing_read_message->message_data, s2n_handler->options.ctx);
        }

        if (slot->adj_right) {
            aws_channel_slot_send_message(slot, outgoing_read_message, AWS_CHANNEL_DIR_READ);
        }
        else {
            aws_channel_release_message_to_pool(slot->channel, outgoing_read_message);
        }
    }

    return AWS_OP_SUCCESS;
}

static int s2n_handler_process_write_message(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                             struct aws_io_message *message) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *) handler->impl;

    if (AWS_UNLIKELY(!s2n_handler->negotiation_finished)) {
        return aws_raise_error(AWS_IO_TLS_ERROR_NOT_NEGOTIATED);
    }

    s2n_handler->latest_message_on_completion = message->on_completion;
    s2n_handler->latest_message_completion_ctx = message->ctx;

    s2n_blocked_status blocked;
    ssize_t write_code = s2n_send(s2n_handler->connection, message->message_data.buffer, (ssize_t)message->message_data.len, &blocked);

    size_t message_len = message->message_data.len;
    aws_channel_release_message_to_pool(slot->channel, message);

    if (write_code < message_len) {
        return aws_raise_error(AWS_IO_TLS_ERROR_WRITE_FAILURE);
    }

    return AWS_OP_SUCCESS;
}

static int s2n_handler_handle_shutdown_direction(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                                 enum aws_channel_direction dir) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *) handler->impl;

    if (dir == AWS_CHANNEL_DIR_WRITE) {
        s2n_handler->write_shutdown = true;
    }
    else {
        s2n_handler->read_shutdown = true;
    }

    if (s2n_handler->read_shutdown && s2n_handler->write_shutdown) {
        s2n_blocked_status blocked;
        /* make a best effort, but the channel is going away after this run, so.... you only get one shot anyways */
        s2n_shutdown(s2n_handler->connection, &blocked);
    }

    return aws_channel_slot_shutdown_notify(slot, dir, AWS_OP_SUCCESS);
}

static int s2n_handler_on_shutdown_notify (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                           enum aws_channel_direction dir, int error_code) {
    return s2n_handler_handle_shutdown_direction(handler, slot, dir);
}

static void run_read(void *arg, aws_task_status status) {
    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_channel_handler *handler = (struct aws_channel_handler *) arg;
        struct s2n_handler *s2n_handler = (struct s2n_handler *) handler->impl;
        s2n_handler_process_read_message(handler, s2n_handler->slot, NULL);
    }
}

static int s2n_handler_on_window_update (struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size) {
    aws_channel_slot_update_window(slot, size + EST_TLS_RECORD_OVERHEAD);

    struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;

    if (s2n_handler->negotiation_finished) {
        /* we have messages in a queue and they need to be run after the socket has popped (even if it didn't have data to read).
         * Alternatively, s2n reads entire records at a time, so we'll need to grab whatever we can and we have no idea what's going
         * on inside there. So we need to attempt another read.*/
        uint64_t now = 0;

        if (aws_channel_current_clock_time(slot->channel, &now)) {
            return AWS_OP_ERR;
        }

        struct aws_task task = {
                .fn = run_read,
                .arg = handler
        };

        return aws_channel_schedule_task(slot->channel, &task, now);
    }

    return AWS_OP_SUCCESS;
}

static size_t s2n_handler_get_current_window_size (struct aws_channel_handler *handler) {
    /* This is going to end up getting reset as soon as an upstream handler is added to the channel, but
     * we don't actually care about our window, we just want to honor the upstream handler's window. Start off
     * with it large, and then take the upstream window when it notifies us.*/
    return SIZE_MAX;
}

struct aws_byte_buf aws_tls_handler_protocol(struct aws_channel_handler *handler) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *) handler->impl;
    return s2n_handler->protocol;
}

struct aws_byte_buf aws_tls_handler_server_name(struct aws_channel_handler *handler) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *) handler->impl;
    return s2n_handler->server_name;
}

static struct aws_channel_handler_vtable handler_vtable = {
        .destroy = s2n_handler_destroy,
        .process_read_message = s2n_handler_process_read_message,
        .process_write_message = s2n_handler_process_write_message,
        .shutdown_direction = s2n_handler_handle_shutdown_direction,
        .on_shutdown_notify = s2n_handler_on_shutdown_notify,
        .on_window_update = s2n_handler_on_window_update,
        .get_current_window_size = s2n_handler_get_current_window_size,
};

static uint8_t s2n_handler_verify_host_callback(const char *host_name, size_t host_name_len, void *data) {
    if (data) {
        struct aws_channel_handler *handler = (struct aws_channel_handler *) data;
        struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;

        if (s2n_handler->options.verify_host_fn) {
            struct aws_byte_buf host_buf = aws_byte_buf_from_array((const uint8_t *)host_name, host_name_len);
            return (uint8_t)s2n_handler->options.verify_host_fn(handler, &host_buf, s2n_handler->options.ctx);
        }
    }

    return 0;
}

struct aws_channel_handler *new_tls_handler (struct aws_allocator *allocator,
                                             struct aws_tls_ctx *ctx,
                                             struct aws_tls_connection_options *options,
                                             struct aws_channel_slot *slot, s2n_mode mode) {
    struct aws_channel_handler *handler = (struct aws_channel_handler *) aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));

    if (!handler) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    struct s2n_handler *s2n_handler = (struct s2n_handler *) aws_mem_acquire(allocator, sizeof(struct s2n_handler));

    if (!s2n_handler) {
        aws_raise_error(AWS_ERROR_OOM);
        goto cleanup_handler;
    }


    struct s2n_ctx *s2n_ctx = (struct s2n_ctx *) ctx->impl;
    s2n_handler->connection = s2n_connection_new(mode);

    if (!s2n_handler->connection) {
        goto cleanup_s2n_handler;
    }

    handler->impl = s2n_handler;
    handler->alloc = allocator;
    handler->vtable = handler_vtable;

    s2n_handler->options = *options;
    s2n_handler->write_shutdown = false;
    s2n_handler->read_shutdown = false;
    s2n_handler->latest_message_completion_ctx = NULL;
    s2n_handler->latest_message_on_completion = NULL;
    s2n_handler->slot = slot;
    aws_linked_list_init(&s2n_handler->input_queue);

    s2n_handler->protocol = aws_byte_buf_from_array(NULL, 0);

    if (options->server_name) {
        s2n_handler->server_name = aws_byte_buf_from_c_str(options->server_name, strlen(options->server_name));
        if (s2n_set_server_name(s2n_handler->connection, options->server_name)) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_conn;
        }
    }

    s2n_handler->negotiation_finished = false;

    s2n_connection_set_recv_cb(s2n_handler->connection, s2n_handler_recv);
    s2n_connection_set_recv_ctx(s2n_handler->connection, s2n_handler);
    s2n_connection_set_send_cb(s2n_handler->connection, s2n_handler_send);
    s2n_connection_set_send_ctx(s2n_handler->connection, s2n_handler);

    if (options->verify_host_fn) {
        if (s2n_connection_set_verify_host_callback(s2n_handler->connection, s2n_handler_verify_host_callback, handler)) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_conn;
        }
    }

    /*TODO: update s2n to support connection level alpn*/

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

struct aws_channel_handler *aws_tls_client_handler_new(struct aws_allocator *allocator,
                                                       struct aws_tls_ctx *ctx,
                                                       struct aws_tls_connection_options *options,
                                                       struct aws_channel_slot *slot) {

    return new_tls_handler(allocator, ctx, options, slot, S2N_CLIENT);
}

struct aws_channel_handler *aws_tls_server_handler_new(struct aws_allocator *allocator, struct aws_tls_ctx *ctx,
                                                       struct aws_tls_connection_options *options,
                                                       struct aws_channel_slot *slot) {

    return new_tls_handler(allocator, ctx, options, slot, S2N_SERVER);
}

void aws_tls_ctx_destroy(struct aws_tls_ctx *ctx) {
    struct s2n_ctx *s2n_ctx = (struct s2n_ctx *) ctx->impl;

    if (s2n_ctx) {
        s2n_config_free(s2n_ctx->s2n_config);
        aws_mem_release(ctx->alloc, (void *) s2n_ctx);
    }

    aws_mem_release(ctx->alloc, ctx);
}

static int read_file_to_blob(struct aws_allocator *alloc, const char *filename, uint8_t **blob, size_t *len) {
    FILE *fp = fopen(filename, "r");

    if (fp) {
        fseek(fp, 0L, SEEK_END);
        *len = (size_t) ftell(fp);

        fseek(fp, 0L, SEEK_SET);
        *blob = (uint8_t *) aws_mem_acquire(alloc, *len + 1);

        if(!*blob) {
            fclose(fp);
            return aws_raise_error(AWS_ERROR_OOM);
        }

        memset(*blob, 0, *len + 1);

        size_t read = fread(*blob, 1, *len, fp);
        fclose(fp);
        if (read < *len) {
            aws_mem_release(alloc, *blob);
            *blob = NULL;
            *len = 0;
            return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
        }

        return 0;
    }

    return aws_raise_error(AWS_IO_FILE_NOT_FOUND);
}

struct aws_tls_ctx *aws_tls_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options, s2n_mode mode) {
    struct aws_tls_ctx *ctx = (struct aws_tls_ctx *) aws_mem_acquire(alloc, sizeof(struct aws_tls_ctx));

    if (!ctx) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    struct s2n_ctx *s2n_ctx = (struct s2n_ctx *) aws_mem_acquire(alloc, sizeof(struct s2n_ctx));

    if (!s2n_ctx) {
        aws_raise_error(AWS_ERROR_OOM);
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
        uint8_t *cert_blob = NULL;
        size_t cert_len = 0;

        if (read_file_to_blob(alloc, options->certificate_path, &cert_blob, &cert_len)) {
            goto cleanup_s2n_config;
        }

        uint8_t *key_blob = NULL;
        size_t key_len = 0;
        if (read_file_to_blob(alloc, options->private_key_path, &key_blob, &key_len)) {
            aws_mem_release(alloc, cert_blob);
            goto cleanup_s2n_config;
        }

        int err_code = s2n_config_add_cert_chain_and_key(s2n_ctx->s2n_config, (const char *) cert_blob,
                                                         (const char *) key_blob);

        aws_mem_release(alloc, cert_blob);
        aws_mem_release(alloc, key_blob);

        if (err_code != S2N_ERR_T_OK) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            fprintf(stderr, "error code %d\n", s2n_errno);
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
    }
    else {
        if (s2n_config_disable_x509_verification(s2n_ctx->s2n_config)) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_s2n_config;
        }
    }

    if (options->alpn_list) {
        struct aws_byte_cursor alpn_list_buffer[4] = {0};
        struct aws_array_list alpn_list;
        struct aws_byte_buf user_alpn_str = aws_byte_buf_from_c_str(options->alpn_list, strlen(options->alpn_list));

        if (aws_array_list_init_static(&alpn_list, alpn_list_buffer, 4, sizeof(struct aws_byte_cursor)) ||
            aws_string_split_on_char(&user_alpn_str, ';', &alpn_list)) {
            goto cleanup_s2n_config;
        }

        int protocols_list_len = (int)aws_array_list_length(&alpn_list);
        if (protocols_list_len <= 1) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_s2n_config;
        }

        const char protocols_tmp[4][128] = {0};
        const char *protocols[4] = {0};
        for(int i = 0; i < protocols_list_len; ++i) {
            struct aws_byte_cursor cursor = {0};
            if (aws_array_list_get_at(&alpn_list, (void *)&cursor, (size_t)i)) {
                goto cleanup_s2n_config;
            }

            memcpy((void *)protocols_tmp[i], cursor.ptr, cursor.len);
            protocols[i] = protocols_tmp[i];
        }

        if (s2n_config_set_protocol_preferences(s2n_ctx->s2n_config, protocols, protocols_list_len)) {
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

struct aws_tls_ctx *aws_tls_client_ctx_new(struct aws_allocator *alloc,
                                              struct aws_tls_ctx_options *options) {
    return aws_tls_ctx_new(alloc, options, S2N_CLIENT);
}





