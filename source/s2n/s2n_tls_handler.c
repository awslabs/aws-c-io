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

#include <aws/io/tls_handler.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/clock.h>

#include <s2n.h>

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

struct s2n_handler {
    struct aws_tls_channel_handler handler;
    struct s2n_connection *connection;
    struct aws_channel *channel;
    aws_message_queue *pump_input_queue;
    uint8_t io_buf[1024];
};

struct s2n_ctx {
    struct aws_allocator *alloc;
    struct s2n_config *s2n_config;
};

void aws_tls_init_static_state(struct aws_allocator *alloc) {
    setenv("S2N_ENABLE_CLIENT_MODE", "1", 1);
    s2n_init();
}

void aws_tls_clean_up_static_state(struct aws_allocator *alloc) {
    s2n_cleanup();
}

static int generic_read(struct aws_channel *channel, aws_message_queue *input, uint8_t *buf, uint32_t len) {

    if(input && !aws_linked_list_empty(input)) {
        size_t written = 0;

        while (input && written < len) {
            struct aws_io_message *message = &aws_container_of(input, struct aws_message_queue, list)->value;

            size_t remaining_message_len = message->data_len - message->copy_mark;
            size_t remaining_buf_len = len - written;

            size_t to_write = remaining_message_len < remaining_buf_len ? remaining_message_len : remaining_buf_len;

            memcpy(buf + written, message->data + message->copy_mark, to_write);
            written += to_write;

            message->copy_mark += to_write;

            if (message->copy_mark == message->data_len) {
                input = aws_linked_list_remove(input);

                if (message->take_ownership) {
                    /* note: value is the first member of the allocated struct */
                    aws_channel_release_message_to_pool(channel, (struct aws_io_message_val *)message);
                }
            }
        }

        if (written) {
            return (int) written;
        }
    }

    errno = EAGAIN;
    return -1;
}

static int s2n_handler_recv(void *io_context, uint8_t *buf, uint32_t len) {
    struct s2n_handler *handler = (struct s2n_handler *) io_context;

    if (handler->pump_input_queue) {
        return generic_read(handler->channel, handler->pump_input_queue, buf, len);
    }

    errno = EAGAIN;
    return -1;
}

static int generic_send(struct aws_channel *channel, aws_message_queue *output, const uint8_t *buf, uint32_t len) {
    struct aws_io_message_val *message = aws_channel_get_message_from_pool(channel, AWS_IO_MESSAGE_TYPE_RAW, len);

    if (!message) {
        errno = ENOMEM;
        return aws_raise_error(AWS_ERROR_OOM);
    }

    memcpy(message->value.data, buf, len);
    aws_linked_list_push_back(output, &message->list);

    return len;
}

static int s2n_handler_send(void *io_context, const uint8_t *buf, uint32_t len) {
    struct s2n_handler *handler = (struct s2n_handler *) io_context;

    return generic_send(handler->channel, &handler->handler.base.output_queue, buf, len);
}


static void handler_destroy(struct aws_channel_handler *handler) {
    if (handler) {
        struct s2n_handler *s2n_handler = (struct s2n_handler *) handler;
        s2n_connection_free(s2n_handler->connection);
        aws_channel_handler_clean_up_base(&s2n_handler->handler.base);
        aws_mem_release(s2n_handler->handler.base.alloc, (void *) handler);
        /* also need to drain the queues? */
    }
}

static int drive_negotiation(struct s2n_handler *s2n_handler, struct aws_channel *channel) {
    s2n_blocked_status blocked;
    do {
        int negotiation_code = s2n_negotiate(s2n_handler->connection, &blocked);
        if (negotiation_code == S2N_ERR_T_OK) {
            s2n_handler->handler.base.can_process_more_output = 1;
            s2n_handler->handler.negotiation_finished = 1;
            s2n_handler->handler.protocol = s2n_get_application_protocol(s2n_handler->connection);
            s2n_handler->handler.server_name = s2n_get_server_name(s2n_handler->connection);
            s2n_handler->handler.on_negotiation((struct aws_tls_channel_handler *) s2n_handler, channel,
                                                AWS_OP_SUCCESS, s2n_handler->handler.negotiation_ctx);
            break;
        } else if (!(blocked && errno == EAGAIN)) {
            s2n_handler->handler.negotiation_finished = 0;
            s2n_handler->handler.on_negotiation((struct aws_tls_channel_handler *) s2n_handler, channel,
                                                AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE,
                                                s2n_handler->handler.negotiation_ctx);
            aws_raise_error(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
            s2n_handler->handler.base.can_process_more_output = 0;
            s2n_handler->handler.base.can_process_more_input = 0;


            return AWS_OP_ERR;
        }

    } while (blocked == S2N_NOT_BLOCKED);

    return AWS_OP_SUCCESS;
}

static void negotiation_task(void *arg) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *) arg;
    drive_negotiation(s2n_handler, s2n_handler->channel);
    aws_channel_flush(s2n_handler->channel);
}

int aws_tls_client_handler_start_negotiation(struct aws_tls_channel_handler *handler,
                                                            struct aws_channel *channel) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *) handler;
    s2n_handler->channel = channel;

    struct aws_task task = {
            .fn = negotiation_task,
            .arg = s2n_handler,
    };

    uint64_t now = 0;
    aws_high_res_clock_get_ticks(&now);
    return aws_channel_schedule_task(channel, &task, now);
}

static int s2n_handler_process_input_messages(struct aws_channel_handler *handler, struct aws_channel *channel,
                                              aws_message_queue *queue, int8_t end_of_chain) {

    struct s2n_handler *s2n_handler = (struct s2n_handler *) handler;

    s2n_handler->pump_input_queue = queue;
    s2n_handler->channel = channel;

    if (!s2n_handler->handler.negotiation_finished) {
        return drive_negotiation(s2n_handler, channel);
    }

    s2n_blocked_status blocked;

    do {
        ssize_t read = s2n_recv(s2n_handler->connection, s2n_handler->io_buf, sizeof(s2n_handler->io_buf), &blocked);

        if (read <= 0) continue;

        if (!end_of_chain) {
            struct aws_io_message_val *message = aws_channel_get_message_from_pool(channel, AWS_IO_MESSAGE_TYPE_RAW, (size_t)read);

            if (!message) {
                return aws_raise_error(AWS_ERROR_OOM);
            }

            memcpy(message->value.data, s2n_handler->io_buf, (size_t) read);
            aws_linked_list_push_back(&s2n_handler->handler.base.input_queue, &message->list);
        }
        if (s2n_handler->handler.on_read) {
            s2n_handler->handler.on_read((struct aws_tls_channel_handler *) s2n_handler,
                                         s2n_handler->io_buf, (size_t) read, s2n_handler->handler.read_ctx);
        }
    } while (blocked == S2N_NOT_BLOCKED);
    return AWS_OP_SUCCESS;
}

static int s2n_handler_process_output_messages(struct aws_channel_handler *handler, struct aws_channel *channel,
                                               aws_message_queue *queue) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *) handler;

    /* this shouldn't be possible if the write flag is being honored, but check anyways. */
    if (AWS_UNLIKELY(!s2n_handler->handler.negotiation_finished)) {
        return aws_raise_error(AWS_IO_TLS_ERROR_NOT_NEGOTIATED);
    }

    if (AWS_UNLIKELY(aws_linked_list_empty(queue))) {
        return AWS_OP_SUCCESS;
    }

    s2n_blocked_status blocked;

    while (!aws_linked_list_empty(queue)) {
        struct aws_io_message *message = &aws_container_of(queue, struct aws_message_queue, list)->value;

        size_t to_write = message->data_len - message->copy_mark;
        uint8_t *data_to_write = message->data + message->copy_mark;
        ssize_t write_code = s2n_send(s2n_handler->connection, data_to_write, (ssize_t) to_write, &blocked);

        if (write_code < 0) {
            if (s2n_errno != S2N_ERR_T_BLOCKED) {
                return aws_raise_error(AWS_IO_TLS_ERROR_WRITE_FAILURE);
            }

            break;
        }

        message->copy_mark += write_code;
        if (message->copy_mark == message->data_len) {
            aws_linked_list_pop_front(queue);
            if (message->take_ownership) {
                /* note: value is the same memory address as it's container. */
                aws_channel_release_message_to_pool(channel, (struct aws_io_message_val *)message);
            }
        }
    }

    return AWS_OP_SUCCESS;
}


static int s2n_handler_handle_channel_shutdown(struct aws_channel_handler *handler, struct aws_channel *channel,
                                               int shutdown_reason) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *) handler;

    s2n_blocked_status blocked;
    /* make a best effort, but the channel is going away after this run, so.... you only get one shot anyways */
    s2n_shutdown(s2n_handler->connection, &blocked);

    return AWS_OP_SUCCESS;
}

static struct aws_channel_handler_vtable handler_vtable = {
        .destroy = handler_destroy,
        .process_input_messages = s2n_handler_process_input_messages,
        .process_output_messages = s2n_handler_process_output_messages,
        .handle_channel_shutdown = s2n_handler_handle_channel_shutdown,
        .type_tag = {.type_name = "s2n_handler"},
        .vtable_size = sizeof(struct aws_channel_handler_vtable)
};

static uint8_t s2n_handler_verify_host_callback(const char *host_name, size_t host_name_len, void *data) {
    if (data) {
        struct aws_io_tls_channel_handler *handler = (struct aws_io_tls_channel_handler *) data;

        if (handler->verify_host)
            return handler->verify_host(handler, host_name, host_name_len, handler->negotiation_ctx);
    }

    return 0;
}

struct aws_tls_channel_handler *aws_tls_client_handler_new(struct aws_tls_ctx *ctx, const char *server_name,
                                                                             aws_on_negotiation_result on_negotiation,
                                                                             aws_verify_host_fn verify_host_fn,
                                                                             void *negotiation_ctx_data) {
    struct s2n_handler *handler = (struct s2n_handler *) aws_mem_acquire(ctx->alloc, sizeof(struct s2n_handler));

    if (!handler) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    if(aws_channel_handler_init_base(&handler->handler.base, ctx->alloc)) {
        goto err;
    }


    struct s2n_ctx *s2n_ctx = (struct s2n_ctx *) ctx;
    handler->connection = s2n_connection_new(S2N_CLIENT);

    if (!handler->connection) {
        goto err;
    }

    /* this can't flip until negotiation has finished */
    handler->handler.base.can_process_more_output = 0;

    handler->handler.base.vtable = handler_vtable;
    handler->handler.negotiation_finished = 0;
    handler->handler.on_negotiation = on_negotiation;
    handler->handler.verify_host = verify_host_fn;
    handler->handler.negotiation_ctx = negotiation_ctx_data;
    handler->handler.read_ctx = NULL;
    handler->handler.on_read = NULL;
    handler->handler.on_error = NULL;
    handler->pump_input_queue = NULL;
    handler->handler.server_name = NULL;
    handler->handler.protocol = NULL;
    s2n_connection_set_config(handler->connection, s2n_ctx->s2n_config);
    s2n_connection_set_recv_cb(handler->connection, s2n_handler_recv);
    s2n_connection_set_recv_ctx(handler->connection, handler);
    s2n_connection_set_send_cb(handler->connection, s2n_handler_send);
    s2n_connection_set_send_ctx(handler->connection, handler);

    if(server_name) {
        s2n_set_server_name(handler->connection, server_name);
    }

    s2n_connection_set_verify_host_callback(handler->connection, s2n_handler_verify_host_callback, handler);

    return (struct aws_tls_channel_handler *) handler;

    err:
    if (handler) {
        aws_mem_release(ctx->alloc, handler);
    }

    return NULL;
}

struct aws_tls_channel_handler *aws_tls_server_handler_new(struct aws_tls_ctx *ctx,
                                                           aws_on_negotiation_result on_negotiation,
                                                           aws_verify_host_fn verify_host_fn,
                                                           void *negotiation_ctx_data) {

    struct s2n_handler *handler = (struct s2n_handler *) aws_mem_acquire(ctx->alloc, sizeof(struct s2n_handler));

    if (!handler) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    if(aws_channel_handler_init_base(&handler->handler.base, ctx->alloc)) {
        goto err;
    }

    struct s2n_ctx *s2n_ctx = (struct s2n_ctx *) ctx;
    handler->connection = s2n_connection_new(S2N_SERVER);

    if (!handler->connection) {
        goto err;
    }

    /* this can't flip until negotiation has finished */
    handler->handler.base.can_process_more_output = 0;

    handler->handler.base.vtable = handler_vtable;
    handler->handler.negotiation_finished = 0;
    handler->handler.on_negotiation = on_negotiation;
    handler->handler.verify_host = verify_host_fn;
    handler->handler.negotiation_ctx = negotiation_ctx_data;
    handler->handler.read_ctx = NULL;
    handler->handler.on_read = NULL;
    handler->handler.on_error = NULL;
    handler->pump_input_queue = NULL;
    handler->handler.server_name = NULL;
    handler->handler.protocol = NULL;
    s2n_connection_set_config(handler->connection, s2n_ctx->s2n_config);
    s2n_connection_set_recv_cb(handler->connection, s2n_handler_recv);
    s2n_connection_set_recv_ctx(handler->connection, handler);
    s2n_connection_set_send_cb(handler->connection, s2n_handler_send);
    s2n_connection_set_send_ctx(handler->connection, handler);
    s2n_connection_set_verify_host_callback(handler->connection, s2n_handler_verify_host_callback, handler);

    return (struct aws_tls_channel_handler *) handler;

    err:
    if (handler) {
        aws_mem_release(ctx->alloc, handler);
    }

    return NULL;
}

void aws_tls_ctx_destroy(struct aws_tls_ctx *ctx) {
    struct s2n_ctx *s2n_ctx = (struct s2n_ctx *) ctx;

    if (s2n_ctx) {
        s2n_config_free(s2n_ctx->s2n_config);
        aws_mem_release(s2n_ctx->alloc, (void *) s2n_ctx);
    }
}

static int
read_file_to_blob(struct aws_allocator *alloc, const char *filename, uint8_t **blob, size_t *len) {
    FILE *fp = fopen(filename, "r");

    if (fp) {
        fseek(fp, 0L, SEEK_END);
        *len = (size_t) ftell(fp);

        fseek(fp, 0L, SEEK_SET);
        *blob = (uint8_t *) aws_mem_acquire(alloc, *len);

        if(!*blob) {
            fclose(fp);
            return aws_raise_error(AWS_ERROR_OOM);
        }

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

struct aws_tls_ctx *aws_tls_server_ctx_new(struct aws_allocator *alloc,
                                           struct aws_tls_server_options *options) {
    struct s2n_ctx *ctx = (struct s2n_ctx *) aws_mem_acquire(alloc, sizeof(struct s2n_ctx));

    if (!ctx) {
        aws_raise_error(AWS_ERROR_OOM);
        goto err;
    }

    ctx->alloc = alloc;
    ctx->s2n_config = s2n_config_new();

    if (!ctx->s2n_config) {
        goto err;
    }

    uint8_t *cert_blob = NULL;
    size_t cert_len = 0;

    if (read_file_to_blob(alloc, options->certificate_path, &cert_blob, &cert_len)) {
        goto err;
    }

    uint8_t *key_blob = NULL;
    size_t key_len = 0;
    if (read_file_to_blob(alloc, options->private_key_path, &key_blob, &key_len)) {
        aws_mem_release(alloc, cert_blob);
        goto err;
    }

    int err_code = s2n_config_add_cert_chain_and_key(ctx->s2n_config, (const char *) cert_blob,
                                                     (const char *) key_blob);

    /** set alpn here */
    /* err_code |= s2n_config_set_protocol_preferences(ctx->s2n_config, options->alpn_list); */

    if (err_code != S2N_ERR_T_OK) {
        aws_raise_error(AWS_IO_TLS_CTX_ERROR);
        fprintf(stderr, "error code %d\n", s2n_errno);
        goto err;
    }

    return (struct aws_tls_ctx *) ctx;

    err:
    if (ctx) {
        if (ctx->s2n_config) {
            s2n_config_free(ctx->s2n_config);
        }

        aws_mem_release(alloc, ctx);
    }

    return NULL;
}

struct aws_tls_ctx *aws_io_tls_client_ctx_new(struct aws_allocator *alloc,
                                                             struct aws_tls_client_options *options) {

    struct s2n_ctx *ctx = (struct s2n_ctx *) aws_mem_acquire(alloc, sizeof(struct s2n_ctx));

    if (!ctx) {
        goto err;
    }

    ctx->alloc = alloc;
    ctx->s2n_config = s2n_config_new();

    if (!ctx->s2n_config) {
        goto err;
    }

    /** set alpn here */
    /* err_code |= s2n_config_set_protocol_preferences(ctx->s2n_config, options->alpn_list); */

    if (!options->verify_peer) {
        s2n_config_disable_x509_verification(ctx->s2n_config);
    }
    else {
        int err_code = s2n_config_set_check_stapled_ocsp_response(ctx->s2n_config, 1);
        if(options->ca_file || options->ca_path) {
            err_code |= s2n_config_set_verification_ca_location(ctx->s2n_config, options->ca_file, options->ca_path);
        }

        if (err_code != S2N_ERR_T_OK) {
            goto err;
        }
    }

    return (struct aws_tls_ctx *) ctx;

    err:
    if (ctx) {
        if (ctx->s2n_config) {
            s2n_config_free(ctx->s2n_config);
        }

        aws_mem_release(alloc, ctx);
    }

    return NULL;
}



