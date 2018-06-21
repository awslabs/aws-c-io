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

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecureTransport.h>
#include <Security/SecCertificate.h>
#include <Security/SecIdentity.h>
#include <Security/SecItem.h>
#include <aws/io/channel.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/encoding.h>

static const size_t EST_TLS_RECORD_OVERHEAD = 53; /* 5 byte header + 32 + 16 bytes for padding */

void aws_tls_init_static_state(struct aws_allocator *alloc) { /* no op */}
void aws_tls_clean_up_static_state(struct aws_allocator *alloc) { /* no op */}

struct secure_transport_handler {
    SSLContextRef ctx;
    struct aws_linked_list input_queue;
    struct aws_channel_slot *parent_slot;
    struct aws_byte_buf protocol;
    struct aws_byte_buf server_name;
    struct aws_tls_connection_options options;
    aws_channel_on_message_write_completed latest_message_on_completion;
    void *latest_message_completion_user_data;
    bool negotiation_finished;
};


static OSStatus aws_tls_read_cb(SSLConnectionRef conn, void *data, size_t *len) {
    struct secure_transport_handler *handler = (struct secure_transport_handler *)conn;

    size_t written = 0;
    struct aws_byte_buf buf = aws_byte_buf_from_array((const uint8_t *)data, *len);

    while (!aws_linked_list_empty(&handler->input_queue) && written < buf.len) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&handler->input_queue);
        struct aws_io_message *message = aws_container_of(node, struct aws_io_message, queueing_handle);

        size_t remaining_message_len = message->message_data.len - message->copy_mark;
        size_t remaining_buf_len = buf.len - written;

        size_t to_write = remaining_message_len < remaining_buf_len ? remaining_message_len : remaining_buf_len;

        struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&message->message_data);
        aws_byte_cursor_advance(&message_cursor, message->copy_mark);
        aws_byte_cursor_read(&message_cursor, buf.buffer + written, to_write);

        written += to_write;

        message->copy_mark += to_write;

        if (message->copy_mark == message->message_data.len) {
            /* note: value is the first member of the allocated struct */
            aws_channel_release_message_to_pool(handler->parent_slot->channel, message);
        } else {
            aws_linked_list_push_front(&handler->input_queue, &message->queueing_handle);
        }
    }

    if (*len == written) {
        return noErr;
    }

    *len = written;
    return errSSLWouldBlock;
}

static OSStatus aws_tls_write_cb(SSLConnectionRef conn, const void *data, size_t *len) {
    struct secure_transport_handler *handler = (struct secure_transport_handler *)conn;

    struct aws_byte_buf buf = aws_byte_buf_from_array((const uint8_t *)data, *len);

    size_t processed = 0;
    while (processed < buf.len) {
        struct aws_io_message *message = aws_channel_acquire_message_from_pool(handler->parent_slot->channel,
                                                                               AWS_IO_MESSAGE_APPLICATION_DATA,
                                                                               buf.len - processed);

        if (!message) {
            aws_raise_error(AWS_ERROR_OOM);
            return errSecMemoryError;
        }

        struct aws_byte_cursor buffer_cursor = aws_byte_cursor_from_buf(&buf);
        aws_byte_buf_append(&message->message_data, &buffer_cursor);
        processed += message->message_data.len;

        if (processed == buf.len) {
            message->on_completion = handler->latest_message_on_completion;
            message->user_data = handler->latest_message_completion_user_data;
            handler->latest_message_on_completion = NULL;
            handler->latest_message_completion_user_data = NULL;
        }

        aws_channel_slot_send_message(handler->parent_slot, message, AWS_CHANNEL_DIR_WRITE);
    }

    if (*len == processed) {
        return noErr;
    }

    *len = processed;
    return errSSLWouldBlock;
}

static void secure_transport_handler_destroy(struct aws_channel_handler *handler) {
    if (handler) {
        struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *) handler->impl;
        CFRelease(secure_transport_handler->ctx);
        aws_mem_release(handler->alloc, (void *) secure_transport_handler);
        aws_mem_release(handler->alloc, (void *) handler);
    }
}


/* NOT SUPPORTING H2 Isn't an option, and I dumped out the dylibs and saw the function is indeed there, AND safari supports it, so there's no way it doesn't work.
 * In fact I don't even feel bad about this. How do you ship safari with support for this and not make H2 available for other applications to use? */
#if (MAC_OS_X_VERSION_MAX_ALLOWED >= 101100 && MAC_OS_X_VERSION_MAX_ALLOWED < 101300)
#define ALPN_SUPPORTED 1
typedef void(*SSLALPNFunc)(SSLContextRef ctx, void *info, const void *alpn_data, size_t alpn_data_length);

extern OSStatus SSLSetALPNFunc(SSLContextRef context, SSLALPNFunc alpnFunc, void *info);
extern OSStatus SSLSetALPNData(SSLContextRef context, const void *data, size_t length);
extern const void *SSLGetALPNData(SSLContextRef context, size_t *length);

static void client_alpn_fn(SSLContextRef context, void *info, const void *alpn_data, size_t alpn_data_length) {

}

static void server_alpn_fn(SSLContextRef context, void *info, const void *alpn_data, size_t alpn_data_length) {

}

#elif MAC_OS_X_VERSION_MAX_ALLOWED >= 101300
#define ALPN_SUPPORTED 1
#else
#define ALPN_NOT_SUPPORTED 0
#endif

static int drive_negotiation(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *)handler->impl;

    OSStatus status = SSLHandshake(secure_transport_handler->ctx);

    if (status == noErr) {
        secure_transport_handler->negotiation_finished = true;
        size_t name_len = 0;
        const char *protocol = SSLGetALPNData(secure_transport_handler->ctx, &name_len);

        if (protocol) {
            secure_transport_handler->protocol = aws_byte_buf_from_array((uint8_t *)protocol, name_len);
        }

        name_len = 0;
        status = SSLGetPeerDomainNameLength(secure_transport_handler->ctx, &name_len);

        if (status == noErr && name_len) {
            char server_name[name_len];
            status = SSLGetPeerDomainName(secure_transport_handler->ctx, server_name, &name_len);
            secure_transport_handler->server_name = aws_byte_buf_from_array((uint8_t *)server_name, name_len);
        }

        if (secure_transport_handler->parent_slot->adj_right && secure_transport_handler->options.advertise_alpn_message && protocol) {
            struct aws_io_message *message = aws_channel_acquire_message_from_pool(secure_transport_handler->parent_slot->channel,
                                                                                   AWS_IO_MESSAGE_APPLICATION_DATA,
                                                                                   sizeof(struct aws_tls_negotiated_protocol_message));
            message->message_tag = AWS_TLS_NEGOTIATED_PROTOCOL_MESSAGE;
            struct aws_tls_negotiated_protocol_message *protocol_message =
                    (struct aws_tls_negotiated_protocol_message *)message->message_data.buffer;

            protocol_message->protocol = secure_transport_handler->protocol;
            message->message_data.len = sizeof(struct aws_tls_negotiated_protocol_message);
            if (aws_channel_slot_send_message(secure_transport_handler->parent_slot, message, AWS_CHANNEL_DIR_READ)) {
                aws_channel_release_message_to_pool(secure_transport_handler->parent_slot->channel, message);
                aws_channel_shutdown(secure_transport_handler->parent_slot->channel, aws_last_error());
                return AWS_OP_SUCCESS;
            }
        }

        if (secure_transport_handler->options.on_negotiation_result) {
            secure_transport_handler->options.on_negotiation_result(handler, secure_transport_handler->parent_slot, AWS_OP_SUCCESS, secure_transport_handler->options.user_data);
        }
    }
    else if (status != errSSLWouldBlock && status != errSSLPeerAuthCompleted) {
        secure_transport_handler->negotiation_finished = false;

        aws_raise_error(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);

        if (secure_transport_handler->options.on_negotiation_result) {
            secure_transport_handler->options.on_negotiation_result(handler, secure_transport_handler->parent_slot,
                                                                    AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE,
                                                                    secure_transport_handler->options.user_data);
        }

        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void negotiation_task(void *arg, aws_task_status status) {
    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_channel_handler *handler = (struct aws_channel_handler *) arg;
        drive_negotiation(handler);
    }
}

int aws_tls_client_handler_start_negotiation(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *) handler->impl;

    if (aws_channel_thread_is_callers_thread(secure_transport_handler->parent_slot->channel)) {
        return drive_negotiation(handler);
    }

    struct aws_task task = {
            .fn = negotiation_task,
            .arg = handler,
    };

    uint64_t now = 0;
    aws_channel_current_clock_time(secure_transport_handler->parent_slot->channel, &now);
    return aws_channel_schedule_task(secure_transport_handler->parent_slot->channel, &task, now);
}

static int secure_transport_handler_process_write_message(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                             struct aws_io_message *message) {
    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *) handler->impl;

    if (AWS_UNLIKELY(!secure_transport_handler->negotiation_finished)) {
        return aws_raise_error(AWS_IO_TLS_ERROR_NOT_NEGOTIATED);
    }

    secure_transport_handler->latest_message_on_completion = message->on_completion;
    secure_transport_handler->latest_message_completion_user_data = message->user_data;

    size_t processed = 0;
    OSStatus status = SSLWrite(secure_transport_handler->ctx, message->message_data.buffer, message->message_data.len, &processed);

    aws_channel_release_message_to_pool(slot->channel, message);

    if (status != noErr) {
        return aws_raise_error(AWS_IO_TLS_ERROR_WRITE_FAILURE);
    }

    return AWS_OP_SUCCESS;
}

static int secure_transport_handler_handle_shutdown(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                       int error_code, bool abort_immediately) {
    /*this should never occur since this couldn't possibly be the first handler in the channel */
    assert(0);
}

static int secure_transport_handler_on_shutdown_notify (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                           enum aws_channel_direction dir, int error_code) {
    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *) handler->impl;

    if (dir == AWS_CHANNEL_DIR_WRITE && !error_code) {
        SSLClose(secure_transport_handler->ctx);
    }
    else {
        while (!aws_linked_list_empty(&secure_transport_handler->input_queue)) {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&secure_transport_handler->input_queue);
            struct aws_io_message *message = aws_container_of(node, struct aws_io_message, queueing_handle);
            aws_channel_release_message_to_pool(secure_transport_handler->parent_slot->channel, message);
        }
    }

    return aws_channel_slot_shutdown_notify(slot, dir, error_code);
}

static int secure_transport_handler_process_read_message(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                            struct aws_io_message *message) {

    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *) handler->impl;

    if (message) {
        aws_linked_list_push_back(&secure_transport_handler->input_queue, &message->queueing_handle);

        if (!secure_transport_handler->negotiation_finished) {
            size_t message_len = message->message_data.len;
            if (!drive_negotiation(handler)) {
                aws_channel_slot_update_window(slot, message_len);
            }
            else {
                aws_channel_shutdown(secure_transport_handler->parent_slot->channel, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
            }
            return AWS_OP_SUCCESS;
        }
    }

    size_t downstream_window = aws_channel_slot_downstream_read_window(slot);
    size_t processed = 0;

    OSStatus status = noErr;
    while (processed < downstream_window && status == noErr) {

        struct aws_io_message *outgoing_read_message = aws_channel_acquire_message_from_pool(slot->channel,
                                                                                             AWS_IO_MESSAGE_APPLICATION_DATA,
                                                                                             downstream_window);
        if (!outgoing_read_message) {
            return aws_raise_error(AWS_ERROR_OOM);
        }

        size_t read = 0;
        status = SSLRead(secure_transport_handler->ctx, outgoing_read_message->message_data.buffer,
                                outgoing_read_message->message_data.capacity, &read);

        if (read <= 0) {
            aws_channel_release_message_to_pool(slot->channel, outgoing_read_message);
            continue;
        };

        processed += read;
        outgoing_read_message->message_data.len = (size_t)read;

        if (secure_transport_handler->options.on_data_read) {
            secure_transport_handler->options.on_data_read(handler, slot, &outgoing_read_message->message_data, secure_transport_handler->options.user_data);
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

static void run_read(void *arg, aws_task_status status) {
    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_channel_handler *handler = (struct aws_channel_handler *) arg;
        struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *) handler->impl;
        secure_transport_handler_process_read_message(handler, secure_transport_handler->parent_slot, NULL);
    }
}

static int secure_transport_handler_on_window_update (struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size) {
    aws_channel_slot_update_window(slot, size + EST_TLS_RECORD_OVERHEAD);

    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *) handler->impl;

    if (secure_transport_handler->negotiation_finished) {
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

static size_t secure_transport_handler_get_current_window_size (struct aws_channel_handler *handler) {
    /* This is going to end up getting reset as soon as an downstream handler is added to the channel, but
     * we don't actually care about our window, we just want to honor the downstream handler's window. Start off
     * with it large, and then take the downstream window when it notifies us.*/
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
        .destroy = secure_transport_handler_destroy,
        .process_read_message = secure_transport_handler_process_read_message,
        .process_write_message = secure_transport_handler_process_write_message,
        .shutdown = secure_transport_handler_handle_shutdown,
        .on_shutdown_notify = secure_transport_handler_on_shutdown_notify,
        .on_window_update = secure_transport_handler_on_window_update,
        .get_current_window_size = secure_transport_handler_get_current_window_size,
};

struct aws_channel_handler *aws_tls_client_handler_new(struct aws_allocator *allocator,
                                                                  struct aws_tls_ctx *ctx,
                                                                  struct aws_tls_connection_options *options,
                                                                  struct aws_channel_slot *slot) {
    struct aws_channel_handler *channel_handler = (struct aws_channel_handler *)aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));

    if (!channel_handler) {
        return NULL;
    }

    channel_handler->alloc = allocator;

    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *)aws_mem_acquire(allocator, sizeof(struct secure_transport_handler));

    if (!secure_transport_handler) {
        goto cleanup_channel_handler;
    }

    secure_transport_handler->ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    if (!secure_transport_handler->ctx) {
        /* TODO raise error here. */
        goto cleanup_st_handler;
    }

    /* we need to add sni and negotiation callbacks */
    if (SSLSetIOFuncs(secure_transport_handler->ctx, aws_tls_read_cb, aws_tls_write_cb) != noErr ||
            SSLSetConnection(secure_transport_handler->ctx, secure_transport_handler) != noErr) {
        /* TODO raise error here */
        goto cleanup_ssl_ctx;
    }

    if (!options->verify_peer) {
        SSLSetSessionOption(secure_transport_handler->ctx, kSSLSessionOptionBreakOnServerAuth, true);
    }

    SSLSetALPNFunc(secure_transport_handler->ctx, client_alpn_fn, secure_transport_handler);
    SSLSetALPNData(secure_transport_handler->ctx, options->alpn_list, strlen(options->alpn_list));

    aws_linked_list_init(&secure_transport_handler->input_queue);
    secure_transport_handler->parent_slot = slot;
    secure_transport_handler->latest_message_completion_user_data = NULL;
    secure_transport_handler->negotiation_finished = false;
    aws_byte_buf_init(NULL, &secure_transport_handler->protocol, 0);
    secure_transport_handler->latest_message_on_completion = NULL;
    secure_transport_handler->server_name = aws_byte_buf_from_c_str(options->server_name);
    aws_byte_buf_init(NULL, &secure_transport_handler->server_name, 0);
    secure_transport_handler->options = *options;

    channel_handler->impl = secure_transport_handler;
    channel_handler->vtable = handler_vtable;

    return channel_handler;

cleanup_ssl_ctx:
    CFRelease(secure_transport_handler->ctx);
cleanup_st_handler:
    aws_mem_release(allocator, (void *)secure_transport_handler);

cleanup_channel_handler:
    aws_mem_release(allocator, (void *)channel_handler);

    return NULL;
}

struct aws_channel_handler *aws_tls_server_handler_new(struct aws_allocator *allocator, struct aws_tls_ctx *ctx,
                                                                  struct aws_tls_connection_options *options,
                                                                  struct aws_channel_slot *slot) {
    struct aws_channel_handler *channel_handler = (struct aws_channel_handler *)aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));

    if (!channel_handler) {
        return NULL;
    }

    channel_handler->alloc = allocator;

    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *)aws_mem_acquire(allocator, sizeof(struct secure_transport_handler));

    if (!secure_transport_handler) {
        goto cleanup_channel_handler;
    }

    secure_transport_handler->ctx = SSLCreateContext(NULL, kSSLServerSide, kSSLStreamType);
    if (!secure_transport_handler->ctx) {
        /* TODO raise error here. */
        goto cleanup_st_handler;
    }

    /* we need to add sni and negotiation callbacks */
    if (SSLSetIOFuncs(secure_transport_handler->ctx, aws_tls_read_cb, aws_tls_write_cb) != noErr ||
        SSLSetConnection(secure_transport_handler->ctx, secure_transport_handler) != noErr) {
        /* TODO raise error here */
        goto cleanup_ssl_ctx;
    }

    if (!options->verify_peer) {
        SSLSetSessionOption(secure_transport_handler->ctx, kSSLSessionOptionBreakOnClientAuth, true);
    }

    SSLSetALPNFunc(secure_transport_handler->ctx, server_alpn_fn, secure_transport_handler);
    SSLSetALPNData(secure_transport_handler->ctx, options->alpn_list, strlen(options->alpn_list));

    aws_linked_list_init(&secure_transport_handler->input_queue);
    secure_transport_handler->parent_slot = slot;
    secure_transport_handler->latest_message_completion_user_data = NULL;
    secure_transport_handler->negotiation_finished = false;
    aws_byte_buf_init(NULL, &secure_transport_handler->protocol, 0);
    secure_transport_handler->latest_message_on_completion = NULL;
    secure_transport_handler->server_name = aws_byte_buf_from_c_str(options->server_name);
    aws_byte_buf_init(NULL, &secure_transport_handler->server_name, 0);
    secure_transport_handler->options = *options;

    channel_handler->impl = secure_transport_handler;
    channel_handler->vtable = handler_vtable;
    return channel_handler;

cleanup_ssl_ctx:
    CFRelease(secure_transport_handler->ctx);

cleanup_st_handler:
    aws_mem_release(allocator, (void *)secure_transport_handler);

cleanup_channel_handler:
    aws_mem_release(allocator, (void *)channel_handler);

    return NULL;
}

struct secure_transport_ctx {
    struct aws_allocator *allocator;
    SecIdentityRef public_private_pair;
};

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

struct aws_tls_ctx *aws_tls_server_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    struct aws_tls_ctx *ctx = (struct aws_tls_ctx *) aws_mem_acquire(alloc, sizeof(struct aws_tls_ctx));

    if (!ctx) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    struct secure_transport_ctx *secure_transport_ctx = (struct secure_transport_ctx *) aws_mem_acquire(alloc, sizeof(struct secure_transport_ctx));

    if (!secure_transport_ctx) {
        aws_raise_error(AWS_ERROR_OOM);
        goto cleanup_ctx;
    }

    if (options->private_key_path && options->certificate_path) {
        uint8_t *cert_blob = NULL;
        size_t cert_len = 0;

        /* TODO this API is the worst I have to go spend 10 years figuring it out. */
    }

    ctx->alloc = alloc;
    ctx->impl = secure_transport_ctx;
}

struct aws_tls_ctx *aws_tls_client_ctx_new(struct aws_allocator *alloc,
                                                      struct aws_tls_ctx_options *options);

void  aws_tls_ctx_destroy(struct aws_tls_ctx *ctx);
