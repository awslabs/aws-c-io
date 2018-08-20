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
#include <aws/common/encoding.h>
#include <aws/common/task_scheduler.h>
#include <aws/io/channel.h>
#include <aws/io/tls_channel_handler.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCertificate.h>
#include <Security/SecureTransport.h>
#include <Security/Security.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"

/* I'm tired of trying to make SSLSetALPNFunc work, upgrade your operating system if you want ALPN support. */
#if (TARGET_OS_MAC && MAC_OS_X_VERSION_MAX_ALLOWED >= 101302) ||                                                       \
    (TARGET_OS_IPHONE && __IPHONE_OS_VERSION_MAX_ALLOWED >= 110000) ||                                                 \
    (TARGET_OS_TV && __TV_OS_VERSION_MAX_ALLOWED >= 110000) ||                                                         \
    (TARGET_OS_WATCH && __WATCH_OS_VERSION_MAX_ALLOWED >= 40000)
#    define ALPN_AVAILABLE true
#    define TLS13_AVAILABLE true
#else
#    define ALPN_AVAILABLE false
#    define TLS13_AVAILABLE false
#endif

bool aws_tls_is_alpn_available(void) {
    return ALPN_AVAILABLE;
}

static const size_t EST_TLS_RECORD_OVERHEAD = 53; /* 5 byte header + 32 + 16 bytes for padding */

void aws_tls_init_static_state(struct aws_allocator *alloc) { /* no op */
}
void aws_tls_clean_up_static_state(struct aws_allocator *alloc) { /* no op */
}

struct secure_transport_handler {
    SSLContextRef ctx;
    CFAllocatorRef wrapped_allocator;
    struct aws_linked_list input_queue;
    struct aws_channel_slot *parent_slot;
    CFStringRef protocol;
    /*per spec the max length for a server name is 255 bytes (plus the null character). */
    char server_name_array[256];
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
    buf.len = 0;

    while (!aws_linked_list_empty(&handler->input_queue) && written < buf.capacity) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&handler->input_queue);
        struct aws_io_message *message = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);

        size_t remaining_message_len = message->message_data.len - message->copy_mark;
        size_t remaining_buf_len = buf.capacity - written;

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
        struct aws_io_message *message = aws_channel_acquire_message_from_pool(
            handler->parent_slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, buf.len - processed);

        if (!message) {
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

        if (aws_channel_slot_send_message(handler->parent_slot, message, AWS_CHANNEL_DIR_WRITE)) {
            aws_channel_release_message_to_pool(handler->parent_slot->channel, message);
        }
    }

    if (*len == processed) {
        return noErr;
    }

    *len = processed;
    return errSSLWouldBlock;
}

static void secure_transport_handler_destroy(struct aws_channel_handler *handler) {
    if (handler) {
        struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *)handler->impl;
        CFRelease(secure_transport_handler->ctx);

        if (secure_transport_handler->protocol) {
            CFRelease(secure_transport_handler->protocol);
        }

        aws_mem_release(handler->alloc, (void *)secure_transport_handler);
        aws_mem_release(handler->alloc, (void *)handler);
    }
}

static CFStringRef get_protocol(struct secure_transport_handler *handler) {
#if ALPN_AVAILABLE
    CFArrayRef protocols = NULL;

    SSLCopyALPNProtocols(handler->ctx, &protocols);

    if (!protocols) {
        return NULL;
    }

    CFIndex count = CFArrayGetCount(protocols);

    if (count <= 0) {
        return NULL;
    }

    CFStringRef alpn_value = CFArrayGetValueAtIndex(protocols, 0);
    CFRelease(protocols);

    return alpn_value;
#else
    return NULL;
#endif
}

static void set_protocols(
    struct secure_transport_handler *handler,
    struct aws_allocator *alloc,
    const char *alpn_list) {
#if ALPN_AVAILABLE
    struct aws_byte_buf alpn_data = aws_byte_buf_from_c_str(alpn_list);
    struct aws_array_list alpn_list_array;
    if (aws_array_list_init_dynamic(&alpn_list_array, alloc, 2, sizeof(struct aws_byte_cursor))) {
        return;
    }

    if (aws_byte_buf_split_on_char(&alpn_data, ',', &alpn_list_array)) {
        return;
    }

    CFArrayRef alpn_array = CFArrayCreateMutable(
        handler->wrapped_allocator, aws_array_list_length(&alpn_list_array), &kCFTypeArrayCallbacks);

    if (!alpn_array) {
        return;
    }

    for (size_t i = 0; i < aws_array_list_length(&alpn_list_array); ++i) {
        struct aws_byte_cursor protocol_cursor;
        aws_array_list_get_at(&alpn_list_array, &protocol, i);
        CFStringRef protocol = CFStringCreateWithBytes(
            handler->wrapped_allocator, protocol_cursor->ptr, protocol_cursor->len, kCFStringEncodingUTF8, false);

        if (!protocol) {
            CFRelease(alpn_array);
            alpn_array = NULL;
            break;
        }

        CFArrayAppendValue(alpn_array, protocol);
        CFRelease(protocol);
    }

    if (alpn_array) {
        SSLSetALPNProtocols(handler->ctx, alpn_array);
    }

    aws_array_list_clean_up(&alpn_list_array);
#endif
}

static int drive_negotiation(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *)handler->impl;

    OSStatus status = SSLHandshake(secure_transport_handler->ctx);

    if (status == noErr) {
        secure_transport_handler->negotiation_finished = true;
        size_t name_len = 0;
        CFStringRef protocol = get_protocol(secure_transport_handler);

        if (protocol) {
            secure_transport_handler->protocol = protocol;
        }

        name_len = 0;
        status = SSLGetPeerDomainNameLength(secure_transport_handler->ctx, &name_len);

        if (status == noErr && name_len) {
            size_t max_len = name_len > sizeof(secure_transport_handler->server_name) - 1
                                 ? sizeof(secure_transport_handler->server_name) - 1
                                 : name_len;
            SSLGetPeerDomainName(secure_transport_handler->ctx, secure_transport_handler->server_name_array, &max_len);
            /* sometimes this api includes the NULL character, sometimes it doesn't, so unfortunately we have to
             * actually call strlen.*/
            size_t actual_length = strlen(secure_transport_handler->server_name_array);
            secure_transport_handler->server_name =
                aws_byte_buf_from_array((uint8_t *)secure_transport_handler->server_name_array, actual_length);
        }

        if (secure_transport_handler->parent_slot->adj_right &&
            secure_transport_handler->options.advertise_alpn_message && protocol) {
            struct aws_io_message *message = aws_channel_acquire_message_from_pool(
                secure_transport_handler->parent_slot->channel,
                AWS_IO_MESSAGE_APPLICATION_DATA,
                sizeof(struct aws_tls_negotiated_protocol_message));
            message->message_tag = AWS_TLS_NEGOTIATED_PROTOCOL_MESSAGE;
            struct aws_tls_negotiated_protocol_message *protocol_message =
                (struct aws_tls_negotiated_protocol_message *)message->message_data.buffer;

            protocol_message->protocol = aws_byte_buf_from_array(
                (uint8_t *)CFStringGetCStringPtr(secure_transport_handler->protocol, kCFStringEncodingUTF8),
                (size_t)CFStringGetLength(secure_transport_handler->protocol));

            message->message_data.len = sizeof(struct aws_tls_negotiated_protocol_message);
            if (aws_channel_slot_send_message(secure_transport_handler->parent_slot, message, AWS_CHANNEL_DIR_READ)) {
                aws_channel_release_message_to_pool(secure_transport_handler->parent_slot->channel, message);
                aws_channel_shutdown(secure_transport_handler->parent_slot->channel, aws_last_error());
                return AWS_OP_SUCCESS;
            }
        }

        if (secure_transport_handler->options.on_negotiation_result) {
            secure_transport_handler->options.on_negotiation_result(
                handler,
                secure_transport_handler->parent_slot,
                AWS_OP_SUCCESS,
                secure_transport_handler->options.user_data);
        }
    } else if (status != errSSLWouldBlock && status != errSSLPeerAuthCompleted) {
        secure_transport_handler->negotiation_finished = false;

        aws_raise_error(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);

        if (secure_transport_handler->options.on_negotiation_result) {
            secure_transport_handler->options.on_negotiation_result(
                handler,
                secure_transport_handler->parent_slot,
                AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE,
                secure_transport_handler->options.user_data);
        }

        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void negotiation_task(void *arg, aws_task_status status) {
    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_channel_handler *handler = (struct aws_channel_handler *)arg;
        drive_negotiation(handler);
    }
}

int aws_tls_client_handler_start_negotiation(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *)handler->impl;

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

static int secure_transport_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *)handler->impl;

    if (AWS_UNLIKELY(!secure_transport_handler->negotiation_finished)) {
        return aws_raise_error(AWS_IO_TLS_ERROR_NOT_NEGOTIATED);
    }

    secure_transport_handler->latest_message_on_completion = message->on_completion;
    secure_transport_handler->latest_message_completion_user_data = message->user_data;

    size_t processed = 0;
    OSStatus status =
        SSLWrite(secure_transport_handler->ctx, message->message_data.buffer, message->message_data.len, &processed);

    aws_channel_release_message_to_pool(slot->channel, message);

    if (status != noErr) {
        return aws_raise_error(AWS_IO_TLS_ERROR_WRITE_FAILURE);
    }

    return AWS_OP_SUCCESS;
}

static int secure_transport_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool abort_immediately) {
    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *)handler->impl;

    if (dir == AWS_CHANNEL_DIR_WRITE && !error_code) {
        SSLClose(secure_transport_handler->ctx);
    } else {
        while (!aws_linked_list_empty(&secure_transport_handler->input_queue)) {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&secure_transport_handler->input_queue);
            struct aws_io_message *message = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);
            aws_channel_release_message_to_pool(secure_transport_handler->parent_slot->channel, message);
        }
    }

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, abort_immediately);
}

static int secure_transport_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *)handler->impl;

    if (message) {
        aws_linked_list_push_back(&secure_transport_handler->input_queue, &message->queueing_handle);

        if (!secure_transport_handler->negotiation_finished) {
            size_t message_len = message->message_data.len;
            if (!drive_negotiation(handler)) {
                aws_channel_slot_increment_read_window(slot, message_len);
            } else {
                aws_channel_shutdown(
                    secure_transport_handler->parent_slot->channel, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
            }
            return AWS_OP_SUCCESS;
        }
    }

    size_t downstream_window = aws_channel_slot_downstream_read_window(slot);
    size_t processed = 0;

    OSStatus status = noErr;
    while (processed < downstream_window && status == noErr) {

        struct aws_io_message *outgoing_read_message =
            aws_channel_acquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, downstream_window);
        if (!outgoing_read_message) {
            return AWS_OP_ERR;
        }

        size_t read = 0;
        status = SSLRead(
            secure_transport_handler->ctx,
            outgoing_read_message->message_data.buffer,
            outgoing_read_message->message_data.capacity,
            &read);

        if (read <= 0) {
            aws_channel_release_message_to_pool(slot->channel, outgoing_read_message);
            continue;
        };

        processed += read;
        outgoing_read_message->message_data.len = (size_t)read;

        if (secure_transport_handler->options.on_data_read) {
            secure_transport_handler->options.on_data_read(
                handler, slot, &outgoing_read_message->message_data, secure_transport_handler->options.user_data);
        }

        if (slot->adj_right) {
            aws_channel_slot_send_message(slot, outgoing_read_message, AWS_CHANNEL_DIR_READ);
        } else {
            aws_channel_release_message_to_pool(slot->channel, outgoing_read_message);
        }
    }

    return AWS_OP_SUCCESS;
}

static void run_read(void *arg, aws_task_status status) {
    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_channel_handler *handler = (struct aws_channel_handler *)arg;
        struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *)handler->impl;
        secure_transport_handler_process_read_message(handler, secure_transport_handler->parent_slot, NULL);
    }
}

static int secure_transport_handler_on_window_update(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {
    aws_channel_slot_increment_read_window(slot, size + EST_TLS_RECORD_OVERHEAD);

    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *)handler->impl;

    if (secure_transport_handler->negotiation_finished) {
        /* we have messages in a queue and they need to be run after the socket has popped (even if it didn't have data
         * to read). Alternatively, s2n reads entire records at a time, so we'll need to grab whatever we can and we
         * have no idea what's going on inside there. So we need to attempt another read.*/
        uint64_t now = 0;

        if (aws_channel_current_clock_time(slot->channel, &now)) {
            return AWS_OP_ERR;
        }

        struct aws_task task = {.fn = run_read, .arg = handler};

        return aws_channel_schedule_task(slot->channel, &task, now);
    }

    return AWS_OP_SUCCESS;
}

static size_t secure_transport_handler_get_current_window_size(struct aws_channel_handler *handler) {
    /* This is going to end up getting reset as soon as an downstream handler is added to the channel, but
     * we don't actually care about our window, we just want to honor the downstream handler's window. Start off
     * with it large, and then take the downstream window when it notifies us.*/
    return SIZE_MAX;
}

struct aws_byte_buf aws_tls_handler_protocol(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *)handler->impl;
    return aws_byte_buf_from_array(
        (uint8_t *)CFStringGetCStringPtr(secure_transport_handler->protocol, kCFStringEncodingUTF8),
        (size_t)CFStringGetLength(secure_transport_handler->protocol));
}

struct aws_byte_buf aws_tls_handler_server_name(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = (struct secure_transport_handler *)handler->impl;
    return secure_transport_handler->server_name;
}

static struct aws_channel_handler_vtable handler_vtable = {
    .destroy = secure_transport_handler_destroy,
    .process_read_message = secure_transport_handler_process_read_message,
    .process_write_message = secure_transport_handler_process_write_message,
    .shutdown = secure_transport_handler_shutdown,
    .increment_read_window = secure_transport_handler_on_window_update,
    .initial_window_size = secure_transport_handler_get_current_window_size,
};

struct secure_transport_ctx {
    struct aws_allocator *allocator;
    CFAllocatorRef wrapped_allocator;
    CFArrayRef certs;
    SecCertificateRef ca_cert;
    aws_tls_versions minimum_version;
    const char *server_name;
    const char *alpn_list;
    bool veriify_peer;
};

static struct aws_channel_handler *tls_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_ctx *ctx,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot,
    SSLProtocolSide protocol_side) {
    struct secure_transport_ctx *secure_transport_ctx = (struct secure_transport_ctx *)ctx->impl;
    struct aws_channel_handler *channel_handler =
        (struct aws_channel_handler *)aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));

    if (!channel_handler) {
        return NULL;
    }

    channel_handler->alloc = allocator;

    struct secure_transport_handler *secure_transport_handler =
        (struct secure_transport_handler *)aws_mem_acquire(allocator, sizeof(struct secure_transport_handler));

    if (!secure_transport_handler) {
        goto cleanup_channel_handler;
    }

    AWS_ZERO_STRUCT(*secure_transport_handler);
    secure_transport_handler->wrapped_allocator = secure_transport_ctx->wrapped_allocator;
    secure_transport_handler->protocol = NULL;
    secure_transport_handler->ctx =
        SSLCreateContext(secure_transport_handler->wrapped_allocator, protocol_side, kSSLStreamType);

    if (!secure_transport_handler->ctx) {
        /* TODO raise error here. */
        goto cleanup_st_handler;
    }

    switch (secure_transport_ctx->minimum_version) {
        case AWS_IO_SSLv3:
            SSLSetProtocolVersionMin(secure_transport_handler->ctx, kSSLProtocol3);
            break;
        case AWS_IO_TLSv1:
            SSLSetProtocolVersionMin(secure_transport_handler->ctx, kTLSProtocol1);
            break;
        case AWS_IO_TLSv1_1:
            SSLSetProtocolVersionMin(secure_transport_handler->ctx, kTLSProtocol12);
            break;
        case AWS_IO_TLSv1_2:
            SSLSetProtocolVersionMin(secure_transport_handler->ctx, kTLSProtocol12);
            break;
        case AWS_IO_TLSv1_3:
#if TLS13_AVAILABLE
            SSLSetProtocolVersionMin(secure_transport_handler->ctx, kTLSProtocol13);
#else
            /*
             * "TLS 1.3 is not supported for your target platform,
             * you can probably get by setting AWS_IO_TLSv1_2 as the minimum and if tls 1.3 is supported it will be
             * used.
             */
            assert(0);
#endif
            break;
        default:
            /* you have to make a decision on this! It's important!!!! */
            assert(0);
            break;
    }

    if (SSLSetIOFuncs(secure_transport_handler->ctx, aws_tls_read_cb, aws_tls_write_cb) != noErr ||
        SSLSetConnection(secure_transport_handler->ctx, secure_transport_handler) != noErr) {
        /* TODO raise error here */
        goto cleanup_ssl_ctx;
    }

    OSStatus status = noErr;

    if (!secure_transport_ctx->veriify_peer) {
        SSLSetAllowsAnyRoot(secure_transport_handler->ctx, true);
    }

    if (!options->verify_peer) {
        status = SSLSetSessionOption(secure_transport_handler->ctx, kSSLSessionOptionBreakOnClientAuth, true);
    }

    if (secure_transport_ctx->certs) {
        status = SSLSetCertificate(secure_transport_handler->ctx, secure_transport_ctx->certs);
    }

    if (secure_transport_ctx->ca_cert && protocol_side == kSSLServerSide) {
        // status = SSLSetTrustedRoots(secure_transport_handler->ctx, secure_transport_ctx->ca_cert, true);
        status = SSLSetCertificateAuthorities(secure_transport_handler->ctx, secure_transport_ctx->ca_cert, true);
    }

    aws_linked_list_init(&secure_transport_handler->input_queue);
    secure_transport_handler->parent_slot = slot;
    secure_transport_handler->latest_message_completion_user_data = NULL;
    secure_transport_handler->negotiation_finished = false;
    secure_transport_handler->latest_message_on_completion = NULL;

    const char *server_name = NULL;
    if (options->server_name) {
        server_name = options->server_name;
    } else {
        server_name = secure_transport_ctx->server_name;
    }

    if (server_name) {
        size_t server_name_len = strlen(server_name);
        SSLSetPeerDomainName(secure_transport_handler->ctx, server_name, server_name_len);
    }

    const char *alpn_list = NULL;
    if (options->alpn_list) {
        alpn_list = options->alpn_list;
    } else {
        alpn_list = secure_transport_ctx->alpn_list;
    }

    if (alpn_list) {
        set_protocols(secure_transport_handler, allocator, alpn_list);
    }

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

struct aws_channel_handler *aws_tls_client_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_ctx *ctx,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {
    return tls_handler_new(allocator, ctx, options, slot, kSSLClientSide);
}

struct aws_channel_handler *aws_tls_server_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_ctx *ctx,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {
    return tls_handler_new(allocator, ctx, options, slot, kSSLServerSide);
}

static int read_file_to_blob(struct aws_allocator *alloc, const char *filename, uint8_t **blob, size_t *len) {
    FILE *fp = fopen(filename, "r");

    if (fp) {
        fseek(fp, 0L, SEEK_END);
        *len = (size_t)ftell(fp);

        fseek(fp, 0L, SEEK_SET);
        *blob = (uint8_t *)aws_mem_acquire(alloc, *len + 1);

        if (!*blob) {
            fclose(fp);
            return AWS_OP_ERR;
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

typedef enum PEM_TO_DER_STATE {
    BEGIN,
    ON_DATA,
    FINISHED

} PEM_TO_DER_STATE;

static int convert_pem_to_raw_base64(uint8_t *pem, size_t len, uint8_t *output, size_t *output_len) {
    uint8_t current_char = *pem;
    PEM_TO_DER_STATE state = BEGIN;
    size_t i = 0;

    while (current_char && i < len && state < FINISHED) {
        switch (state) {
            case BEGIN:
                if (current_char == '\n') {
                    state = ON_DATA;
                    break;
                }
                break;
            case ON_DATA:
                if (current_char == '\n') {
                    break;
                }
                if (current_char == '-') {
                    state = FINISHED;
                    break;
                }
                output[i++] = current_char;
                break;
            case FINISHED:
                break;
        }
        current_char = *++pem;
    }

    *output_len = i;

    if (state == FINISHED) {
        return AWS_OP_SUCCESS;
    } else {
        return aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
    }
}

static struct aws_tls_ctx *tls_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    struct aws_tls_ctx *ctx = (struct aws_tls_ctx *)aws_mem_acquire(alloc, sizeof(struct aws_tls_ctx));

    if (!ctx) {
        return NULL;
    }

    struct secure_transport_ctx *secure_transport_ctx =
        (struct secure_transport_ctx *)aws_mem_acquire(alloc, sizeof(struct secure_transport_ctx));

    if (!secure_transport_ctx) {
        goto cleanup_ctx;
    }

    AWS_ZERO_STRUCT(*secure_transport_ctx);
    secure_transport_ctx->wrapped_allocator = aws_wrapped_cf_allocator_new(alloc);
    secure_transport_ctx->minimum_version = options->minimum_tls_version;

    if (!secure_transport_ctx->wrapped_allocator) {
        goto cleanup_secure_transport_ctx;
    }

    secure_transport_ctx->server_name = options->server_name;
    secure_transport_ctx->alpn_list = options->alpn_list;
    secure_transport_ctx->veriify_peer = options->verify_peer;
    secure_transport_ctx->ca_cert = NULL;
    secure_transport_ctx->certs = NULL;
    secure_transport_ctx->allocator = alloc;

    if (options->pkcs12_path) {
        assert(options->pkcs12_password);

        uint8_t *cert_blob = NULL;
        size_t cert_len = 0;

        if (read_file_to_blob(alloc, options->pkcs12_path, &cert_blob, &cert_len)) {
            goto cleanup_wrapped_allocator;
        }

        CFDataRef pkcs12_data = CFDataCreate(secure_transport_ctx->wrapped_allocator, cert_blob, cert_len);
        aws_mem_release(alloc, cert_blob);
        CFArrayRef items = NULL;

        CFMutableDictionaryRef dictionary =
            CFDictionaryCreateMutable(secure_transport_ctx->wrapped_allocator, 0, NULL, NULL);
        CFStringRef password = CFStringCreateWithCString(
            secure_transport_ctx->wrapped_allocator, options->pkcs12_password, kCFStringEncodingUTF8);
        CFDictionaryAddValue(dictionary, kSecImportExportPassphrase, password);

        OSStatus status = SecPKCS12Import(pkcs12_data, dictionary, &items);
        CFRelease(pkcs12_data);
        CFRelease(password);
        CFRelease(dictionary);

        CFTypeRef item = (CFTypeRef)CFArrayGetValueAtIndex(items, 0);
        CFTypeID itemId = CFGetTypeID(item);
        CFTypeID certTypeId = SecCertificateGetTypeID();
        CFTypeID dictionaryId = CFDictionaryGetTypeID();

        CFTypeRef identity = (CFTypeRef)CFDictionaryGetValue((CFDictionaryRef)item, kSecImportItemIdentity);
        CFTypeRef certs[] = {identity};
        secure_transport_ctx->certs =
            CFArrayCreate(secure_transport_ctx->wrapped_allocator, (const void **)certs, 1L, &kCFTypeArrayCallBacks);
    }

    if (options->ca_file) {
        uint8_t *cert_blob = NULL;
        size_t cert_len = 0;

        if (read_file_to_blob(alloc, options->ca_file, &cert_blob, &cert_len)) {
            goto cleanup_wrapped_allocator;
        }

        uint8_t raw_cert_base64_blob[cert_len];
        size_t cert_base64_len = 0;
        convert_pem_to_raw_base64(cert_blob, cert_len, raw_cert_base64_blob, &cert_base64_len);
        size_t decoded_len = 0;
        aws_base64_compute_decoded_len((const char *)raw_cert_base64_blob, cert_base64_len, &decoded_len);
        uint8_t cert_der[decoded_len];
        struct aws_byte_buf to_decode = aws_byte_buf_from_array(raw_cert_base64_blob, cert_base64_len);
        struct aws_byte_buf decoded = aws_byte_buf_from_array(cert_der, decoded_len);
        aws_base64_decode(&to_decode, &decoded);

        CFDataRef cert_data_ref = CFDataCreate(secure_transport_ctx->wrapped_allocator, decoded.buffer, decoded.len);
        aws_mem_release(alloc, cert_blob);
        SecCertificateRef cert = SecCertificateCreateWithData(secure_transport_ctx->wrapped_allocator, cert_data_ref);
        CFRelease(cert_data_ref);
        secure_transport_ctx->ca_cert = cert;
    }

    ctx->alloc = alloc;
    ctx->impl = secure_transport_ctx;

    return ctx;

cleanup_wrapped_allocator:
    aws_wrapped_cf_allocator_destroy(secure_transport_ctx->wrapped_allocator);

cleanup_secure_transport_ctx:
    aws_mem_release(alloc, secure_transport_ctx);

cleanup_ctx:
    aws_mem_release(alloc, ctx);

    return NULL;
}

struct aws_tls_ctx *aws_tls_server_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    return tls_ctx_new(alloc, options);
}

struct aws_tls_ctx *aws_tls_client_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    return tls_ctx_new(alloc, options);
}

void aws_tls_ctx_destroy(struct aws_tls_ctx *ctx) {
    struct secure_transport_ctx *secure_transport_ctx = (struct secure_transport_ctx *)ctx->impl;

    if (secure_transport_ctx->certs) {
        CFRelease(secure_transport_ctx->certs);
    }

    if (secure_transport_ctx->ca_cert) {
        CFRelease(secure_transport_ctx->ca_cert);
    }

    CFRelease(secure_transport_ctx->wrapped_allocator);
    aws_mem_release(secure_transport_ctx->allocator, secure_transport_ctx);
    aws_mem_release(ctx->alloc, ctx);
}

#pragma clang diagnostic pop
