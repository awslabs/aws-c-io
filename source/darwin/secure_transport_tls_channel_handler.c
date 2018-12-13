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

#include <aws/common/encoding.h>
#include <aws/common/task_scheduler.h>

#include <AvailabilityMacros.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCertificate.h>
#include <Security/SecureTransport.h>
#include <Security/Security.h>
#include <dlfcn.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-function"

static OSStatus (*s_SSLSetALPNProtocols)(SSLContextRef context, CFArrayRef protocols) = NULL;
static OSStatus (*s_SSLCopyALPNProtocols)(SSLContextRef context, CFArrayRef *protocols) = NULL;

#define EST_TLS_RECORD_OVERHEAD 53 /* 5 byte header + 32 + 16 bytes for padding */
#define KB_1 1024
#define MAX_RECORD_SIZE (KB_1 * 16)
#define EST_HANDSHAKE_SIZE (7 * KB_1)

/* We couldn't make SSLSetALPNFunc work, so we have to use the public API which isn't available until High-Sierra */
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
#if ALPN_AVAILABLE
    return s_SSLCopyALPNProtocols != NULL;
#endif
    return false;
}

void aws_tls_init_static_state(struct aws_allocator *alloc) {
    (void)alloc;
    /* keep from breaking users that built on later versions of the mac os sdk but deployed
     * to an older version. */
    s_SSLSetALPNProtocols = (OSStatus(*)(SSLContextRef, CFArrayRef))dlsym(RTLD_DEFAULT, "SSLSetALPNProtocols");
    s_SSLCopyALPNProtocols = (OSStatus(*)(SSLContextRef, CFArrayRef *))dlsym(RTLD_DEFAULT, "SSLCopyALPNProtocols");
}

void aws_tls_clean_up_thread_local_state(void) { /* no op */
}

void aws_tls_clean_up_static_state(void) { /* no op */
}

struct secure_transport_handler {
    struct aws_channel_handler handler;
    SSLContextRef ctx;
    CFAllocatorRef wrapped_allocator;
    struct aws_linked_list input_queue;
    struct aws_channel_slot *parent_slot;
    struct aws_byte_buf protocol;
    /*per spec the max length for a server name is 255 bytes (plus the null character). */
    char server_name_array[256];
    struct aws_byte_buf server_name;
    struct aws_tls_connection_options options;
    aws_channel_on_message_write_completed_fn *latest_message_on_completion;
    void *latest_message_completion_user_data;
    CFArrayRef ca_certs;
    struct aws_channel_task read_task;
    bool negotiation_finished;
    bool verify_peer;
    bool read_task_pending;
};

static OSStatus s_read_cb(SSLConnectionRef conn, void *data, size_t *len) {
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

static OSStatus s_write_cb(SSLConnectionRef conn, const void *data, size_t *len) {
    struct secure_transport_handler *handler = (struct secure_transport_handler *)conn;

    struct aws_byte_buf buf = aws_byte_buf_from_array((const uint8_t *)data, *len);
    struct aws_byte_cursor buffer_cursor = aws_byte_cursor_from_buf(&buf);

    size_t processed = 0;
    while (processed < buf.len) {
        struct aws_io_message *message = aws_channel_acquire_message_from_pool(
            handler->parent_slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, buf.len - processed);

        if (!message) {
            return errSecMemoryError;
        }

        const size_t to_write =
            message->message_data.capacity > buffer_cursor.len ? buffer_cursor.len : message->message_data.capacity;
        struct aws_byte_cursor chunk = aws_byte_cursor_advance(&buffer_cursor, to_write);
        if (aws_byte_buf_append(&message->message_data, &chunk)) {
            aws_channel_release_message_to_pool(handler->parent_slot->channel, message);
            return errSecBufferTooSmall;
        }
        processed += message->message_data.len;

        if (processed == buf.len) {
            message->on_completion = handler->latest_message_on_completion;
            message->user_data = handler->latest_message_completion_user_data;
            handler->latest_message_on_completion = NULL;
            handler->latest_message_completion_user_data = NULL;
        }

        if (aws_channel_slot_send_message(handler->parent_slot, message, AWS_CHANNEL_DIR_WRITE)) {
            aws_channel_release_message_to_pool(handler->parent_slot->channel, message);
            return errSSLClosedNoNotify;
        }
    }

    if (*len == processed) {
        return noErr;
    }

    *len = processed;
    return errSSLWouldBlock;
}

static void s_destroy(struct aws_channel_handler *handler) {
    if (handler) {
        struct secure_transport_handler *secure_transport_handler = handler->impl;
        CFRelease(secure_transport_handler->ctx);

        if (secure_transport_handler->protocol.buffer) {
            aws_byte_buf_clean_up(&secure_transport_handler->protocol);
        }

        aws_mem_release(handler->alloc, secure_transport_handler);
    }
}

static CFStringRef s_get_protocol(struct secure_transport_handler *handler) {
#if ALPN_AVAILABLE
    if (s_SSLCopyALPNProtocols) {
        CFArrayRef protocols = NULL;

        OSStatus status = s_SSLCopyALPNProtocols(handler->ctx, &protocols);
        (void)status;

        if (!protocols) {
            return NULL;
        }

        CFIndex count = CFArrayGetCount(protocols);

        if (count <= 0) {
            return NULL;
        }

        CFStringRef alpn_value = CFArrayGetValueAtIndex(protocols, 0);
        CFRetain(alpn_value);
        CFRelease(protocols);

        return alpn_value;
    }

    return NULL;
#else
    (void)handler;
    return NULL;
#endif
}

static void s_set_protocols(
    struct secure_transport_handler *handler,
    struct aws_allocator *alloc,
    const char *alpn_list) {

    (void)handler;
    (void)alloc;
    (void)alpn_list;
/* I have no idea if this code is correct, I can't test it until I have a machine with high-sierra on it
 * but my employer hasn't pushed it out yet so.... sorry about that. */
#if ALPN_AVAILABLE
    if (s_SSLSetALPNProtocols) {
        struct aws_byte_cursor alpn_data = aws_byte_cursor_from_c_str(alpn_list);
        struct aws_array_list alpn_list_array;
        if (aws_array_list_init_dynamic(&alpn_list_array, alloc, 2, sizeof(struct aws_byte_cursor))) {
            return;
        }

        if (aws_byte_cursor_split_on_char(&alpn_data, ';', &alpn_list_array)) {
            return;
        }

        CFMutableArrayRef alpn_array = CFArrayCreateMutable(
            handler->wrapped_allocator, aws_array_list_length(&alpn_list_array), &kCFTypeArrayCallBacks);

        if (!alpn_array) {
            return;
        }

        for (size_t i = 0; i < aws_array_list_length(&alpn_list_array); ++i) {
            struct aws_byte_cursor protocol_cursor;
            aws_array_list_get_at(&alpn_list_array, &protocol_cursor, i);
            CFStringRef protocol = CFStringCreateWithBytes(
                handler->wrapped_allocator, protocol_cursor.ptr, protocol_cursor.len, kCFStringEncodingASCII, false);

            if (!protocol) {
                CFRelease(alpn_array);
                alpn_array = NULL;
                break;
            }

            CFArrayAppendValue(alpn_array, protocol);
            CFRelease(protocol);
        }

        if (alpn_array) {
            OSStatus status = s_SSLSetALPNProtocols(handler->ctx, alpn_array);
            (void)status;

            CFRelease(alpn_array);
        }

        aws_array_list_clean_up(&alpn_list_array);
    }
#endif
}

static void s_invoke_negotiation_callback(struct aws_channel_handler *handler, int err_code) {
    struct secure_transport_handler *secure_transport_handler = handler->impl;

    if (secure_transport_handler->options.on_negotiation_result) {
        secure_transport_handler->options.on_negotiation_result(
            handler, secure_transport_handler->parent_slot, err_code, secure_transport_handler->options.user_data);
    }
}

static int s_drive_negotiation(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = handler->impl;

    OSStatus status = SSLHandshake(secure_transport_handler->ctx);

    /* yay!!!! negotiation finished successfully. */
    if (status == noErr) {
        secure_transport_handler->negotiation_finished = true;
        size_t name_len = 0;
        CFStringRef protocol = s_get_protocol(secure_transport_handler);

        if (protocol) {
            if (aws_byte_buf_init(
                    &secure_transport_handler->protocol, handler->alloc, (size_t)CFStringGetLength(protocol))) {
                CFRelease(protocol);
                s_invoke_negotiation_callback(handler, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                return AWS_OP_ERR;
            }

            CFRange byte_range = CFRangeMake(0, CFStringGetLength(protocol));
            CFStringGetBytes(
                protocol,
                byte_range,
                kCFStringEncodingASCII,
                0,
                false,
                secure_transport_handler->protocol.buffer,
                secure_transport_handler->protocol.capacity,
                NULL);
            secure_transport_handler->protocol.len = secure_transport_handler->protocol.capacity;
            CFRelease(protocol);
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

            protocol_message->protocol = secure_transport_handler->protocol;

            message->message_data.len = sizeof(struct aws_tls_negotiated_protocol_message);
            if (aws_channel_slot_send_message(secure_transport_handler->parent_slot, message, AWS_CHANNEL_DIR_READ)) {
                aws_channel_release_message_to_pool(secure_transport_handler->parent_slot->channel, message);
                aws_channel_shutdown(secure_transport_handler->parent_slot->channel, aws_last_error());
                return AWS_OP_SUCCESS;
            }
        }

        s_invoke_negotiation_callback(handler, AWS_OP_SUCCESS);

        /* this branch gets hit only when verification is disabled,
         * or a custom CA bundle is being used. */
    } else if (status == errSSLPeerAuthCompleted) {

        if (secure_transport_handler->verify_peer) {
            if (!secure_transport_handler->ca_certs) {
                s_invoke_negotiation_callback(handler, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                return AWS_OP_ERR;
            }

            SecTrustRef trust;
            status = SSLCopyPeerTrust(secure_transport_handler->ctx, &trust);

            if (status != errSecSuccess) {
                s_invoke_negotiation_callback(handler, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                return AWS_OP_ERR;
            }

            status = SecTrustSetAnchorCertificates(trust, secure_transport_handler->ca_certs);

            if (status != errSecSuccess) {
                CFRelease(trust);
                s_invoke_negotiation_callback(handler, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                return AWS_OP_ERR;
            }

            SecTrustResultType trust_eval = 0;
            status = SecTrustEvaluate(trust, &trust_eval);
            CFRelease(trust);

            if (status == errSecSuccess &&
                (trust_eval == kSecTrustResultProceed || trust_eval == kSecTrustResultUnspecified ||
                 trust_eval == kSecTrustResultRecoverableTrustFailure)) {
                return s_drive_negotiation(handler);
            }

            return AWS_OP_ERR;
        }
        return AWS_OP_SUCCESS;
        /* if this is here, everything went wrong. */
    } else if (status != errSSLWouldBlock) {
        secure_transport_handler->negotiation_finished = false;

        aws_raise_error(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);

        s_invoke_negotiation_callback(handler, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_negotiation_task(struct aws_channel_task *task, void *arg, aws_task_status status) {
    struct aws_channel_handler *handler = arg;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        s_drive_negotiation(handler);
    }

    aws_mem_release(handler->alloc, task);
}

int aws_tls_client_handler_start_negotiation(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = handler->impl;

    if (aws_channel_thread_is_callers_thread(secure_transport_handler->parent_slot->channel)) {
        return s_drive_negotiation(handler);
    }

    struct aws_channel_task *negotiation_task = aws_mem_acquire(handler->alloc, sizeof(struct aws_task));

    if (!negotiation_task) {
        return AWS_OP_ERR;
    }

    aws_channel_task_init(negotiation_task, s_negotiation_task, handler);
    aws_channel_schedule_task_now(secure_transport_handler->parent_slot->channel, negotiation_task);
    return AWS_OP_SUCCESS;
}

static int s_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    struct secure_transport_handler *secure_transport_handler = handler->impl;

    if (AWS_UNLIKELY(!secure_transport_handler->negotiation_finished)) {
        return aws_raise_error(AWS_IO_TLS_ERROR_NOT_NEGOTIATED);
    }

    secure_transport_handler->latest_message_on_completion = message->on_completion;
    secure_transport_handler->latest_message_completion_user_data = message->user_data;

    size_t processed = 0;
    OSStatus status =
        SSLWrite(secure_transport_handler->ctx, message->message_data.buffer, message->message_data.len, &processed);

    if (status != noErr) {
        return aws_raise_error(AWS_IO_TLS_ERROR_WRITE_FAILURE);
    }

    aws_channel_release_message_to_pool(slot->channel, message);

    return AWS_OP_SUCCESS;
}

static int s_handle_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool abort_immediately) {
    struct secure_transport_handler *secure_transport_handler = handler->impl;

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

static int s_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct secure_transport_handler *secure_transport_handler = handler->impl;

    if (message) {
        aws_linked_list_push_back(&secure_transport_handler->input_queue, &message->queueing_handle);

        if (!secure_transport_handler->negotiation_finished) {
            size_t message_len = message->message_data.len;
            if (!s_drive_negotiation(handler)) {
                aws_channel_slot_increment_read_window(slot, message_len);
            } else {
                aws_channel_shutdown(
                    secure_transport_handler->parent_slot->channel, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
            }
            return AWS_OP_SUCCESS;
        }
    }

    size_t downstream_window = SIZE_MAX;
    /* process as much as we have queued that will fit in the downstream window. */
    if (slot->adj_right) {
        downstream_window = aws_channel_slot_downstream_read_window(slot);
    }
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
            if (aws_channel_slot_send_message(slot, outgoing_read_message, AWS_CHANNEL_DIR_READ)) {
                aws_channel_release_message_to_pool(slot->channel, outgoing_read_message);
                return AWS_OP_ERR;
            }
        } else {
            aws_channel_release_message_to_pool(slot->channel, outgoing_read_message);
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_run_read(struct aws_channel_task *task, void *arg, aws_task_status status) {
    (void)task;
    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_channel_handler *handler = arg;
        struct secure_transport_handler *secure_transport_handler = handler->impl;
        secure_transport_handler->read_task_pending = false;
        s_process_read_message(handler, secure_transport_handler->parent_slot, NULL);
    }
}

static int s_increment_read_window(struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size) {
    aws_channel_slot_increment_read_window(slot, size + EST_TLS_RECORD_OVERHEAD);

    struct secure_transport_handler *secure_transport_handler = handler->impl;

    size_t downstream_size = aws_channel_slot_downstream_read_window(slot);
    size_t current_window_size = slot->window_size;

    if (downstream_size <= current_window_size) {
        size_t likely_records_count = (downstream_size - current_window_size) % MAX_RECORD_SIZE;
        size_t offset_size = likely_records_count * (EST_TLS_RECORD_OVERHEAD);
        size_t window_update_size = (downstream_size - current_window_size) + offset_size;
        aws_channel_slot_increment_read_window(slot, window_update_size);
    }

    if (secure_transport_handler->negotiation_finished) {
        /* TLS requires full records before it can decrypt anything. As a result we need to check everything we've
         * buffered instead of just waiting on a read from the socket, or we'll hit a deadlock.
         *
         * We have messages in a queue and they need to be run after the socket has popped (even if it didn't have data
         * to read). Alternatively, s2n reads entire records at a time, so we'll need to grab whatever we can and we
         * have no idea what's going on inside there. So we need to attempt another read.
         */
        secure_transport_handler->read_task_pending = true;
        aws_channel_task_init(&secure_transport_handler->read_task, s_run_read, handler);
        aws_channel_schedule_task_now(slot->channel, &secure_transport_handler->read_task);
    }

    return AWS_OP_SUCCESS;
}

static size_t s_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;
    return EST_HANDSHAKE_SIZE;
}

struct aws_byte_buf aws_tls_handler_protocol(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = handler->impl;
    return secure_transport_handler->protocol;
}

struct aws_byte_buf aws_tls_handler_server_name(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = handler->impl;
    return secure_transport_handler->server_name;
}

static struct aws_channel_handler_vtable s_handler_vtable = {
    .destroy = s_destroy,
    .process_read_message = s_process_read_message,
    .process_write_message = s_process_write_message,
    .shutdown = s_handle_shutdown,
    .increment_read_window = s_increment_read_window,
    .initial_window_size = s_initial_window_size,
};

struct secure_transport_ctx {
    struct aws_tls_ctx ctx;
    CFAllocatorRef wrapped_allocator;
    CFArrayRef certs;
    CFArrayRef ca_cert;
    enum aws_tls_versions minimum_version;
    const char *alpn_list;
    bool veriify_peer;
};

static struct aws_channel_handler *s_tls_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot,
    SSLProtocolSide protocol_side) {
    assert(options->ctx);
    struct secure_transport_ctx *secure_transport_ctx = options->ctx->impl;

    struct secure_transport_handler *secure_transport_handler =
        (struct secure_transport_handler *)aws_mem_acquire(allocator, sizeof(struct secure_transport_handler));

    if (!secure_transport_handler) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*secure_transport_handler);
    secure_transport_handler->handler.alloc = allocator;
    secure_transport_handler->handler.impl = secure_transport_handler;
    secure_transport_handler->handler.vtable = &s_handler_vtable;
    secure_transport_handler->wrapped_allocator = secure_transport_ctx->wrapped_allocator;
    secure_transport_handler->ctx =
        SSLCreateContext(secure_transport_handler->wrapped_allocator, protocol_side, kSSLStreamType);

    if (!secure_transport_handler->ctx) {
        aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
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
        case AWS_IO_TLS_VER_SYS_DEFAULTS:
        default:
            /* kSSLProtocolUnknown means use system defaults. */
            SSLSetProtocolVersionMin(secure_transport_handler->ctx, kSSLProtocolUnknown);

            break;
    }

    if (SSLSetIOFuncs(secure_transport_handler->ctx, s_read_cb, s_write_cb) != noErr ||
        SSLSetConnection(secure_transport_handler->ctx, secure_transport_handler) != noErr) {
        /* TODO raise error here */
        goto cleanup_ssl_ctx;
    }

    OSStatus status = noErr;
    secure_transport_handler->verify_peer = secure_transport_ctx->veriify_peer;

    if (!secure_transport_ctx->veriify_peer && protocol_side == kSSLClientSide) {
        SSLSetSessionOption(secure_transport_handler->ctx, kSSLSessionOptionBreakOnServerAuth, true);
    }

    if (secure_transport_ctx->certs) {
        status = SSLSetCertificate(secure_transport_handler->ctx, secure_transport_ctx->certs);
    }

    secure_transport_handler->ca_certs = NULL;
    if (secure_transport_ctx->ca_cert) {
        secure_transport_handler->ca_certs = secure_transport_ctx->ca_cert;
        if (protocol_side == kSSLServerSide && secure_transport_ctx->veriify_peer) {
            SSLSetSessionOption(secure_transport_handler->ctx, kSSLSessionOptionBreakOnClientAuth, true);
        } else if (secure_transport_ctx->veriify_peer) {
            SSLSetSessionOption(secure_transport_handler->ctx, kSSLSessionOptionBreakOnServerAuth, true);
        }
    }

    (void)status;

    aws_linked_list_init(&secure_transport_handler->input_queue);
    secure_transport_handler->parent_slot = slot;
    secure_transport_handler->latest_message_completion_user_data = NULL;
    secure_transport_handler->negotiation_finished = false;
    secure_transport_handler->latest_message_on_completion = NULL;

    if (options->server_name) {
        size_t server_name_len = strlen(options->server_name);
        SSLSetPeerDomainName(secure_transport_handler->ctx, options->server_name, server_name_len);
    }

    const char *alpn_list = NULL;
    if (options->alpn_list) {
        alpn_list = options->alpn_list;
    } else {
        alpn_list = secure_transport_ctx->alpn_list;
    }

    if (alpn_list) {
        s_set_protocols(secure_transport_handler, allocator, alpn_list);
    }

    secure_transport_handler->options = *options;

    return &secure_transport_handler->handler;

cleanup_ssl_ctx:
    CFRelease(secure_transport_handler->ctx);

cleanup_st_handler:
    aws_mem_release(allocator, secure_transport_handler);

    return NULL;
}

struct aws_channel_handler *aws_tls_client_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {
    return s_tls_handler_new(allocator, options, slot, kSSLClientSide);
}

struct aws_channel_handler *aws_tls_server_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {
    return s_tls_handler_new(allocator, options, slot, kSSLServerSide);
}

static struct aws_tls_ctx *s_tls_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    struct secure_transport_ctx *secure_transport_ctx = aws_mem_acquire(alloc, sizeof(struct secure_transport_ctx));

    if (!secure_transport_ctx) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*secure_transport_ctx);
    secure_transport_ctx->wrapped_allocator = aws_wrapped_cf_allocator_new(alloc);
    secure_transport_ctx->minimum_version = options->minimum_tls_version;

    if (!secure_transport_ctx->wrapped_allocator) {
        goto cleanup_secure_transport_ctx;
    }

    secure_transport_ctx->alpn_list = options->alpn_list;
    secure_transport_ctx->veriify_peer = options->verify_peer;
    secure_transport_ctx->ca_cert = NULL;
    secure_transport_ctx->certs = NULL;
    secure_transport_ctx->ctx.alloc = alloc;
    secure_transport_ctx->ctx.impl = secure_transport_ctx;

    if (options->certificate_path && options->private_key_path) {

        struct aws_byte_buf cert_chain;
        if (aws_byte_buf_init_from_file(&cert_chain, alloc, options->certificate_path)) {
            goto cleanup_wrapped_allocator;
        }

        struct aws_byte_buf private_key;
        if (aws_byte_buf_init_from_file(&private_key, alloc, options->private_key_path)) {
            aws_secure_zero(cert_chain.buffer, cert_chain.len);
            aws_byte_buf_clean_up(&cert_chain);
            goto cleanup_wrapped_allocator;
        }

        struct aws_byte_cursor cert_chain_cur = aws_byte_cursor_from_buf(&cert_chain);
        struct aws_byte_cursor private_key_cur = aws_byte_cursor_from_buf(&private_key);
        if (aws_import_public_and_private_keys_to_identity(
                alloc,
                secure_transport_ctx->wrapped_allocator,
                &cert_chain_cur,
                &private_key_cur,
                &secure_transport_ctx->certs)) {
            aws_secure_zero(cert_chain.buffer, cert_chain.len);
            aws_byte_buf_clean_up(&cert_chain);
            aws_secure_zero(private_key.buffer, private_key.len);
            aws_byte_buf_clean_up(&private_key);
            goto cleanup_wrapped_allocator;
        }

        aws_secure_zero(cert_chain.buffer, cert_chain.len);
        aws_byte_buf_clean_up(&cert_chain);
        aws_secure_zero(private_key.buffer, private_key.len);
        aws_byte_buf_clean_up(&private_key);
    } else if (options->pkcs12_path) {

        struct aws_byte_buf pkcs12_blob;
        if (aws_byte_buf_init_from_file(&pkcs12_blob, alloc, options->pkcs12_path)) {
            goto cleanup_wrapped_allocator;
        }

        struct aws_byte_buf password = {.buffer = NULL, .len = 0, .allocator = NULL, .capacity = 0};

        if (options->pkcs12_password) {
            password = aws_byte_buf_from_c_str(options->pkcs12_password);
        }

        struct aws_byte_cursor pkcs12_blob_cur = aws_byte_cursor_from_buf(&pkcs12_blob);
        struct aws_byte_cursor password_cur = aws_byte_cursor_from_buf(&password);
        if (aws_import_pkcs12_to_identity(
                secure_transport_ctx->wrapped_allocator,
                &pkcs12_blob_cur,
                &password_cur,
                &secure_transport_ctx->certs)) {
            aws_secure_zero(pkcs12_blob.buffer, pkcs12_blob.len);
            aws_byte_buf_clean_up(&pkcs12_blob);
            goto cleanup_wrapped_allocator;
        }
        aws_secure_zero(pkcs12_blob.buffer, pkcs12_blob.len);
        aws_byte_buf_clean_up(&pkcs12_blob);
    }

    if (options->ca_file) {

        struct aws_byte_buf ca_blob;
        if (aws_byte_buf_init_from_file(&ca_blob, alloc, options->ca_file)) {
            goto cleanup_wrapped_allocator;
        }

        struct aws_byte_cursor ca_cursor = aws_byte_cursor_from_buf(&ca_blob);
        if (aws_import_trusted_certificates(
                alloc, secure_transport_ctx->wrapped_allocator, &ca_cursor, &secure_transport_ctx->ca_cert)) {
            aws_byte_buf_clean_up(&ca_blob);
            goto cleanup_wrapped_allocator;
        }

        aws_byte_buf_clean_up(&ca_blob);
    }

    return &secure_transport_ctx->ctx;

cleanup_wrapped_allocator:
    aws_wrapped_cf_allocator_destroy(secure_transport_ctx->wrapped_allocator);

cleanup_secure_transport_ctx:
    aws_mem_release(alloc, secure_transport_ctx);

    return NULL;
}

struct aws_tls_ctx *aws_tls_server_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    return s_tls_ctx_new(alloc, options);
}

struct aws_tls_ctx *aws_tls_client_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    return s_tls_ctx_new(alloc, options);
}

void aws_tls_ctx_destroy(struct aws_tls_ctx *ctx) {
    struct secure_transport_ctx *secure_transport_ctx = ctx->impl;

    if (secure_transport_ctx->certs) {
        aws_release_identity(secure_transport_ctx->certs);
    }

    if (secure_transport_ctx->ca_cert) {
        aws_release_certificates(secure_transport_ctx->ca_cert);
    }

    CFRelease(secure_transport_ctx->wrapped_allocator);
    aws_mem_release(secure_transport_ctx->ctx.alloc, secure_transport_ctx);
}

#pragma clang diagnostic pop
