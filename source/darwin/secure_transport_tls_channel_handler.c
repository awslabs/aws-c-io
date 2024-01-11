/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/tls_channel_handler.h>

#include <aws/io/channel.h>
#include <aws/io/file_utils.h>
#include <aws/io/private/pki_utils.h>
#include <aws/io/private/tls_channel_handler_shared.h>
#include <aws/io/statistics.h>

#include <aws/io/logging.h>

#include <aws/common/encoding.h>
#include <aws/common/string.h>
#include <aws/common/task_scheduler.h>

#include <AvailabilityMacros.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCertificate.h>
#include <Security/SecureTransport.h>
#include <Security/Security.h>
#include <dlfcn.h>
#include <math.h>

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

bool aws_tls_is_cipher_pref_supported(enum aws_tls_cipher_pref cipher_pref) {
    switch (cipher_pref) {
        case AWS_IO_TLS_CIPHER_PREF_SYSTEM_DEFAULT:
            return true;

        case AWS_IO_TLS_CIPHER_PREF_KMS_PQ_TLSv1_0_2019_06:
        default:
            return false;
    }
}

void aws_tls_init_static_state(struct aws_allocator *alloc) {
    (void)alloc;
    /* keep from breaking users that built on later versions of the mac os sdk but deployed
     * to an older version. */
    s_SSLSetALPNProtocols = (OSStatus(*)(SSLContextRef, CFArrayRef))dlsym(RTLD_DEFAULT, "SSLSetALPNProtocols");
    s_SSLCopyALPNProtocols = (OSStatus(*)(SSLContextRef, CFArrayRef *))dlsym(RTLD_DEFAULT, "SSLCopyALPNProtocols");

    AWS_LOGF_INFO(AWS_LS_IO_TLS, "static: initializing TLS implementation as Apple SecureTransport.");

    if (s_SSLSetALPNProtocols) {
        AWS_LOGF_INFO(AWS_LS_IO_TLS, "static: ALPN support detected.");
    } else {
        AWS_LOGF_WARN(
            AWS_LS_IO_TLS,
            "static: ALPN isn't supported on your apple device, you can improve support and performance by upgrading.");
    }
}

void aws_tls_clean_up_static_state(void) { /* no op */
}

struct secure_transport_handler {
    struct aws_channel_handler handler;
    struct aws_tls_channel_handler_shared shared_state;
    SSLContextRef ctx;
    CFAllocatorRef wrapped_allocator;
    struct aws_linked_list input_queue;
    struct aws_channel_slot *parent_slot;
    struct aws_byte_buf protocol;
    /* Note: This is just a copy of the expected server name.
     * The Secure Transport API doesn't seem to expose actual server name.
     * SSLGetPeerDomainName just returns whatever was passed earlier to SSLSetPeerDomainName */
    struct aws_string *server_name;
    aws_channel_on_message_write_completed_fn *latest_message_on_completion;
    void *latest_message_completion_user_data;
    CFArrayRef ca_certs;
    struct aws_channel_task read_task;
    aws_tls_on_negotiation_result_fn *on_negotiation_result;
    aws_tls_on_data_read_fn *on_data_read;
    aws_tls_on_error_fn *on_error;
    void *user_data;
    bool advertise_alpn_message;
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
            aws_mem_release(message->allocator, message);
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
        const size_t overhead = aws_channel_slot_upstream_message_overhead(handler->parent_slot);
        const size_t message_size_hint = (buf.len - processed) + overhead;
        struct aws_io_message *message = aws_channel_acquire_message_from_pool(
            handler->parent_slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, message_size_hint);

        if (!message || message->message_data.capacity <= overhead) {
            return errSecMemoryError;
        }

        const size_t available_msg_write_capacity = message->message_data.capacity - overhead;
        const size_t to_write =
            available_msg_write_capacity >= buffer_cursor.len ? buffer_cursor.len : available_msg_write_capacity;

        struct aws_byte_cursor chunk = aws_byte_cursor_advance(&buffer_cursor, to_write);
        if (aws_byte_buf_append(&message->message_data, &chunk)) {
            aws_mem_release(message->allocator, message);
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
            aws_mem_release(message->allocator, message);
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

        aws_tls_channel_handler_shared_clean_up(&secure_transport_handler->shared_state);

        aws_string_destroy(secure_transport_handler->server_name);

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
    struct aws_string *alpn_list) {

    (void)handler;
    (void)alloc;
    (void)alpn_list;
#if ALPN_AVAILABLE
    if (s_SSLSetALPNProtocols) {
        struct aws_byte_cursor alpn_data = aws_byte_cursor_from_string(alpn_list);
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

    aws_on_tls_negotiation_completed(&secure_transport_handler->shared_state, err_code);

    if (secure_transport_handler->on_negotiation_result) {
        secure_transport_handler->on_negotiation_result(
            handler, secure_transport_handler->parent_slot, err_code, secure_transport_handler->user_data);
    }
}

static int s_drive_negotiation(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = handler->impl;

    aws_on_drive_tls_negotiation(&secure_transport_handler->shared_state);

    OSStatus status = SSLHandshake(secure_transport_handler->ctx);
    /* yay!!!! negotiation finished successfully. */
    if (status == noErr) {
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "id=%p: negotiation succeeded", (void *)handler);
        secure_transport_handler->negotiation_finished = true;
        CFStringRef protocol = s_get_protocol(secure_transport_handler);

        if (protocol) {
            if (aws_byte_buf_init(
                    &secure_transport_handler->protocol, handler->alloc, (size_t)CFStringGetLength(protocol) + 1)) {
                CFRelease(protocol);
                s_invoke_negotiation_callback(handler, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                return AWS_OP_ERR;
            }

            memset(secure_transport_handler->protocol.buffer, 0, secure_transport_handler->protocol.capacity);

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
            secure_transport_handler->protocol.len = secure_transport_handler->protocol.capacity - 1;
            CFRelease(protocol);
            AWS_LOGF_DEBUG(
                AWS_LS_IO_TLS,
                "id=%p: negotiated protocol: %s",
                (void *)handler,
                secure_transport_handler->protocol.buffer);
        }

        if (secure_transport_handler->server_name) {
            /* Log server name to be consistent with other tls_channel_handler implementations,
             * but this is just a copy of the EXPECTED server name,
             * the Secure Transport API doesn't seem to expose actual server name. */
            AWS_LOGF_DEBUG(
                AWS_LS_IO_TLS,
                "id=%p: Remote Server Name: %s",
                (void *)handler,
                aws_string_c_str(secure_transport_handler->server_name));
        }

        if (secure_transport_handler->parent_slot->adj_right && secure_transport_handler->advertise_alpn_message &&
            protocol) {
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
                aws_mem_release(message->allocator, message);
                aws_channel_shutdown(secure_transport_handler->parent_slot->channel, aws_last_error());
                return AWS_OP_SUCCESS;
            }
        }

        s_invoke_negotiation_callback(handler, AWS_ERROR_SUCCESS);

    } else if (status == errSSLPeerAuthCompleted) {
        /* this branch gets hit only when verification is disabled,
         * or a custom CA bundle is being used. */

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

            SecPolicyRef policy;
            if (secure_transport_handler->server_name) {
                CFStringRef server_name = CFStringCreateWithCString(
                    secure_transport_handler->wrapped_allocator,
                    aws_string_c_str(secure_transport_handler->server_name),
                    kCFStringEncodingUTF8);
                policy = SecPolicyCreateSSL(true, server_name);
                CFRelease(server_name);
            } else {
                policy = SecPolicyCreateBasicX509();
            }
            status = SecTrustSetPolicies(trust, policy);
            CFRelease(policy);

            if (status != errSecSuccess) {
                AWS_LOGF_ERROR(AWS_LS_IO_TLS, "id=%p: Failed to set trust policy %d\n", (void *)handler, (int)status);
                CFRelease(trust);
                s_invoke_negotiation_callback(handler, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                return AWS_OP_ERR;
            }

            status = SecTrustSetAnchorCertificates(trust, secure_transport_handler->ca_certs);
            if (status != errSecSuccess) {
                AWS_LOGF_ERROR(
                    AWS_LS_IO_TLS,
                    "id=%p: Failed to set anchor certificate with OSStatus %d\n",
                    (void *)handler,
                    (int)status);
                CFRelease(trust);
                s_invoke_negotiation_callback(handler, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                return AWS_OP_ERR;
            }

            /* Use ONLY the custom CA bundle (ignoring system anchors) */
            status = SecTrustSetAnchorCertificatesOnly(trust, true);
            if (status != errSecSuccess) {
                AWS_LOGF_ERROR(
                    AWS_LS_IO_TLS,
                    "id=%p: Failed to ignore system anchors with OSStatus %d\n",
                    (void *)handler,
                    (int)status);
                CFRelease(trust);
                s_invoke_negotiation_callback(handler, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                return AWS_OP_ERR;
            }

            SecTrustResultType trust_eval = 0;
            status = SecTrustEvaluate(trust, &trust_eval);
            CFRelease(trust);

            if (status == errSecSuccess &&
                (trust_eval == kSecTrustResultProceed || trust_eval == kSecTrustResultUnspecified)) {
                return s_drive_negotiation(handler);
            }

            AWS_LOGF_WARN(
                AWS_LS_IO_TLS,
                "id=%p: Using custom CA, certificate validation failed with OSStatus %d and Trust Eval %d.",
                (void *)handler,
                (int)status,
                (int)trust_eval);
            return AWS_OP_ERR;
        }
        return s_drive_negotiation(handler);
        /* if this is here, everything went wrong. */
    } else if (status != errSSLWouldBlock) {
        secure_transport_handler->negotiation_finished = false;

        AWS_LOGF_WARN(AWS_LS_IO_TLS, "id=%p: negotiation failed with OSStatus %d.", (void *)handler, (int)status);
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

    AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p, starting TLS negotiation", (void *)handler);
    if (aws_channel_thread_is_callers_thread(secure_transport_handler->parent_slot->channel)) {
        return s_drive_negotiation(handler);
    }

    struct aws_channel_task *negotiation_task = aws_mem_acquire(handler->alloc, sizeof(struct aws_task));

    if (!negotiation_task) {
        return AWS_OP_ERR;
    }

    aws_channel_task_init(
        negotiation_task, s_negotiation_task, handler, "secure_transport_channel_handler_start_negotiation");
    aws_channel_schedule_task_now(secure_transport_handler->parent_slot->channel, negotiation_task);
    return AWS_OP_SUCCESS;
}

static int s_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)slot;

    struct secure_transport_handler *secure_transport_handler = handler->impl;

    if (AWS_UNLIKELY(!secure_transport_handler->negotiation_finished)) {
        return aws_raise_error(AWS_IO_TLS_ERROR_NOT_NEGOTIATED);
    }

    secure_transport_handler->latest_message_on_completion = message->on_completion;
    secure_transport_handler->latest_message_completion_user_data = message->user_data;

    size_t processed = 0;
    OSStatus status =
        SSLWrite(secure_transport_handler->ctx, message->message_data.buffer, message->message_data.len, &processed);

    AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: bytes written: %llu", (void *)handler, (unsigned long long)processed);

    if (status != noErr) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_TLS, "id=%p: SSLWrite failed with OSStatus error code %d.", (void *)handler, (int)status);
        return aws_raise_error(AWS_IO_TLS_ERROR_WRITE_FAILURE);
    }

    aws_mem_release(message->allocator, message);

    return AWS_OP_SUCCESS;
}

static int s_handle_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool abort_immediately) {
    struct secure_transport_handler *secure_transport_handler = handler->impl;

    if (dir == AWS_CHANNEL_DIR_WRITE) {
        if (!abort_immediately && error_code != AWS_IO_SOCKET_CLOSED) {
            AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: shutting down write direction.", (void *)handler);
            SSLClose(secure_transport_handler->ctx);
        }
    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_TLS,
            "id=%p: shutting down read direction with error %d. Flushing queues.",
            (void *)handler,
            error_code);
        while (!aws_linked_list_empty(&secure_transport_handler->input_queue)) {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&secure_transport_handler->input_queue);
            struct aws_io_message *message = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);
            aws_mem_release(message->allocator, message);
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
    AWS_LOGF_TRACE(
        AWS_LS_IO_TLS, "id=%p: downstream window is %llu", (void *)handler, (unsigned long long)downstream_window);
    size_t processed = 0;

    OSStatus status = noErr;
    while (processed < downstream_window && status == noErr) {

        struct aws_io_message *outgoing_read_message = aws_channel_acquire_message_from_pool(
            slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, downstream_window - processed);
        if (!outgoing_read_message) {
            /* even though this is a failure, this handler has taken ownership of the message */
            aws_channel_shutdown(secure_transport_handler->parent_slot->channel, aws_last_error());
            return AWS_OP_SUCCESS;
        }

        size_t read = 0;
        status = SSLRead(
            secure_transport_handler->ctx,
            outgoing_read_message->message_data.buffer,
            outgoing_read_message->message_data.capacity,
            &read);

        AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: bytes read %llu", (void *)handler, (unsigned long long)read);
        if (read <= 0) {
            aws_mem_release(outgoing_read_message->allocator, outgoing_read_message);

            if (status != errSSLWouldBlock) {
                AWS_LOGF_ERROR(
                    AWS_LS_IO_TLS,
                    "id=%p: error reported during SSLRead. OSStatus code %d",
                    (void *)handler,
                    (int)status);

                if (status != errSSLClosedGraceful) {
                    aws_raise_error(AWS_IO_TLS_ERROR_READ_FAILURE);
                    aws_channel_shutdown(secure_transport_handler->parent_slot->channel, AWS_IO_TLS_ERROR_READ_FAILURE);
                } else {
                    AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: connection shutting down gracefully.", (void *)handler);
                    aws_channel_shutdown(secure_transport_handler->parent_slot->channel, AWS_ERROR_SUCCESS);
                }
            }
            continue;
        };

        processed += read;
        outgoing_read_message->message_data.len = read;

        if (secure_transport_handler->on_data_read) {
            secure_transport_handler->on_data_read(
                handler, slot, &outgoing_read_message->message_data, secure_transport_handler->user_data);
        }

        if (slot->adj_right) {
            if (aws_channel_slot_send_message(slot, outgoing_read_message, AWS_CHANNEL_DIR_READ)) {
                aws_mem_release(outgoing_read_message->allocator, outgoing_read_message);
                aws_channel_shutdown(secure_transport_handler->parent_slot->channel, aws_last_error());
                /* incoming message was pushed to the input_queue, so this handler owns it now */
                return AWS_OP_SUCCESS;
            }
        } else {
            aws_mem_release(outgoing_read_message->allocator, outgoing_read_message);
        }
    }
    AWS_LOGF_TRACE(
        AWS_LS_IO_TLS,
        "id=%p, Remaining window for this event-loop tick: %llu",
        (void *)handler,
        (unsigned long long)downstream_window - processed);

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
    struct secure_transport_handler *secure_transport_handler = handler->impl;

    AWS_LOGF_TRACE(
        AWS_LS_IO_TLS, "id=%p: increment read window message received %llu", (void *)handler, (unsigned long long)size);

    size_t downstream_size = aws_channel_slot_downstream_read_window(slot);
    size_t current_window_size = slot->window_size;

    size_t likely_records_count = (size_t)ceil((double)(downstream_size) / (double)(MAX_RECORD_SIZE));
    size_t offset_size = aws_mul_size_saturating(likely_records_count, EST_TLS_RECORD_OVERHEAD);
    size_t total_desired_size = aws_add_size_saturating(offset_size, downstream_size);

    if (total_desired_size > current_window_size) {
        size_t window_update_size = total_desired_size - current_window_size;
        AWS_LOGF_TRACE(
            AWS_LS_IO_TLS,
            "id=%p: Propagating read window increment of size %llu",
            (void *)handler,
            (unsigned long long)window_update_size);
        aws_channel_slot_increment_read_window(slot, window_update_size);
    }

    if (secure_transport_handler->negotiation_finished && !secure_transport_handler->read_task.node.next) {
        /* TLS requires full records before it can decrypt anything. As a result we need to check everything we've
         * buffered instead of just waiting on a read from the socket, or we'll hit a deadlock.
         *
         * We have messages in a queue and they need to be run after the socket has popped (even if it didn't have data
         * to read). Alternatively, s2n reads entire records at a time, so we'll need to grab whatever we can and we
         * have no idea what's going on inside there. So we need to attempt another read.
         */
        secure_transport_handler->read_task_pending = true;
        aws_channel_task_init(
            &secure_transport_handler->read_task,
            s_run_read,
            handler,
            "secure_transport_channel_handler_read_on_window_increment");
        aws_channel_schedule_task_now(slot->channel, &secure_transport_handler->read_task);
    }

    return AWS_OP_SUCCESS;
}

static size_t s_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;
    return EST_TLS_RECORD_OVERHEAD;
}

static size_t s_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;
    return EST_HANDSHAKE_SIZE;
}

static void s_reset_statistics(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = handler->impl;

    aws_crt_statistics_tls_reset(&secure_transport_handler->shared_state.stats);
}

static void s_gather_statistics(struct aws_channel_handler *handler, struct aws_array_list *stats) {
    struct secure_transport_handler *secure_transport_handler = handler->impl;

    void *stats_base = &secure_transport_handler->shared_state.stats;
    aws_array_list_push_back(stats, &stats_base);
}

struct aws_byte_buf aws_tls_handler_protocol(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = handler->impl;
    return secure_transport_handler->protocol;
}

struct aws_byte_buf aws_tls_handler_server_name(struct aws_channel_handler *handler) {
    struct secure_transport_handler *secure_transport_handler = handler->impl;
    const uint8_t *bytes = NULL;
    size_t len = 0;
    if (secure_transport_handler->server_name) {
        bytes = secure_transport_handler->server_name->bytes;
        len = secure_transport_handler->server_name->len;
    }
    return aws_byte_buf_from_array(bytes, len);
}

static struct aws_channel_handler_vtable s_handler_vtable = {
    .destroy = s_destroy,
    .process_read_message = s_process_read_message,
    .process_write_message = s_process_write_message,
    .shutdown = s_handle_shutdown,
    .increment_read_window = s_increment_read_window,
    .initial_window_size = s_initial_window_size,
    .message_overhead = s_message_overhead,
    .reset_statistics = s_reset_statistics,
    .gather_statistics = s_gather_statistics,
};

struct secure_transport_ctx {
    struct aws_tls_ctx ctx;
    CFAllocatorRef wrapped_allocator;
    CFArrayRef certs;
    CFArrayRef ca_cert;
    enum aws_tls_versions minimum_version;
    struct aws_string *alpn_list;
    bool veriify_peer;
};

static struct aws_channel_handler *s_tls_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot,
    SSLProtocolSide protocol_side) {
    AWS_ASSERT(options->ctx);
    struct secure_transport_ctx *secure_transport_ctx = options->ctx->impl;

    struct secure_transport_handler *secure_transport_handler =
        (struct secure_transport_handler *)aws_mem_calloc(allocator, 1, sizeof(struct secure_transport_handler));
    if (!secure_transport_handler) {
        return NULL;
    }

    secure_transport_handler->handler.alloc = allocator;
    secure_transport_handler->handler.impl = secure_transport_handler;
    secure_transport_handler->handler.vtable = &s_handler_vtable;
    secure_transport_handler->handler.slot = slot;
    secure_transport_handler->wrapped_allocator = secure_transport_ctx->wrapped_allocator;
    secure_transport_handler->advertise_alpn_message = options->advertise_alpn_message;
    secure_transport_handler->on_data_read = options->on_data_read;
    secure_transport_handler->on_error = options->on_error;
    secure_transport_handler->on_negotiation_result = options->on_negotiation_result;
    secure_transport_handler->user_data = options->user_data;

    aws_tls_channel_handler_shared_init(
        &secure_transport_handler->shared_state, &secure_transport_handler->handler, options);

    secure_transport_handler->ctx =
        SSLCreateContext(secure_transport_handler->wrapped_allocator, protocol_side, kSSLStreamType);

    if (!secure_transport_handler->ctx) {
        AWS_LOGF_FATAL(
            AWS_LS_IO_TLS, "id=%p: failed to initialize an SSL Context.", (void *)&secure_transport_handler->handler);
        aws_raise_error(AWS_IO_TLS_CTX_ERROR);
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
            AWS_LOGF_FATAL(
                AWS_LS_IO_TLS,
                "static: TLS 1.3 is not supported on this device. You may just want to specify "
                "AWS_IO_TLS_VER_SYS_DEFAULTS and you will automatically"
                "use the latest version of the protocol when it is available.");
            /*
             * "TLS 1.3 is not supported for your target platform,
             * you can probably get by setting AWS_IO_TLSv1_2 as the minimum and if tls 1.3 is supported it will be
             * used.
             */
            AWS_ASSERT(0);
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
        AWS_LOGF_FATAL(
            AWS_LS_IO_TLS, "id=%p: failed to initialize an SSL Context.", (void *)&secure_transport_handler->handler);
        aws_raise_error(AWS_IO_TLS_CTX_ERROR);
        goto cleanup_ssl_ctx;
    }

    OSStatus status = noErr;
    secure_transport_handler->verify_peer = secure_transport_ctx->veriify_peer;

    if (!secure_transport_ctx->veriify_peer && protocol_side == kSSLClientSide) {
        AWS_LOGF_WARN(
            AWS_LS_IO_TLS,
            "id=%p: x.509 validation has been disabled. "
            "If this is not running in a test environment, this is likely a security vulnerability.",
            (void *)&secure_transport_handler->handler);
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
        secure_transport_handler->server_name = aws_string_new_from_string(allocator, options->server_name);
        size_t server_name_len = options->server_name->len;
        SSLSetPeerDomainName(secure_transport_handler->ctx, aws_string_c_str(options->server_name), server_name_len);
    }

    struct aws_string *alpn_list = NULL;
    if (options->alpn_list) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_TLS,
            "id=%p: setting ALPN list %s",
            (void *)&secure_transport_handler->handler,
            aws_string_c_str(options->alpn_list));
        alpn_list = options->alpn_list;

    } else if (secure_transport_ctx->alpn_list) {
        alpn_list = secure_transport_ctx->alpn_list;
    }

    if (alpn_list) {
        s_set_protocols(secure_transport_handler, allocator, alpn_list);
    }

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

static void s_aws_secure_transport_ctx_destroy(struct secure_transport_ctx *secure_transport_ctx) {
    if (secure_transport_ctx == NULL) {
        return;
    }

    if (secure_transport_ctx->certs) {
        aws_release_identity(secure_transport_ctx->certs);
    }

    if (secure_transport_ctx->ca_cert) {
        aws_release_certificates(secure_transport_ctx->ca_cert);
    }

    if (secure_transport_ctx->alpn_list) {
        aws_string_destroy(secure_transport_ctx->alpn_list);
    }

    CFRelease(secure_transport_ctx->wrapped_allocator);
    aws_mem_release(secure_transport_ctx->ctx.alloc, secure_transport_ctx);
}

static struct aws_tls_ctx *s_tls_ctx_new(struct aws_allocator *alloc, const struct aws_tls_ctx_options *options) {
    struct secure_transport_ctx *secure_transport_ctx = aws_mem_calloc(alloc, 1, sizeof(struct secure_transport_ctx));
    if (!secure_transport_ctx) {
        return NULL;
    }

    if (!aws_tls_is_cipher_pref_supported(options->cipher_pref)) {
        aws_raise_error(AWS_IO_TLS_CIPHER_PREF_UNSUPPORTED);
        AWS_LOGF_ERROR(AWS_LS_IO_TLS, "static: TLS Cipher Preference is not supported: %d.", options->cipher_pref);
        return NULL;
    }

    secure_transport_ctx->wrapped_allocator = aws_wrapped_cf_allocator_new(alloc);
    secure_transport_ctx->minimum_version = options->minimum_tls_version;

    if (!secure_transport_ctx->wrapped_allocator) {
        goto cleanup_secure_transport_ctx;
    }

    if (options->alpn_list) {
        secure_transport_ctx->alpn_list = aws_string_new_from_string(alloc, options->alpn_list);

        if (!secure_transport_ctx->alpn_list) {
            goto cleanup_secure_transport_ctx;
        }
    }

    secure_transport_ctx->veriify_peer = options->verify_peer;
    secure_transport_ctx->ca_cert = NULL;
    secure_transport_ctx->certs = NULL;
    secure_transport_ctx->ctx.alloc = alloc;
    secure_transport_ctx->ctx.impl = secure_transport_ctx;
    aws_ref_count_init(
        &secure_transport_ctx->ctx.ref_count,
        secure_transport_ctx,
        (aws_simple_completion_callback *)s_aws_secure_transport_ctx_destroy);

    if (aws_tls_options_buf_is_set(&options->certificate) && aws_tls_options_buf_is_set(&options->private_key)) {
#if !defined(AWS_OS_IOS)
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "static: certificate and key have been set, setting them up now.");

        if (!aws_text_is_utf8(options->certificate.buffer, options->certificate.len)) {
            AWS_LOGF_ERROR(AWS_LS_IO_TLS, "static: failed to import certificate, must be ASCII/UTF-8 encoded");
            aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto cleanup_wrapped_allocator;
        }

        if (!aws_text_is_utf8(options->private_key.buffer, options->private_key.len)) {
            AWS_LOGF_ERROR(AWS_LS_IO_TLS, "static: failed to import private key, must be ASCII/UTF-8 encoded");
            aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto cleanup_wrapped_allocator;
        }

        struct aws_byte_cursor cert_chain_cur = aws_byte_cursor_from_buf(&options->certificate);
        struct aws_byte_cursor private_key_cur = aws_byte_cursor_from_buf(&options->private_key);
        if (aws_import_public_and_private_keys_to_identity(
                alloc,
                secure_transport_ctx->wrapped_allocator,
                &cert_chain_cur,
                &private_key_cur,
                &secure_transport_ctx->certs,
                options->keychain_path)) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_TLS, "static: failed to import certificate and private key with error %d.", aws_last_error());
            goto cleanup_wrapped_allocator;
        }
#endif
    } else if (aws_tls_options_buf_is_set(&options->pkcs12)) {
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "static: a pkcs$12 certificate and key has been set, setting it up now.");

        struct aws_byte_cursor pkcs12_blob_cur = aws_byte_cursor_from_buf(&options->pkcs12);
        struct aws_byte_cursor password_cur = aws_byte_cursor_from_buf(&options->pkcs12_password);
        if (aws_import_pkcs12_to_identity(
                secure_transport_ctx->wrapped_allocator,
                &pkcs12_blob_cur,
                &password_cur,
                &secure_transport_ctx->certs)) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_TLS, "static: failed to import pkcs#12 certificate with error %d.", aws_last_error());
            goto cleanup_wrapped_allocator;
        }
    }

    if (aws_tls_options_buf_is_set(&options->ca_file)) {
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "static: loading custom CA file.");

        struct aws_byte_cursor ca_cursor = aws_byte_cursor_from_buf(&options->ca_file);
        if (aws_import_trusted_certificates(
                alloc, secure_transport_ctx->wrapped_allocator, &ca_cursor, &secure_transport_ctx->ca_cert)) {
            AWS_LOGF_ERROR(AWS_LS_IO_TLS, "static: failed to import custom CA with error %d", aws_last_error());
            goto cleanup_wrapped_allocator;
        }
    }

    return &secure_transport_ctx->ctx;

cleanup_wrapped_allocator:
    aws_wrapped_cf_allocator_destroy(secure_transport_ctx->wrapped_allocator);

    if (secure_transport_ctx->alpn_list) {
        aws_string_destroy(secure_transport_ctx->alpn_list);
    }

cleanup_secure_transport_ctx:
    aws_mem_release(alloc, secure_transport_ctx);

    return NULL;
}

struct aws_tls_ctx *aws_tls_server_ctx_new(struct aws_allocator *alloc, const struct aws_tls_ctx_options *options) {
    return s_tls_ctx_new(alloc, options);
}

struct aws_tls_ctx *aws_tls_client_ctx_new(struct aws_allocator *alloc, const struct aws_tls_ctx_options *options) {
    return s_tls_ctx_new(alloc, options);
}

#pragma clang diagnostic pop
