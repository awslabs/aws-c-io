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
#include <aws/io/file_utils.h>
#include <aws/io/logging.h>
#include <aws/io/pki_utils.h>

#include <aws/common/task_scheduler.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <s2n.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/crypto.h>

#define EST_TLS_RECORD_OVERHEAD 53 /* 5 byte header + 32 + 16 bytes for padding */
#define KB_1 1024
#define MAX_RECORD_SIZE (KB_1 * 16)
#define EST_HANDSHAKE_SIZE (7 * KB_1)

/* this is completely absurd and the reason I hate dependencies, but I'm assuming
 * you don't want your older versions of openssl's libcrypto crashing on you. */
#if defined(LIBRESSL_VERSION_NUMBER) && (OPENSSL_VERSION_NUMBER == 0x20000000L)
#    undef OPENSSL_VERSION_NUMBER
#    define OPENSSL_VERSION_NUMBER 0x1000107fL
#endif
#define OPENSSL_VERSION_LESS_1_1 (OPENSSL_VERSION_NUMBER < 0x10100003L)

#if OPENSSL_VERSION_LESS_1_1
#    include <aws/common/mutex.h>
#    include <aws/common/thread.h>

static struct aws_mutex *s_libcrypto_locks = NULL;
static struct aws_allocator *s_libcrypto_allocator = NULL;

static void s_locking_fn(int mode, int n, const char *unused0, int unused1) {
    (void)unused0;
    (void)unused1;

    if (mode & CRYPTO_LOCK) {
        aws_mutex_lock(&s_libcrypto_locks[n]);
    } else {
        aws_mutex_unlock(&s_libcrypto_locks[n]);
    }
}

static unsigned long s_id_fn(void) {
    return (unsigned long)aws_thread_current_thread_id();
}
#endif

struct s2n_handler {
    struct aws_channel_handler handler;
    struct s2n_connection *connection;
    struct aws_channel_slot *slot;
    struct aws_linked_list input_queue;
    struct aws_byte_buf protocol;
    struct aws_byte_buf server_name;
    struct aws_tls_connection_options options;
    aws_channel_on_message_write_completed_fn *latest_message_on_completion;
    struct aws_channel_task sequential_tasks;
    void *latest_message_completion_user_data;
    bool negotiation_finished;
};

struct s2n_ctx {
    struct aws_tls_ctx ctx;
    struct s2n_config *s2n_config;
};

void aws_tls_init_static_state(struct aws_allocator *alloc) {

    (void)alloc;
    AWS_LOGF_INFO(AWS_LS_IO_TLS, "static: Initializing TLS using s2n.");

    setenv("S2N_ENABLE_CLIENT_MODE", "1", 1);
    setenv("S2N_DONT_MLOCK", "1", 1);
    s2n_init();

#if OPENSSL_VERSION_LESS_1_1
    AWS_LOGF_WARN(AWS_LS_IO_TLS, "static: OpenSSL version less than 1.1 detected. Please upgrade.");
    if (!CRYPTO_get_locking_callback()) {
        s_libcrypto_allocator = alloc;
        s_libcrypto_locks = aws_mem_acquire(alloc, sizeof(struct aws_mutex) * CRYPTO_num_locks());
        AWS_FATAL_ASSERT(s_libcrypto_locks);
        size_t lock_count = (size_t)CRYPTO_num_locks();
        for (size_t i = 0; i < lock_count; ++i) {
            aws_mutex_init(&s_libcrypto_locks[i]);
        }
        CRYPTO_set_locking_callback(s_locking_fn);
    }

    if (!CRYPTO_get_id_callback()) {
        CRYPTO_set_id_callback(s_id_fn);
    }
#endif
}

void aws_tls_clean_up_thread_local_state(void) {
    /* if you're wondering why this function exists, this is why.... s2n_cleanup() cleans up some allocated
     * memory in thread local state (sigh.....). */
    s2n_cleanup();
}

void aws_tls_clean_up_static_state(void) {
    s2n_cleanup();

#if OPENSSL_VERSION_LESS_1_1
    if (CRYPTO_get_locking_callback() == s_locking_fn) {
        CRYPTO_set_locking_callback(NULL);
        size_t lock_count = (size_t)CRYPTO_num_locks();
        for (size_t i = 0; i < lock_count; ++i) {
            aws_mutex_clean_up(&s_libcrypto_locks[i]);
        }
        aws_mem_release(s_libcrypto_allocator, s_libcrypto_locks);
    }

    if (CRYPTO_get_id_callback() == s_id_fn) {
        CRYPTO_set_id_callback(NULL);
    }
#endif
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
            aws_mem_release(message->allocator, message);
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

    struct aws_byte_cursor buffer_cursor = aws_byte_cursor_from_buf(buf);

    size_t processed = 0;
    while (processed < buf->len) {
        struct aws_io_message *message = aws_channel_acquire_message_from_pool(
            handler->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, buf->len - processed);

        if (!message) {
            errno = ENOMEM;
            return -1;
        }

        const size_t overhead = aws_channel_slot_upstream_message_overhead(handler->slot);
        const size_t available_msg_write_capacity = buffer_cursor.len - overhead;

        const size_t to_write = message->message_data.capacity > available_msg_write_capacity
                                    ? available_msg_write_capacity
                                    : message->message_data.capacity;

        struct aws_byte_cursor chunk = aws_byte_cursor_advance(&buffer_cursor, to_write);
        if (aws_byte_buf_append(&message->message_data, &chunk)) {
            aws_mem_release(message->allocator, message);
            return -1;
        }
        processed += message->message_data.len;

        if (processed == buf->len) {
            message->on_completion = handler->latest_message_on_completion;
            message->user_data = handler->latest_message_completion_user_data;
            handler->latest_message_on_completion = NULL;
            handler->latest_message_completion_user_data = NULL;
        }

        if (aws_channel_slot_send_message(handler->slot, message, AWS_CHANNEL_DIR_WRITE)) {
            aws_mem_release(message->allocator, message);
            errno = EPIPE;
            return -1;
        }
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
                AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "id=%p: Alpn protocol negotiated as %s", handler, protocol);
                s2n_handler->protocol = aws_byte_buf_from_c_str(protocol);
            }

            const char *server_name = s2n_get_server_name(s2n_handler->connection);

            if (server_name) {
                AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "id=%p: Remote server name is %s", handler, server_name);
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
                    aws_mem_release(message->allocator, message);
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
            AWS_LOGF_WARN(
                AWS_LS_IO_TLS, "id=%p: negotiation failed with error %s", handler, s2n_strerror_debug(s2n_error, "EN"));

            if (s2n_error_get_type(s2n_error) == S2N_ERR_T_ALERT) {
                AWS_LOGF_DEBUG(
                    AWS_LS_IO_TLS, "id=%p: Alert code %d", handler, s2n_connection_get_alert(s2n_handler->connection));
            }

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

static void s_negotiation_task(struct aws_channel_task *task, void *arg, aws_task_status status) {
    task->task_fn = NULL;
    task->arg = NULL;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_channel_handler *handler = arg;
        s_drive_negotiation(handler);
    }
}

int aws_tls_client_handler_start_negotiation(struct aws_channel_handler *handler) {
    struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;

    AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: Kicking off TLS negotiation.", handler)
    if (aws_channel_thread_is_callers_thread(s2n_handler->slot->channel)) {
        return s_drive_negotiation(handler);
    }

    aws_channel_task_init(&s2n_handler->sequential_tasks, s_negotiation_task, handler);
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
    AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: Downstream window %llu", handler, (unsigned long long)downstream_window);

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

        AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: Bytes read %ll", handler, (long long)read);

        /* weird race where we received an alert from the peer, but s2n doesn't tell us about it.....
         * if this happens, it's a graceful shutdown, so kick it off here.
         *
         * In other words, s2n, upon graceful shutdown, follows the unix EOF idiom. So just shutdown with
         * SUCCESS.
         */
        if (read == 0) {
            AWS_LOGF_DEBUG(
                AWS_LS_IO_TLS, "id=%p: Alert code %d", handler, s2n_connection_get_alert(s2n_handler->connection));
            aws_mem_release(outgoing_read_message->allocator, outgoing_read_message);
            aws_channel_shutdown(slot->channel, AWS_OP_SUCCESS);
            return AWS_OP_SUCCESS;
        }

        if (read < 0) {
            aws_mem_release(outgoing_read_message->allocator, outgoing_read_message);
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
            aws_mem_release(outgoing_read_message->allocator, outgoing_read_message);
        }
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_TLS,
        "id=%p: Remaining window for this event-loop tick: %llu",
        handler,
        (unsigned long long)downstream_window - processed);

    return AWS_OP_SUCCESS;
}

static int s_s2n_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)slot;
    struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;

    if (AWS_UNLIKELY(!s2n_handler->negotiation_finished)) {
        return aws_raise_error(AWS_IO_TLS_ERROR_NOT_NEGOTIATED);
    }

    s2n_handler->latest_message_on_completion = message->on_completion;
    s2n_handler->latest_message_completion_user_data = message->user_data;

    s2n_blocked_status blocked;
    ssize_t write_code =
        s2n_send(s2n_handler->connection, message->message_data.buffer, (ssize_t)message->message_data.len, &blocked);

    AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: Bytes written: %llu", handler, (unsigned long long)write_code);

    ssize_t message_len = (ssize_t)message->message_data.len;
    aws_mem_release(message->allocator, message);

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
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "id=%p: Shutting down write direction", handler)
        s2n_blocked_status blocked;
        /* make a best effort, but the channel is going away after this run, so.... you only get one shot anyways */
        s2n_shutdown(s2n_handler->connection, &blocked);
    } else {
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "id=%p: Shutting down read direction with error code %d", handler, error_code);

        while (!aws_linked_list_empty(&s2n_handler->input_queue)) {
            struct aws_linked_list_node *node = aws_linked_list_pop_front(&s2n_handler->input_queue);
            struct aws_io_message *message = AWS_CONTAINER_OF(node, struct aws_io_message, queueing_handle);
            aws_mem_release(message->allocator, message);
        }
    }

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, abort_immediately);
}

static void s_run_read(struct aws_channel_task *task, void *arg, aws_task_status status) {
    task->task_fn = NULL;
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
    (void)size;
    struct s2n_handler *s2n_handler = (struct s2n_handler *)handler->impl;

    size_t downstream_size = aws_channel_slot_downstream_read_window(slot);
    size_t current_window_size = slot->window_size;

    AWS_LOGF_TRACE(
        AWS_LS_IO_TLS, "id=%p: Increment read window message received %llu", handler, (unsigned long long)size);

    if (downstream_size <= current_window_size) {
        size_t likely_records_count = (downstream_size - current_window_size) % MAX_RECORD_SIZE;
        size_t offset_size = likely_records_count * (EST_TLS_RECORD_OVERHEAD);
        size_t window_update_size = (downstream_size - current_window_size) + offset_size;
        AWS_LOGF_TRACE(
            AWS_LS_IO_TLS,
            "id=%p: Propagating read window increment of size %llu",
            handler,
            (unsigned long long)window_update_size);
        aws_channel_slot_increment_read_window(slot, window_update_size);
    }

    if (s2n_handler->negotiation_finished && !s2n_handler->sequential_tasks.node.next) {
        /* TLS requires full records before it can decrypt anything. As a result we need to check everything we've
         * buffered instead of just waiting on a read from the socket, or we'll hit a deadlock.
         *
         * We have messages in a queue and they need to be run after the socket has popped (even if it didn't have data
         * to read). Alternatively, s2n reads entire records at a time, so we'll need to grab whatever we can and we
         * have no idea what's going on inside there. So we need to attempt another read.*/
        aws_channel_task_init(&s2n_handler->sequential_tasks, s_run_read, handler);
        aws_channel_schedule_task_now(slot->channel, &s2n_handler->sequential_tasks);
    }

    return AWS_OP_SUCCESS;
}

static size_t s_s2n_handler_message_overhead(struct aws_channel_handler *handler) {
    (void)handler;
    return EST_TLS_RECORD_OVERHEAD;
}

static size_t s_s2n_handler_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;

    return EST_HANDSHAKE_SIZE;
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
    .initial_window_size = s_s2n_handler_initial_window_size,
    .message_overhead = s_s2n_handler_message_overhead,
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
    struct aws_byte_cursor user_alpn_str = aws_byte_cursor_from_c_str(alpn_list_str);

    aws_array_list_init_static(&alpn_list, alpn_list_buffer, 4, sizeof(struct aws_byte_cursor));

    if (aws_byte_cursor_split_on_char(&user_alpn_str, ';', &alpn_list)) {
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

static struct aws_channel_handler *s_new_tls_handler(
    struct aws_allocator *allocator,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot,
    s2n_mode mode) {

    assert(options->ctx);
    struct s2n_handler *s2n_handler = aws_mem_acquire(allocator, sizeof(struct s2n_handler));

    if (!s2n_handler) {
        return NULL;
    }

    AWS_ZERO_STRUCT(*s2n_handler);
    struct s2n_ctx *s2n_ctx = (struct s2n_ctx *)options->ctx->impl;
    s2n_handler->connection = s2n_connection_new(mode);

    if (!s2n_handler->connection) {
        goto cleanup_s2n_handler;
    }

    s2n_handler->handler.impl = s2n_handler;
    s2n_handler->handler.alloc = allocator;
    s2n_handler->handler.vtable = &s_handler_vtable;

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
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "id=%p: Setting ALPN list %s", &s2n_handler->handler, options->alpn_list);

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
        AWS_LOGF_WARN(
            AWS_LS_IO_TLS, "id=%p: configuration error %s", &s2n_handler->handler, s2n_strerror_debug(s2n_errno, "EN"));
        aws_raise_error(AWS_IO_TLS_CTX_ERROR);
        goto cleanup_conn;
    }

    return &s2n_handler->handler;

cleanup_conn:
    s2n_connection_free(s2n_handler->connection);

cleanup_s2n_handler:
    aws_mem_release(allocator, s2n_handler);

    return NULL;
}

struct aws_channel_handler *aws_tls_client_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {

    return s_new_tls_handler(allocator, options, slot, S2N_CLIENT);
}

struct aws_channel_handler *aws_tls_server_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {

    return s_new_tls_handler(allocator, options, slot, S2N_SERVER);
}

void aws_tls_ctx_destroy(struct aws_tls_ctx *ctx) {
    struct s2n_ctx *s2n_ctx = ctx->impl;

    if (s2n_ctx) {
        s2n_config_free(s2n_ctx->s2n_config);
        aws_mem_release(ctx->alloc, s2n_ctx);
    }
}

static struct aws_tls_ctx *s_tls_ctx_new(
    struct aws_allocator *alloc,
    struct aws_tls_ctx_options *options,
    s2n_mode mode) {
    struct s2n_ctx *s2n_ctx = (struct s2n_ctx *)aws_mem_acquire(alloc, sizeof(struct s2n_ctx));

    if (!s2n_ctx) {
        return NULL;
    }

    s2n_ctx->ctx.alloc = alloc;
    s2n_ctx->ctx.impl = s2n_ctx;
    s2n_ctx->s2n_config = s2n_config_new();

    if (!s2n_ctx->s2n_config) {
        goto cleanup_s2n_ctx;
    }

    switch (options->minimum_tls_version) {
        case AWS_IO_SSLv3:
            s2n_config_set_cipher_preferences(s2n_ctx->s2n_config, "CloudFront-SSL-v-3");
            break;
        case AWS_IO_TLSv1:
            s2n_config_set_cipher_preferences(s2n_ctx->s2n_config, "CloudFront-TLS-1-0-2016");
            break;
        case AWS_IO_TLSv1_1:
            s2n_config_set_cipher_preferences(s2n_ctx->s2n_config, "CloudFront-TLS-1-1-2016");
            break;
        case AWS_IO_TLSv1_2:
            s2n_config_set_cipher_preferences(s2n_ctx->s2n_config, "CloudFront-TLS-1-2-2018");
            break;
        case AWS_IO_TLSv1_3:
            AWS_LOGF_ERROR(AWS_LS_IO_TLS, "TLS 1.3 is not supported yet.");
            /* sorry guys, we'll add this as soon as s2n does. */
            aws_raise_error(AWS_IO_TLS_VERSION_UNSUPPORTED);
            goto cleanup_s2n_ctx;
        case AWS_IO_TLS_VER_SYS_DEFAULTS:
        default:
            s2n_config_set_cipher_preferences(s2n_ctx->s2n_config, "default");
    }

    if (options->certificate_path && options->private_key_path) {
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "ctx: Certificate and key have been set, setting them up now.");

        struct aws_byte_buf certificate_chain, private_key;

        if (aws_byte_buf_init_from_file(&certificate_chain, alloc, options->certificate_path)) {
            AWS_LOGF_ERROR(AWS_LS_IO_TLS, "ctx: Failed to load %s", options->certificate_path);
            goto cleanup_s2n_config;
        }

        if (aws_byte_buf_init_from_file(&private_key, alloc, options->private_key_path)) {
            AWS_LOGF_ERROR(AWS_LS_IO_TLS, "ctx: Failed to load %s", options->private_key_path);
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
            AWS_LOGF_ERROR(AWS_LS_IO_TLS, "ctx: configuration error %s", s2n_strerror_debug(s2n_errno, "EN"));
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
                AWS_LOGF_ERROR(AWS_LS_IO_TLS, "ctx: configuration error %s", s2n_strerror_debug(s2n_errno, "EN"));
                aws_raise_error(AWS_IO_TLS_CTX_ERROR);
                goto cleanup_s2n_config;
            }
        }

        if (mode == S2N_SERVER && s2n_config_set_client_auth_type(s2n_ctx->s2n_config, S2N_CERT_AUTH_REQUIRED)) {
            AWS_LOGF_ERROR(AWS_LS_IO_TLS, "ctx: configuration error %s", s2n_strerror_debug(s2n_errno, "EN"));
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_s2n_config;
        }
    } else if (mode != S2N_SERVER) {
        AWS_LOGF_WARN(
            AWS_LS_IO_TLS,
            "ctx: X.509 validation has been disabled. "
            "If this is not running in a test environment, this is likely a security vulnerability.");
        if (s2n_config_disable_x509_verification(s2n_ctx->s2n_config)) {
            aws_raise_error(AWS_IO_TLS_CTX_ERROR);
            goto cleanup_s2n_config;
        }
    }

    if (options->alpn_list) {
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "ctx: Setting ALPN list %s", options->alpn_list);
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

    if (options->max_fragment_size == 512) {
        s2n_config_send_max_fragment_length(s2n_ctx->s2n_config, S2N_TLS_MAX_FRAG_LEN_512);
    } else if (options->max_fragment_size == 1024) {
        s2n_config_send_max_fragment_length(s2n_ctx->s2n_config, S2N_TLS_MAX_FRAG_LEN_1024);
    } else if (options->max_fragment_size == 2048) {
        s2n_config_send_max_fragment_length(s2n_ctx->s2n_config, S2N_TLS_MAX_FRAG_LEN_2048);
    } else if (options->max_fragment_size == 4096) {
        s2n_config_send_max_fragment_length(s2n_ctx->s2n_config, S2N_TLS_MAX_FRAG_LEN_4096);
    }

    return &s2n_ctx->ctx;

cleanup_s2n_config:
    s2n_config_free(s2n_ctx->s2n_config);

cleanup_s2n_ctx:
    aws_mem_release(alloc, s2n_ctx);

    return NULL;
}

struct aws_tls_ctx *aws_tls_server_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    return s_tls_ctx_new(alloc, options, S2N_SERVER);
}

struct aws_tls_ctx *aws_tls_client_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    return s_tls_ctx_new(alloc, options, S2N_CLIENT);
}
