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
#include <aws/io/socket_channel_handler.h>

#include <aws/common/task_scheduler.h>

#include <aws/io/event_loop.h>
#include <aws/io/socket.h>

#include <assert.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

struct socket_handler {
    struct aws_socket *socket;
    struct aws_channel_slot *slot;
    size_t max_rw_size;
    struct aws_task read_task_storage;
    struct aws_task shutdown_task_storage;
    int shutdown_err_code;
    bool shutdown_in_progress;
};

static int s_socket_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)handler;
    (void)slot;
    (void)message;

    /*since a socket handler will ALWAYS be the first handler in a channel,
     * this should NEVER happen, if it does it's a programmer error.*/
    assert(0);
    return aws_raise_error(AWS_IO_CHANNEL_ERROR_ERROR_CANT_ACCEPT_INPUT);
}

/* invoked by the socket when a write has completed or failed. */
static void s_on_socket_write_complete(struct aws_socket *socket, int error_code, struct aws_byte_cursor *data_written, void *user_data) {
    (void)data_written;
    (void)socket;

    if (user_data) {
        struct aws_io_message *message = user_data;
        struct aws_channel *channel = message->owning_channel;

        if (message->on_completion) {
            message->on_completion(channel, message, error_code, message->user_data);
        }

        aws_channel_release_message_to_pool(channel, message);

        if (error_code) {
            aws_channel_shutdown(channel, error_code);
        }
    }
}

static int s_socket_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    (void)slot;
    struct socket_handler *socket_handler = (struct socket_handler *)handler->impl;

    struct aws_byte_cursor cursor = aws_byte_cursor_from_buf(&message->message_data);
    if (aws_socket_write(socket_handler->socket, &cursor, s_on_socket_write_complete, message)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static void s_read_task(struct aws_task *task, void *arg, aws_task_status status);

static void s_on_readable_notification(struct aws_socket *socket, int error_code, void *user_data);

/* Ok this next function is VERY important for how back pressure works. Here's what it's supposed to be doing:
 *
 * See how much data downstream is willing to accept.
 * See how much we're actually willing to read per event loop tick (usually 16 kb).
 * Take the minimum of those two.
 * Try and read as much as possible up to the calculated max read.
 * If we didn't read up to the max_read, we go back to waiting on the event loop to tell us we can read more.
 * If we did read up to the max_read, we stop reading immediately and wait for either for a window update,
 * or schedule a task to enforce fairness for other sockets in the event loop if we read up to the max
 * read per event loop tick.
 */
static void s_do_read(struct socket_handler *socket_handler) {

    size_t downstream_window = aws_channel_slot_downstream_read_window(socket_handler->slot);
    size_t max_to_read =
        downstream_window > socket_handler->max_rw_size ? socket_handler->max_rw_size : downstream_window;

    if (max_to_read) {
        size_t total_read = 0, read = 0;
        while (total_read < max_to_read && !socket_handler->shutdown_in_progress) {
            struct aws_io_message *message = aws_channel_acquire_message_from_pool(
                socket_handler->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, max_to_read);

            if (aws_socket_read(socket_handler->socket, &message->message_data, &read)) {
                aws_channel_release_message_to_pool(socket_handler->slot->channel, message);
                break;
            }

            total_read += read;
            if (aws_channel_slot_send_message(socket_handler->slot, message, AWS_CHANNEL_DIR_READ)) {
                aws_channel_release_message_to_pool(socket_handler->slot->channel, message);
                return;
            }
        }

        int last_error = aws_last_error();
        /* resubscribe as long as there's no error, just return if we're in a would block scenario. */
        if (total_read < max_to_read ) {
            if (last_error != AWS_IO_READ_WOULD_BLOCK && !socket_handler->shutdown_in_progress) {
                aws_channel_shutdown(socket_handler->slot->channel, last_error);
            }
            return;
        }
        /* in this case, everything was fine, but there's still pending reads. We need to schedule a task to do the read
         * again. */
        if (!socket_handler->shutdown_in_progress && total_read == socket_handler->max_rw_size
            && !socket_handler->read_task_storage.fn) {
            socket_handler->read_task_storage.fn = s_read_task;
            socket_handler->read_task_storage.arg = socket_handler;

            aws_channel_schedule_task_now(socket_handler->slot->channel, &socket_handler->read_task_storage);
        }
    }
}

/* the socket is either readable or errored out. If it's readable, kick of s_do_read() to do its thing.
 * If an error, start the channel shutdown process. */
static void s_on_readable_notification(struct aws_socket *socket, int error_code, void *user_data) {
    (void)socket;

    struct socket_handler *socket_handler = user_data;
    if (!error_code) {
        s_do_read(socket_handler);
    }
    else if (!socket_handler->shutdown_in_progress) {
        aws_channel_shutdown(socket_handler->slot->channel, error_code);
    }
}

/* Either the result of a context switch (for fairness in the event loop), or a window update. */
static void s_read_task(struct aws_task *task, void *arg, aws_task_status status) {
    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct socket_handler *socket_handler = (struct socket_handler *)arg;
        s_do_read(socket_handler);
    }
    task->fn = NULL;
    task->arg = NULL;
}

int socket_increment_read_window(struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size) {
    (void)size;
    struct socket_handler *socket_handler = (struct socket_handler *)handler->impl;

    if (!socket_handler->shutdown_in_progress && !socket_handler->read_task_storage.fn) {
        socket_handler->read_task_storage.fn = s_read_task;
        socket_handler->read_task_storage.arg = socket_handler;
        aws_channel_schedule_task_now(slot->channel, &socket_handler->read_task_storage); 
    }

    return AWS_OP_SUCCESS;
}

static void s_shutdown_task(struct aws_task *task, void *arg, aws_task_status status) {
    (void)status;
    (void)task;

    struct aws_channel_handler *handler = (struct aws_channel_handler *)arg;
    struct socket_handler *socket_handler = (struct socket_handler *)handler->impl;

    /* this only happens in write direction. */
    /* we also don't care about the abort code since we're always the last one in the shutdown sequence. */
    aws_channel_slot_on_handler_shutdown_complete(
        socket_handler->slot, AWS_CHANNEL_DIR_WRITE, socket_handler->shutdown_err_code, false);
}

static int s_socket_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool abort) {
    struct socket_handler *socket_handler = (struct socket_handler *)handler->impl;

    socket_handler->shutdown_in_progress = true;
    if (dir == AWS_CHANNEL_DIR_READ) {
        if (abort && aws_socket_is_open(socket_handler->socket)) {
            if (aws_socket_shutdown(socket_handler->socket)) {
                return AWS_OP_ERR;
            }
        }

        return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, abort);
    }

    if (aws_socket_is_open(socket_handler->socket)) {
        aws_socket_shutdown(socket_handler->socket);
    }

    /* we have an edge case where this was initiated by an io event (not from the user), we've already a do_read task
     * pending, if abort is true, we've mitigated the worries that the socket is still being abused by a hostile peer.
     * But the final shutdown notification needs to happen after we've done the socket shutdown to make sure we don't
     * pick up an errant events and crash. */
    socket_handler->shutdown_task_storage.fn = s_shutdown_task;
    socket_handler->shutdown_task_storage.arg = handler;


    socket_handler->shutdown_err_code = error_code;
    aws_channel_schedule_task_now(slot->channel, &socket_handler->shutdown_task_storage);
    return AWS_OP_SUCCESS;
}

size_t socket_get_current_window_size(struct aws_channel_handler *handler) {
    (void)handler;
    return SIZE_MAX;
}

void socket_destroy(struct aws_channel_handler *handler) {
    struct socket_handler *socket_handler = (struct socket_handler *)handler->impl;
    aws_socket_clean_up(socket_handler->socket);
    aws_mem_release(handler->alloc, socket_handler);
    aws_mem_release(handler->alloc, handler);
}

static struct aws_channel_handler_vtable s_vtable = {.process_read_message = s_socket_process_read_message,
                                                   .destroy = socket_destroy,
                                                   .process_write_message = s_socket_process_write_message,
                                                   .initial_window_size = socket_get_current_window_size,
                                                   .increment_read_window = socket_increment_read_window,
                                                   .shutdown = s_socket_shutdown};

struct aws_channel_handler *aws_socket_handler_new(
    struct aws_allocator *allocator,
    struct aws_socket *socket,
    struct aws_channel_slot *slot,
    size_t max_rw_size) {

    /* make sure something has assigned this socket to an event loop, in client mode this will already have occurred. 
       In server mode, someone should have assigned it before calling us.*/
    assert(aws_socket_get_event_loop(socket));

    struct aws_channel_handler *handler =
        (struct aws_channel_handler *)aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));

    if (!handler) {
        return NULL;
    }

    struct socket_handler *impl = (struct socket_handler *)aws_mem_acquire(allocator, sizeof(struct socket_handler));
    if (!impl) {
        goto cleanup_handler;
    }

    impl->socket = socket;
    impl->slot = slot;
    impl->max_rw_size = max_rw_size;
    impl->read_task_storage.fn = NULL;
    impl->read_task_storage.arg = NULL;
    impl->shutdown_in_progress = false;

    handler->alloc = allocator;
    handler->impl = impl;
    handler->vtable = s_vtable;
    if (aws_socket_subscribe_to_readable_events(socket, s_on_readable_notification, impl)) {
        goto cleanup_impl;
    }

    return handler;

cleanup_impl:
    aws_mem_release(allocator, impl);

cleanup_handler:
    aws_mem_release(allocator, handler);

    return NULL;
}
