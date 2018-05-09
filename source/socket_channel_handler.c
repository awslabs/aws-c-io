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
#include <aws/io/socket.h>
#include <aws/io/event_loop.h>
#include <aws/common/task_scheduler.h>

#include <assert.h>


struct socket_handler {
    struct aws_socket *socket;
    struct aws_event_loop *event_loop;
    struct aws_channel_slot *slot;
    struct aws_linked_list_node write_queue;
    size_t max_rw_size;
};

static int socket_process_read_message(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                        struct aws_io_message *message) {
    /*this should NEVER happen, if it does it's a programmer error.*/
    assert(0);
    return aws_raise_error(AWS_IO_CHANNEL_ERROR_ERROR_CANT_ACCEPT_INPUT);
}

int socket_shutdown_direction (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                               enum aws_channel_direction dir);

static int do_write(struct socket_handler *socket_handler);

static void write_task (void *arg, aws_task_status status) {
    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct socket_handler *socket_handler = (struct socket_handler *)arg;
        do_write(socket_handler);
    }
}

static int do_write(struct socket_handler *socket_handler) {
    size_t written = 0;

    /* while we have data in the queue send as many messages as possible until we either run out or hit the
     * context switch value */
    while (!aws_linked_list_empty(&socket_handler->write_queue) && written < socket_handler->max_rw_size) {
        struct aws_linked_list_node *head = aws_linked_list_remove(&socket_handler->write_queue);
        struct aws_io_message *next_message = aws_container_of(head, struct aws_io_message, queueing_handle);

        size_t left_to_write = next_message->message_data.len - next_message->copy_mark;
        size_t available_to_write = socket_handler->max_rw_size - written;
        size_t max_write = left_to_write <= available_to_write ?
                           left_to_write : available_to_write;

        struct aws_byte_buf buffer = aws_byte_buf_from_array(next_message->message_data.buffer + next_message->copy_mark,
                                                             max_write);
        size_t written_to_wire = 0;

        /* if we didn't write everything we requested */
        if (aws_socket_write(socket_handler->socket, &buffer, &written_to_wire)) {
            /* this is a normal case, we just got a would block back from the socket. no need to schedule a task,
             * the edge trigger will wake us up. */
            if (aws_last_error() == AWS_IO_WRITE_WOULD_BLOCK) {
                next_message->copy_mark += written_to_wire;
                aws_linked_list_push_front(&socket_handler->write_queue, &next_message->queueing_handle);
                socket_handler->write_queue = *head;
                return aws_raise_error(AWS_IO_WRITE_WOULD_BLOCK);
            }

            /* this case something bad happened and we should initiate a shutdown. */
            if (next_message->on_completion) {
                next_message->on_completion(socket_handler->slot->channel, next_message, aws_last_error(), next_message->ctx);
            }
            socket_handler->write_queue = *head->next;
            return socket_shutdown_direction(socket_handler->slot->handler, socket_handler->slot, AWS_CHANNEL_DIR_WRITE);
        }

        written += written_to_wire;
        next_message->copy_mark += written_to_wire;
        if (next_message->copy_mark == next_message->message_data.len) {
            if (next_message->on_completion) {
                next_message->on_completion(socket_handler->slot->channel, next_message, AWS_OP_SUCCESS, next_message->ctx);
            }
            aws_channel_release_message_to_pool(socket_handler->slot->channel, next_message);
        }
    }

    if (!aws_linked_list_empty(&socket_handler->write_queue)) {
        /* if we got here, the socket is still in the write state. We won't receive edge trigger and we still have data to send
         * go ahead and schedule another run. */
        struct aws_task task = {
                .fn = write_task,
                .arg = socket_handler,
        };

        uint64_t now = 0;
        if (!aws_channel_current_clock_time(socket_handler->slot->channel, &now)) {
            return AWS_OP_ERR;
        }

        return aws_channel_schedule_task(socket_handler->slot->channel, &task, now);
    }

    return AWS_OP_SUCCESS;
}

static int socket_process_write_message( struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                               struct aws_io_message *message ) {
    struct socket_handler *socket_handler = (struct socket_handler *)handler->impl;

    struct aws_linked_list_node *head = &socket_handler->write_queue;

    if (message) {
        aws_linked_list_push_back(head, &message->queueing_handle);
    }

    return do_write(socket_handler);
}

static void read_task(void *arg, aws_task_status status);

static void do_read(struct socket_handler *socket_handler) {
    size_t upstream_window = aws_channel_slot_upstream_read_window(socket_handler->slot);
    size_t max_to_read =
            upstream_window > socket_handler->max_rw_size ? socket_handler->max_rw_size : upstream_window;

    if (max_to_read) {

        size_t total_read = 0, read = 0;
        while (total_read < max_to_read) {
            struct aws_io_message *message =
                    aws_channel_aquire_message_from_pool(socket_handler->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA,
                                                         max_to_read);

            if (aws_socket_read(socket_handler->socket, &message->message_data, &read)) {
                aws_channel_release_message_to_pool(socket_handler->slot->channel, message);
                break;
            }

            total_read += read;

            message->message_data.len = read;
            if (aws_channel_slot_send_message(socket_handler->slot, message, AWS_CHANNEL_DIR_READ)) {
                aws_channel_release_message_to_pool(socket_handler->slot->channel, message);
                return;
            }

        }

        /* do nothing, this is how async io works! */
        if (total_read < max_to_read && aws_last_error() == AWS_IO_READ_WOULD_BLOCK) {
            return;
        }
        /* in this case, everything was fine, but there's still pending reads. We need to schedule a task to do the read again. */
        else if (total_read == socket_handler->max_rw_size) {
            struct aws_task task = {
                    .fn = read_task,
                    .arg = socket_handler,
            };

            uint64_t now = 0;
            if (!aws_channel_current_clock_time(socket_handler->slot->channel, &now)) {
                aws_channel_schedule_task(socket_handler->slot->channel, &task, now);
            }
        }
    }
}

static void read_task(void *arg, aws_task_status status) {
    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct socket_handler *socket_handler = (struct socket_handler *)arg;
        do_read(socket_handler);
    }
}

static void on_socket_event(struct aws_event_loop *event_loop, struct aws_io_handle *handle, int events, void *arg) {
    struct aws_channel_handler *channel_handler = (struct aws_channel_handler *)arg;
    struct socket_handler *socket_handler = (struct socket_handler *)channel_handler->impl;

    if (events & AWS_IO_EVENT_TYPE_ERROR) {
        int error = aws_socket_get_error(socket_handler->socket);
        aws_channel_slot_shutdown_notify(socket_handler->slot, AWS_CHANNEL_DIR_READ, error);
        return;
    }

    if (events & AWS_IO_EVENT_TYPE_CLOSED || events & AWS_IO_EVENT_TYPE_REMOTE_HANG_UP) {
        aws_channel_slot_shutdown_notify(socket_handler->slot, AWS_CHANNEL_DIR_READ, AWS_IO_SOCKET_CLOSED);
        return;
    }

    if (events & AWS_IO_EVENT_TYPE_READABLE) {
        do_read(socket_handler);
    }

    if (events & AWS_IO_EVENT_TYPE_WRITABLE) {
        socket_process_write_message(channel_handler, socket_handler->slot, NULL);
    }

}

int socket_on_window_update(struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size) {
    struct socket_handler *socket_handler = (struct socket_handler *)handler->impl;

    struct aws_task task = {
            .fn = read_task,
            .arg = socket_handler,
    };

    uint64_t now = 0;
    if (!aws_channel_current_clock_time(slot->channel, &now)) {
        return aws_channel_schedule_task(slot->channel, &task, now);
    }

    return AWS_OP_ERR;
}

int do_shutdown(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                enum aws_channel_direction dir, int error_code) {
    struct socket_handler *socket_handler = (struct socket_handler *) handler->impl;
    aws_socket_half_close(socket_handler->socket, dir);

    if (dir == AWS_CHANNEL_DIR_WRITE) {

        while(!aws_linked_list_empty(&socket_handler->write_queue)) {
            struct aws_linked_list_node *node = aws_linked_list_remove(&socket_handler->write_queue);
            struct aws_io_message *message = aws_container_of(node, struct aws_io_message, queueing_handle);

            if (message->on_completion) {
                message->on_completion(slot->channel, message, AWS_IO_SOCKET_CLOSED, message->ctx);
            }

            aws_channel_release_message_to_pool(slot->channel, message);
        }
    }

    return aws_channel_slot_shutdown_notify(slot, dir, error_code);
}

int socket_on_shutdown_notify (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                           enum aws_channel_direction dir, int error_code) {
    return do_shutdown(handler, slot, dir, error_code);
}

int socket_shutdown_direction (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                           enum aws_channel_direction dir) {
    return do_shutdown(handler, slot, dir, AWS_OP_SUCCESS);
}

size_t socket_get_current_window_size (struct aws_channel_handler *handler) {
    return SIZE_MAX;
}

void socket_destroy(struct aws_channel_handler *handler) {
    struct socket_handler *socket_handler = (struct socket_handler *) handler->impl;
    aws_event_loop_unsubscribe_from_io_events(socket_handler->event_loop, &socket_handler->socket->io_handle);
    aws_socket_clean_up(socket_handler->socket);
    aws_mem_release(handler->alloc, socket_handler);
    aws_mem_release(handler->alloc, handler);
}

static struct aws_channel_handler_vtable vtable = {
        .process_read_message = socket_process_read_message,
        .destroy = socket_destroy,
        .process_write_message = socket_process_write_message,
        .get_current_window_size = socket_get_current_window_size,
        .on_window_update = socket_on_window_update,
        .on_shutdown_notify = socket_on_shutdown_notify,
        .shutdown_direction = socket_shutdown_direction
};

struct aws_channel_handler *aws_socket_handler_new(struct aws_allocator *allocator, struct aws_socket *socket,
                                                   struct aws_channel_slot *slot, struct aws_event_loop *event_loop,
                                                   size_t max_rw_size) {
    struct aws_channel_handler *handler = (struct aws_channel_handler *)aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));

    if (!handler) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    struct socket_handler *impl = (struct socket_handler *)aws_mem_acquire(allocator, sizeof(struct socket_handler));
    if (!impl) {
        aws_raise_error(AWS_ERROR_OOM);
        goto cleanup_handler;
    }

    impl->socket = socket;
    impl->slot = slot;
    impl->max_rw_size = max_rw_size;
    impl->event_loop = event_loop;
    aws_linked_list_init(&impl->write_queue);

    handler->alloc = allocator;
    handler->impl = impl;
    handler->vtable = vtable;

    if (aws_event_loop_subscribe_to_io_events(event_loop, &socket->io_handle, AWS_IO_EVENT_TYPE_READABLE | AWS_IO_EVENT_TYPE_WRITABLE,
                                          on_socket_event, handler)) {
        goto cleanup_impl;
    }

    return handler;

cleanup_impl:
    aws_mem_release(allocator, impl);

cleanup_handler:
    aws_mem_release(allocator, handler);

    return NULL;
}

