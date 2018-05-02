#ifndef AWS_IO_CHANNEL_H
#define AWS_IO_CHANNEL_H
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

#include <aws/io/io.h>
#include <aws/common/linked_list.h>
#include <aws/common/mutex.h>
#include <aws/common/byte_buf.h>
#include <stdbool.h>

typedef enum aws_channel_direction {
    AWS_CHANNEL_DIR_READ = 0x01,
    AWS_CHANNEL_DIR_WRITE = 0x02
} aws_channel_direction;

struct aws_event_loop;
struct aws_event_loop_local_object;
struct aws_task;
struct aws_message_pool;

typedef void(*aws_channel_on_setup_completed)(struct aws_channel *channel, int error_code, void *ctx);

typedef void(*aws_channel_on_shutdown_completed)(struct aws_channel *channel, void *ctx);

struct aws_channel {
    struct aws_allocator *alloc;
    struct aws_event_loop *loop;
    struct aws_channel_slot *first;
    struct aws_message_pool *msg_pool;
    aws_channel_on_shutdown_completed on_read_shutdown_completed;
    void *read_shutdown_ctx;
    aws_channel_on_shutdown_completed on_write_shutdown_completed;
    void *write_shutdown_ctx;
};

struct aws_channel_handler;

struct aws_channel_slot_ref;

struct aws_channel_slot {
    struct aws_allocator *alloc;
    struct aws_channel *channel;
    struct aws_channel_slot *adj_left;
    struct aws_channel_slot *adj_right;
    struct aws_channel_handler *handler;
    size_t window_size;
};


struct aws_channel_handler_vtable {
    /**
     * Called by the channel when a message is available for processing in the read direction. It is your
     * responsibility to call aws_channel_release_message_to_pool() on message when you are finished with it.
     */
    int (*process_read_message) ( struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                     struct aws_io_message *message );
    /**
     * Called by the channel when a message is available for processing in the write direction. It is your
     * responsibility to call aws_channel_release_message_to_pool() on message when you are finished with it.
     */
    int (*process_write_message) ( struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                      struct aws_io_message *message );
    /**
     * Called by the channel when an upstream handler has issued a window update. You'll want to update your internal
     * state and likely propogate a window update message of your own.
     */
    int (*on_window_update) (struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size);

    /**
     * Called by the channel when an adjacent handler (based on dir), has completed it's shutdown in that direction.
     * This is your notification to shutdown to a safe state. You need to issue a shutdown notification when you are finished
     * shutting down.
     */
    int (*on_shutdown_notify) (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                               enum aws_channel_direction dir, int error_code);

    /**
     * Called by the channel for handlers on the edge (beginning or end) of the channel to begin iniating a shutdown. Issue a
     * shutdown notification once this has completed.
     */
    int (*shutdown_direction) (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                               enum aws_channel_direction dir);

    /**
     * Called by the channel when the handler is added to a slot, to get the initial window size.
     */
    size_t (*get_current_window_size) (struct aws_channel_handler *handler);

    /**
     * Clean up any resources and deallocate yourself.
     */
    void (*destroy)(struct aws_channel_handler *handler);
};

struct aws_channel_handler {
    struct aws_channel_handler_vtable vtable;
    struct aws_allocator *alloc;
    void *impl;
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initializes the channel, with event loop to use for IO and tasks. on_completed will be invoked when the setup process is finished
 * It will be executed in the event loop's thread.
 */
AWS_IO_API int aws_channel_init(struct aws_channel *channel, struct aws_allocator *alloc,
                                struct aws_event_loop *event_loop, aws_channel_on_setup_completed on_completed, void *ctx);

/**
 * Shuts down the channel if it hasn't been already, cleans up all slots and handlers.
 */
AWS_IO_API void aws_channel_clean_up(struct aws_channel *channel);

/**
 * Shuts down the channel in the dir direction. on_completed will be executed in the event loops thread upon completion.
 */
AWS_IO_API int aws_channel_shutdown(struct aws_channel *channel, enum aws_channel_direction dir,
                                    aws_channel_on_shutdown_completed on_completed, void *ctx);

/**
 * Allocates and initializes a new slot for use with the channel. If this is the first slot in the channel, it will automatically
 * be added to the channel as the first slot. For all subsequent calls on a given channel, the slot will need to be added to the channel
 * via. the aws_channel_slot_insert_right() and aws_channel_slot_insert_left() APIs.
 */
AWS_IO_API struct aws_channel_slot *aws_channel_slot_new(struct aws_channel *channel);

/**
 * Fetches the current timestamp from the event-loop's clock.
 */
AWS_IO_API int aws_channel_current_clock_time(struct aws_channel *, uint64_t *ticks);

/**
 * Retrieves an item by key from the event loop's local storage. This function must be executed in the context of the event loop's
 * thread.
 */
AWS_IO_API int aws_channel_fetch_local_item (struct aws_channel *, const void *key, struct aws_event_loop_local_object *item);

/**
 * Stores an item by key in the event loop's local storage. This function must be executed in the context of the event loop's
 * thread.
 */
AWS_IO_API int aws_channel_put_local_item (struct aws_channel *, const void *key, const struct aws_event_loop_local_object *item);

/**
 * Removes an item by key from the event loop's local storage. This function must be executed in the context of the event loop's
 * thread.
 */
AWS_IO_API int aws_channel_remove_local_item ( struct aws_channel *, const void *key, struct aws_event_loop_local_object *removed_item);

/**
 * Acquires a message from the event loop's message pool. data_size is merely a hint, it may be smaller than you requested and you
 * are responsible for checking the bounds of it. If the returned message is not large enough, you must send multiple messages.
 */
AWS_IO_API struct aws_io_message *aws_channel_aquire_message_from_pool(struct aws_channel *,
                                                                             aws_io_message_type message_type, size_t data_size);

/**
 * Returns a message back to the event loop's message pool for reuse.
 */
AWS_IO_API void aws_channel_release_message_to_pool ( struct aws_channel *, struct aws_io_message *message);

/**
 * Schedules a task to run on the event loop. This is the ideal way to move a task into the correct thread. It's also handy for
 * context switches.
 */
AWS_IO_API int aws_channel_schedule_task(struct aws_channel *, struct aws_task *task, uint64_t run_at);

/**
 * Returns true if the caller is on the event loop's thread. If false, you likely need to use aws_channel_schedule_task().
 */
AWS_IO_API bool aws_channel_is_on_callers_thread (struct aws_channel *);

/**
 * Sets the handler for a slot, the slot will also call get_current_window_size() and propagate a window update upstream.
 */
AWS_IO_API int aws_channel_slot_set_handler ( struct aws_channel_slot *, struct aws_channel_handler *handler );

/**
 * Removes slot from the channel and deallocates the slot and its handler.
 */
AWS_IO_API int aws_channel_slot_remove (struct aws_channel_slot *slot);

/**
 * Replaces remove with new. Deallocates remove and its handler.
 */
AWS_IO_API int aws_channel_slot_replace (struct aws_channel_slot *remove, struct aws_channel_slot *new);

/**
 * inserts 'right' to the position immediately to the right of slot.
 */
AWS_IO_API int aws_channel_slot_insert_right (struct aws_channel_slot *slot, struct aws_channel_slot *right);

/**
 * inserts 'left' to the position immediately to the left of slot.
 */
AWS_IO_API int aws_channel_slot_insert_left (struct aws_channel_slot *slot, struct aws_channel_slot *left);

/**
 * Sends a message to the adjacent slot in the channel based on dir. Also does window size checking.
 */
AWS_IO_API int aws_channel_slot_send_message (struct aws_channel_slot *slot, struct aws_io_message *message, enum aws_channel_direction dir);

/**
 * Issues a window update notification upstream.
 */
AWS_IO_API int aws_channel_slot_update_window (struct aws_channel_slot *slot, size_t window);

/**
 * Issues a shutdown notification to adjacent slots in the channel based on dir.
 */
AWS_IO_API int aws_channel_slot_shutdown_notify (struct aws_channel_slot *slot, aws_channel_direction dir, int error_code);

/**
 * Initiates shutdown on slot based on dir. In the read direction the first slot in the channel will be called. In write direction
 * the last slot in the channel will be called.
 */
AWS_IO_API int aws_channel_slot_shutdown_direction (struct aws_channel_slot *slot, aws_channel_direction dir);

/**
 * Fetches the upstream read window. This gives you the information necessary to honor the read window. If you call send_message()
 * and it exceeds this window, the message will be rejected.
 */
AWS_IO_API size_t aws_channel_slot_upstream_read_window (struct aws_channel_slot *slot);

/** The following functions simply call the vtable for the handler */
AWS_IO_API void aws_channel_handler_destroy(struct aws_channel_handler *handler);
AWS_IO_API int aws_channel_handler_process_read_message(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                 struct aws_io_message *message );
AWS_IO_API int aws_channel_handler_process_write_message(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                                          struct aws_io_message *message);
AWS_IO_API int aws_channel_handler_on_window_update(struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size);
AWS_IO_API int aws_channel_handler_on_shutdown_notify(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                           enum aws_channel_direction dir, int error_code);
AWS_IO_API int aws_channel_handler_shutdown_direction(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                           enum aws_channel_direction dir);
AWS_IO_API size_t aws_channel_handler_get_current_window_size(struct aws_channel_handler *handler);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_CHANNEL_H */
