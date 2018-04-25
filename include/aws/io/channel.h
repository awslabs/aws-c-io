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
struct aws_channel_slot_ref;
struct aws_task;
struct aws_message_pool;

struct aws_channel_slot_control_block {
    struct aws_channel_slot *slot;
    int16_t ref_count;
    struct aws_mutex count_guard;
};

struct aws_channel_slot_ref {
    struct aws_allocator *alloc;
    struct aws_channel_slot_control_block *control_block;
};

typedef void(*aws_channel_on_setup_completed)(struct aws_channel *channel, int error_code, void *ctx);

struct aws_channel {
    struct aws_allocator *alloc;
    struct aws_event_loop *loop;
    struct aws_channel_slot_ref first;
    struct aws_message_pool *msg_pool;
};

struct aws_channel_handler;

struct aws_channel_slot_ref;

struct aws_channel_slot {
    struct aws_allocator *alloc;
    struct aws_channel *channel;
    struct aws_linked_list_node write_queue;
    struct aws_linked_list_node read_queue;
    struct aws_channel_slot_ref adj_left;
    struct aws_channel_slot_ref adj_right;
    struct aws_channel_handler *handler;
    struct aws_channel_slot_ref owner;
};

typedef void(*aws_channel_on_shutdown_completed)(struct aws_channel *channel, void *ctx);

struct aws_channel_handler_vtable {
    int (*process_read_message) ( struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                     struct aws_io_message_queue *message );
    int (*process_write_message) ( struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                      struct aws_io_message_queue *message );
    int (*on_window_update) (struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size);
    int (*on_shutdown_notify) (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                               enum aws_channel_direction dir, int error_code);
    int (*shutdown_direction) (struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                               enum aws_channel_direction dir);
    size_t (*get_current_window_size) (struct aws_channel_handler *handler);
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

AWS_IO_API int aws_channel_init(struct aws_channel *channel, struct aws_allocator *alloc,
                                struct aws_event_loop *event_loop, aws_channel_on_setup_completed on_completed, void *ctx);
AWS_IO_API void aws_channel_clean_up(struct aws_channel *channel);
AWS_IO_API int aws_channel_shutdown(struct aws_channel *channel, enum aws_channel_direction dir,
                                    aws_channel_on_shutdown_completed on_completed, void *ctx);
AWS_IO_API int aws_channel_slot_new(struct aws_channel *channel, struct aws_channel_slot_ref *ref);
AWS_IO_API int aws_channel_current_clock_time(struct aws_channel *, uint64_t *ticks);
AWS_IO_API int aws_channel_fetch_local_item (struct aws_channel *, const void *key, struct aws_event_loop_local_object *item);
AWS_IO_API int aws_channel_put_local_item (struct aws_channel *, const void *key, const struct aws_event_loop_local_object *item);
AWS_IO_API int aws_channel_remove_local_item ( struct aws_channel *, const void *key, struct aws_event_loop_local_object *removed_item);
AWS_IO_API struct aws_io_message_queue *aws_channel_aquire_message_from_pool(struct aws_channel *,
                                                                             aws_io_message_type message_type, size_t data_size);
AWS_IO_API void aws_channel_release_message_to_pool ( struct aws_channel *, struct aws_io_message_queue *message);

AWS_IO_API int aws_channel_schedule_task(struct aws_channel *, struct aws_task *task, uint64_t run_at);
AWS_IO_API bool aws_channel_is_on_callers_thread (struct aws_channel *);


AWS_IO_API int aws_channel_slot_set_handler ( struct aws_channel_slot *, struct aws_channel_handler *handler );
AWS_IO_API int aws_channel_slot_ref_decrement (struct aws_channel_slot_ref *ref);
AWS_IO_API int aws_channel_slot_ref_increment (struct aws_channel_slot_ref *ref);
AWS_IO_API int aws_channel_remove_slot_ref (struct aws_channel *channel, struct aws_channel_slot_ref *ref);
AWS_IO_API int aws_channel_slot_insert_right (struct aws_channel_slot *slot, struct aws_channel_slot_ref *right);
AWS_IO_API int aws_channel_slot_insert_left (struct aws_channel_slot *slot, struct aws_channel_slot_ref *left);
AWS_IO_API int aws_channel_slot_invoke (struct aws_channel_slot *slot, aws_channel_direction dir);
AWS_IO_API int aws_channel_slot_send_message (struct aws_channel_slot *slot, struct aws_io_message_queue *message, enum aws_channel_direction dir);
AWS_IO_API int aws_channel_slot_update_window (struct aws_channel_slot *slot, size_t window);
AWS_IO_API int aws_channel_slot_shutdown_notify (struct aws_channel_slot *slot, aws_channel_direction dir, int error_code);
AWS_IO_API int aws_channel_slot_shutdown_direction (struct aws_channel_slot *slot, aws_channel_direction dir);

AWS_IO_API void aws_channel_handler_destroy(struct aws_channel_handler *handler);
AWS_IO_API int aws_channel_handler_process_read_message(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                 struct aws_io_message_queue *message );
AWS_IO_API int aws_channel_handler_process_write_message(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                                          struct aws_io_message_queue *message);
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
