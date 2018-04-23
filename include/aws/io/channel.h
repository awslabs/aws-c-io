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
};

struct aws_event_loop;
struct aws_event_loop_local_object;
struct aws_channel_slot_ref;
struct aws_task;

struct aws_channel {
    struct aws_allocator *alloc;
    struct aws_event_loop *loop;
    struct aws_channel_slot_ref *first;
};

struct aws_io_message;

typedef void(*aws_channel_on_message_write_completed)(struct aws_channel *, struct aws_io_message *, int err_code, void *ctx);

struct aws_io_message {
    struct aws_allocator *allocator;
    struct aws_byte_buf message_data;
    int message_type_id;
    size_t copy_mark;
    aws_channel_on_message_write_completed on_completion;
    void *ctx;
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
    struct aws_channel_slot_ref *owner;
};

struct aws_channel_slot_control_block {
    struct aws_channel_slot *slot;
    uint16_t ref_count;
    struct aws_mutex count_guard;
};

struct aws_channel_slot_ref {
    struct aws_allocator *alloc;
    struct aws_channel_slot_control_block *control_block;
};

typedef void(*aws_channel_on_shutdown_completed)(struct aws_channel *channel, void *ctx);
#ifdef __cplusplus
extern "C" {
#endif

AWS_IO_API int aws_channel_init(struct aws_channel *channel, struct aws_allocator *alloc, struct aws_event_loop *event_loop);
AWS_IO_API void aws_channel_clean_up(struct aws_channel *channel);
AWS_IO_API int aws_channel_shutdown(struct aws_channel *channel, enum aws_channel_direction dir,
                                    aws_channel_on_shutdown_completed on_completed, void *ctx);
AWS_IO_API struct aws_channel_slot_ref *aws_channel_slot_new(struct aws_channel *channel);
AWS_IO_API int aws_channel_current_clock_time(struct aws_channel *, uint64_t *ticks);
AWS_IO_API int aws_channel_fetch_local_item (struct aws_channel *, const void *key, struct aws_event_loop_local_object *item);
AWS_IO_API int aws_channel_put_local_item (struct aws_channel *, const void *key, const struct aws_event_loop_local_object *item);
AWS_IO_API int aws_channel_remove_local_item ( struct aws_channel *, const void *key, struct aws_event_loop_local_object *removed_item);

AWS_IO_API int aws_channel_schedule_task(struct aws_channel *, struct aws_task *task, uint64_t run_at);
AWS_IO_API bool aws_channel_is_on_callers_thread (struct aws_channel *);


AWS_IO_API int aws_channel_slot_set_handler ( struct aws_channel_slot *, struct aws_channel_handler *handler );
AWS_IO_API int aws_channel_slot_ref_decrement (struct aws_channel_slot_ref *ref);
AWS_IO_API int aws_channel_slot_ref_increment (struct aws_channel_slot_ref *ref);
AWS_IO_API int aws_channel_remove_slot_ref (struct aws_channel *channel, struct aws_channel_slot_ref *ref);
AWS_IO_API int aws_channel_slot_insert_right (struct aws_channel_slot *slot, struct aws_channel_slot_ref *right);
AWS_IO_API int aws_channel_slot_insert_left (struct aws_channel_slot *slot, struct aws_channel_slot_ref *left);
AWS_IO_API int aws_channel_slot_invoke (struct aws_channel_slot *slot, enum aws_channel_direction dir);
AWS_IO_API int aws_channel_slot_send_message (struct aws_channel_slot *slot, struct aws_io_message *message, enum aws_channel_direction dir);
AWS_IO_API int aws_channel_slot_update_window (struct aws_channel_slot *slot, size_t window);
AWS_IO_API int aws_channel_slot_shutdown_notify (struct aws_channel_slot *slot, enum aws_channel_direction dir, int error_code);
AWS_IO_API int aws_channel_slot_shutdown_direction (struct aws_channel_slot *slot, enum aws_channel_direction dir);


#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_CHANNEL_H */
