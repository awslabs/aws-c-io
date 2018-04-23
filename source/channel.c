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

#include <aws/io/channel.h>
#include <aws/io/event_loop.h>

int aws_channel_init(struct aws_channel *channel, struct aws_allocator *alloc, struct aws_event_loop *event_loop) {
    channel->alloc = alloc;
    channel->loop = event_loop;
    channel->first = NULL;

    return AWS_OP_SUCCESS;
}

void aws_channel_clean_up(struct aws_channel *channel) {
    struct aws_channel_slot_ref *current_ref = channel->first;
    while (current_ref && current_ref->control_block) {
        current_ref = &current_ref->control_block->slot->adj_right;
        aws_channel_slot_ref_decrement(current_ref);
    }
    *channel = (struct aws_channel){0};
}

int aws_channel_shutdown(struct aws_channel *channel, enum aws_channel_direction dir,
                         aws_channel_on_shutdown_completed on_completed, void *ctx) {
    struct aws_channel_slot_ref *current_ref = channel->first;
    while (current_ref && current_ref->control_block) {
        aws_channel_slot_shutdown_direction(current_ref->control_block->slot, dir);
        current_ref = &current_ref->control_block->slot->adj_right;
    }
}

struct aws_channel_slot_ref *aws_channel_slot_new(struct aws_channel *channel) {
    struct aws_channel_slot *new_slot =
            (struct aws_channel_slot *)aws_mem_acquire(channel->alloc, sizeof(struct aws_channel_slot));

    if (!new_slot) {
        aws_raise_error(AWS_OP_ERR);
        return NULL;
    }

    struct aws_channel_slot_control_block *control_block =
        (struct aws_channel_slot_control_block *)aws_mem_acquire(channel->alloc, sizeof(struct aws_channel_slot_control_block));

    if (!control_block) {
        aws_mem_release(channel->alloc, new_slot);
        aws_raise_error(AWS_OP_ERR);
        return NULL;
    }

    struct aws_channel_slot_ref *new_slot_ref = (struct aws_channel_slot_ref *)aws_mem_acquire(channel->alloc,
                                                                                           sizeof(struct aws_channel_slot_ref));

    if (!new_slot_ref) {
        aws_mem_release(channel->alloc, control_block);
        aws_mem_release(channel->alloc, new_slot);
        aws_raise_error(AWS_OP_ERR);
        return NULL;
    }

    new_slot->alloc = channel->alloc;
    new_slot->adj_right = (struct aws_channel_slot_ref){0};
    new_slot->adj_left = (struct aws_channel_slot_ref){0};
    new_slot->handler = NULL;
    new_slot->channel = channel;
    new_slot->read_queue = (struct aws_linked_list_node){0};
    new_slot->write_queue = (struct aws_linked_list_node){0};
    new_slot->owner = new_slot_ref;
    control_block->slot = new_slot;
    control_block->count_guard = AWS_MUTEX_INIT;
    control_block->ref_count = 1;
    new_slot_ref->control_block = control_block;
    new_slot_ref->alloc = channel->alloc;

    return new_slot_ref;
}

int aws_channel_current_clock_time(struct aws_channel *channel, uint64_t *ticks) {
    return aws_event_loop_current_ticks(channel->loop, ticks);
}

int aws_channel_fetch_local_item (struct aws_channel *channel, const void *key, struct aws_event_loop_local_object *item) {
    return aws_event_loop_fetch_local_item(channel->loop, (void *)key, item);
}
int aws_channel_put_local_item (struct aws_channel *channel, const void *key, const struct aws_event_loop_local_object *item) {
    return aws_event_loop_put_local_item(channel->loop, (struct aws_event_loop_local_object *)item);
}

int aws_channel_remove_local_item ( struct aws_channel *channel, const void *key, struct aws_event_loop_local_object *removed_item) {
    return aws_event_loop_remove_local_item(channel->loop, (void *)key, removed_item);
}

int aws_channel_schedule_task(struct aws_channel *channel, struct aws_task *task, uint64_t run_at) {
    return aws_event_loop_schedule_task(channel->loop, task, run_at);
}

bool aws_channel_is_on_callers_thread (struct aws_channel *channel) {
    return aws_event_loop_is_on_callers_thread(channel->loop);
}

int aws_channel_slot_set_handler ( struct aws_channel_slot *slot, struct aws_channel_handler *handler ) {
    slot->handler = handler;
}

int aws_channel_slot_ref_decrement (struct aws_channel_slot_ref *ref) {
    aws_mutex_lock(&ref->control_block->count_guard);
    ref->control_block->ref_count -= 1;

    if (ref->control_block == 0) {
        /* TODO: call the handler cleanup */
        aws_mem_release(ref->alloc, ref->control_block->slot);
        aws_mutex_unlock(&ref->control_block->count_guard);
        aws_mem_release(ref->alloc, ref->control_block);
        aws_mem_release(ref->alloc, ref);
        *ref = (struct aws_channel_slot_ref){0};
        return AWS_OP_SUCCESS;
    }

    return aws_mutex_unlock(&ref->control_block->count_guard);
}

int aws_channel_slot_ref_increment (struct aws_channel_slot_ref *ref) {
    aws_mutex_lock(&ref->control_block->count_guard);
    ref->control_block->ref_count += 1;
    return aws_mutex_unlock(&ref->control_block->count_guard);
}

int aws_channel_remove_slot_ref (struct aws_channel *channel, struct aws_channel_slot_ref *ref) {

    if (ref->control_block->slot->adj_left.control_block) {
        ref->control_block->slot->adj_left.control_block->slot->adj_right = ref->control_block->slot->adj_right;
        aws_channel_slot_ref_decrement(ref);
    }

    if (ref->control_block->slot->adj_right.control_block) {
        ref->control_block->slot->adj_right.control_block->slot->adj_left = ref->control_block->slot->adj_left;
        aws_channel_slot_ref_decrement(ref);
    }
    return AWS_OP_SUCCESS;
}

int aws_channel_slot_insert_right (struct aws_channel_slot *slot, struct aws_channel_slot_ref *right) {
    if (slot->adj_right.control_block->slot) {
        right->control_block->slot->adj_right = slot->adj_right;
        slot->adj_right.control_block->slot->adj_left = *right;
        aws_channel_slot_ref_increment(right);
    }

    right->control_block->slot->adj_left = *slot->owner;
    aws_channel_slot_ref_increment(right);
    return AWS_OP_SUCCESS;
}

int aws_channel_slot_insert_left (struct aws_channel_slot *slot, struct aws_channel_slot_ref *left) {
    if (slot->adj_left.control_block->slot) {
        left->control_block->slot->adj_left = slot->adj_left;
        slot->adj_left.control_block->slot->adj_right = *left;
        aws_channel_slot_ref_increment(left);
    }

    left->control_block->slot->adj_right = *slot->owner;
    aws_channel_slot_ref_increment(left);
    return AWS_OP_SUCCESS;
}

int aws_channel_slot_invoke (struct aws_channel_slot *slot, enum aws_channel_direction dir) {
    if (slot->handler) {
        /* dequeue all messages in dir and send them to the appropriate handler functions. */
    }
}

int aws_channel_slot_send_message (struct aws_channel_slot *slot, struct aws_io_message *message, enum aws_channel_direction dir) {
    /* queue the message on the appropriate queue (based on dir) */
}

int aws_channel_slot_update_window (struct aws_channel_slot *slot, size_t window) {
    /* construct io message of type update window and call send_message */
}
int aws_channel_slot_shutdown_notify (struct aws_channel_slot *slot, enum aws_channel_direction dir, int error_code) {
    /* construct io message of type shutdown notify and call send_message */
}

int aws_channel_slot_shutdown_direction (struct aws_channel_slot *slot, enum aws_channel_direction dir) {
    /* call shutdown on the handler */
}