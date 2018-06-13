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
#include <aws/io/message_pool.h>
#include <aws/common/task_scheduler.h>
#include <aws/common/condition_variable.h>

#include <assert.h>

static size_t MESSAGE_POOL_KEY = 0;
static size_t KB_16 = 16 * 1024;

struct channel_setup_args {
    struct aws_allocator *alloc;
    struct aws_channel *channel;
    aws_channel_on_setup_completed on_setup_completed;
    void *user_data;
};

static void on_msg_pool_removed(struct aws_event_loop_local_object *object) {
    struct aws_message_pool *msg_pool = (struct aws_message_pool *)object->object;
    struct aws_allocator *alloc = msg_pool->alloc;
    aws_message_pool_clean_up(msg_pool);
    aws_mem_release(alloc, msg_pool);
    aws_mem_release(alloc, object);
}

static void on_channel_setup_complete(void *arg, aws_task_status task_status) {
    struct channel_setup_args *setup_args = (struct channel_setup_args *)arg;
    struct aws_message_pool *message_pool = NULL;
    struct aws_event_loop_local_object *local_object = NULL;

    if (task_status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_event_loop_local_object stack_obj = (struct aws_event_loop_local_object){0};
        local_object = &stack_obj;

        if (aws_event_loop_fetch_local_object(setup_args->channel->loop, &MESSAGE_POOL_KEY, local_object) ) {
            local_object = (struct aws_event_loop_local_object *)aws_mem_acquire(setup_args->alloc, sizeof(struct aws_event_loop_local_object));
            message_pool = (struct aws_message_pool *)aws_mem_acquire(setup_args->alloc, sizeof(struct aws_message_pool));

            if (!message_pool) {
                aws_raise_error(AWS_ERROR_OOM);
                goto cleanup_setup_args;
            }
            struct aws_message_pool_creation_args creation_args = {
                    .application_data_msg_data_size = KB_16,
                    .application_data_msg_count = 4
            };

            if (aws_message_pool_init(message_pool, setup_args->alloc, &creation_args)) {
                goto cleanup_msg_pool_mem;
            }

            local_object->key = &MESSAGE_POOL_KEY;
            local_object->object = message_pool;
            local_object->on_object_removed = on_msg_pool_removed;

            if (aws_event_loop_put_local_object(setup_args->channel->loop, local_object)) {
                goto cleanup_msg_pool;
            }
        }
        else {
            message_pool = (struct aws_message_pool *)local_object->object;
        }

        setup_args->channel->msg_pool = message_pool;
        setup_args->on_setup_completed(setup_args->channel, AWS_OP_SUCCESS, setup_args->user_data);
        setup_args->channel->channel_state = AWS_CHANNEL_ACTIVE;
        aws_mem_release(setup_args->alloc, setup_args);
        return;
    }

    goto cleanup_setup_args;

cleanup_msg_pool:
    aws_message_pool_clean_up(message_pool);

cleanup_msg_pool_mem:
    aws_mem_release(setup_args->alloc, message_pool);
    aws_mem_release(setup_args->alloc, local_object);

cleanup_setup_args:
    setup_args->on_setup_completed(setup_args->channel, AWS_OP_ERR, setup_args->user_data);
    aws_mem_release(setup_args->alloc, setup_args);

}

int aws_channel_init(struct aws_channel *channel, struct aws_allocator *alloc,
                     struct aws_event_loop *event_loop, struct aws_channel_creation_callbacks *callbacks) {
    channel->alloc = alloc;
    channel->loop = event_loop;
    channel->first = NULL;
    channel->msg_pool = NULL;
    channel->on_shutdown_completed = callbacks->on_shutdown_completed;
    channel->shutdown_user_data = callbacks->shutdown_user_data;

    struct channel_setup_args *setup_args = (struct channel_setup_args *)aws_mem_acquire(alloc, sizeof(struct channel_setup_args));

    if (!setup_args) {
        return aws_raise_error(AWS_ERROR_OOM);
    }

    channel->channel_state = AWS_CHANNEL_SETTING_UP;
    setup_args->alloc = alloc;
    setup_args->channel = channel;
    setup_args->on_setup_completed = callbacks->on_setup_completed;
    setup_args->user_data = callbacks->setup_user_data;

    struct aws_task task = {
        .fn = on_channel_setup_complete,
        .arg = setup_args,
    };

    uint64_t current_time = 0;
    if (aws_event_loop_current_ticks(event_loop, &current_time)) {
        aws_mem_release(alloc, (void *)setup_args);
        return AWS_OP_ERR;
    }

    if (aws_event_loop_schedule_task(event_loop, &task, current_time)) {
        aws_mem_release(alloc, (void *)setup_args);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

static inline void cleanup_slot(struct aws_channel_slot *slot) {

    if (slot) {
        if (slot->handler) {
            aws_channel_handler_destroy(slot->handler);
        }
        aws_mem_release(slot->alloc, slot);
    }
}

struct channel_shutdown_args {
    struct aws_channel *channel;
    struct aws_condition_variable condition_variable;
    aws_channel_on_shutdown_completed on_shutdown_completed;
    void *shutdown_user_data;
};

static bool shutdown_finished_predicate(void *arg) {
    struct channel_shutdown_args *shutdown_args = (struct channel_shutdown_args *)arg;
    return shutdown_args->channel->channel_state == AWS_CHANNEL_SHUT_DOWN;
}

static void shutdown_finished(struct aws_channel *channel, void *user_data) {
    struct channel_shutdown_args *shutdown_args = (struct channel_shutdown_args *)user_data;

    if (shutdown_args->on_shutdown_completed) {
        shutdown_args->on_shutdown_completed(shutdown_args->channel, shutdown_args->shutdown_user_data);
    }
    shutdown_args->channel->channel_state = AWS_CHANNEL_SHUT_DOWN;

    aws_condition_variable_notify_one(&shutdown_args->condition_variable);
}

void aws_channel_clean_up(struct aws_channel *channel) {

    struct aws_channel_slot *current = channel->first;

    if (!current) {
        channel->channel_state = AWS_CHANNEL_SHUT_DOWN;
        return;
    }

    if (!current->handler) {
        channel->channel_state = AWS_CHANNEL_SHUT_DOWN;
    }

    assert(channel->channel_state == AWS_CHANNEL_SHUT_DOWN);

    while (current) {
        struct aws_channel_slot *tmp = current->adj_right;
        cleanup_slot(current);
        current = tmp;
    }

    *channel = (struct aws_channel){0};
}

struct channel_shutdown_task_args {
    struct aws_channel *channel;
    int error_code;
};

static void shutdown_task(void *arg, aws_task_status status) {
    struct channel_shutdown_task_args *task_args = (struct channel_shutdown_task_args *)arg;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        aws_channel_shutdown(task_args->channel, task_args->error_code);
    }

    aws_mem_release(task_args->channel->alloc, (void *)task_args);
}

int aws_channel_shutdown(struct aws_channel *channel, int error_code) {
    if (aws_channel_thread_is_callers_thread(channel)) {
        if (channel->channel_state < AWS_CHANNEL_SHUTTING_DOWN) {
            struct aws_channel_slot *slot = channel->first;
            channel->channel_state = AWS_CHANNEL_SHUTTING_DOWN;

            if (slot) {
                return aws_channel_slot_shutdown(slot, error_code, error_code != AWS_OP_SUCCESS);
            }
        }
    }
    else {
        struct channel_shutdown_task_args *task_args =
                (struct channel_shutdown_task_args *)aws_mem_acquire(channel->alloc, sizeof(struct channel_shutdown_task_args));

        if (!task_args) {
            return aws_raise_error(AWS_ERROR_OOM);
        }

        task_args->channel = channel;
        task_args->error_code = error_code;

        uint64_t now;
        if (aws_channel_current_clock_time(channel, &now)) {
            aws_mem_release(channel->alloc, (void *)task_args);
        }

        struct aws_task task = {
            .fn = shutdown_task,
            .arg = task_args,
        };

        return aws_channel_schedule_task(channel, &task, now);
    }

    return AWS_OP_SUCCESS;
}

struct aws_io_message *aws_channel_acquire_message_from_pool(struct aws_channel *channel,
                                                             aws_io_message_type message_type, size_t size_hint) {
    return aws_message_pool_acquire(channel->msg_pool, message_type, size_hint);
}

void aws_channel_release_message_to_pool ( struct aws_channel *channel, struct aws_io_message *message) {
    aws_message_pool_release(channel->msg_pool, message);
}

struct aws_channel_slot *aws_channel_slot_new(struct aws_channel *channel) {
    struct aws_channel_slot *new_slot =
            (struct aws_channel_slot *)aws_mem_acquire(channel->alloc, sizeof(struct aws_channel_slot));

    if (!new_slot) {
        aws_raise_error(AWS_ERROR_OOM);
        return NULL;
    }

    new_slot->alloc = channel->alloc;
    new_slot->adj_right = NULL;
    new_slot->adj_left = NULL;
    new_slot->handler = NULL;
    new_slot->channel = channel;
    new_slot->window_size = 0;

    if (!channel->first) {
        channel->first = new_slot;
    }

    return new_slot;
}

int aws_channel_current_clock_time(struct aws_channel *channel, uint64_t *ticks) {
    return aws_event_loop_current_ticks(channel->loop, ticks);
}

int aws_channel_fetch_local_object(struct aws_channel *channel, const void *key,
                                   struct aws_event_loop_local_object *obj) {
    return aws_event_loop_fetch_local_object(channel->loop, (void *) key, obj);
}
int aws_channel_put_local_object(struct aws_channel *channel, const void *key,
                                 const struct aws_event_loop_local_object *obj) {
    return aws_event_loop_put_local_object(channel->loop, (struct aws_event_loop_local_object *) obj);
}

int aws_channel_remove_local_object(struct aws_channel *channel, const void *key,
                                    struct aws_event_loop_local_object *removed_obj) {
    return aws_event_loop_remove_local_object(channel->loop, (void *) key, removed_obj);
}

int aws_channel_schedule_task(struct aws_channel *channel, struct aws_task *task, uint64_t run_at) {
    return aws_event_loop_schedule_task(channel->loop, task, run_at);
}

bool aws_channel_thread_is_callers_thread(struct aws_channel *channel) {
    return aws_event_loop_thread_is_callers_thread(channel->loop);
}

int aws_channel_slot_set_handler ( struct aws_channel_slot *slot, struct aws_channel_handler *handler ) {
    slot->handler = handler;
    return aws_channel_slot_update_window(slot, slot->handler->vtable.get_current_window_size(handler));
}

int aws_channel_slot_remove (struct aws_channel_slot *slot) {
    if (slot->adj_right) {
        slot->adj_right->adj_left = slot->adj_left;

        if (slot == slot->channel->first) {
            slot->channel->first = slot->adj_right;
        }
    }

    if (slot->adj_left) {
        slot->adj_left->adj_right = slot->adj_right;
    }

    cleanup_slot(slot);
    return AWS_OP_SUCCESS;
}

int aws_channel_slot_replace (struct aws_channel_slot *remove, struct aws_channel_slot *new) {
    new->adj_left = remove->adj_left;

    if (remove->adj_left) {
        remove->adj_left->adj_right = new;
    }

    new->adj_right = remove->adj_right;

    if (remove->adj_right) {
        remove->adj_right->adj_left = new;
    }

    if (remove == remove->channel->first) {
        remove->channel->first = new;
    }

    cleanup_slot(remove);
    return AWS_OP_SUCCESS;
}

int aws_channel_slot_insert_right (struct aws_channel_slot *slot, struct aws_channel_slot *to_add) {
    to_add->adj_right = slot->adj_right;

    if (slot->adj_right) {
        slot->adj_right->adj_left = to_add;
    }

    slot->adj_right = to_add;
    to_add->adj_left = slot;

    return AWS_OP_SUCCESS;
}

int aws_channel_slot_insert_end (struct aws_channel *channel, struct aws_channel_slot *to_add) {
    /* It's actually impossible there's not a first if the user went through the aws_channel_slot_new() function.
     * But also check that a user didn't call insert_end if it's the first slot in the channel since first would already
     * have been set. */
    if (AWS_LIKELY(channel->first && channel->first != to_add)) {
        struct aws_channel_slot *cur = channel->first;
        while (cur->adj_right) {
            cur = cur->adj_right;
        }

        return aws_channel_slot_insert_right(cur, to_add);
    }

    assert(0);
    return AWS_OP_ERR;
}

int aws_channel_slot_insert_left (struct aws_channel_slot *slot, struct aws_channel_slot *to_add) {
    to_add->adj_left = slot->adj_left;

    if (slot->adj_left) {
        slot->adj_left->adj_right = to_add;
    }

    slot->adj_left = to_add;
    to_add->adj_right = slot;

    if (slot == slot->channel->first) {
        slot->channel->first = to_add;
    }

    return AWS_OP_SUCCESS;
}

int aws_channel_slot_send_message (struct aws_channel_slot *slot, struct aws_io_message *message, enum aws_channel_direction dir) {
    if (dir == AWS_CHANNEL_DIR_READ) {
        assert(slot->adj_right);
        assert(slot->adj_right->handler);

        if (slot->adj_right->window_size >= message->message_data.len) {
            return aws_channel_handler_process_read_message(slot->adj_right->handler, slot->adj_right, message);
        }
        return aws_raise_error(AWS_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW);
    }
    else {
        assert(slot->adj_left);
        assert(slot->adj_left->handler);
        return aws_channel_handler_process_write_message(slot->adj_left->handler, slot->adj_left, message);
    }
}

int aws_channel_slot_update_window (struct aws_channel_slot *slot, size_t window) {

    if (slot->channel->channel_state < AWS_CHANNEL_SHUTTING_DOWN) {
        slot->window_size += window;
        if (slot->adj_left && slot->adj_left->handler) {
            return aws_channel_handler_on_window_update(slot->adj_left->handler, slot->adj_left, window);
        }
    }

    return AWS_OP_SUCCESS;
}

int aws_channel_slot_shutdown_notify (struct aws_channel_slot *slot, enum aws_channel_direction dir, int error_code) {
    if (slot->channel->channel_state == AWS_CHANNEL_SHUT_DOWN) {
        return AWS_OP_SUCCESS;
    }

    if (dir == AWS_CHANNEL_DIR_READ) {
        if (slot->adj_right && slot->adj_right->handler) {
            return aws_channel_handler_on_shutdown_notify(slot->adj_right->handler, slot->adj_right, dir, error_code);
        }
        else {
            return aws_channel_handler_on_shutdown_notify(slot->handler, slot, AWS_CHANNEL_DIR_WRITE, error_code);
        }

        return AWS_OP_SUCCESS;
    }
    else {
        if (slot->adj_left && slot->adj_left->handler) {
            return aws_channel_handler_on_shutdown_notify(slot->adj_left->handler, slot->adj_left, dir,
                                                          error_code);
        }

        if (slot->channel->first == slot && slot->channel->on_shutdown_completed) {
            slot->channel->channel_state = AWS_CHANNEL_SHUT_DOWN;
            slot->channel->on_shutdown_completed(slot->channel, slot->channel->shutdown_user_data);
        }

        return AWS_OP_SUCCESS;
    }

    return AWS_OP_ERR;
}

size_t aws_channel_slot_downstream_read_window (struct aws_channel_slot *slot) {
    assert(slot->adj_right);
    return slot->adj_right->window_size;
}

int aws_channel_slot_shutdown (struct aws_channel_slot *slot, int err_code, bool abort_immediately) {
    assert(slot->handler);
    return aws_channel_handler_shutdown(slot->handler, slot, err_code, abort_immediately);
}

void aws_channel_handler_destroy(struct aws_channel_handler *handler) {
    assert(handler->vtable.destroy);
    handler->vtable.destroy(handler);
}

int aws_channel_handler_process_read_message(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                                        struct aws_io_message *message) {
    assert(handler->vtable.process_read_message);
    slot->window_size -= message->message_data.len;
    return handler->vtable.process_read_message(handler, slot, message);
}

int aws_channel_handler_process_write_message(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                                         struct aws_io_message *message) {
    assert(handler->vtable.process_write_message);
    return handler->vtable.process_write_message(handler, slot, message);
}

int aws_channel_handler_on_window_update(struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size) {
    assert(handler->vtable.on_window_update);
    return handler->vtable.on_window_update(handler, slot, size);
}

int aws_channel_handler_on_shutdown_notify(struct aws_channel_handler *handler, struct aws_channel_slot *slot,
                                                      enum aws_channel_direction dir, int error_code) {
    assert(handler->vtable.on_shutdown_notify);
    return handler->vtable.on_shutdown_notify(handler, slot, dir, error_code);
}

int aws_channel_handler_shutdown(struct aws_channel_handler *handler, struct aws_channel_slot *slot, int error_code,
                                 bool abort_immediately) {
    assert(handler->vtable.shutdown);
    return handler->vtable.shutdown(handler, slot, error_code, abort_immediately);
}

size_t aws_channel_handler_get_current_window_size(struct aws_channel_handler *handler) {
    assert(handler->vtable.get_current_window_size);
    return handler->vtable.get_current_window_size(handler);
}
