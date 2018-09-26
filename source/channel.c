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

#include <aws/common/condition_variable.h>

#include <aws/io/event_loop.h>
#include <aws/io/message_pool.h>

#include <assert.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

static size_t s_message_pool_key = 0; /* Address of variable serves as key in hash table */

enum {
    KB_16 = 16 * 1024,
};

struct channel_setup_args {
    struct aws_allocator *alloc;
    struct aws_channel *channel;
    aws_channel_on_setup_completed_fn *on_setup_completed;
    void *user_data;
    struct aws_task task;
};

static void s_on_msg_pool_removed(struct aws_event_loop_local_object *object) {
    struct aws_message_pool *msg_pool = (struct aws_message_pool *)object->object;
    struct aws_allocator *alloc = msg_pool->alloc;
    aws_message_pool_clean_up(msg_pool);
    aws_mem_release(alloc, msg_pool);
    aws_mem_release(alloc, object);
}

static void s_on_channel_setup_complete(struct aws_task *task, void *arg, enum aws_task_status task_status) {

    (void)task;
    struct channel_setup_args *setup_args = (struct channel_setup_args *)arg;
    struct aws_message_pool *message_pool = NULL;
    struct aws_event_loop_local_object *local_object = NULL;

    if (task_status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_event_loop_local_object stack_obj;
        AWS_ZERO_STRUCT(stack_obj);
        local_object = &stack_obj;

        if (aws_event_loop_fetch_local_object(setup_args->channel->loop, &s_message_pool_key, local_object)) {
            local_object = aws_mem_acquire(setup_args->alloc, sizeof(struct aws_event_loop_local_object));

            if (!local_object) {
                goto cleanup_setup_args;
            }

            message_pool = aws_mem_acquire(setup_args->alloc, sizeof(struct aws_message_pool));

            if (!message_pool) {
                goto cleanup_local_obj;
            }
            struct aws_message_pool_creation_args creation_args = {
                .application_data_msg_data_size = KB_16,
                .application_data_msg_count = 4,
            };

            if (aws_message_pool_init(message_pool, setup_args->alloc, &creation_args)) {
                goto cleanup_msg_pool_mem;
            }

            local_object->key = &s_message_pool_key;
            local_object->object = message_pool;
            local_object->on_object_removed = s_on_msg_pool_removed;

            if (aws_event_loop_put_local_object(setup_args->channel->loop, local_object)) {
                goto cleanup_msg_pool;
            }
        } else {
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

cleanup_local_obj:
    aws_mem_release(setup_args->alloc, local_object);

cleanup_setup_args:
    setup_args->on_setup_completed(setup_args->channel, AWS_OP_ERR, setup_args->user_data);
    aws_mem_release(setup_args->alloc, setup_args);
}

int aws_channel_init(
    struct aws_channel *channel,
    struct aws_allocator *alloc,
    struct aws_event_loop *event_loop,
    struct aws_channel_creation_callbacks *callbacks) {
    AWS_ZERO_STRUCT(*channel);

    channel->alloc = alloc;
    channel->loop = event_loop;
    channel->on_shutdown_completed = callbacks->on_shutdown_completed;
    channel->shutdown_user_data = callbacks->shutdown_user_data;

    struct channel_setup_args *setup_args = aws_mem_acquire(alloc, sizeof(struct channel_setup_args));
    if (!setup_args) {
        return AWS_OP_ERR;
    }

    channel->channel_state = AWS_CHANNEL_SETTING_UP;
    setup_args->alloc = alloc;
    setup_args->channel = channel;
    setup_args->on_setup_completed = callbacks->on_setup_completed;
    setup_args->user_data = callbacks->setup_user_data;

    aws_task_init(&setup_args->task, s_on_channel_setup_complete, setup_args);
    aws_event_loop_schedule_task_now(event_loop, &setup_args->task);

    return AWS_OP_SUCCESS;
}

static void s_cleanup_slot(struct aws_channel_slot *slot) {

    if (slot) {
        if (slot->handler) {
            aws_channel_handler_destroy(slot->handler);
        }
        aws_mem_release(slot->alloc, slot);
    }
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
        s_cleanup_slot(current);
        current = tmp;
    }

    AWS_ZERO_STRUCT(*channel);
}

struct channel_shutdown_task_args {
    struct aws_channel *channel;
    struct aws_allocator *alloc;
    int error_code;
    struct aws_task task;
};

static void s_shutdown_task(struct aws_task *task, void *arg, enum aws_task_status status) {

    (void)task;
    struct channel_shutdown_task_args *task_args = (struct channel_shutdown_task_args *)arg;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        aws_channel_shutdown(task_args->channel, task_args->error_code);
    }

    aws_mem_release(task_args->alloc, (void *)task_args);
}

int aws_channel_shutdown(struct aws_channel *channel, int error_code) {
    if (aws_channel_thread_is_callers_thread(channel)) {
        if (channel->channel_state < AWS_CHANNEL_SHUTTING_DOWN) {
            struct aws_channel_slot *slot = channel->first;
            channel->channel_state = AWS_CHANNEL_SHUTTING_DOWN;

            if (slot) {
                return aws_channel_slot_shutdown(slot, AWS_CHANNEL_DIR_READ, error_code, error_code != AWS_OP_SUCCESS);
            }
        }
    } else {
        struct channel_shutdown_task_args *task_args =
            aws_mem_acquire(channel->alloc, sizeof(struct channel_shutdown_task_args));

        if (!task_args) {
            return AWS_OP_ERR;
        }

        task_args->channel = channel;
        task_args->error_code = error_code;
        task_args->alloc = channel->alloc;
        aws_task_init(&task_args->task, s_shutdown_task, task_args);

        aws_channel_schedule_task_now(channel, &task_args->task);
    }

    return AWS_OP_SUCCESS;
}

struct aws_io_message *aws_channel_acquire_message_from_pool(
    struct aws_channel *channel,
    enum aws_io_message_type message_type,
    size_t size_hint) {

    struct aws_io_message *message = aws_message_pool_acquire(channel->msg_pool, message_type, size_hint);
    if (AWS_LIKELY(message)) {
        message->owning_channel = channel;
    }

    return message;
}

void aws_channel_release_message_to_pool(struct aws_channel *channel, struct aws_io_message *message) {
    aws_message_pool_release(channel->msg_pool, message);
}

struct aws_channel_slot *aws_channel_slot_new(struct aws_channel *channel) {
    struct aws_channel_slot *new_slot = aws_mem_acquire(channel->alloc, sizeof(struct aws_channel_slot));

    if (!new_slot) {
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

int aws_channel_current_clock_time(struct aws_channel *channel, uint64_t *time_nanos) {
    return aws_event_loop_current_clock_time(channel->loop, time_nanos);
}

int aws_channel_fetch_local_object(
    struct aws_channel *channel,
    const void *key,
    struct aws_event_loop_local_object *obj) {

    return aws_event_loop_fetch_local_object(channel->loop, (void *)key, obj);
}
int aws_channel_put_local_object(
    struct aws_channel *channel,
    const void *key,
    const struct aws_event_loop_local_object *obj) {

    (void)key;
    return aws_event_loop_put_local_object(channel->loop, (struct aws_event_loop_local_object *)obj);
}

int aws_channel_remove_local_object(
    struct aws_channel *channel,
    const void *key,
    struct aws_event_loop_local_object *removed_obj) {

    return aws_event_loop_remove_local_object(channel->loop, (void *)key, removed_obj);
}

void aws_channel_schedule_task_now(struct aws_channel *channel, struct aws_task *task) {
    aws_event_loop_schedule_task_now(channel->loop, task);
}

void aws_channel_schedule_task_future(struct aws_channel *channel, struct aws_task *task, uint64_t run_at_nanos) {
    aws_event_loop_schedule_task_future(channel->loop, task, run_at_nanos);
}

bool aws_channel_thread_is_callers_thread(struct aws_channel *channel) {
    return aws_event_loop_thread_is_callers_thread(channel->loop);
}

int aws_channel_slot_set_handler(struct aws_channel_slot *slot, struct aws_channel_handler *handler) {
    slot->handler = handler;
    return aws_channel_slot_increment_read_window(slot, slot->handler->vtable.initial_window_size(handler));
}

int aws_channel_slot_remove(struct aws_channel_slot *slot) {
    if (slot->adj_right) {
        slot->adj_right->adj_left = slot->adj_left;

        if (slot == slot->channel->first) {
            slot->channel->first = slot->adj_right;
        }
    }

    if (slot->adj_left) {
        slot->adj_left->adj_right = slot->adj_right;
    }

    if (slot == slot->channel->first) {
        slot->channel->first = NULL;
    }

    s_cleanup_slot(slot);
    return AWS_OP_SUCCESS;
}

int aws_channel_slot_replace(struct aws_channel_slot *remove, struct aws_channel_slot *new) {
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

    s_cleanup_slot(remove);
    return AWS_OP_SUCCESS;
}

int aws_channel_slot_insert_right(struct aws_channel_slot *slot, struct aws_channel_slot *to_add) {
    to_add->adj_right = slot->adj_right;

    if (slot->adj_right) {
        slot->adj_right->adj_left = to_add;
    }

    slot->adj_right = to_add;
    to_add->adj_left = slot;

    return AWS_OP_SUCCESS;
}

int aws_channel_slot_insert_end(struct aws_channel *channel, struct aws_channel_slot *to_add) {
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

int aws_channel_slot_insert_left(struct aws_channel_slot *slot, struct aws_channel_slot *to_add) {
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

int aws_channel_slot_send_message(
    struct aws_channel_slot *slot,
    struct aws_io_message *message,
    enum aws_channel_direction dir) {

    if (dir == AWS_CHANNEL_DIR_READ) {
        assert(slot->adj_right);
        assert(slot->adj_right->handler);

        if (slot->adj_right->window_size >= message->message_data.len) {
            slot->adj_right->window_size -= message->message_data.len;
            return aws_channel_handler_process_read_message(slot->adj_right->handler, slot->adj_right, message);
        }
        return aws_raise_error(AWS_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW);
    }

    assert(slot->adj_left);
    assert(slot->adj_left->handler);
    return aws_channel_handler_process_write_message(slot->adj_left->handler, slot->adj_left, message);
}

int aws_channel_slot_increment_read_window(struct aws_channel_slot *slot, size_t window) {

    if (slot->channel->channel_state < AWS_CHANNEL_SHUTTING_DOWN) {
        size_t temp = slot->window_size + window;
        if (temp < slot->window_size) {
            slot->window_size = SIZE_MAX;
        } else {
            slot->window_size = temp;
        }

        if (slot->adj_left && slot->adj_left->handler) {
            return aws_channel_handler_increment_read_window(slot->adj_left->handler, slot->adj_left, window);
        }
    }

    return AWS_OP_SUCCESS;
}

int aws_channel_slot_shutdown(
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int err_code,
    bool free_scarce_resources_immediately) {
    assert(slot->handler);
    return aws_channel_handler_shutdown(slot->handler, slot, dir, err_code, free_scarce_resources_immediately);
}

static void s_on_shutdown_completion_task(struct aws_task *task, void *arg, enum aws_task_status status) {

    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_shutdown_notification_task *shutdown_notify = (struct aws_shutdown_notification_task *)task;
        struct aws_channel *channel = arg;
        channel->on_shutdown_completed(channel, shutdown_notify->error_code, channel->shutdown_user_data);
    }
}

static void s_run_shutdown_write_direction(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)arg;
    if (status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_shutdown_notification_task *shutdown_notify = (struct aws_shutdown_notification_task *)task;
        task->fn = NULL;
        task->arg = NULL;
        struct aws_channel_slot *slot = shutdown_notify->slot;
        aws_channel_handler_shutdown(
            slot->handler,
            slot,
            AWS_CHANNEL_DIR_WRITE,
            shutdown_notify->error_code,
            shutdown_notify->shutdown_immediately);
    }
}

int aws_channel_slot_on_handler_shutdown_complete(
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int err_code,
    bool free_scarce_resources_immediately) {

    if (slot->channel->channel_state == AWS_CHANNEL_SHUT_DOWN) {
        return AWS_OP_SUCCESS;
    }

    if (dir == AWS_CHANNEL_DIR_READ) {
        if (slot->adj_right && slot->adj_right->handler) {
            return aws_channel_handler_shutdown(
                slot->adj_right->handler, slot->adj_right, dir, err_code, free_scarce_resources_immediately);
        }

        /* break the shutdown sequence so we don't have handlers having to deal with their memory disappearing out from
         * under them during a shutdown process. */
        slot->channel->shutdown_notify_task.slot = slot;
        slot->channel->shutdown_notify_task.shutdown_immediately = free_scarce_resources_immediately;
        slot->channel->shutdown_notify_task.error_code = err_code;
        slot->channel->shutdown_notify_task.task.fn = s_run_shutdown_write_direction;
        slot->channel->shutdown_notify_task.task.arg = NULL;

        aws_channel_schedule_task_now(slot->channel, &slot->channel->shutdown_notify_task.task);
        return AWS_OP_SUCCESS;
    }

    if (slot->adj_left && slot->adj_left->handler) {
        return aws_channel_handler_shutdown(
            slot->adj_left->handler, slot->adj_left, dir, err_code, free_scarce_resources_immediately);
    }

    if (slot->channel->first == slot) {
        slot->channel->channel_state = AWS_CHANNEL_SHUT_DOWN;
        if (slot->channel->on_shutdown_completed) {
            slot->channel->shutdown_notify_task.task.fn = s_on_shutdown_completion_task;
            slot->channel->shutdown_notify_task.task.arg = slot->channel;
            slot->channel->shutdown_notify_task.error_code = err_code;
            aws_channel_schedule_task_now(slot->channel, &slot->channel->shutdown_notify_task.task);
        }
    }

    return AWS_OP_SUCCESS;
}

size_t aws_channel_slot_downstream_read_window(struct aws_channel_slot *slot) {
    assert(slot->adj_right);
    return slot->adj_right->window_size;
}

void aws_channel_handler_destroy(struct aws_channel_handler *handler) {
    assert(handler->vtable.destroy);
    handler->vtable.destroy(handler);
}

int aws_channel_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    assert(handler->vtable.process_read_message);
    return handler->vtable.process_read_message(handler, slot, message);
}

int aws_channel_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    assert(handler->vtable.process_write_message);
    return handler->vtable.process_write_message(handler, slot, message);
}

int aws_channel_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {

    assert(handler->vtable.increment_read_window);
    return handler->vtable.increment_read_window(handler, slot, size);
}

int aws_channel_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    assert(handler->vtable.shutdown);
    return handler->vtable.shutdown(handler, slot, dir, error_code, free_scarce_resources_immediately);
}

size_t aws_channel_handler_initial_window_size(struct aws_channel_handler *handler) {
    assert(handler->vtable.initial_window_size);
    return handler->vtable.initial_window_size(handler);
}
