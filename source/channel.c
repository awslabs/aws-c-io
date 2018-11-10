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

#include <aws/common/atomics.h>
#include <aws/common/mutex.h>

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

enum aws_channel_state {
    AWS_CHANNEL_SETTING_UP,
    AWS_CHANNEL_ACTIVE,
    AWS_CHANNEL_SHUTTING_DOWN,
    AWS_CHANNEL_SHUT_DOWN,
};

struct aws_shutdown_notification_task {
    struct aws_task task;
    int error_code;
    struct aws_channel_slot *slot;
    bool shutdown_immediately;
};

struct aws_channel {
    struct aws_allocator *alloc;
    struct aws_event_loop *loop;
    struct aws_channel_slot *first;
    struct aws_message_pool *msg_pool;
    enum aws_channel_state channel_state;
    struct aws_shutdown_notification_task shutdown_notify_task;
    aws_channel_on_shutdown_completed_fn *on_shutdown_completed;
    void *shutdown_user_data;
    struct aws_atomic_var refcount;
    struct aws_task deletion_task;
    struct {
        struct aws_linked_list list;
    } channel_thread_tasks;
    struct {
        struct aws_mutex lock;
        struct aws_linked_list list;
        struct aws_task scheduling_task;
        bool is_channel_shut_down;
    } cross_thread_tasks;
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
        setup_args->channel->channel_state = AWS_CHANNEL_ACTIVE;
        setup_args->on_setup_completed(setup_args->channel, AWS_OP_SUCCESS, setup_args->user_data);
        aws_channel_release_hold(setup_args->channel);
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
    aws_channel_release_hold(setup_args->channel);
    aws_mem_release(setup_args->alloc, setup_args);
}

static void s_schedule_cross_thread_tasks(struct aws_task *task, void *arg, enum aws_task_status status);

struct aws_channel *aws_channel_new(
    struct aws_allocator *alloc,
    struct aws_event_loop *event_loop,
    struct aws_channel_creation_callbacks *callbacks) {

    struct aws_channel *channel = aws_mem_acquire(alloc, sizeof(struct aws_channel));
    if (!channel) {
        return NULL;
    }
    AWS_ZERO_STRUCT(*channel);

    channel->alloc = alloc;
    channel->loop = event_loop;
    channel->on_shutdown_completed = callbacks->on_shutdown_completed;
    channel->shutdown_user_data = callbacks->shutdown_user_data;

    /* Start refcount at 2:
     * 1 for self-reference, released from aws_channel_destroy()
     * 1 for the setup task, released when task executes */
    aws_atomic_init_int(&channel->refcount, 2);

    struct channel_setup_args *setup_args = aws_mem_acquire(alloc, sizeof(struct channel_setup_args));
    if (!setup_args) {
        aws_mem_release(alloc, channel);
        return NULL;
    }

    channel->channel_state = AWS_CHANNEL_SETTING_UP;
    aws_linked_list_init(&channel->channel_thread_tasks.list);
    aws_linked_list_init(&channel->cross_thread_tasks.list);
    channel->cross_thread_tasks.lock = (struct aws_mutex)AWS_MUTEX_INIT;
    aws_task_init(&channel->cross_thread_tasks.scheduling_task, s_schedule_cross_thread_tasks, channel);

    setup_args->alloc = alloc;
    setup_args->channel = channel;
    setup_args->on_setup_completed = callbacks->on_setup_completed;
    setup_args->user_data = callbacks->setup_user_data;

    aws_task_init(&setup_args->task, s_on_channel_setup_complete, setup_args);
    aws_event_loop_schedule_task_now(event_loop, &setup_args->task);

    return channel;
}

static void s_cleanup_slot(struct aws_channel_slot *slot) {

    if (slot) {
        if (slot->handler) {
            aws_channel_handler_destroy(slot->handler);
        }
        aws_mem_release(slot->alloc, slot);
    }
}

void aws_channel_destroy(struct aws_channel *channel) {
    aws_channel_release_hold(channel);
}

static void s_final_channel_deletion_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct aws_channel *channel = arg;

    struct aws_channel_slot *current = channel->first;

    if (!current || !current->handler) {
        /* Allow channels with no valid slots to skip shutdown process */
        channel->channel_state = AWS_CHANNEL_SHUT_DOWN;
    }

    assert(channel->channel_state == AWS_CHANNEL_SHUT_DOWN);

    while (current) {
        struct aws_channel_slot *tmp = current->adj_right;
        s_cleanup_slot(current);
        current = tmp;
    }

    aws_mem_release(channel->alloc, channel);
}

void aws_channel_acquire_hold(struct aws_channel *channel) {
    size_t prev_refcount = aws_atomic_fetch_add(&channel->refcount, 1);
    assert(prev_refcount != 0);
    (void)prev_refcount;
}

void aws_channel_release_hold(struct aws_channel *channel) {
    size_t prev_refcount = aws_atomic_fetch_sub(&channel->refcount, 1);
    assert(prev_refcount != 0);

    if (prev_refcount == 1) {
        /* Refcount is now 0, finish cleaning up channel memory. */
        if (aws_channel_thread_is_callers_thread(channel)) {
            s_final_channel_deletion_task(NULL, channel, AWS_TASK_STATUS_RUN_READY);
        } else {
            aws_task_init(&channel->deletion_task, s_final_channel_deletion_task, channel);
            aws_event_loop_schedule_task_now(channel->loop, &channel->deletion_task);
        }
    }
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

static void s_on_shutdown_completion_task(struct aws_task *task, void *arg, enum aws_task_status status);

int aws_channel_shutdown(struct aws_channel *channel, int error_code) {
    if (aws_channel_thread_is_callers_thread(channel)) {
        if (channel->channel_state < AWS_CHANNEL_SHUTTING_DOWN) {
            struct aws_channel_slot *slot = channel->first;
            channel->channel_state = AWS_CHANNEL_SHUTTING_DOWN;

            if (slot) {
                return aws_channel_slot_shutdown(slot, AWS_CHANNEL_DIR_READ, error_code, error_code != AWS_OP_SUCCESS);
            }

            channel->channel_state = AWS_CHANNEL_SHUT_DOWN;
            aws_mutex_lock(&channel->cross_thread_tasks.lock);
            channel->cross_thread_tasks.is_channel_shut_down = true;
            aws_mutex_unlock(&channel->cross_thread_tasks.lock);

            if (channel->on_shutdown_completed) {
                channel->shutdown_notify_task.task.fn = s_on_shutdown_completion_task;
                channel->shutdown_notify_task.task.arg = channel;
                channel->shutdown_notify_task.error_code = error_code;
                aws_event_loop_schedule_task_now(channel->loop, &channel->shutdown_notify_task.task);
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

        aws_event_loop_schedule_task_now(channel->loop, &task_args->task);
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

static void s_channel_task_run(struct aws_task *task, void *arg, enum aws_task_status status) {
    struct aws_channel_task *channel_task = AWS_CONTAINER_OF(task, struct aws_channel_task, wrapper_task);
    struct aws_channel *channel = arg;

    /* Any task that runs after shutdown completes is considered canceled */
    if (channel->channel_state == AWS_CHANNEL_SHUT_DOWN) {
        status = AWS_TASK_STATUS_CANCELED;
    }

    aws_linked_list_remove(&channel_task->node);
    channel_task->task_fn(channel_task, channel_task->arg, status);
}

static void s_schedule_cross_thread_tasks(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    struct aws_channel *channel = arg;

    struct aws_linked_list cross_thread_task_list;
    aws_linked_list_init(&cross_thread_task_list);

    /* Grab contents of cross-thread task list while we have the lock */
    aws_mutex_lock(&channel->cross_thread_tasks.lock);
    aws_linked_list_swap_contents(&channel->cross_thread_tasks.list, &cross_thread_task_list);
    aws_mutex_unlock(&channel->cross_thread_tasks.lock);

    /* If the channel has shut down since the cross-thread tasks were scheduled, run tasks immediately as canceled */
    if (channel->channel_state == AWS_CHANNEL_SHUT_DOWN) {
        status = AWS_TASK_STATUS_CANCELED;
    }

    while (!aws_linked_list_empty(&cross_thread_task_list)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&cross_thread_task_list);
        struct aws_channel_task *channel_task = AWS_CONTAINER_OF(node, struct aws_channel_task, node);

        if ((channel_task->wrapper_task.timestamp == 0) || (status == AWS_TASK_STATUS_CANCELED)) {
            /* Run "now" tasks, and canceled tasks, immediately */
            channel_task->task_fn(channel_task, channel_task->arg, status);
        } else {
            /* "Future" tasks are scheduled with the event-loop. */
            aws_linked_list_push_back(&channel->channel_thread_tasks.list, &channel_task->node);
            aws_event_loop_schedule_task_future(
                channel->loop, &channel_task->wrapper_task, channel_task->wrapper_task.timestamp);
        }
    }
}

void aws_channel_task_init(struct aws_channel_task *channel_task, aws_channel_task_fn *task_fn, void *arg) {
    AWS_ZERO_STRUCT(*channel_task);
    channel_task->task_fn = task_fn;
    channel_task->arg = arg;
}

/* Common functionality for scheduling "now" and "future" tasks.
 * For "now" tasks, pass 0 for `run_at_nanos` */
static void s_register_pending_task(
    struct aws_channel *channel,
    struct aws_channel_task *channel_task,
    uint64_t run_at_nanos) {

    /* Reset every property on channel task other than user's fn & arg.*/
    aws_task_init(&channel_task->wrapper_task, s_channel_task_run, channel);
    channel_task->wrapper_task.timestamp = run_at_nanos;
    aws_linked_list_node_reset(&channel_task->node);

    if (aws_channel_thread_is_callers_thread(channel)) {
        /* If channel is shut down, run task immediately as canceled */
        if (channel->channel_state == AWS_CHANNEL_SHUT_DOWN) {
            channel_task->task_fn(channel_task, channel_task->arg, AWS_TASK_STATUS_CANCELED);
            return;
        }

        aws_linked_list_push_back(&channel->channel_thread_tasks.list, &channel_task->node);
        if (run_at_nanos == 0) {
            aws_event_loop_schedule_task_now(channel->loop, &channel_task->wrapper_task);
        } else {
            aws_event_loop_schedule_task_future(
                channel->loop, &channel_task->wrapper_task, channel_task->wrapper_task.timestamp);
        }
        return;
    }

    /* Outside event-loop thread... */
    bool should_cancel_task = false;

    /* Begin Critical Section */
    aws_mutex_lock(&channel->cross_thread_tasks.lock);
    if (channel->cross_thread_tasks.is_channel_shut_down) {
        should_cancel_task = true; /* run task outside critical section to avoid deadlock */
    } else {
        bool list_was_empty = aws_linked_list_empty(&channel->cross_thread_tasks.list);
        aws_linked_list_push_back(&channel->cross_thread_tasks.list, &channel_task->node);

        if (list_was_empty) {
            aws_event_loop_schedule_task_now(channel->loop, &channel->cross_thread_tasks.scheduling_task);
        }
    }
    aws_mutex_unlock(&channel->cross_thread_tasks.lock);
    /* End Critical Section */

    if (should_cancel_task) {
        channel_task->task_fn(channel_task, channel_task->arg, AWS_TASK_STATUS_CANCELED);
    }
}

void aws_channel_schedule_task_now(struct aws_channel *channel, struct aws_channel_task *task) {
    s_register_pending_task(channel, task, 0);
}

void aws_channel_schedule_task_future(
    struct aws_channel *channel,
    struct aws_channel_task *task,
    uint64_t run_at_nanos) {

    s_register_pending_task(channel, task, run_at_nanos);
}

bool aws_channel_thread_is_callers_thread(struct aws_channel *channel) {
    return aws_event_loop_thread_is_callers_thread(channel->loop);
}

int aws_channel_slot_set_handler(struct aws_channel_slot *slot, struct aws_channel_handler *handler) {
    slot->handler = handler;
    return aws_channel_slot_increment_read_window(slot, slot->handler->vtable->initial_window_size(handler));
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
    (void)status;

    struct aws_shutdown_notification_task *shutdown_notify = (struct aws_shutdown_notification_task *)task;
    struct aws_channel *channel = arg;
    assert(channel->channel_state == AWS_CHANNEL_SHUT_DOWN);

    /* Cancel tasks that have been scheduled with the event loop */
    while (!aws_linked_list_empty(&channel->channel_thread_tasks.list)) {
        struct aws_linked_list_node *node = aws_linked_list_front(&channel->channel_thread_tasks.list);
        struct aws_channel_task *channel_task = AWS_CONTAINER_OF(node, struct aws_channel_task, node);

        /* The task will remove itself from the list when it's canceled */
        aws_event_loop_cancel_task(channel->loop, &channel_task->wrapper_task);
    }

    /* Cancel off-thread tasks, which haven't made it to the event-loop thread yet */
    aws_mutex_lock(&channel->cross_thread_tasks.lock);
    bool cancel_cross_thread_tasks = !aws_linked_list_empty(&channel->cross_thread_tasks.list);
    aws_mutex_unlock(&channel->cross_thread_tasks.lock);

    if (cancel_cross_thread_tasks) {
        aws_event_loop_cancel_task(channel->loop, &channel->cross_thread_tasks.scheduling_task);
    }

    assert(aws_linked_list_empty(&channel->channel_thread_tasks.list));
    assert(aws_linked_list_empty(&channel->cross_thread_tasks.list));

    channel->on_shutdown_completed(channel, shutdown_notify->error_code, channel->shutdown_user_data);
}

static void s_run_shutdown_write_direction(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)arg;
    (void)status;

    struct aws_shutdown_notification_task *shutdown_notify = (struct aws_shutdown_notification_task *)task;
    task->fn = NULL;
    task->arg = NULL;
    struct aws_channel_slot *slot = shutdown_notify->slot;
    aws_channel_handler_shutdown(
        slot->handler, slot, AWS_CHANNEL_DIR_WRITE, shutdown_notify->error_code, shutdown_notify->shutdown_immediately);
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

        aws_event_loop_schedule_task_now(slot->channel->loop, &slot->channel->shutdown_notify_task.task);
        return AWS_OP_SUCCESS;
    }

    if (slot->adj_left && slot->adj_left->handler) {
        return aws_channel_handler_shutdown(
            slot->adj_left->handler, slot->adj_left, dir, err_code, free_scarce_resources_immediately);
    }

    if (slot->channel->first == slot) {
        slot->channel->channel_state = AWS_CHANNEL_SHUT_DOWN;
        aws_mutex_lock(&slot->channel->cross_thread_tasks.lock);
        slot->channel->cross_thread_tasks.is_channel_shut_down = true;
        aws_mutex_unlock(&slot->channel->cross_thread_tasks.lock);

        if (slot->channel->on_shutdown_completed) {
            slot->channel->shutdown_notify_task.task.fn = s_on_shutdown_completion_task;
            slot->channel->shutdown_notify_task.task.arg = slot->channel;
            slot->channel->shutdown_notify_task.error_code = err_code;
            aws_event_loop_schedule_task_now(slot->channel->loop, &slot->channel->shutdown_notify_task.task);
        }
    }

    return AWS_OP_SUCCESS;
}

size_t aws_channel_slot_downstream_read_window(struct aws_channel_slot *slot) {
    assert(slot->adj_right);
    return slot->adj_right->window_size;
}

void aws_channel_handler_destroy(struct aws_channel_handler *handler) {
    assert(handler->vtable && handler->vtable->destroy);
    handler->vtable->destroy(handler);
}

int aws_channel_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    assert(handler->vtable && handler->vtable->process_read_message);
    return handler->vtable->process_read_message(handler, slot, message);
}

int aws_channel_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    assert(handler->vtable && handler->vtable->process_write_message);
    return handler->vtable->process_write_message(handler, slot, message);
}

int aws_channel_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {

    assert(handler->vtable && handler->vtable->increment_read_window);
    return handler->vtable->increment_read_window(handler, slot, size);
}

int aws_channel_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    assert(handler->vtable && handler->vtable->shutdown);
    return handler->vtable->shutdown(handler, slot, dir, error_code, free_scarce_resources_immediately);
}

size_t aws_channel_handler_initial_window_size(struct aws_channel_handler *handler) {
    assert(handler->vtable && handler->vtable->initial_window_size);
    return handler->vtable->initial_window_size(handler);
}
