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
#include <aws/io/logging.h>
#include <aws/io/message_pool.h>

#if _MSC_VER
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#endif

static size_t s_message_pool_key = 0; /* Address of variable serves as key in hash table */

enum {
    KB_16 = 16 * 1024,
};

size_t g_aws_channel_max_fragment_size = KB_16;

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

struct shutdown_task {
    struct aws_channel_task task;
    struct aws_channel *channel;
    int error_code;
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
        struct shutdown_task shutdown_task;
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
    struct aws_message_pool *msg_pool = object->object;
    AWS_LOGF_TRACE(
        AWS_LS_IO_CHANNEL,
        "static: message pool %p has been purged "
        "from the event-loop: likely because of shutdown",
        (void *)msg_pool);
    struct aws_allocator *alloc = msg_pool->alloc;
    aws_message_pool_clean_up(msg_pool);
    aws_mem_release(alloc, msg_pool);
    aws_mem_release(alloc, object);
}

static void s_on_channel_setup_complete(struct aws_task *task, void *arg, enum aws_task_status task_status) {

    (void)task;
    struct channel_setup_args *setup_args = arg;
    struct aws_message_pool *message_pool = NULL;
    struct aws_event_loop_local_object *local_object = NULL;

    AWS_LOGF_DEBUG(AWS_LS_IO_CHANNEL, "id=%p: setup complete, notifying caller.", (void *)setup_args->channel);
    if (task_status == AWS_TASK_STATUS_RUN_READY) {
        struct aws_event_loop_local_object stack_obj;
        AWS_ZERO_STRUCT(stack_obj);
        local_object = &stack_obj;

        if (aws_event_loop_fetch_local_object(setup_args->channel->loop, &s_message_pool_key, local_object)) {

            local_object = aws_mem_calloc(setup_args->alloc, 1, sizeof(struct aws_event_loop_local_object));
            if (!local_object) {
                goto cleanup_setup_args;
            }

            message_pool = aws_mem_acquire(setup_args->alloc, sizeof(struct aws_message_pool));
            if (!message_pool) {
                goto cleanup_local_obj;
            }

            AWS_LOGF_DEBUG(
                AWS_LS_IO_CHANNEL,
                "id=%p: no message pool is currently stored in the event-loop "
                "local storage, adding %p with max message size %llu, "
                "message count 4, with 4 small blocks of 128 bytes.",
                (void *)setup_args->channel,
                (void *)message_pool,
                (unsigned long long)g_aws_channel_max_fragment_size);

            struct aws_message_pool_creation_args creation_args = {
                .application_data_msg_data_size = g_aws_channel_max_fragment_size,
                .application_data_msg_count = 4,
                .small_block_msg_count = 4,
                .small_block_msg_data_size = 128,
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
            message_pool = local_object->object;
            AWS_LOGF_DEBUG(
                AWS_LS_IO_CHANNEL,
                "id=%p: message pool %p found in event-loop local storage: using it.",
                (void *)setup_args->channel,
                (void *)message_pool)
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

    struct aws_channel *channel = aws_mem_calloc(alloc, 1, sizeof(struct aws_channel));
    if (!channel) {
        return NULL;
    }

    AWS_LOGF_DEBUG(AWS_LS_IO_CHANNEL, "id=%p: Beginning creation and setup of new channel.", (void *)channel);
    channel->alloc = alloc;
    channel->loop = event_loop;
    channel->on_shutdown_completed = callbacks->on_shutdown_completed;
    channel->shutdown_user_data = callbacks->shutdown_user_data;

    /* Start refcount at 2:
     * 1 for self-reference, released from aws_channel_destroy()
     * 1 for the setup task, released when task executes */
    aws_atomic_init_int(&channel->refcount, 2);

    struct channel_setup_args *setup_args = aws_mem_calloc(alloc, 1, sizeof(struct channel_setup_args));
    if (!setup_args) {
        aws_mem_release(alloc, channel);
        return NULL;
    }

    channel->channel_state = AWS_CHANNEL_SETTING_UP;
    aws_linked_list_init(&channel->channel_thread_tasks.list);
    aws_linked_list_init(&channel->cross_thread_tasks.list);
    channel->cross_thread_tasks.lock = (struct aws_mutex)AWS_MUTEX_INIT;
    aws_task_init(
        &channel->cross_thread_tasks.scheduling_task,
        s_schedule_cross_thread_tasks,
        channel,
        "schedule_cross_thread_tasks");

    setup_args->alloc = alloc;
    setup_args->channel = channel;
    setup_args->on_setup_completed = callbacks->on_setup_completed;
    setup_args->user_data = callbacks->setup_user_data;

    aws_task_init(&setup_args->task, s_on_channel_setup_complete, setup_args, "on_channel_setup_complete");
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
    AWS_LOGF_DEBUG(AWS_LS_IO_CHANNEL, "id=%p: destroying channel.", (void *)channel);

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

    AWS_ASSERT(channel->channel_state == AWS_CHANNEL_SHUT_DOWN);

    while (current) {
        struct aws_channel_slot *tmp = current->adj_right;
        s_cleanup_slot(current);
        current = tmp;
    }

    aws_mem_release(channel->alloc, channel);
}

void aws_channel_acquire_hold(struct aws_channel *channel) {
    size_t prev_refcount = aws_atomic_fetch_add(&channel->refcount, 1);
    AWS_ASSERT(prev_refcount != 0);
    (void)prev_refcount;
}

void aws_channel_release_hold(struct aws_channel *channel) {
    size_t prev_refcount = aws_atomic_fetch_sub(&channel->refcount, 1);
    AWS_ASSERT(prev_refcount != 0);

    if (prev_refcount == 1) {
        /* Refcount is now 0, finish cleaning up channel memory. */
        if (aws_channel_thread_is_callers_thread(channel)) {
            s_final_channel_deletion_task(NULL, channel, AWS_TASK_STATUS_RUN_READY);
        } else {
            aws_task_init(&channel->deletion_task, s_final_channel_deletion_task, channel, "final_channel_deletion");
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

static int s_channel_shutdown(struct aws_channel *channel, int error_code, bool shutdown_immediately);

static void s_shutdown_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {

    (void)task;

    struct shutdown_task *shutdown_task = arg;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        s_channel_shutdown(shutdown_task->channel, shutdown_task->error_code, shutdown_task->shutdown_immediately);
    }
}

static void s_on_shutdown_completion_task(struct aws_task *task, void *arg, enum aws_task_status status);

static int s_channel_shutdown(struct aws_channel *channel, int error_code, bool shutdown_immediately) {
    if (aws_channel_thread_is_callers_thread(channel)) {
        if (channel->channel_state < AWS_CHANNEL_SHUTTING_DOWN) {
            AWS_LOGF_DEBUG(AWS_LS_IO_CHANNEL, "id=%p: beginning shutdown process", (void *)channel);

            struct aws_channel_slot *slot = channel->first;
            channel->channel_state = AWS_CHANNEL_SHUTTING_DOWN;

            if (slot) {
                AWS_LOGF_TRACE(
                    AWS_LS_IO_CHANNEL,
                    "id=%p: shutting down slot %p (the first one) in the read direction",
                    (void *)channel,
                    (void *)slot);

                return aws_channel_slot_shutdown(slot, AWS_CHANNEL_DIR_READ, error_code, shutdown_immediately);
            }

            channel->channel_state = AWS_CHANNEL_SHUT_DOWN;
            AWS_LOGF_TRACE(AWS_LS_IO_CHANNEL, "id=%p: shutdown completed", (void *)channel);

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
        AWS_LOGF_TRACE(
            AWS_LS_IO_CHANNEL,
            "id=%p: channel shutdown called from outside the "
            "event-loop thread, scheduling task.",
            (void *)channel);

        bool need_to_schedule = true;
        aws_mutex_lock(&channel->cross_thread_tasks.lock);
        if (channel->cross_thread_tasks.shutdown_task.task.task_fn) {
            need_to_schedule = false;
            AWS_LOGF_DEBUG(
                AWS_LS_IO_CHANNEL,
                "id=%p: Channel shutdown is already pending, not scheduling another.",
                (void *)channel);

        } else {
            aws_channel_task_init(
                &channel->cross_thread_tasks.shutdown_task.task,
                s_shutdown_task,
                &channel->cross_thread_tasks.shutdown_task,
                "channel_cross_thread_shutdown");
            channel->cross_thread_tasks.shutdown_task.shutdown_immediately = shutdown_immediately;
            channel->cross_thread_tasks.shutdown_task.channel = channel;
            channel->cross_thread_tasks.shutdown_task.error_code = error_code;
        }

        aws_mutex_unlock(&channel->cross_thread_tasks.lock);

        if (need_to_schedule) {
            aws_channel_schedule_task_now(channel, &channel->cross_thread_tasks.shutdown_task.task);
        }
    }

    return AWS_OP_SUCCESS;
}

int aws_channel_shutdown(struct aws_channel *channel, int error_code) {
    return s_channel_shutdown(channel, error_code, false);
}

struct aws_io_message *aws_channel_acquire_message_from_pool(
    struct aws_channel *channel,
    enum aws_io_message_type message_type,
    size_t size_hint) {

    struct aws_io_message *message = aws_message_pool_acquire(channel->msg_pool, message_type, size_hint);

    if (AWS_LIKELY(message)) {
        message->owning_channel = channel;
        AWS_LOGF_TRACE(
            AWS_LS_IO_CHANNEL,
            "id=%p: acquired message %p of length %llu from pool %p. Requested size was %llu",
            (void *)channel,
            (void *)message,
            (unsigned long long)message->message_data.len,
            (void *)channel->msg_pool,
            (unsigned long long)size_hint);
    }

    return message;
}

struct aws_channel_slot *aws_channel_slot_new(struct aws_channel *channel) {
    struct aws_channel_slot *new_slot = aws_mem_calloc(channel->alloc, 1, sizeof(struct aws_channel_slot));
    if (!new_slot) {
        return NULL;
    }

    AWS_LOGF_TRACE(AWS_LS_IO_CHANNEL, "id=%p: creating new slot %p.", (void *)channel, (void *)new_slot);
    new_slot->alloc = channel->alloc;
    new_slot->adj_right = NULL;
    new_slot->adj_left = NULL;
    new_slot->handler = NULL;
    new_slot->channel = channel;
    new_slot->window_size = 0;
    new_slot->upstream_message_overhead = 0;

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

void aws_channel_task_init(
    struct aws_channel_task *channel_task,
    aws_channel_task_fn *task_fn,
    void *arg,
    const char *type_tag) {
    AWS_ZERO_STRUCT(*channel_task);
    channel_task->task_fn = task_fn;
    channel_task->arg = arg;
    channel_task->type_tag = type_tag;
}

/* Common functionality for scheduling "now" and "future" tasks.
 * For "now" tasks, pass 0 for `run_at_nanos` */
static void s_register_pending_task(
    struct aws_channel *channel,
    struct aws_channel_task *channel_task,
    uint64_t run_at_nanos) {

    /* Reset every property on channel task other than user's fn & arg.*/
    aws_task_init(&channel_task->wrapper_task, s_channel_task_run, channel, channel_task->type_tag);
    channel_task->wrapper_task.timestamp = run_at_nanos;
    aws_linked_list_node_reset(&channel_task->node);

    if (aws_channel_thread_is_callers_thread(channel)) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_CHANNEL,
            "id=%p: scheduling task with wrapper task id %p.",
            (void *)channel,
            (void *)&channel_task->wrapper_task);

        /* If channel is shut down, run task immediately as canceled */
        if (channel->channel_state == AWS_CHANNEL_SHUT_DOWN) {
            AWS_LOGF_DEBUG(
                AWS_LS_IO_CHANNEL,
                "id=%p: Running %s channel task immediately as canceled due to shut down channel",
                (void *)channel,
                channel_task->type_tag);
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

    AWS_LOGF_TRACE(
        AWS_LS_IO_CHANNEL,
        "id=%p: scheduling task with wrapper task id %p from "
        "outside the event-loop thread.",
        (void *)channel,
        (void *)&channel_task->wrapper_task);
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

static void s_update_channel_slot_message_overheads(struct aws_channel *channel) {
    size_t overhead = 0;
    struct aws_channel_slot *slot_iter = channel->first;
    while (slot_iter) {
        slot_iter->upstream_message_overhead = overhead;

        if (slot_iter->handler) {
            overhead += slot_iter->handler->vtable->message_overhead(slot_iter->handler);
        }
        slot_iter = slot_iter->adj_right;
    }
}

int aws_channel_slot_set_handler(struct aws_channel_slot *slot, struct aws_channel_handler *handler) {
    slot->handler = handler;

    s_update_channel_slot_message_overheads(slot->channel);

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

    s_update_channel_slot_message_overheads(slot->channel);
    s_cleanup_slot(slot);
    return AWS_OP_SUCCESS;
}

int aws_channel_slot_replace(struct aws_channel_slot *remove, struct aws_channel_slot *new_slot) {
    new_slot->adj_left = remove->adj_left;

    if (remove->adj_left) {
        remove->adj_left->adj_right = new_slot;
    }

    new_slot->adj_right = remove->adj_right;

    if (remove->adj_right) {
        remove->adj_right->adj_left = new_slot;
    }

    if (remove == remove->channel->first) {
        remove->channel->first = new_slot;
    }

    s_update_channel_slot_message_overheads(remove->channel);
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

    AWS_ASSERT(0);
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
        AWS_ASSERT(slot->adj_right);
        AWS_ASSERT(slot->adj_right->handler);

        if (slot->adj_right->window_size >= message->message_data.len) {
            AWS_LOGF_TRACE(
                AWS_LS_IO_CHANNEL,
                "id=%p: sending read message of size %llu, "
                "from slot %p to slot %p with handler %p.",
                (void *)slot->channel,
                (unsigned long long)message->message_data.len,
                (void *)slot,
                (void *)slot->adj_right,
                (void *)slot->adj_right->handler);
            slot->adj_right->window_size -= message->message_data.len;
            return aws_channel_handler_process_read_message(slot->adj_right->handler, slot->adj_right, message);
        }
        AWS_LOGF_ERROR(
            AWS_LS_IO_CHANNEL,
            "id=%p: sending message of size %llu, "
            "from slot %p to slot %p with handler %p, but this would exceed the channel's "
            "read window, this is always a programming error.",
            (void *)slot->channel,
            (unsigned long long)message->message_data.len,
            (void *)slot,
            (void *)slot->adj_right,
            (void *)slot->adj_right->handler);
        return aws_raise_error(AWS_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW);
    }

    AWS_ASSERT(slot->adj_left);
    AWS_ASSERT(slot->adj_left->handler);
    AWS_LOGF_TRACE(
        AWS_LS_IO_CHANNEL,
        "id=%p: sending write message of size %llu, "
        "from slot %p to slot %p with handler %p.",
        (void *)slot->channel,
        (unsigned long long)message->message_data.len,
        (void *)slot,
        (void *)slot->adj_left,
        (void *)slot->adj_left->handler);
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
            AWS_LOGF_TRACE(
                AWS_LS_IO_CHANNEL,
                "id=%p: sending increment read window of size %llu, "
                "on slot %p and notifying slot %p with handler %p.",
                (void *)slot->channel,
                (unsigned long long)window,
                (void *)slot,
                (void *)slot->adj_left,
                (void *)slot->adj_left->handler);
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
    AWS_ASSERT(slot->handler);
    AWS_LOGF_TRACE(
        AWS_LS_IO_CHANNEL,
        "id=%p: shutting down slot %p, with handler %p "
        "in %s direction with error code %d",
        (void *)slot->channel,
        (void *)slot,
        (void *)slot->handler,
        (dir == AWS_CHANNEL_DIR_READ) ? "read" : "write",
        err_code);
    return aws_channel_handler_shutdown(slot->handler, slot, dir, err_code, free_scarce_resources_immediately);
}

static void s_on_shutdown_completion_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)status;

    struct aws_shutdown_notification_task *shutdown_notify = (struct aws_shutdown_notification_task *)task;
    struct aws_channel *channel = arg;
    AWS_ASSERT(channel->channel_state == AWS_CHANNEL_SHUT_DOWN);

    /* Cancel tasks that have been scheduled with the event loop */
    while (!aws_linked_list_empty(&channel->channel_thread_tasks.list)) {
        struct aws_linked_list_node *node = aws_linked_list_front(&channel->channel_thread_tasks.list);
        struct aws_channel_task *channel_task = AWS_CONTAINER_OF(node, struct aws_channel_task, node);
        AWS_LOGF_DEBUG(
            AWS_LS_IO_CHANNEL,
            "id=%p: during shutdown, canceling task %p",
            (void *)channel,
            (void *)&channel_task->wrapper_task);
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

    AWS_ASSERT(aws_linked_list_empty(&channel->channel_thread_tasks.list));
    AWS_ASSERT(aws_linked_list_empty(&channel->cross_thread_tasks.list));

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

    AWS_LOGF_DEBUG(
        AWS_LS_IO_CHANNEL,
        "id=%p: handler %p shutdown in %s dir completed.",
        (void *)slot->channel,
        (void *)slot->handler,
        (dir == AWS_CHANNEL_DIR_READ) ? "read" : "write");

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
    AWS_ASSERT(slot->adj_right);
    return slot->adj_right->window_size;
}

size_t aws_channel_slot_upstream_message_overhead(struct aws_channel_slot *slot) {
    return slot->upstream_message_overhead;
}

void aws_channel_handler_destroy(struct aws_channel_handler *handler) {
    AWS_ASSERT(handler->vtable && handler->vtable->destroy);
    handler->vtable->destroy(handler);
}

int aws_channel_handler_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    AWS_ASSERT(handler->vtable && handler->vtable->process_read_message);
    return handler->vtable->process_read_message(handler, slot, message);
}

int aws_channel_handler_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    AWS_ASSERT(handler->vtable && handler->vtable->process_write_message);
    return handler->vtable->process_write_message(handler, slot, message);
}

int aws_channel_handler_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {

    AWS_ASSERT(handler->vtable && handler->vtable->increment_read_window);
    return handler->vtable->increment_read_window(handler, slot, size);
}

int aws_channel_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool free_scarce_resources_immediately) {

    AWS_ASSERT(handler->vtable && handler->vtable->shutdown);
    return handler->vtable->shutdown(handler, slot, dir, error_code, free_scarce_resources_immediately);
}

size_t aws_channel_handler_initial_window_size(struct aws_channel_handler *handler) {
    AWS_ASSERT(handler->vtable && handler->vtable->initial_window_size);
    return handler->vtable->initial_window_size(handler);
}
