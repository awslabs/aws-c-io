/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/event_loop.h>

#include <aws/common/clock.h>
#include <aws/common/system_info.h>
#include <aws/common/thread.h>

int aws_event_loop_group_init(
    struct aws_event_loop_group *el_group,
    struct aws_allocator *alloc,
    aws_io_clock_fn *clock,
    uint16_t el_count,
    aws_new_event_loop_fn *new_loop_fn,
    void *new_loop_user_data) {

    AWS_ASSERT(new_loop_fn);

    el_group->allocator = alloc;
    aws_atomic_init_int(&el_group->current_index, 0);

    if (aws_array_list_init_dynamic(&el_group->event_loops, alloc, el_count, sizeof(struct aws_event_loop *))) {
        return AWS_OP_ERR;
    }

    for (uint16_t i = 0; i < el_count; ++i) {
        struct aws_event_loop *loop = new_loop_fn(alloc, clock, new_loop_user_data);

        if (!loop) {
            goto cleanup_error;
        }

        if (aws_array_list_push_back(&el_group->event_loops, (const void *)&loop)) {
            aws_event_loop_destroy(loop);
            goto cleanup_error;
        }

        if (aws_event_loop_run(loop)) {
            goto cleanup_error;
        }
    }

    return AWS_OP_SUCCESS;

cleanup_error:
    aws_event_loop_group_clean_up(el_group);
    return AWS_OP_ERR;
}

static struct aws_event_loop *default_new_event_loop(
    struct aws_allocator *allocator,
    aws_io_clock_fn *clock,
    void *user_data) {

    (void)user_data;
    return aws_event_loop_new_default(allocator, clock);
}

int aws_event_loop_group_default_init(
    struct aws_event_loop_group *el_group,
    struct aws_allocator *alloc,
    uint16_t max_threads) {
    if (!max_threads) {
        max_threads = (uint16_t)aws_system_info_processor_count();
    }

    return aws_event_loop_group_init(
        el_group, alloc, aws_high_res_clock_get_ticks, max_threads, default_new_event_loop, NULL);
}

void aws_event_loop_group_clean_up(struct aws_event_loop_group *el_group) {
    while (aws_array_list_length(&el_group->event_loops) > 0) {
        struct aws_event_loop *loop = NULL;

        if (!aws_array_list_back(&el_group->event_loops, &loop)) {
            aws_event_loop_destroy(loop);
        }

        aws_array_list_pop_back(&el_group->event_loops);
    }

    aws_array_list_clean_up(&el_group->event_loops);
}

struct aws_event_loop_group_destroy_async_data {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *el_group;
    aws_event_loop_group_cleanup_complete_fn *completion_callback;
    void *user_data;
};

static void s_event_loop_destroy_async_thread_fn(void *thread_data) {
    struct aws_event_loop_group_destroy_async_data *completion_data = thread_data;

    aws_event_loop_group_clean_up(completion_data->el_group);

    aws_event_loop_group_cleanup_complete_fn *completion_callback = completion_data->completion_callback;
    void *user_data = completion_data->user_data;

    aws_mem_release(completion_data->allocator, thread_data);

    completion_callback(user_data);
}

void aws_event_loop_group_clean_up_async(
    struct aws_event_loop_group *el_group,
    aws_event_loop_group_cleanup_complete_fn completion_callback,
    void *user_data) {
    struct aws_thread cleanup_thread;
    AWS_ZERO_STRUCT(cleanup_thread);

    struct aws_event_loop_group_destroy_async_data *data =
        aws_mem_calloc(el_group->allocator, 1, sizeof(struct aws_event_loop_group_destroy_async_data));
    AWS_FATAL_ASSERT(data != NULL);

    data->allocator = el_group->allocator;
    data->el_group = el_group;
    data->completion_callback = completion_callback;
    data->user_data = user_data;

    AWS_FATAL_ASSERT(aws_thread_init(&cleanup_thread, el_group->allocator) == AWS_OP_SUCCESS);

    struct aws_thread_options thread_options;
    AWS_ZERO_STRUCT(thread_options);

    AWS_FATAL_ASSERT(
        aws_thread_launch(&cleanup_thread, s_event_loop_destroy_async_thread_fn, data, &thread_options) ==
        AWS_OP_SUCCESS);

    aws_thread_clean_up(&cleanup_thread);
}

size_t aws_event_loop_group_get_loop_count(struct aws_event_loop_group *el_group) {
    return aws_array_list_length(&el_group->event_loops);
}

struct aws_event_loop *aws_event_loop_group_get_loop_at(struct aws_event_loop_group *el_group, size_t index) {
    struct aws_event_loop *el = NULL;
    aws_array_list_get_at(&el_group->event_loops, &el, index);
    return el;
}

struct aws_event_loop *aws_event_loop_group_get_next_loop(struct aws_event_loop_group *el_group) {
    size_t loop_count = aws_array_list_length(&el_group->event_loops);
    AWS_ASSERT(loop_count > 0);
    if (loop_count == 0) {
        return NULL;
    }

    /* thread safety: atomic CAS to ensure we got the best loop, and that the index is within bounds */
    size_t old_index = 0;
    size_t new_index = 0;
    do {
        old_index = aws_atomic_load_int(&el_group->current_index);
        new_index = (old_index + 1) % loop_count;
    } while (!aws_atomic_compare_exchange_int(&el_group->current_index, &old_index, new_index));

    struct aws_event_loop *loop = NULL;

    /* if the fetch fails, we don't really care since loop will be NULL and error code will already be set. */
    aws_array_list_get_at(&el_group->event_loops, &loop, old_index);
    return loop;
}

static void s_object_removed(void *value) {
    struct aws_event_loop_local_object *object = (struct aws_event_loop_local_object *)value;
    if (object->on_object_removed) {
        object->on_object_removed(object);
    }
}

int aws_event_loop_init_base(struct aws_event_loop *event_loop, struct aws_allocator *alloc, aws_io_clock_fn *clock) {
    AWS_ZERO_STRUCT(*event_loop);

    event_loop->alloc = alloc;
    event_loop->clock = clock;

    if (aws_hash_table_init(&event_loop->local_data, alloc, 20, aws_hash_ptr, aws_ptr_eq, NULL, s_object_removed)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

void aws_event_loop_clean_up_base(struct aws_event_loop *event_loop) {
    aws_hash_table_clean_up(&event_loop->local_data);
}

void aws_event_loop_destroy(struct aws_event_loop *event_loop) {
    if (!event_loop) {
        return;
    }

    AWS_ASSERT(event_loop->vtable && event_loop->vtable->destroy);
    AWS_ASSERT(!aws_event_loop_thread_is_callers_thread(event_loop));

    event_loop->vtable->destroy(event_loop);
}

int aws_event_loop_fetch_local_object(
    struct aws_event_loop *event_loop,
    void *key,
    struct aws_event_loop_local_object *obj) {

    AWS_ASSERT(aws_event_loop_thread_is_callers_thread(event_loop));

    struct aws_hash_element *object = NULL;
    if (!aws_hash_table_find(&event_loop->local_data, key, &object) && object) {
        *obj = *(struct aws_event_loop_local_object *)object->value;
        return AWS_OP_SUCCESS;
    }

    return AWS_OP_ERR;
}

int aws_event_loop_put_local_object(struct aws_event_loop *event_loop, struct aws_event_loop_local_object *obj) {
    AWS_ASSERT(aws_event_loop_thread_is_callers_thread(event_loop));

    struct aws_hash_element *object = NULL;
    int was_created = 0;

    if (!aws_hash_table_create(&event_loop->local_data, obj->key, &object, &was_created)) {
        object->key = obj->key;
        object->value = obj;
        return AWS_OP_SUCCESS;
    }

    return AWS_OP_ERR;
}

int aws_event_loop_remove_local_object(
    struct aws_event_loop *event_loop,
    void *key,
    struct aws_event_loop_local_object *removed_obj) {

    AWS_ASSERT(aws_event_loop_thread_is_callers_thread(event_loop));

    struct aws_hash_element existing_object;
    AWS_ZERO_STRUCT(existing_object);

    int was_present = 0;

    struct aws_hash_element *remove_candidate = removed_obj ? &existing_object : NULL;

    if (!aws_hash_table_remove(&event_loop->local_data, key, remove_candidate, &was_present)) {
        if (remove_candidate && was_present) {
            *removed_obj = *(struct aws_event_loop_local_object *)existing_object.value;
        }

        return AWS_OP_SUCCESS;
    }

    return AWS_OP_ERR;
}

int aws_event_loop_run(struct aws_event_loop *event_loop) {
    AWS_ASSERT(event_loop->vtable && event_loop->vtable->run);
    return event_loop->vtable->run(event_loop);
}

int aws_event_loop_stop(struct aws_event_loop *event_loop) {
    AWS_ASSERT(event_loop->vtable && event_loop->vtable->stop);
    return event_loop->vtable->stop(event_loop);
}

int aws_event_loop_wait_for_stop_completion(struct aws_event_loop *event_loop) {
    AWS_ASSERT(!aws_event_loop_thread_is_callers_thread(event_loop));
    AWS_ASSERT(event_loop->vtable && event_loop->vtable->wait_for_stop_completion);
    return event_loop->vtable->wait_for_stop_completion(event_loop);
}

void aws_event_loop_schedule_task_now(struct aws_event_loop *event_loop, struct aws_task *task) {
    AWS_ASSERT(event_loop->vtable && event_loop->vtable->schedule_task_now);
    AWS_ASSERT(task);
    event_loop->vtable->schedule_task_now(event_loop, task);
}

void aws_event_loop_schedule_task_future(
    struct aws_event_loop *event_loop,
    struct aws_task *task,
    uint64_t run_at_nanos) {

    AWS_ASSERT(event_loop->vtable && event_loop->vtable->schedule_task_future);
    AWS_ASSERT(task);
    event_loop->vtable->schedule_task_future(event_loop, task, run_at_nanos);
}

void aws_event_loop_cancel_task(struct aws_event_loop *event_loop, struct aws_task *task) {
    AWS_ASSERT(event_loop->vtable && event_loop->vtable->cancel_task);
    AWS_ASSERT(aws_event_loop_thread_is_callers_thread(event_loop));
    AWS_ASSERT(task);
    event_loop->vtable->cancel_task(event_loop, task);
}

#if AWS_USE_IO_COMPLETION_PORTS

int aws_event_loop_connect_handle_to_io_completion_port(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle) {

    AWS_ASSERT(event_loop->vtable && event_loop->vtable->connect_to_io_completion_port);
    return event_loop->vtable->connect_to_io_completion_port(event_loop, handle);
}

#else  /* !AWS_USE_IO_COMPLETION_PORTS */

int aws_event_loop_subscribe_to_io_events(
    struct aws_event_loop *event_loop,
    struct aws_io_handle *handle,
    int events,
    aws_event_loop_on_event_fn *on_event,
    void *user_data) {

    AWS_ASSERT(event_loop->vtable && event_loop->vtable->subscribe_to_io_events);
    return event_loop->vtable->subscribe_to_io_events(event_loop, handle, events, on_event, user_data);
}
#endif /* AWS_USE_IO_COMPLETION_PORTS */

int aws_event_loop_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    AWS_ASSERT(aws_event_loop_thread_is_callers_thread(event_loop));
    AWS_ASSERT(event_loop->vtable && event_loop->vtable->unsubscribe_from_io_events);
    return event_loop->vtable->unsubscribe_from_io_events(event_loop, handle);
}

void aws_event_loop_free_io_event_resources(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    AWS_ASSERT(event_loop && event_loop->vtable->free_io_event_resources);
    event_loop->vtable->free_io_event_resources(handle->additional_data);
}

bool aws_event_loop_thread_is_callers_thread(struct aws_event_loop *event_loop) {
    AWS_ASSERT(event_loop->vtable && event_loop->vtable->is_on_callers_thread);
    return event_loop->vtable->is_on_callers_thread(event_loop);
}

int aws_event_loop_current_clock_time(struct aws_event_loop *event_loop, uint64_t *time_nanos) {
    AWS_ASSERT(event_loop->clock);
    return event_loop->clock(time_nanos);
}
