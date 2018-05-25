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

#include <aws/io/event_loop.h>
#include <assert.h>

static void object_removed(struct aws_hash_element element) {
    struct aws_event_loop_local_object *object = (struct aws_event_loop_local_object *)element.value;
    if(object->on_object_removed) {
        object->on_object_removed(object);
    }
}

int aws_event_loop_base_init(struct aws_event_loop *event_loop, struct aws_allocator *alloc, aws_io_clock clock) {

    event_loop->alloc = alloc;
    event_loop->clock = clock;

    if (aws_hash_table_init(&event_loop->local_data, alloc, 20, aws_hash_ptr,
                                        aws_ptr_eq, object_removed)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

void aws_event_loop_base_clean_up(struct aws_event_loop *event_loop) {
    aws_hash_table_clean_up(&event_loop->local_data);
}

void aws_event_loop_destroy(struct aws_event_loop *event_loop) {
    assert(event_loop->vtable.destroy);

    aws_event_loop_base_clean_up(event_loop);

    event_loop->vtable.destroy(event_loop);
}

int aws_event_loop_fetch_local_object(struct aws_event_loop *event_loop, void *key,
                                      struct aws_event_loop_local_object *obj) {
    struct aws_hash_element *object = NULL;
    if (!aws_hash_table_find(&event_loop->local_data, key, &object) && object) {
        *obj = *(struct aws_event_loop_local_object *)object->value;
        return AWS_OP_SUCCESS;
    }

    return AWS_OP_ERR;
}

int aws_event_loop_put_local_object(struct aws_event_loop *event_loop, struct aws_event_loop_local_object *obj) {
    struct aws_hash_element *object = NULL;
    int was_created = 0;

    if (!aws_hash_table_create(&event_loop->local_data, obj->key, &object, &was_created)) {
        object->key = obj->key;
        object->value = obj;
        return AWS_OP_SUCCESS;
    }

    return AWS_OP_ERR;
}

int aws_event_loop_remove_local_object(struct aws_event_loop *event_loop, void *key,
                                       struct aws_event_loop_local_object *removed_obj) {
    struct aws_hash_element existing_object = {0};
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
    assert(event_loop->vtable.run);
    return event_loop->vtable.run(event_loop);
}

int aws_event_loop_stop(struct aws_event_loop *event_loop, void (*stopped_promise) (struct aws_event_loop *, void *), void *promise_user_data) {
    assert(event_loop->vtable.stop);
    return event_loop->vtable.stop(event_loop, stopped_promise, promise_user_data);
}

int aws_event_loop_schedule_task(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at) {
    assert(event_loop->vtable.schedule_task);
    return event_loop->vtable.schedule_task(event_loop, task, run_at);
}

int aws_event_loop_subscribe_to_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle, int events,
                                                     aws_event_loop_on_event on_event, void *user_data) {
    assert(event_loop->vtable.subscribe_to_io_events);
    return event_loop->vtable.subscribe_to_io_events(event_loop, handle, events, on_event, user_data);
}

int aws_event_loop_unsubscribe_from_io_events(struct aws_event_loop *event_loop, struct aws_io_handle *handle) {
    assert(event_loop->vtable.unsubscribe_from_io_events);
    return event_loop->vtable.unsubscribe_from_io_events(event_loop, handle);
}

bool aws_event_loop_thread_is_callers_thread (struct aws_event_loop *event_loop) {
    assert(event_loop->vtable.is_on_callers_thread);
    return event_loop->vtable.is_on_callers_thread(event_loop);
}

int aws_event_loop_current_ticks ( struct aws_event_loop *event_loop, uint64_t *ticks) {
    assert(event_loop->clock);
    return event_loop->clock(ticks);
}
