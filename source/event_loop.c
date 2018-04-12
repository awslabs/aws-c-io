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

static void cache_element_removed(struct aws_common_hash_element element) {
    struct aws_event_loop_cache_object *object = (struct aws_event_loop_cache_object *)element.value;
    if(object->on_cache_eviction) {
        object->on_cache_eviction(object);
    }
}

struct aws_event_loop *aws_event_loop_new(struct aws_allocator *alloc) {
    struct aws_event_loop *new_loop = aws_event_loop_new_impl(alloc);

    if(new_loop) {
        new_loop->alloc = alloc;

        if (aws_common_hash_table_init(&new_loop->cache_data, alloc, 20, aws_common_hash_ptr,
                                        aws_common_ptr_eq, cache_element_removed)) {
            aws_event_loop_destroy_impl(new_loop);
            return NULL;
        }

        return new_loop;
    }

    /* assumption here is that aws_event_loop_new_impl set an error code. */
    return NULL;
}

void aws_event_loop_destroy(struct aws_event_loop *event_loop) {
    aws_common_hash_table_clean_up(&event_loop->cache_data);
    aws_event_loop_destroy_impl(event_loop);
}

int aws_event_loop_fetch_cache_data_obj(struct aws_event_loop *event_loop, void *key, struct aws_event_loop_cache_object *cache_obj) {
    struct aws_common_hash_element object = {0};

    if (!aws_common_hash_table_find(&event_loop->cache_data, &key, (void *)&object)) {
        *cache_obj = *(struct aws_event_loop_cache_object *)object.value;
        return AWS_OP_SUCCESS;
    }

    return AWS_OP_ERR;
}

int aws_event_loop_put_cache_data_obj(struct aws_event_loop *event_loop, struct aws_event_loop_cache_object *cache_obj) {
    struct aws_common_hash_element *object = NULL;
    int was_created = 0;

    if (!aws_common_hash_table_create(&event_loop->cache_data, (const void *)&cache_obj->key, &object, &was_created)) {
        object->key = cache_obj->key;
        object->value = cache_obj;
        return AWS_OP_SUCCESS;
    }

    return AWS_OP_ERR;
}
