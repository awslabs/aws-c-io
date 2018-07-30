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

#include <assert.h>
#include <aws/common/thread.h>
#include <aws/io/message_pool.h>

int aws_memory_pool_init(
    struct aws_memory_pool *mempool,
    struct aws_allocator *alloc,
    uint16_t ideal_segment_count,
    size_t segment_size) {

    mempool->alloc = alloc;
    mempool->ideal_segment_count = ideal_segment_count;
    mempool->segment_size = segment_size;
    mempool->data_ptr = aws_mem_acquire(alloc, ideal_segment_count * sizeof(void *));

    if (!mempool->data_ptr) {
        return AWS_OP_ERR;
    }

    aws_array_list_init_static(&mempool->stack, mempool->data_ptr, ideal_segment_count, sizeof(void *));

    for (uint16_t i = 0; i < ideal_segment_count; ++i) {
        void *memory = aws_mem_acquire(alloc, segment_size);
        if (memory) {
            aws_array_list_push_back(&mempool->stack, &memory);
        } else {
            goto clean_up;
        }
    }

    return AWS_OP_SUCCESS;

clean_up:
    aws_memory_pool_clean_up(mempool);
    return AWS_OP_ERR;
}

void aws_memory_pool_clean_up(struct aws_memory_pool *mempool) {
    void *cur = NULL;

    while (aws_array_list_length(&mempool->stack) > 0) {
        /* the only way this fails is not possible since I already checked the length. */
        aws_array_list_back(&mempool->stack, &cur);
        aws_array_list_pop_back(&mempool->stack);
        aws_mem_release(mempool->alloc, cur);
    }

    aws_array_list_clean_up(&mempool->stack);
    aws_mem_release(mempool->alloc, mempool->data_ptr);
}

void *aws_memory_pool_acquire(struct aws_memory_pool *mempool) {
    void *back = NULL;
    if (aws_array_list_length(&mempool->stack) > 0) {
        aws_array_list_back(&mempool->stack, &back);
        aws_array_list_pop_back(&mempool->stack);

        return back;
    }

    void *mem = aws_mem_acquire(mempool->alloc, mempool->segment_size);
    return mem;
}

void aws_memory_pool_release(struct aws_memory_pool *mempool, void *to_release) {
    size_t pool_size = aws_array_list_length(&mempool->stack);

    if (pool_size >= mempool->ideal_segment_count) {
        aws_mem_release(mempool->alloc, to_release);
        return;
    }

    aws_array_list_push_back(&mempool->stack, &to_release);
}

int aws_message_pool_init(
    struct aws_message_pool *msg_pool,
    struct aws_allocator *alloc,
    struct aws_message_pool_creation_args *args) {

    msg_pool->alloc = alloc;

    size_t msg_data_size = args->application_data_msg_data_size + sizeof(struct aws_io_message);

    if (aws_memory_pool_init(
            &msg_pool->application_data_pool, alloc, args->application_data_msg_count, msg_data_size)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

void aws_message_pool_clean_up(struct aws_message_pool *msg_pool) {
    aws_memory_pool_clean_up(&msg_pool->application_data_pool);

    *msg_pool = (struct aws_message_pool){0};
}

struct aws_io_message *aws_message_pool_acquire(
    struct aws_message_pool *msg_pool,
    enum aws_io_message_type message_type,
    size_t size_hint) {

    struct aws_io_message *message = NULL;
    size_t max_size = 0;
    switch (message_type) {
        case AWS_IO_MESSAGE_APPLICATION_DATA:
            message = aws_memory_pool_acquire(&msg_pool->application_data_pool);
            max_size = msg_pool->application_data_pool.segment_size - sizeof(struct aws_io_message);
            break;
        default:
            assert(0);
            aws_raise_error(AWS_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE);
            return NULL;
    }

    if (!message) {
        return NULL;
    }

    message->message_type = message_type;
    message->message_tag = 0;
    message->user_data = 0;
    message->allocator = NULL;
    message->copy_mark = 0;
    message->on_completion = 0;
    /* the buffer shares the allocation with the message. It's the bit at the end. */
    message->message_data.buffer = (uint8_t *)message + sizeof(struct aws_io_message);
    message->message_data.len = 0;
    message->message_data.capacity = size_hint <= max_size ? size_hint : max_size;

    return message;
}

void aws_message_pool_release(struct aws_message_pool *msg_pool, struct aws_io_message *message) {

    memset(message->message_data.buffer, 0, message->message_data.len);

    switch (message->message_type) {
        case AWS_IO_MESSAGE_APPLICATION_DATA:
            aws_memory_pool_release(&msg_pool->application_data_pool, message);
            break;
        default:
            assert(0);
            aws_raise_error(AWS_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE);
    }
}
