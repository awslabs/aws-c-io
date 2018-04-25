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

#include <aws/io/message_pool.h>
#include <assert.h>

int aws_memory_pool_init(struct aws_memory_pool *mempool, struct aws_allocator *alloc,
                         uint16_t ideal_segment_count, size_t segment_size) {
    mempool->alloc = alloc;
    mempool->ideal_segment_count = ideal_segment_count;
    mempool->segment_size = segment_size;

    aws_array_list_init_dynamic(&mempool->stack, alloc, ideal_segment_count, sizeof(void *));

    for(uint16_t i = 0; i < ideal_segment_count; ++i) {
        void *memory = aws_mem_acquire(alloc, segment_size);
        if(memory) {
            aws_array_list_push_back(&mempool->stack, &memory);
        }
        else {
            aws_raise_error(AWS_ERROR_OOM);
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

    while(!aws_array_list_back(&mempool->stack, &cur)) {
        aws_array_list_pop_back(&mempool->stack);
        aws_mem_release(mempool->alloc, cur);
    }

    aws_array_list_clean_up(&mempool->stack);
}

void *aws_memory_pool_acquire(struct aws_memory_pool *mempool) {
    void *back = NULL;

    if(!aws_array_list_back(&mempool->stack, &back)) {
        aws_array_list_pop_back(&mempool->stack);
        return back;
    }

    return aws_mem_acquire(mempool->alloc, mempool->segment_size);
}

void aws_memory_pool_release(struct aws_memory_pool *mempool, void *to_release) {
    size_t pool_size =  aws_array_list_length(&mempool->stack);

    if(pool_size >= mempool->ideal_segment_count) {
        aws_mem_release(mempool->alloc, to_release);
        return;
    }

    aws_array_list_push_back(&mempool->stack, &to_release);
}

int aws_message_pool_init(struct aws_message_pool *msg_pool, struct aws_allocator *alloc,
                          struct aws_message_pool_creation_args *args) {
    msg_pool->alloc = alloc;

    size_t msg_data_size = args->window_msg_data_size + sizeof(struct aws_io_message_queue);
    if (aws_memory_pool_init(&msg_pool->window_pool, alloc, args->window_msg_count, msg_data_size)) {
        goto cleanup_window_up_pool;
    }

    msg_data_size = args->shutdown_notify_msg_data_size + sizeof(struct aws_io_message_queue);
    if (aws_memory_pool_init(&msg_pool->shutdown_notify_pool, alloc, args->shutdown_notify_msg_count, msg_data_size)) {
        goto cleanup_shutdown_notify_pool;
    }

    msg_data_size = args->shutdown_msg_data_size + sizeof(struct aws_io_message_queue);
    if (aws_memory_pool_init(&msg_pool->shutdown_pool, alloc, args->shutdown_msg_count, msg_data_size)) {
        goto cleanup_shutdown_pool;
    }

    msg_data_size = args->application_data_msg_data_size + sizeof(struct aws_io_message_queue);

    if (aws_memory_pool_init(&msg_pool->application_data_pool, alloc, args->application_data_msg_count, msg_data_size)) {
        goto cleanup_app_pool;
    }

    return AWS_OP_SUCCESS;

cleanup_app_pool:
    aws_memory_pool_clean_up(&msg_pool->application_data_pool);

cleanup_shutdown_pool:
    aws_memory_pool_clean_up(&msg_pool->shutdown_pool);

cleanup_shutdown_notify_pool:
    aws_memory_pool_clean_up(&msg_pool->shutdown_notify_pool);

cleanup_window_up_pool:
    aws_memory_pool_clean_up(&msg_pool->window_pool);

    return AWS_OP_ERR;
}

void aws_message_pool_clean_up(struct aws_message_pool *msg_pool) {
    aws_memory_pool_clean_up(&msg_pool->application_data_pool);
    aws_memory_pool_clean_up(&msg_pool->shutdown_pool);
    aws_memory_pool_clean_up(&msg_pool->shutdown_notify_pool);
    aws_memory_pool_clean_up(&msg_pool->window_pool);

    *msg_pool = (struct aws_message_pool){0};
}

struct aws_io_message_queue *aws_message_pool_acquire ( struct aws_message_pool* msg_pool, aws_io_message_type message_type,
                                                  size_t data_size) {
    struct aws_io_message_queue *message = NULL;

    switch(message_type) {
        case AWS_IO_MESSAGE_APPLICATION_DATA:
            message = aws_memory_pool_acquire(&msg_pool->application_data_pool);
            break;
        case AWS_IO_MESSAGE_SHUTDOWN_NOTIFY:
            message = aws_memory_pool_acquire(&msg_pool->shutdown_notify_pool);
            break;
        case AWS_IO_MESSAGE_SHUTDOWN:
            message = aws_memory_pool_acquire(&msg_pool->shutdown_pool);
            break;
        case AWS_IO_MESSAGE_WINDOW_UPDATE:
            message = aws_memory_pool_acquire(&msg_pool->window_pool);
            break;
        default:
            assert(0);
            aws_raise_error(AWS_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE);
            return NULL;
    }

    message->value->message_type = message_type;
    message->value->message_tag = 0;
    message->value->ctx = 0;
    message->value->allocator = NULL;
    message->value->copy_mark = 0;
    message->value->on_completion = 0;
    /* the buffer shares the allocation with the message. It's the bit at the end. */
    message->value->message_data.buffer = (uint8_t *)message + sizeof(struct aws_io_message_queue);
    message->value->message_data.len = data_size;

    return message;
}

void aws_message_pool_release (struct aws_message_pool* msg_pool, struct aws_io_message_queue *message) {
    switch(message->value->message_type) {
        case AWS_IO_MESSAGE_APPLICATION_DATA:
            aws_memory_pool_release(&msg_pool->application_data_pool, message);
            break;
        case AWS_IO_MESSAGE_SHUTDOWN_NOTIFY:
            aws_memory_pool_release(&msg_pool->shutdown_notify_pool, message);
            break;
        case AWS_IO_MESSAGE_SHUTDOWN:
            aws_memory_pool_release(&msg_pool->shutdown_pool, message);
            break;
        case AWS_IO_MESSAGE_WINDOW_UPDATE:
            aws_memory_pool_release(&msg_pool->window_pool, message);
            break;
        default:
            assert(0);
            aws_raise_error(AWS_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE);
    }
}
