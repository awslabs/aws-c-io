#ifndef AWS_IO_MESSAGE_POOL_H
#define AWS_IO_MESSAGE_POOL_H
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
#include <aws/io/io.h>
#include <aws/common/array_list.h>

struct aws_memory_pool {
    struct aws_allocator *alloc;
    struct aws_array_list stack;
    uint16_t ideal_segment_count;
    size_t segment_size;
};

struct aws_message_pool {
    struct aws_allocator *alloc;
    struct aws_memory_pool application_data_pool;
};

struct aws_message_pool_creation_args {
    size_t application_data_msg_data_size;
    uint8_t application_data_msg_count;
};

#ifdef __cplusplus
extern "C" {
#endif

AWS_IO_API int aws_memory_pool_init(struct aws_memory_pool *mempool, struct aws_allocator *alloc,
                            uint16_t ideal_segment_count, size_t segment_size);

AWS_IO_API void aws_memory_pool_clean_up(struct aws_memory_pool *mempool);

AWS_IO_API void *aws_memory_pool_acquire(struct aws_memory_pool *mempool);

AWS_IO_API void aws_memory_pool_release(struct aws_memory_pool *mempool, void *to_release);

/**
 * Initializes message pool using 'msg_pool' as the backing pool, 'args' is copied.
 */
AWS_IO_API int aws_message_pool_init(struct aws_message_pool *msg_pool, struct aws_allocator *alloc,
                                     struct aws_message_pool_creation_args *args);

AWS_IO_API void aws_message_pool_clean_up(struct aws_message_pool *msg_pool);

AWS_IO_API struct aws_io_message *aws_message_pool_acquire ( struct aws_message_pool*,
                                                                   aws_io_message_type message_type, size_t size_hint);

AWS_IO_API void aws_message_pool_release (struct aws_message_pool*, struct aws_io_message *message);



#ifdef __cplusplus
}
#endif

#endif /*AWS_IO_MESSAGE_POOL_H */
