#ifndef AWS_IO_CHANNEL_H
#define AWS_IO_CHANNEL_H

/*
* Copyright 2010-2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
#include <aws/common/linked_list.h>

struct aws_channel_handler;

#define AWS_IO_MESSAGE_TYPE_RAW 1

struct aws_io_message {
    uint8_t take_ownership;
    uint16_t message_type;
    uint8_t *data;
    size_t data_len;
    size_t copy_mark;
};

typedef aws_linked_list_of(struct aws_io_message, aws_io_message_val);
typedef struct aws_linked_list_node aws_message_queue;

struct aws_event_loop;
struct aws_task;
struct aws_channel;
struct aws_memory_pool;
struct aws_event_loop_cache_object;

typedef void(*aws_channel_on_shutdown)(struct aws_io_channel *, void *user_data);

struct aws_channel {
    struct aws_allocator *alloc;
    struct aws_array_list handler_chain;
    struct aws_event_loop *loop_affinity;
    aws_channel_on_shutdown  on_shutdown;
    void *user_data;
    struct aws_socket *socket;
    struct aws_memory_pool *message_pool;
    aws_message_queue input_queue;
    aws_message_queue output_queue;
    int8_t read_ready;
    int8_t write_ready;
    size_t handler_input_pos;
    size_t handler_output_pos;
    int8_t open;
};


#ifdef __cplusplus
extern "C" {
#endif

AWS_IO_API int aws_channel_init(struct aws_channel *channel, struct aws_allocator *alloc,
            struct aws_event_loop *loop, struct aws_socket *socket, aws_channel_on_shutdown on_shutdown,
                                                   void *user_data);

AWS_IO_API void aws_channel_clean_up(struct aws_channel *channel);
AWS_IO_API void aws_channel_set_readable(struct aws_channel *channel, int8_t readable);
AWS_IO_API int8_t aws_channel_is_readable(struct aws_channel *channel);
AWS_IO_API void aws_channel_set_writeable(struct aws_channel *channel, int8_t writeable);
AWS_IO_API int8_t aws_channel_is_writeable(struct aws_channel *channel);
AWS_IO_API int aws_channel_append_handler(struct aws_channel *channel, struct aws_channel_handler *handler);
AWS_IO_API int8_t aws_channel_thread_check(struct aws_channel *channel);
AWS_IO_API struct aws_io_message_val *aws_channel_get_message_from_pool(struct aws_channel *channel,
                                                                    uint16_t message_type, size_t data_len);
AWS_IO_API void aws_channel_release_message_to_pool(struct aws_channel *channel, struct aws_io_message_val *message);
AWS_IO_API int aws_channel_get_cache_object(struct aws_channel *channel, size_t key, struct aws_event_loop_cache_object *obj);
AWS_IO_API int aws_channel_put_cache_object(struct aws_channel *channel, struct aws_event_loop_cache_object *obj);
AWS_IO_API int aws_channel_schedule_task(struct aws_channel *channel, struct aws_task *task, uint64_t run_at);
AWS_IO_API int aws_channel_process_input_data_chunk(struct aws_channel *channel, const uint8_t *data, size_t data_len);
AWS_IO_API int aws_channel_process_output_data_chunks(struct aws_channel *channel, uint8_t *data, size_t data_len, size_t *written);
AWS_IO_API void aws_channel_output_put_back(struct aws_channel *channel, const uint8_t *data, size_t data_len);
AWS_IO_API int aws_channel_flush(struct aws_channel *channel);
AWS_IO_API struct aws_socket *aws_channel_get_socket(struct aws_channel *channel);
AWS_IO_API void aws_channel_process_shutdown(struct aws_channel *channel, int shutdown_reason);
AWS_IO_API void aws_channel_close(struct aws_channel *channel);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_CHANNEL */
