#ifndef AWS_IO_CHANNEL_H
#define AWS_IO_CHANNEL_H

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

/**
 * The channel is responsible for receiving read notifications from the event loop and queuing data to be written by the event loop.
 * In addition, the channel is the only interface through which a user should interact with the event loop.
 * A channel is assumed to always run in one thread (the thread of the owning event loop).
 * If anything wants to interact with a channel or its components, it must go through the channel's task scheduler
 * which will handle moving the request action to the correct thread. As a result, memory-barriers can be entirely avoided when
 * they aren't explicitly needed.
 * Each channel has one or more channel handlers installed. As a channel processes data from the event loop,
 * it walks the list of channel handlers.
 * After processing each handler, it passes any data ready for writing to the transport layer to the event loop.
 */
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

/**
 * Initializes a channel for usage with an io handle and an event loop.
 */
AWS_IO_API int aws_channel_init(struct aws_channel *channel, struct aws_allocator *alloc,
            struct aws_event_loop *loop, struct aws_socket *socket, aws_channel_on_shutdown on_shutdown,
                                                   void *user_data);
/**
 * Cleans up memory/resources for the channel.
 */
AWS_IO_API void aws_channel_clean_up(struct aws_channel *channel);

/**
 * Sets the readable flag on the channel
 */
AWS_IO_API void aws_channel_set_readable(struct aws_channel *channel, int8_t readable);

/**
 * Returns whether or not the channel can process more input.
 */
AWS_IO_API int8_t aws_channel_is_readable(struct aws_channel *channel);

/**
 * Sets the writable flag on the channel
 */
AWS_IO_API void aws_channel_set_writeable(struct aws_channel *channel, int8_t writeable);

/**
 * Returns whether or not the channel can process output.
 */
AWS_IO_API int8_t aws_channel_is_writeable(struct aws_channel *channel);

/**
 * Appends an implementation of aws_channel_handler to the end of the handler chain. channel will take ownership
 * of cleanup and processing of the handler.
 */
AWS_IO_API int aws_channel_append_handler(struct aws_channel *channel, struct aws_channel_handler *handler);

/**
 * Convenience function for testing if it is safe to mutate channel and handler state directly, or if you should go
 * through the task scheduler to do so.
 */
AWS_IO_API int8_t aws_channel_thread_check(struct aws_channel *channel);

/**
 * To save on cache contention and heap space, each channel is equipped with a message pool.
 * To acquire a message for queuing, or to release a message when it is no longer used
 */
AWS_IO_API struct aws_io_message_val *aws_channel_get_message_from_pool(struct aws_channel *channel,
                                                                    uint16_t message_type, size_t data_len);
AWS_IO_API void aws_channel_release_message_to_pool(struct aws_channel *channel, struct aws_io_message_val *message);

/**
 * Each event loop keeps a cache of objects that the channel and/or any handlers need to cache.
 * Examples may be frame buffer pools, tables etc... These are objects that don't need to be scoped to an individual
 * instance of a handler or channel but do need to be thread safe. In order to do this, each event loop has extra
 * storage for objects that need to be cached.
 *
 * key can be anything. Most likely the address of an object with file scope (static) is the best choice.
 */
AWS_IO_API int aws_channel_get_cache_object(struct aws_channel *channel, size_t key, struct aws_event_loop_cache_object *obj);
AWS_IO_API int aws_channel_put_cache_object(struct aws_channel *channel, struct aws_event_loop_cache_object *obj);

/**
 * Schedules a task to run at some point in the future, run_at is unix epoch in nanoseconds, using the same (MONOTONIC) clock as the event
 * loop.
 */
AWS_IO_API int aws_channel_schedule_task(struct aws_channel *channel, struct aws_task *task, uint64_t run_at);

/**
 * Called by the event loop on a read event. Channel will pass the incoming data to the first handler in its chain, and then walk the chain.
 */
AWS_IO_API int aws_channel_process_input_data_chunk(struct aws_channel *channel, const uint8_t *data, size_t data_len);

/**
 * Called by the event loop on a write event. Channel will walk the chain and then copy its buffers into the data field.
 */
AWS_IO_API int aws_channel_process_output_data_chunks(struct aws_channel *channel, uint8_t *data, size_t data_len, size_t *written);

/**
 * Callbed by the event loop when on a write event, the event loop read more data from the channel than it can actually
 * write to the underlying io handle. In this case, it puts it back at the top of the channel's queue.
 */
AWS_IO_API void aws_channel_output_put_back(struct aws_channel *channel, const uint8_t *data, size_t data_len);

/**
 * Triggers a walking of the input and output chain and then writing as much as possible to the underlying io handle.
 * Does not block.
 */
AWS_IO_API int aws_channel_flush(struct aws_channel *channel);

/**
 * Gets the socket backing the channel
 */
AWS_IO_API struct aws_socket *aws_channel_get_socket(struct aws_channel *channel);

/**
 * Begins the shutdown process for the channel.
 */
AWS_IO_API void aws_channel_process_shutdown(struct aws_channel *channel, int shutdown_reason);

/**
 * Closes all IO for the channel and removes the io handle from the event loop.
 */
AWS_IO_API void aws_channel_close(struct aws_channel *channel);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_CHANNEL */
