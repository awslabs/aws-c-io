#ifndef AWS_IO_EVENT_LOOP_H
#define AWS_IO_EVENT_LOOP_H

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

#include <aws/io/channel.h>
#include <aws/common/hash_table.h>

/**
 * An event loop drives one or more channels. In addition, event loops handle task queuing and execution,
 * socket connect and accept, and IO read and write.
 * An event loop is tied to one and only one thread. It is responsible for making sure a channel is pumped or polled
 * in that thread. There can be any number of event loops, but memory once assigned to an event loop should never be
 * accessed by more than one thread at once.
 *
 * The default event loop implementations are:
 *
 * Edge Triggered Epoll for Linux
 * KQueue for BSD systems (including Apple)
 * IOCP for windows.
 * Fallback to Select or Poll if one of the above is unavailable.
 * A user can also define their own event loop
 *
 * The event loop calls the channel, and vice versa.
 *
 * The event loop initiates the following interactions with its channels:
 *
 * int aws_channel_process_output_data_chunks(struct aws_channel *channel, uint8_t *data, size_t data_len, size_t *written);
 * void aws_channel_output_put_back(struct aws_channel *channel, uint8_t *data, size_t data_len);
 * int aws_channel_process_input_data_chunk(struct aws_channel *channel, uint8_t *data, size_t data_len);
 *
 * When an io handle becomes writable, the event loop will call aws_channel_process_output_data_chunks() to get available data to write.
 * Any data that can't be written to the socket will be put back via. aws_channel_output_put_back.
 *
 * aws_channel_process_input_data_chunk() will be invoked by the event loop upon a read event on the io handle.
 */
struct aws_event_loop {
    struct aws_allocator *alloc;
    struct aws_common_hash_table cache_data;
};

struct aws_socket;
struct aws_event_loop_cache_object;
struct aws_task;

typedef void(*aws_event_loop_on_cache_eviction)(struct aws_event_loop_cache_object *);

struct aws_event_loop_cache_object {
    const void *key;
    void *object;
    aws_event_loop_on_cache_eviction on_cache_eviction;
};

typedef void(*aws_event_loop_on_connection_success)(struct aws_io_socket *);
typedef void(*aws_event_loop_on_connection_error)(struct aws_io_socket *, int error);
typedef void(*aws_event_loop_on_incoming_connection)(struct aws_io_socket *acceptingSocket, const char *host,
                                                        uint16_t port, sock_handle new_sock);

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Calls aws_event_loop_new_impl() and initializes some additional state (such as the event loop cache).
 * Returns new instance of event_loop. If NULL, call aws_last_error() for more info.
 */
AWS_IO_API struct aws_event_loop *aws_event_loop_new(struct aws_allocator *alloc);

/**
 * Allocates and initializes an event loop. This gives each implementation the opportunity to have a larger object size
 * than the interface structure declaration. This function should not trigger the running of the loop. This function
 * should only be invoked indirectly by aws_event_loop_new(); If you are implementing a custom event loop, you need to
 * provide a symbol for this function.
 */
AWS_IO_API struct aws_event_loop *aws_event_loop_new_impl(struct aws_allocator *alloc);

/**
 * fetches an object from the event loop's cache by key. (Already Implemented for all event loops).
 */
AWS_IO_API int aws_event_loop_fetch_cache_data_obj(struct aws_event_loop *event_loop, void *key,
                                                                      struct aws_event_loop_cache_object *cache_obj);

/**
 * puts an object into the event loop's cache by key. (Already Implemented for all event loops).
 */
AWS_IO_API int aws_event_loop_put_cache_data_obj(struct aws_event_loop *event_loop,
                                                                    struct aws_event_loop_cache_object *cache_obj);

/**
 * Calls aws_event_loop_destroy_impl() and flushes any remaining state. Deallocates the memory pointed to by
 * event_loop.
 */
AWS_IO_API void aws_event_loop_destroy(struct aws_event_loop *event_loop);

/**
 * Cleans up any resources for the event loop and deallocates the memory for the loop itself. Should only be invoked
 * indirectly by aws_event_loop_destroy(); If you are implementing a custom event loop, you need to provide a symbol
 * for this function.
 */
AWS_IO_API void aws_event_loop_destroy_impl(struct aws_event_loop *event_loop);

/**
 * Triggers the running of the event loop. This function must not block. The event loop is not active until this function
 * is invoked.
 */
AWS_IO_API int aws_event_loop_run(struct aws_event_loop *event_loop);

/**
 * Stops the event loop. If block is specified this function must block until the loop has stopped.
 * This function is called from destroy(), so, in that context, when the function returns,
 * the memory for the loop will be freed.
 */
AWS_IO_API int aws_event_loop_stop(struct aws_event_loop *event_loop, int8_t block);

/**
 * Queues a write for the channel for the event loop. The channel invokes this function when it wants to write out-of-band
 * from the normal processing of the chain e.g. when flush() is called.
 */
AWS_IO_API void aws_event_loop_trigger_write(struct aws_event_loop *event_loop, struct aws_channel *channel);

/**
 * The event loop is responsible for queuing and executing scheduled tasks. If this function is invoked outside
 * of the event-loop's thread it is responsible for pushing the task into the correct thread before mutating state.
 * For example on edge triggered epoll, if this function is called outside of the event loop thread,
 * the task is written to a pipe. Epoll will notice the change on the pipe and then the loop will queue the task and execute it.
 */
AWS_IO_API int aws_event_loop_schedule_task(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at);

/**
 * Gives ownership of a channel to event_loop (must be thread-safe).
 * After this call the event_loop is responsible for handling IO events for that channel, and all callbacks for the channel
 * will happen in the event-loop's thread.
 */
AWS_IO_API int aws_event_loop_assign_channel(struct aws_event_loop *event_loop, struct aws_channel *channel);


AWS_IO_API int8_t aws_event_loop_loop_thread_check(struct aws_event_loop *event_loop);

/**
 * Socket has had a non-blocking connect call made. This function registers the monitoring of the socket to event_loop.
 * The event loop must invoke the connection_success_handler when the connection succeeds or
 * connection_error_handler when it fails.
 * Before invoking the callback the event loop should remove the socket from the IO handles it is observing.
 */
AWS_IO_API int aws_event_loop_register_connect(struct aws_event_loop *event_loop, struct aws_socket *socket,
                                                   uint32_t connect_timeout_ms,
                                                   aws_event_loop_on_connection_success connection_success_handler,
                                                   aws_event_loop_on_connection_error connection_error_handler);

/**
 * Registers a socket in a listening state with event_loop. The event loop is responsible for calling accept()
 * when there is an incoming connection. Upon receiving a new connection, the event loop invokes incoming_connection_handler().
 * The listening socket remains in the event_loop in order to handle more incoming connections. On failure for the socket,
 * the event loop invokes connection_error_handler and removes the socket from the io handles it is observing.
 */
AWS_IO_API int aws_event_loop_register_accept(struct aws_event_loop *event_loop, struct aws_isocket *socket,
                                                              aws_event_loop_on_incoming_connection incoming_connection_handler,
                                                              aws_event_loop_on_connection_error connection_error_handler);
/**
 * Shuts down a socket and removes it from the event loop.
 */
AWS_IO_API int aws_event_loop_shutdown_socket(struct aws_event_loop *event_loop, struct aws_socket *socket);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_EVENT_LOOP_H */
