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

AWS_IO_API struct aws_event_loop *aws_event_loop_new(struct aws_allocator *alloc);
AWS_IO_API struct aws_event_loop *aws_event_loop_new_impl(struct aws_allocator *alloc);
AWS_IO_API int aws_event_loop_fetch_cache_data_obj(struct aws_event_loop *event_loop, void *key,
                                                                      struct aws_event_loop_cache_object *cache_obj);
AWS_IO_API int aws_event_loop_put_cache_data_obj(struct aws_event_loop *event_loop,
                                                                    struct aws_event_loop_cache_object *cache_obj);
AWS_IO_API void aws_event_loop_destroy(struct aws_event_loop *event_loop);
AWS_IO_API void aws_event_loop_destroy_impl(struct aws_event_loop *event_loop);
AWS_IO_API int aws_event_loop_run(struct aws_event_loop *event_loop);
AWS_IO_API int aws_event_loop_stop(struct aws_event_loop *event_loop, int8_t block);
AWS_IO_API void aws_event_loop_trigger_write(struct aws_event_loop *event_loop, struct aws_channel *channel);
AWS_IO_API int aws_event_loop_schedule_task(struct aws_event_loop *event_loop, struct aws_task *task, uint64_t run_at);
AWS_IO_API int aws_event_loop_assign_channel(struct aws_event_loop *event_loop, struct aws_channel *channel);
AWS_IO_API int8_t aws_event_loop_loop_thread_check(struct aws_event_loop *event_loop);
AWS_IO_API int aws_event_loop_register_connect(struct aws_event_loop *event_loop, struct aws_socket *socket,
                                                   uint32_t connect_timeout_ms,
                                                   aws_event_loop_on_connection_success connection_success_handler,
                                                   aws_event_loop_on_connection_error connection_error_handler);

AWS_IO_API int aws_event_loop_register_accept(struct aws_io_event_loop *event_loop, struct aws_io_socket *socket,
                                                              aws_event_loop_on_incoming_connection incoming_connection_handler,
                                                              aws_event_loop_on_connection_error connection_error_handler);
AWS_IO_API int aws_event_loop_shutdown_socket(struct aws_event_loop *event_loop, struct aws_socket *socket);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_EVENT_LOOP_H */
