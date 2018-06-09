#ifndef AWS_IO_CHANNEL_BOOTSTRAP_H
#define AWS_IO_CHANNEL_BOOTSTRAP_H

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
#include <aws/io/channel.h>
#include <aws/io/socket.h>
#include <aws/common/hash_table.h>

struct aws_client_bootstrap;
typedef int (*aws_channel_client_setup_callback)(struct aws_client_bootstrap *bootstrap, int error_code, struct aws_channel *, void *user_data);
typedef int (*aws_channel_client_shutdown_callback)(struct aws_client_bootstrap *bootstrap, int error_code, struct aws_channel *, void *user_data);


struct aws_event_loop_group;
struct aws_client_bootstrap {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *event_loop_group;
};

struct aws_server_bootstrap;
typedef int (*aws_channel_server_incoming_channel_callback)(struct aws_server_bootstrap *bootstrap, int error_code, struct aws_channel *channel, void *user_data);
typedef int (*aws_channel_server_channel_shutdown_callback)(struct aws_server_bootstrap *bootstrap, int error_code, struct aws_channel *channel, void *user_data);



struct aws_server_bootstrap {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *event_loop_group;
};

#ifdef __cplusplus
extern "C" {
#endif

AWS_IO_API int aws_client_bootstrap_init (struct aws_client_bootstrap *bootstrap, struct aws_allocator *allocator, struct aws_event_loop_group *el_group);
AWS_IO_API void aws_client_bootstrap_clean_up (struct aws_client_bootstrap *bootstrap);
AWS_IO_API int aws_client_bootstrap_new_socket_channel (struct aws_client_bootstrap *bootstrap,
                                                         struct aws_socket_endpoint *endpoint,
                                                         struct aws_socket_options *options,
                                                         aws_channel_client_setup_callback setup_callback,
                                                         aws_channel_client_shutdown_callback shutdown_callback,
                                                         void *user_data);

AWS_IO_API int aws_server_bootstrap_init (struct aws_server_bootstrap *bootstrap, struct aws_allocator *allocator, struct aws_event_loop_group *el_group);
AWS_IO_API void aws_server_bootstrap_clean_up (struct aws_server_bootstrap *bootstrap);

AWS_IO_API struct aws_socket *aws_server_bootstrap_add_socket_listener (struct aws_server_bootstrap *bootstrap,
                                                         struct aws_socket_endpoint *endpoint,
                                                         struct aws_socket_options *options,
                                                         aws_channel_server_incoming_channel_callback incoming_callback,
                                                         aws_channel_server_channel_shutdown_callback shutdown_callback,
                                                         void *user_data);

AWS_IO_API int aws_server_bootstrap_remove_socket_listener (struct aws_server_bootstrap *bootstrap,
                                                            struct aws_socket *listener);


#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_CHANNEL_BOOTSTRAP_H */
