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

struct aws_client_bootstrap;
struct aws_socket;
struct aws_socket_options;
struct aws_socket_endpoint;

/**
 * If TLS is being used, this function is called once the socket has connected, the channel has been initialized, and
 * TLS has been successfully negotiated. A TLS handler has already been added to the channel. If TLS negotiation fails,
 * this function will be called with the corresponding error code.
 *
 * If TLS is not being used, this function is called once the socket has connected and the channel has been initialized.
 *
 * This function is always called within the thread of the event-loop that the new channel is assigned to.
 *
 * This function does NOT mean "success", if error_code is AWS_OP_SUCCESS then everything was successful, otherwise an
 * error condition occurred.
 */
typedef void(aws_client_bootstrap_on_channel_setup_fn)(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data);

/**
 * Once the channel shuts down, this function will be invoked within the thread of the event-loop that the channel is
 * assigned to.
 *
 * Note: this function is only invoked if the channel was successfully setup, e.g.
 * aws_client_bootstrap_on_channel_setup_fn() was invoked without an error code.
 */
typedef void(aws_client_bootstrap_on_channel_shutdown_fn)(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data);

/**
 * If ALPN is being used, this function will be invoked by the channel once an ALPN message is received. The returned
 * channel_handler will be added to, and managed by, the channel.
 */
typedef struct aws_channel_handler *(aws_channel_on_protocol_negotiated_fn)(
    struct aws_channel_slot *new_slot,
    struct aws_byte_buf *protocol,
    void *user_data);

struct aws_event_loop_group;

/**
 * aws_client_bootstrap handles creation and setup of channels that communicate via socket with a specific endpoint.
 */
struct aws_client_bootstrap {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *event_loop_group;
    aws_channel_on_protocol_negotiated_fn *on_protocol_negotiated;
};

struct aws_server_bootstrap;

/**
 * If TLS is being used, this function is called once the socket has received an incoming connection, the channel has
 * been initialized, and TLS has been successfully negotiated. A TLS handler has already been added to the channel. If
 * TLS negotiation fails, this function will be called with the corresponding error code.
 *
 * If TLS is not being used, this function is called once the socket has received an incoming connection and the channel
 * has been initialized.
 *
 * This function is always called within the thread of the event-loop that the new channel is assigned to upon success.
 *
 * On failure, the channel might not be assigned to an event loop yet, and will thus be invoked on the listener's
 * event-loop thread.
 *
 * This function does NOT mean "success", if error_code is AWS_OP_SUCCESS then everything was successful, otherwise an
 * error condition occurred.
 *
 * If an error occurred, you do not need to shutdown the channel. The `aws_channel_client_shutdown_callback` will be
 * invoked once the channel has finished shutting down.
 */
typedef void(aws_server_bootstrap_on_accept_channel_setup_fn)(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data);

/**
 * Once the channel shuts down, this function will be invoked within the thread of
 * the event-loop that the channel is assigned to.
 *
 * Note: this function is only invoked if the channel was successfully setup,
 * e.g. aws_server_bootstrap_on_accept_channel_setup_fn() was invoked without an error code.
 */
typedef void(aws_server_bootsrap_on_accept_channel_shutdown_fn)(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data);

/**
 * aws_server_bootstrap manages listening sockets, creating and setting up channels to handle each incoming connection.
 */
struct aws_server_bootstrap {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *event_loop_group;
    aws_channel_on_protocol_negotiated_fn *on_protocol_negotiated;
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initializes the client bootstrap with `allocator` and `el_group`. This object manages client connections and
 * channels.
 */
AWS_IO_API int aws_client_bootstrap_init(
    struct aws_client_bootstrap *bootstrap,
    struct aws_allocator *allocator,
    struct aws_event_loop_group *el_group);

/**
 * Cleans up the bootstrap's resources. Does not clean up any of your channels. You must shutdown your channels before
 * calling this if you don't want a memory leak.
 */
AWS_IO_API void aws_client_bootstrap_clean_up(struct aws_client_bootstrap *bootstrap);

/**
 * Sets up a client socket channel. If you are planning on using tls, use `aws_client_bootstrap_new_tls_socket_channel`
 * instead. The connection is made to `remote_endpoint` using socket options `options`. `setup_callback` will be invoked
 * once the channel is ready for use or if an error is encountered. `shutdown_callback` will be invoked once the channel
 * has shutdown. Immediately after the `shutdown_callback` returns, the channel is cleaned up automatically. All
 * callbacks are invoked in the thread of the event-loop that the new channel is assigned to.
 */
AWS_IO_API int aws_client_bootstrap_new_socket_channel(
    struct aws_client_bootstrap *bootstrap,
    const struct aws_socket_endpoint *remote_endpoint,
    const struct aws_socket_options *options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data);

/**
 * Initializes the server bootstrap with `allocator` and `el_group`. This object manages listeners, server connections,
 * and channels.
 */
AWS_IO_API int aws_server_bootstrap_init(
    struct aws_server_bootstrap *bootstrap,
    struct aws_allocator *allocator,
    struct aws_event_loop_group *el_group);

/**
 * Cleans up the bootstrap's resources. Does not clean up any of your channels. You must shutdown your channels before
 * calling this if you don't want a memory leak.
 */
AWS_IO_API void aws_server_bootstrap_clean_up(struct aws_server_bootstrap *bootstrap);

/**
 * Sets up a server socket listener. If you are planning on using tls, use
 * `aws_server_bootstrap_new_tls_socket_listener` instead. This creates a socket listener bound to `local_endpoint`
 * using socket options `options`. `incoming_callback` will be invoked once an incoming channel is ready for use or if
 * an error is encountered. `shutdown_callback` will be invoked once the channel has shutdown. Immediately after the
 * `shutdown_callback` returns, the channel is cleaned up automatically. All callbacks are invoked the thread of
 * the event-loop that the listening socket is assigned to
 *
 * Upon shutdown of your application, you'll want to call `aws_server_bootstrap_destroy_socket_listener` with the return
 * value from this function.
 */
AWS_IO_API struct aws_socket *aws_server_bootstrap_new_socket_listener(
    struct aws_server_bootstrap *bootstrap,
    const struct aws_socket_endpoint *local_endpoint,
    const struct aws_socket_options *options,
    aws_server_bootstrap_on_accept_channel_setup_fn *incoming_callback,
    aws_server_bootsrap_on_accept_channel_shutdown_fn *shutdown_callback,
    void *user_data);

/**
 * Shuts down 'listener' and cleans up any resources associated with it. Any incoming channels on `listener` will still
 * be active.
 *
 * Note: this function should be called by either a user thread (like the main entry point, or from the event-loop the
 * listener is assigned to. Otherwise a deadlock is possible. If you call this function from outside the assigned
 * event-loop, this function will block waiting on the assigned event-loop runs the close sequence in its thread.
 */
AWS_IO_API int aws_server_bootstrap_destroy_socket_listener(
    struct aws_server_bootstrap *bootstrap,
    struct aws_socket *listener);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_CHANNEL_BOOTSTRAP_H */
