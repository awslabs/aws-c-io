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
#include <aws/common/atomics.h>
#include <aws/io/channel.h>
#include <aws/io/host_resolver.h>

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
 * If ALPN is being used this function will be invoked by the channel once an ALPN message is received. The returned
 * channel_handler will be added to, and managed by, the channel.
 */
typedef struct aws_channel_handler *(aws_channel_on_protocol_negotiated_fn)(
    struct aws_channel_slot *new_slot,
    struct aws_byte_buf *protocol,
    void *user_data);

struct aws_tls_connection_options;

struct aws_event_loop_group;

/**
 * aws_client_bootstrap handles creation and setup of channels that communicate via socket with a specific endpoint.
 */
struct aws_client_bootstrap {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *event_loop_group;
    struct aws_host_resolver *host_resolver;
    struct aws_host_resolution_config host_resolver_config;
    aws_channel_on_protocol_negotiated_fn *on_protocol_negotiated;
    struct aws_atomic_var ref_count;
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
typedef void(aws_server_bootstrap_on_accept_channel_shutdown_fn)(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data);

/**
 * Once the server listener socket is finished destroying, all the existing connection is closed, this fuction will be
 * invoked.
 */
typedef void(
    aws_server_bootstrap_on_server_listener_destroy_fn)(struct aws_server_bootstrap *bootstrap, void *user_data);

/**
 * aws_server_bootstrap manages listening sockets, creating and setting up channels to handle each incoming connection.
 */
struct aws_server_bootstrap {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *event_loop_group;
    aws_channel_on_protocol_negotiated_fn *on_protocol_negotiated;
    struct aws_atomic_var ref_count;
};

AWS_EXTERN_C_BEGIN

/**
 * Initializes the client bootstrap with `allocator` and `el_group`. This object manages client connections and
 * channels. host_resolver will be used for resolving host names.
 * If host_resolution_config is NULL, the default will be used, host_resolution_config will be copied.
 */
AWS_IO_API struct aws_client_bootstrap *aws_client_bootstrap_new(
    struct aws_allocator *allocator,
    struct aws_event_loop_group *el_group,
    struct aws_host_resolver *host_resolver,
    struct aws_host_resolution_config *host_resolution_config);

/**
 * Cleans up the bootstrap's resources. Does not clean up any of your channels. You must shutdown your channels before
 * calling this if you don't want a memory leak. Note that this will not necessarily free the memory immediately if
 * there are channels or channel events outstanding.
 */
AWS_IO_API void aws_client_bootstrap_release(struct aws_client_bootstrap *bootstrap);

/**
 * When using TLS, if ALPN is used, this callback will be invoked from the channel. The returned handler will be added
 * to the channel.
 */
AWS_IO_API int aws_client_bootstrap_set_alpn_callback(
    struct aws_client_bootstrap *bootstrap,
    aws_channel_on_protocol_negotiated_fn *on_protocol_negotiated);

/**
 * Sets up a client socket channel. If you are planning on using TLS, use `aws_client_bootstrap_new_tls_socket_channel`
 * instead. The connection is made to `host_name` and `port` using socket options `options`. If AWS_SOCKET_LOCAL is
 * used, host_name should be the name of the socket or named pipe, and port is ignored. If `host_name` is a dns address,
 * it will be resolved prior to attempting a connection. `setup_callback` will be invoked once the channel is ready for
 * use or if an error is encountered. `shutdown_callback` will be invoked once the channel has shutdown. Immediately
 * after the `shutdown_callback` returns, the channel is cleaned up automatically. All callbacks are invoked in the
 * thread of the event-loop that the new channel is assigned to.
 */
AWS_IO_API int aws_client_bootstrap_new_socket_channel(
    struct aws_client_bootstrap *bootstrap,
    const char *host_name,
    uint16_t port,
    const struct aws_socket_options *options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data);

/**
 * Sets up a client TLS socket channel. The connection is made to `host_name` and `port` using socket options `options`
 * and `connection_options` for TLS configuration.
 * If AWS_SOCKET_LOCAL is used, host_name should be the name of the socket or named pipe, and port is ignored.
 * If `host_name` is a dns address, it will be resolved prior to attempting a connection.
 * `setup_callback` will be invoked once the channel is ready for use and TLS has been
 * negotiated or if an error is encountered. `shutdown_callback` will be invoked once the channel has shutdown.
 * Immediately after the `shutdown_callback` returns, the channel is cleaned up automatically. All callbacks are invoked
 * in the thread of the event-loop that the new channel is assigned to.
 *
 * `connection_options` is copied.
 *
 * The socket type in `options` must be AWS_SOCKET_STREAM. DTLS is not supported via. this API.
 */
AWS_IO_API int aws_client_bootstrap_new_tls_socket_channel(
    struct aws_client_bootstrap *bootstrap,
    const char *host_name,
    uint16_t port,
    const struct aws_socket_options *options,
    const struct aws_tls_connection_options *connection_options,
    aws_client_bootstrap_on_channel_setup_fn *setup_callback,
    aws_client_bootstrap_on_channel_shutdown_fn *shutdown_callback,
    void *user_data);

/**
 * Initializes the server bootstrap with `allocator` and `el_group`. This object manages listeners, server connections,
 * and channels.
 */
AWS_IO_API struct aws_server_bootstrap *aws_server_bootstrap_new(
    struct aws_allocator *allocator,
    struct aws_event_loop_group *el_group);

/**
 * Cleans up the bootstrap's resources. Does not clean up any of your channels. You must shutdown your channels before
 * calling this if you don't want a memory leak. Note that the memory will not be freed right away if there are
 * outstanding channels or channel events
 */
AWS_IO_API void aws_server_bootstrap_release(struct aws_server_bootstrap *bootstrap);

/**
 * When using TLS, if ALPN is used, this callback will be invoked from the channel. The returned handler will be added
 * to the channel.
 */
AWS_IO_API int aws_server_bootstrap_set_alpn_callback(
    struct aws_server_bootstrap *bootstrap,
    aws_channel_on_protocol_negotiated_fn *on_protocol_negotiated);

/**
 * Sets up a server socket listener. If you are planning on using TLS, use
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
    aws_server_bootstrap_on_accept_channel_shutdown_fn *shutdown_callback,
    aws_server_bootstrap_on_server_listener_destroy_fn *destroy_callback,
    void *user_data);

/**
 * Sets up a server socket listener which will also negotiate and configure TLS.
 * This creates a socket listener bound to `local_endpoint` using socket options `options`, and TLS options
 * `connection_options`. `incoming_callback` will be invoked once an incoming channel is ready for use and TLS is
 * finished negotiating, or if an error is encountered. `shutdown_callback` will be invoked once the channel has
 * shutdown. Immediately after the `shutdown_callback` returns, the channel is cleaned up automatically. All callbacks
 * are invoked in the thread of the event-loop that listener is assigned to.
 *
 * Upon shutdown of your application, you'll want to call `aws_server_bootstrap_destroy_socket_listener` with the return
 * value from this function.
 *
 * The socket type in `options` must be AWS_SOCKET_STREAM. DTLS is not supported via. this API.
 */
AWS_IO_API struct aws_socket *aws_server_bootstrap_new_tls_socket_listener(
    struct aws_server_bootstrap *bootstrap,
    const struct aws_socket_endpoint *local_endpoint,
    const struct aws_socket_options *options,
    const struct aws_tls_connection_options *connection_options,
    aws_server_bootstrap_on_accept_channel_setup_fn *incoming_callback,
    aws_server_bootstrap_on_accept_channel_shutdown_fn *shutdown_callback,
    aws_server_bootstrap_on_server_listener_destroy_fn *destroy_callback,
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

AWS_EXTERN_C_END

#endif /* AWS_IO_CHANNEL_BOOTSTRAP_H */
