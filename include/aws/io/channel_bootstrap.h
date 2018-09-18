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

struct aws_client_bootstrap;

/**
 * If TLS is being used, this function is called once the socket has connected, the channel has been initialized, and
 * TLS has been successfully negotiated. A TLS handler has already been added to the channel. If TLS negotiation fails,
 * this function will be called with the corresponding error code.
 *
 * If TLS is not being used, this function is called once the socket has connected and the channel has been initialized.
 *
 * This function is always called within an event-loop's thread.
 *
 * This function does NOT mean "success", if error_code is AWS_OP_SUCCESS then everything was successful, otherwise an
 * error condition occurred.
 *
 * If an error occurred, you do not need to shutdown the channel. The `aws_channel_client_shutdown_callback` will be
 * invoked once the channel has finished shutting down.
 */
typedef int (*aws_channel_client_setup_callback)(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data);

/**
 * Once the channel shuts down, this function will be invoked within the event-loop's thread.
 */
typedef int (*aws_channel_client_shutdown_callback)(
    struct aws_client_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data);

/**
 * If ALPN is being used, this function will be invoked by the channel once an ALPN message is received. The returned
 * channel_handler will be added to, and managed by, the channel.
 */
typedef struct aws_channel_handler *(*aws_channel_on_protocol_negotiated)(
    struct aws_channel_slot *new_slot,
    struct aws_byte_buf *protocol,
    void *user_data);

struct aws_tls_connection_options;

struct aws_event_loop_group;



struct aws_client_bootstrap {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *event_loop_group;
    struct aws_tls_ctx *tls_ctx;
    aws_channel_on_protocol_negotiated on_protocol_negotiated;
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
 * This function is always called within an event-loop's thread.
 *
 * This function does NOT mean "success", if error_code is AWS_OP_SUCCESS then everything was successful, otherwise an
 * error condition occurred.
 *
 * If an error occurred, you do not need to shutdown the channel. The `aws_channel_client_shutdown_callback` will be
 * invoked once the channel has finished shutting down.
 */
typedef int (*aws_channel_server_incoming_channel_callback)(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data);

/**
 * Once the channel shuts down, this function will be invoked within the event-loop's thread.
 */
typedef int (*aws_channel_server_channel_shutdown_callback)(
    struct aws_server_bootstrap *bootstrap,
    int error_code,
    struct aws_channel *channel,
    void *user_data);

struct aws_server_bootstrap {
    struct aws_allocator *allocator;
    struct aws_event_loop_group *event_loop_group;
    struct aws_tls_ctx *tls_ctx;
    aws_channel_on_protocol_negotiated on_protocol_negotiated;
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
 * Sets the tls context for use with `aws_client_bootstrap_new_tls_socket_channel`. This function must be called before
 * calling, `aws_client_bootstrap_new_tls_socket_channel`
 */
AWS_IO_API int aws_client_bootstrap_set_tls_ctx(struct aws_client_bootstrap *bootstrap, struct aws_tls_ctx *ctx);

/**
 * When using tls, if ALPN is used, this callback will be invoked from the channel. The returned handler will be added
 * to the channel.
 */
AWS_IO_API int aws_client_bootstrap_set_alpn_callback(
    struct aws_client_bootstrap *bootstrap,
    aws_channel_on_protocol_negotiated on_protocol_negotiated);

/**
 * Sets up a client socket channel. If you are planning on using tls, use `aws_client_bootstrap_new_tls_socket_channel`
 * instead. The connection is made to `endpoint` using socket options `options`. `setup_callback` will be invoked once
 * the channel is ready for use or if an error is encountered. `shutdown_callback` will be invoked once the channel has
 * shutdown. Immediately after the `shutdown_callback` returns, the channel is cleaned up automatically. All callbacks
 * are invoked in an event-loop's thread.
 */
AWS_IO_API int aws_client_bootstrap_new_socket_channel(
    struct aws_client_bootstrap *bootstrap,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *options,
    aws_channel_client_setup_callback setup_callback,
    aws_channel_client_shutdown_callback shutdown_callback,
    void *user_data);

/**
 * Sets up a client tls socket channel. The connection is made to `endpoint` using socket options `options`, and tls
 * options `connection_options`. `setup_callback` will be invoked once the channel is ready for use and TLS has been
 * negotiated, or if an error is encountered. `shutdown_callback` will be invoked once the channel has shutdown.
 * Immediately after the `shutdown_callback` returns, the channel is cleaned up automatically. All callbacks are invoked
 * in an event-loop's thread.
 *
 * `connection_options` is copied.
 */
AWS_IO_API int aws_client_bootstrap_new_tls_socket_channel(
    struct aws_client_bootstrap *bootstrap,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *options,
    const struct aws_tls_connection_options *connection_options,
    aws_channel_client_setup_callback setup_callback,
    aws_channel_client_shutdown_callback shutdown_callback,
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
 * Sets the tls context for use with `aws_server_bootstrap_add_tls_socket_listener`. This function must be called before
 * calling, `aws_server_bootstrap_add_tls_socket_listener`
 */
AWS_IO_API int aws_server_bootstrap_set_tls_ctx(struct aws_server_bootstrap *bootstrap, struct aws_tls_ctx *ctx);

/**
 * When using tls, if ALPN is used, this callback will be invoked from the channel. The returned handler will be added
 * to the channel.
 */
AWS_IO_API int aws_server_bootstrap_set_alpn_callback(
    struct aws_server_bootstrap *bootstrap,
    aws_channel_on_protocol_negotiated on_protocol_negotiated);

/**
 * Sets up a server socket listener. If you are planning on using tls, use
 * `aws_server_bootstrap_add_tls_socket_listener` instead. This creates a socket listener bound to `endpoint` using
 * socket options `options`. `incoming_callback` will be invoked once an incoming channel is ready for use or if an
 * error is encountered. `shutdown_callback` will be invoked once the channel has shutdown. Immediately after the
 * `shutdown_callback` returns, the channel is cleaned up automatically. All callbacks are invoked in an event-loop's
 * thread.
 *
 * Upon shutdown of your application, you'll want to call `aws_server_bootstrap_remove_socket_listener` with the return
 * value from this function.
 */
AWS_IO_API struct aws_socket *aws_server_bootstrap_add_socket_listener(
    struct aws_server_bootstrap *bootstrap,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *options,
    aws_channel_server_incoming_channel_callback incoming_callback,
    aws_channel_server_channel_shutdown_callback shutdown_callback,
    void *user_data);

/**
 * Sets up a server socket listener which will also negotiate and configure TLS.
 * This creates a socket listener bound to `endpoint` using socket options `options`, and tls options
 * `connection_options`. `incoming_callback` will be invoked once an incoming channel is ready for use and TLS is
 * finished negotiating, or if an error is encountered. `shutdown_callback` will be invoked once the channel has
 * shutdown. Immediately after the `shutdown_callback` returns, the channel is cleaned up automatically. All callbacks
 * are invoked in an event-loop's thread.
 *
 * Upon shutdown of your application, you'll want to call `aws_server_bootstrap_remove_socket_listener` with the return
 * value from this function.
 */
AWS_IO_API struct aws_socket *aws_server_bootstrap_add_tls_socket_listener(
    struct aws_server_bootstrap *bootstrap,
    struct aws_socket_endpoint *endpoint,
    struct aws_socket_options *options,
    const struct aws_tls_connection_options *connection_options,
    aws_channel_server_incoming_channel_callback incoming_callback,
    aws_channel_server_channel_shutdown_callback shutdown_callback,
    void *user_data);

/**
 * Shuts down 'listener' and cleans up any resources associated with it. Any incoming channels on `listener` will still
 * be active.
 */
AWS_IO_API int aws_server_bootstrap_remove_socket_listener(
    struct aws_server_bootstrap *bootstrap,
    struct aws_socket *listener);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_CHANNEL_BOOTSTRAP_H */
