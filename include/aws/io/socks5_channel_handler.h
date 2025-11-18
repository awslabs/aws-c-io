/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifndef AWS_IO_SOCKS5_CHANNEL_HANDLER_H
#define AWS_IO_SOCKS5_CHANNEL_HANDLER_H

#include <aws/io/channel.h>
#include <aws/io/channel_bootstrap.h>
#include <aws/common/hash_table.h>
#include <aws/common/byte_buf.h>
#include <aws/io/host_resolver.h>
#include <aws/io/socket.h>
#include <aws/io/socks5.h>
#include <aws/io/tls_channel_handler.h>
#include <aws/common/mutex.h>

/* SOCKS5 proxy connection states */
enum aws_socks5_proxy_connection_state {
    AWS_SPCS_NONE = 0,
    AWS_SPCS_SOCKET_CONNECT,
    AWS_SPCS_SOCKS5_NEGOTIATION,
    AWS_SPCS_SUCCESS,
    AWS_SPCS_FAILURE,
};

/**
 * Context struct for SOCKS5 proxy connections, used as user_data throughout the SOCKS5 bootstrap/setup chain.
 * 
 * This structure coordinates the connection flow through a SOCKS5 proxy and optional TLS setup,
 * maintaining state through the entire connection lifecycle and ensuring proper callback chaining.
 * The structure serves as a bridge between the original connection request and the SOCKS5-specific
 * connection process, preserving critical context needed for proper callback invocation.
 * 
 * During a SOCKS5 proxy connection:
 * 1. This structure is initialized with connection parameters and callbacks
 * 2. The bootstrap process installs a SOCKS5 channel handler that handles the proxy protocol
 * 3. After successful SOCKS5 handshake, TLS can be established if requested
 * 4. Original callbacks are invoked at appropriate points to maintain the expected behavior
 */
struct aws_socks5_bootstrap {
    /** Memory allocator used for all allocations related to this bootstrap */
    struct aws_allocator *allocator;
    
    /** SOCKS5 proxy configuration */
    struct aws_socks5_proxy_options *socks5_proxy_options;
    
    /** User data to pass to callbacks; preserved from the original connection request */
    void *user_data;

    /** 
     * Callback function called when the SOCKS5 setup has successfully completed.
     */
    aws_client_bootstrap_on_channel_event_fn *on_socks5_setup_completed;
    
    /** Original callback function to invoke when the channel is successfully established */
    aws_client_bootstrap_on_channel_event_fn *setup_callback;
    
    /** Original callback function to invoke when the channel is being shut down */
    aws_client_bootstrap_on_channel_event_fn *shutdown_callback;
    
    /** TLS connection options to apply after SOCKS5 handshake completes (if TLS is requested) */
    struct aws_tls_connection_options *tls_options;
    
    /** Flag indicating whether to establish TLS after SOCKS5 handshake completes */
    bool use_tls;
    
    /** Reference to the client bootstrap used for the connection */
    struct aws_client_bootstrap *bootstrap;
    
    /** Original TLS negotiation callback to invoke after TLS handshake completes */
    aws_tls_on_negotiation_result_fn *original_on_negotiation_result;
    
    /** User data to pass to the original TLS negotiation callback */
    void *original_tls_user_data;

    /** Destination endpoint resolved from the original connection request */
    struct aws_string *endpoint_host;
    struct aws_string *original_endpoint_host;
    uint16_t endpoint_port;
    enum aws_socks5_address_type endpoint_address_type;
    enum aws_socks5_host_resolution_mode host_resolution_mode;
    bool endpoint_ready;
    bool resolution_in_progress;
    int resolution_error_code;
    struct aws_channel *pending_channel;
    struct aws_channel_task resolution_success_task;
    struct aws_channel_task resolution_failure_task;
    bool resolution_task_scheduled;
    bool resolution_failure_task_scheduled;
    /** Set when shutdown is requested while resolution is still running so the bootstrap can be destroyed safely after the callback completes */
    bool cleanup_pending;
    struct aws_host_resolution_config host_resolution_config;
    bool has_host_resolution_override;
    struct aws_mutex lock;
};

/**
 * System vtable used to decouple production behavior from tests.
 * Tests may override these functions to observe or modify bootstrap behavior.
 */
struct aws_socks5_system_vtable {
    int (*aws_client_bootstrap_new_socket_channel)(struct aws_socket_channel_bootstrap_options *options);
};


AWS_EXTERN_C_BEGIN

/**
 * Creates a SOCKS5 channel handler that will establish a connection through a SOCKS5 proxy
 * to the target host and port specified in the options.
 *
 * This handler manages the initial SOCKS5 handshake and authentication, and then becomes transparent
 * once the connection is established.
 *
 * For a TLS connection through a SOCKS5 proxy, this handler should be installed before the TLS handler.
 */
AWS_IO_API struct aws_channel_handler *aws_socks5_channel_handler_new(
    struct aws_allocator *allocator,
    const struct aws_socks5_proxy_options *proxy_options,
    struct aws_byte_cursor endpoint_host,
    uint16_t endpoint_port,
    enum aws_socks5_address_type endpoint_address_type,
    aws_channel_on_setup_completed_fn *on_setup_completed,
    void *user_data);

/**
 * Creates a new socket channel through a SOCKS5 proxy using the provided bootstrap options.
 * This function wraps the standard socket channel creation process to insert a SOCKS5 channel handler
 * into the channel's handler chain, enabling connections through the specified SOCKS5 proxy.
 * @param options The socket channel bootstrap options, including SOCKS5 proxy configuration
 * @return AWS_OP_SUCCESS if the channel creation process was initiated successfully, AWS_OP_ERR otherwise with error code set
 */
AWS_IO_API int aws_socks5_client_bootstrap_new_socket_channel(
    struct aws_socket_channel_bootstrap_options *options);

/**
 * Creates a new socket channel through a SOCKS5 proxy using the provided bootstrap options.
 * This function is similar to aws_client_bootstrap_new_socket_channel but specifically handles
 * the inclusion of SOCKS5 proxy options.
 * @param allocator The allocator to use for memory allocations
 * @param channel_options The socket channel bootstrap
 * options, including SOCKS5 proxy configuration
 * @param socks5_proxy_options The SOCKS5 proxy options to use for the connection
 * @return AWS_OP_SUCCESS if the channel creation process was initiated successfully, AWS_OP_ERR otherwise
 *  with error code set
 */
AWS_IO_API int aws_client_bootstrap_new_socket_channel_with_socks5(
    struct aws_allocator *allocator,
    struct aws_socket_channel_bootstrap_options *channel_options,
    const struct aws_socks5_proxy_options *socks5_proxy_options);

/**
 * Starts the SOCKS5 handshake process. Must be called after the handler is added to a slot.
 */
AWS_IO_API int aws_socks5_channel_handler_start_handshake(
    struct aws_channel_handler *handler);

/**
 * Overrides the system vtable used by the SOCKS5 bootstrap logic. Pass NULL to restore defaults.
 * Intended for testing.
 */
AWS_IO_API void aws_socks5_channel_handler_set_system_vtable(
    const struct aws_socks5_system_vtable *system_vtable);

AWS_EXTERN_C_END

#endif /* AWS_IO_SOCKS5_CHANNEL_HANDLER_H */
