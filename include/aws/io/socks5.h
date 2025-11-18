#ifndef AWS_IO_SOCKS5_H
#define AWS_IO_SOCKS5_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/io.h>

/**
 * SOCKS5 Protocol implementation for AWS CRT.
 * 
 * This module provides functionality for connecting to TCP servers through a SOCKS5 proxy.
 * It implements the client-side of the SOCKS5 protocol as defined in:
 * 
 * - RFC 1928: "SOCKS Protocol Version 5"
 * - RFC 1929: "Username/Password Authentication for SOCKS V5"
 * 
 * The implementation supports:
 * - No authentication and username/password authentication methods
 * - IPv4, IPv6, and domain name address types
 * - The CONNECT command
 * 
 * Usage flow:
 * 1. Initialize proxy options with aws_socks5_proxy_options_init()
 * 2. Initialize SOCKS5 context with aws_socks5_context_init()
 * 3. Perform the protocol handshake sequence:
 *    - Write greeting → Read greeting response
 *    - Write auth request → Read auth response (if required)
 *    - Write connect request → Read connect response
 * 4. After success, the connection can be used normally for application protocols
 */

/* SOCKS5 Protocol Constants */
#define AWS_SOCKS5_VERSION 0x05
#define AWS_SOCKS5_RESERVED 0x00
#define AWS_SOCKS5_AUTH_VERSION 0x01

/* SOCKS5 Message Sizes */
#define AWS_SOCKS5_GREETING_MIN_SIZE 3
#define AWS_SOCKS5_GREETING_RESP_SIZE 2
#define AWS_SOCKS5_AUTH_REQ_MIN_SIZE 5 /* Version(1) + ULen(1) + UName(1+) + PLen(1) + Pass(1+) */
#define AWS_SOCKS5_AUTH_RESP_SIZE 2
#define AWS_SOCKS5_CONN_REQ_MIN_SIZE 6 /* Version(1) + CMD(1) + RSV(1) + ATYP(1) + ADDR(1+) + PORT(2) */
#define AWS_SOCKS5_CONN_RESP_MIN_SIZE 6 /* Version(1) + Status(1) + RSV(1) + ATYP(1) + ADDR(1+) + PORT(2) */

/* SOCKS5 Address Type */
enum aws_socks5_address_type {
    AWS_SOCKS5_ATYP_IPV4 = 0x01,
    AWS_SOCKS5_ATYP_DOMAIN = 0x03,
    AWS_SOCKS5_ATYP_IPV6 = 0x04,
};

/* SOCKS5 Authentication Methods */
enum aws_socks5_auth_method {
    AWS_SOCKS5_AUTH_NONE = 0x00,
    AWS_SOCKS5_AUTH_GSSAPI = 0x01,
    AWS_SOCKS5_AUTH_USERNAME_PASSWORD = 0x02,
    AWS_SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF,
};

/* SOCKS5 Commands */
enum aws_socks5_command {
    AWS_SOCKS5_COMMAND_CONNECT = 0x01,
    AWS_SOCKS5_COMMAND_BIND = 0x02,
    AWS_SOCKS5_COMMAND_UDP_ASSOCIATE = 0x03,
};

/* SOCKS5 Reply Status Codes */
enum aws_socks5_response_status {
    AWS_SOCKS5_STATUS_SUCCESS = 0x00,
    AWS_SOCKS5_STATUS_GENERAL_FAILURE = 0x01,
    AWS_SOCKS5_STATUS_CONNECTION_NOT_ALLOWED = 0x02,
    AWS_SOCKS5_STATUS_NETWORK_UNREACHABLE = 0x03,
    AWS_SOCKS5_STATUS_HOST_UNREACHABLE = 0x04,
    AWS_SOCKS5_STATUS_CONNECTION_REFUSED = 0x05,
    AWS_SOCKS5_STATUS_TTL_EXPIRED = 0x06,
    AWS_SOCKS5_STATUS_COMMAND_NOT_SUPPORTED = 0x07,
    AWS_SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
};

/* SOCKS5 Protocol State */
enum aws_socks5_state {
    AWS_SOCKS5_STATE_INIT,
    AWS_SOCKS5_STATE_GREETING_SENT,
    AWS_SOCKS5_STATE_GREETING_RECEIVED,
    AWS_SOCKS5_STATE_AUTH_STARTED,
    AWS_SOCKS5_STATE_AUTH_COMPLETED,
    AWS_SOCKS5_STATE_REQUEST_SENT,
    AWS_SOCKS5_STATE_RESPONSE_RECEIVED,
    AWS_SOCKS5_STATE_CONNECTED,
    AWS_SOCKS5_STATE_ERROR,
};

/* SOCKS5 Proxy Options */
enum aws_socks5_host_resolution_mode {
    AWS_SOCKS5_HOST_RESOLUTION_PROXY = 0,
    AWS_SOCKS5_HOST_RESOLUTION_CLIENT = 1,
};

struct aws_socks5_proxy_options {
    /* Proxy server host and port */
    struct aws_string *host;
    uint16_t port;

    /* Authentication credentials (optional) */
    struct aws_string *username;
    struct aws_string *password;

    /* Configuration options */
    uint32_t connection_timeout_ms;
    enum aws_socks5_host_resolution_mode host_resolution_mode;
};


/* SOCKS5 Context - internal state for protocol handling */
struct aws_socks5_context {
    struct aws_allocator *allocator;
    enum aws_socks5_state state;
    struct aws_array_list auth_methods; /* List of enum aws_socks5_auth_method */
    enum aws_socks5_auth_method selected_auth;
    
    /* Connection information */
    struct aws_socks5_proxy_options options;
    struct aws_string *endpoint_host;
    uint16_t endpoint_port;
    enum aws_socks5_address_type endpoint_address_type;
    
    /* Buffer management */
    struct aws_byte_buf send_buf;
    struct aws_byte_buf recv_buf;
};

AWS_EXTERN_C_BEGIN

/**
 * Initialize SOCKS5 proxy options with defaults.
 * 
 * @param options The options structure to initialize
 * @param allocator The allocator to use for internal memory allocation
 * @param host The proxy server hostname or IP address as a byte cursor
 * @param port The proxy server port
 * 
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise with error code set
 */
AWS_IO_API int aws_socks5_proxy_options_init(
    struct aws_socks5_proxy_options *options,
    struct aws_allocator *allocator,
    struct aws_byte_cursor host,
    uint16_t port);

/**
 * Initialize SOCKS5 proxy options with default values.
 *
 * @param options The options structure to initialize
 *
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise with error code set
 */
AWS_IO_API int aws_socks5_proxy_options_init_default(
    struct aws_socks5_proxy_options *options);

/**
 * Deep copy SOCKS5 proxy options from source to destination.
 * Destination must be already zero-initialized.
 *
 * @param dest The destination options structure (must be zero-initialized)
 * @param src The source options structure to copy from
 * 
 * @return AWS_OP_SUCCESS on success, AWS_OP_ERR on failure
 */
AWS_IO_API int aws_socks5_proxy_options_copy(
    struct aws_socks5_proxy_options *dest,
    const struct aws_socks5_proxy_options *src);

/**
 * Clean up SOCKS5 proxy options and free all internally allocated memory.
 * 
 * @param options The SOCKS5 proxy options to clean up
 */
AWS_IO_API void aws_socks5_proxy_options_clean_up(struct aws_socks5_proxy_options *options);

/**
 * Set authentication credentials for SOCKS5 proxy. If set, the SOCKS5 client will
 * attempt to authenticate using username/password authentication method.
 * 
 * @param options The SOCKS5 proxy options to update
 * @param username The username as a byte cursor
 * @param password The password as a byte cursor
 * 
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise with error code set
 * 
 * @note Both username and password must have length > 0 and <= 255 bytes as per RFC 1929
 */
AWS_IO_API int aws_socks5_proxy_options_set_auth(
    struct aws_socks5_proxy_options *options,
    struct aws_allocator *allocator,
    struct aws_byte_cursor username,
    struct aws_byte_cursor password);

/**
 * Set the host resolution mode for the SOCKS5 proxy.
 * 
 * @param options The SOCKS5 proxy options to update
 * @param mode The host resolution mode to set
 */
AWS_IO_API void aws_socks5_proxy_options_set_host_resolution_mode(
    struct aws_socks5_proxy_options *options,
    enum aws_socks5_host_resolution_mode mode);

/**
 * Get the host resolution mode for the SOCKS5 proxy.
 * 
 * @param options The SOCKS5 proxy options to query
 * @return The host resolution mode
 */
AWS_IO_API enum aws_socks5_host_resolution_mode aws_socks5_proxy_options_get_host_resolution_mode(
    const struct aws_socks5_proxy_options *options);

/**
 * Helper to infer the appropriate SOCKS5 address type for a given host string. If the host is an IPv4 or IPv6 literal,
 * the corresponding address type will be returned even if AWS_SOCKS5_ATYP_DOMAIN was requested.
 */
AWS_IO_API enum aws_socks5_address_type aws_socks5_infer_address_type(
    struct aws_byte_cursor host,
    enum aws_socks5_address_type requested_type);

/**
 * Initialize a SOCKS5 protocol context for establishing a connection through a SOCKS5 proxy.
 * The context manages the state and buffers needed for the SOCKS5 protocol handshake.
 * 
 * @param context The context structure to initialize
 * @param allocator The allocator to use for internal memory allocation
 * @param options Configuration options for the SOCKS5 proxy connection
 * @param target_host Destination host the proxy should reach (byte cursor)
 * @param target_port Destination port the proxy should reach
 * @param address_type Address type hint (DOMAIN will trigger automatic IPv4/IPv6 detection)
 * 
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise with error code set
 */
AWS_IO_API int aws_socks5_context_init(
    struct aws_socks5_context *context,
    struct aws_allocator *allocator,
    const struct aws_socks5_proxy_options *options,
    struct aws_byte_cursor target_host,
    uint16_t target_port,
    enum aws_socks5_address_type address_type);

/**
 * Clean up a SOCKS5 context and free all internally allocated memory.
 * 
 * @param context The SOCKS5 context to clean up
 */
AWS_IO_API void aws_socks5_context_clean_up(struct aws_socks5_context *context);

/**
 * Format the initial SOCKS5 greeting message into the provided buffer.
 * This message contains the list of supported authentication methods and
 * is the first message sent to a SOCKS5 proxy server.
 * 
 * @param context The SOCKS5 context containing connection information
 * @param buffer The buffer to write the greeting message into (will be resized if needed)
 * 
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise with error code set
 */
AWS_IO_API int aws_socks5_write_greeting(
    struct aws_socks5_context *context,
    struct aws_byte_buf *buffer);

/**
 * Process the SOCKS5 greeting response from the server.
 * The server selects an authentication method or rejects the connection.
 * 
 * @param context The SOCKS5 context to update with server's selected auth method
 * @param data The received data from the server to process
 * 
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise with error code set
 * 
 * @note Updates context->state to AWS_SOCKS5_STATE_GREETING_RECEIVED on success
 * @note Updates context->selected_auth with the server's chosen authentication method
 */
AWS_IO_API int aws_socks5_read_greeting_response(
    struct aws_socks5_context *context,
    struct aws_byte_cursor *data);

/**
 * Format the username/password authentication request into the provided buffer.
 * This message is sent after the server has selected username/password authentication.
 * 
 * @param context The SOCKS5 context containing authentication credentials
 * @param buffer The buffer to write the authentication request into
 * 
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise with error code set
 * 
 * @note If the selected authentication method is AWS_SOCKS5_AUTH_NONE, this function
 *       will update the context state without writing to the buffer
 */
AWS_IO_API int aws_socks5_write_auth_request(
    struct aws_socks5_context *context,
    struct aws_byte_buf *buffer);

/**
 * Process the SOCKS5 authentication response from the server.
 * This verifies if authentication was successful.
 * 
 * @param context The SOCKS5 context to update based on authentication result
 * @param data The received data from the server to process
 * 
 * @return AWS_OP_SUCCESS if authentication succeeded, AWS_OP_ERR otherwise with error code set
 * 
 * @note Updates context->state to AWS_SOCKS5_STATE_AUTH_COMPLETED on success
 * @note If the selected authentication method is AWS_SOCKS5_AUTH_NONE, this function
 *       will update the context state without processing the data
 */
AWS_IO_API int aws_socks5_read_auth_response(
    struct aws_socks5_context *context,
    struct aws_byte_cursor *data);

/**
 * Format the SOCKS5 connection request into the provided buffer.
 * This message requests the proxy to establish a connection to the target host.
 * 
 * @param context The SOCKS5 context containing target host information
 * @param buffer The buffer to write the connect request into
 * 
 * @return AWS_OP_SUCCESS if successful, AWS_OP_ERR otherwise with error code set
 * 
 * @note Updates context->state to AWS_SOCKS5_STATE_REQUEST_SENT on success
 * @note Currently only supports the CONNECT command (not BIND or UDP ASSOCIATE)
 */
AWS_IO_API int aws_socks5_write_connect_request(
    struct aws_socks5_context *context,
    struct aws_byte_buf *buffer);

/**
 * Process the SOCKS5 connection response from the server.
 * This verifies if the connection to the target host was successful.
 * 
 * @param context The SOCKS5 context to update based on connection result
 * @param data The received data from the server to process
 * 
 * @return AWS_OP_SUCCESS if connection succeeded, AWS_OP_ERR otherwise with error code set
 * 
 * @note Updates context->state to AWS_SOCKS5_STATE_CONNECTED on success
 * @note On error, the specific SOCKS5 error code will be mapped to an appropriate AWS error code
 */
AWS_IO_API int aws_socks5_read_connect_response(
    struct aws_socks5_context *context,
    struct aws_byte_cursor *data);

AWS_EXTERN_C_END

#endif /* AWS_IO_SOCKS5_H */
