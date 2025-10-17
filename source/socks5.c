/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/socks5.h>

#include <aws/io/logging.h>
#include <aws/io/socket.h>
#include <aws/common/byte_buf.h>
#include <aws/common/string.h>

#include <string.h>
#include <inttypes.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

AWS_STATIC_STRING_FROM_LITERAL(s_socks_none_method, "NONE");
AWS_STATIC_STRING_FROM_LITERAL(s_socks_username_password_method, "USERNAME_PASSWORD");
AWS_STATIC_STRING_FROM_LITERAL(s_socks_gssapi_method, "GSSAPI");

/* Buffer size constants for SOCKS5 protocol operations */
#define AWS_SOCKS5_SEND_BUFFER_INITIAL_SIZE 256
#define AWS_SOCKS5_RECV_BUFFER_INITIAL_SIZE 512

static size_t s_string_length(const struct aws_string *str) {
    return str ? str->len : 0;
}

static const uint8_t *s_string_bytes(const struct aws_string *str) {
    return str ? aws_string_bytes(str) : NULL;
}

/**
 * Helper function to ensure a buffer has enough capacity for additional data.
 * 
 * This function checks if the buffer has enough remaining capacity for the required
 * space, and if not, reserves more space in the buffer.
 * 
 * @param buffer The buffer to check and potentially resize
 * @param required_space How much additional space is needed
 * @return AWS_OP_SUCCESS if the buffer has enough space, AWS_OP_ERR otherwise
 */
static int s_ensure_buffer_has_capacity(
    struct aws_byte_buf *buffer,
    size_t required_space) {
    
    if (!buffer) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    /* Calculate available space safely */
    size_t available_space = (buffer->capacity > buffer->len) ? 
                            (buffer->capacity - buffer->len) : 0;
    
    /* Only reserve more if we don't have enough */
    if (required_space > available_space) {
        if (aws_byte_buf_reserve(buffer, buffer->len + required_space)) {
            return AWS_OP_ERR;
        }
    }
    
    return AWS_OP_SUCCESS;
}

/* Helper for converting auth method enum to string for logging */
static struct aws_string *s_auth_method_to_string(enum aws_socks5_auth_method method) {
    switch (method) {
        case AWS_SOCKS5_AUTH_NONE:
            return (struct aws_string *)s_socks_none_method;
        case AWS_SOCKS5_AUTH_USERNAME_PASSWORD:
            return (struct aws_string *)s_socks_username_password_method;
        case AWS_SOCKS5_AUTH_GSSAPI:
            return (struct aws_string *)s_socks_gssapi_method;
        default:
            return NULL;
    }
}

int aws_socks5_proxy_options_init(
    struct aws_socks5_proxy_options *options,
    struct aws_allocator *allocator,
    struct aws_byte_cursor host,
    uint16_t port) {

    if (!options || !allocator) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* Validate host cursor */
    if (!aws_byte_cursor_is_valid(&host) || host.len == 0 || host.ptr == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Invalid host provided to SOCKS5 proxy options init");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    aws_socks5_proxy_options_init_default(options);
    options->port = port;
    options->host = aws_string_new_from_cursor(allocator, &host);
    if (options->host == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Failed to copy host for SOCKS5 proxy options");
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_socks5_proxy_options_init_default(
    struct aws_socks5_proxy_options *options) {
    AWS_ZERO_STRUCT(*options);
    options->port = 1080; /* Default SOCKS5 port */
    options->connection_timeout_ms = 3000; /* Default timeout of 3 seconds */
    options->host_resolution_mode = AWS_SOCKS5_HOST_RESOLUTION_PROXY;
        
    return AWS_OP_SUCCESS;
}

/* Destination must be zero-initialized before calling to avoid leaking prior allocations. */
int aws_socks5_proxy_options_copy(
    struct aws_socks5_proxy_options *dest,
    const struct aws_socks5_proxy_options *src) {
    
    if (!dest || !src) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }
    
    AWS_ZERO_STRUCT(*dest);
    dest->port = src->port;
    dest->connection_timeout_ms = src->connection_timeout_ms;
    dest->host_resolution_mode = src->host_resolution_mode;

    if (src->host) {
        dest->host = aws_string_new_from_string(src->host->allocator, src->host);
        if (!dest->host) {
            goto on_error;
        }
    }

    if (src->username) {
        dest->username = aws_string_new_from_string(src->username->allocator, src->username);
        if (!dest->username) {
            goto on_error;
        }
    }

    if (src->password) {
        dest->password = aws_string_new_from_string(src->password->allocator, src->password);
        if (!dest->password) {
            goto on_error;
        }
    }

    return AWS_OP_SUCCESS;

on_error:
    aws_socks5_proxy_options_clean_up(dest);
    return AWS_OP_ERR;
}

void aws_socks5_proxy_options_clean_up(struct aws_socks5_proxy_options *options) {
    if (!options) {
        return;
    }

    aws_string_destroy(options->host);
    aws_string_destroy_secure(options->username);
    aws_string_destroy_secure(options->password);

    AWS_ZERO_STRUCT(*options);
}

int aws_socks5_proxy_options_set_auth(
    struct aws_socks5_proxy_options *options,
    struct aws_allocator *allocator,
    struct aws_byte_cursor username,
    struct aws_byte_cursor password) {

    if (!options || !allocator) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (options->username) {
        aws_string_destroy_secure(options->username);
        options->username = NULL;
    }
    if (options->password) {
        aws_string_destroy_secure(options->password);
        options->password = NULL;
    }
    if (username.len > 0) {
        options->username = aws_string_new_from_cursor(allocator, &username);
        if (!options->username) {
            return AWS_OP_ERR;
        }
    }
    if (password.len > 0) {
        options->password = aws_string_new_from_cursor(allocator, &password);
        if (!options->password) {
            return AWS_OP_ERR;
        }
    }
    return AWS_OP_SUCCESS;
}

void aws_socks5_proxy_options_set_host_resolution_mode(
    struct aws_socks5_proxy_options *options,
    enum aws_socks5_host_resolution_mode mode) {

    if (!options) {
        return;
    }

    options->host_resolution_mode = mode;
}

enum aws_socks5_host_resolution_mode aws_socks5_proxy_options_get_host_resolution_mode(
    const struct aws_socks5_proxy_options *options) {

    if (!options) {
        return AWS_SOCKS5_HOST_RESOLUTION_PROXY;
    }

    return options->host_resolution_mode;
}

AWS_IO_API enum aws_socks5_address_type aws_socks5_infer_address_type(
    struct aws_byte_cursor target_host,
    enum aws_socks5_address_type requested_type) {

    if (requested_type != AWS_SOCKS5_ATYP_DOMAIN || target_host.len == 0 || target_host.ptr == NULL) {
        return requested_type;
    }

    char address_buffer[AWS_ADDRESS_MAX_LEN];
    size_t host_len = target_host.len;
    if (host_len >= sizeof(address_buffer)) {
        host_len = sizeof(address_buffer) - 1;
    }
    memcpy(address_buffer, target_host.ptr, host_len);
    address_buffer[host_len] = '\0';

    if (address_buffer[0] == '[') {
        size_t buf_len = strlen(address_buffer);
        if (buf_len > 1 && address_buffer[buf_len - 1] == ']') {
            memmove(address_buffer, address_buffer + 1, buf_len - 2);
            address_buffer[buf_len - 2] = '\0';
        }
    }

    char *zone_delimiter = strchr(address_buffer, '%');
    if (zone_delimiter) {
        *zone_delimiter = '\0';
    }

    unsigned char ipv4_buffer[4];
    unsigned char ipv6_buffer[16];

    if (inet_pton(AF_INET, address_buffer, ipv4_buffer) == 1) {
        return AWS_SOCKS5_ATYP_IPV4;
    }

    if (inet_pton(AF_INET6, address_buffer, ipv6_buffer) == 1) {
        return AWS_SOCKS5_ATYP_IPV6;
    }

    return requested_type;
}

int aws_socks5_context_init(
    struct aws_socks5_context *context,
    struct aws_allocator *allocator,
    const struct aws_socks5_proxy_options *options,
    struct aws_byte_cursor target_host,
    uint16_t target_port,
    enum aws_socks5_address_type address_type) {

    if (!context) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: context is NULL in aws_socks5_context_init");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (!allocator) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: allocator is NULL in aws_socks5_context_init");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (!options) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: options is NULL in aws_socks5_context_init");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (!target_host.ptr || target_host.len == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: target host is invalid (NULL or empty) in aws_socks5_context_init");
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=static: Proxy options: host=%p len=%zu, port=%d",
        (void *)options->host,
        s_string_length(options->host),
        options->port);

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=static: Proxy endpoint host='%.*s', port=%d",
        (int)target_host.len,
        target_host.ptr ? (const char *)target_host.ptr : "",
        target_port);

    AWS_ZERO_STRUCT(*context);
    context->allocator = allocator;
    context->state = AWS_SOCKS5_STATE_INIT;

    if (aws_array_list_init_dynamic(&context->auth_methods, allocator, 3, sizeof(enum aws_socks5_auth_method))) {
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_INIT);
    }

    enum aws_socks5_auth_method no_auth = AWS_SOCKS5_AUTH_NONE;
    aws_array_list_push_back(&context->auth_methods, &no_auth);

    size_t options_username_len = options->username ? options->username->len : 0;
    size_t options_password_len = options->password ? options->password->len : 0;

    if (options_username_len > 0 && options_password_len > 0) {
        enum aws_socks5_auth_method user_pass = AWS_SOCKS5_AUTH_USERNAME_PASSWORD;
        aws_array_list_push_back(&context->auth_methods, &user_pass);
    }

    if (options->host == NULL || options->host->len == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Invalid host in SOCKS5 proxy options (buffer=%p, len=%zu)",
            (void *)options->host,
            options->host ? options->host->len : 0);
        aws_socks5_context_clean_up(context);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (aws_socks5_proxy_options_copy(&context->options, options)) {
        int error_code = aws_last_error();
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Failed to copy proxy options: error=%d (%s)",
            error_code,
            aws_error_str(error_code));
        aws_array_list_clean_up(&context->auth_methods);
        return AWS_OP_ERR;
    }

    struct aws_byte_cursor host_copy = target_host;
    context->endpoint_host = aws_string_new_from_cursor(allocator, &host_copy);
    if (!context->endpoint_host) {
        aws_array_list_clean_up(&context->auth_methods);
        aws_socks5_proxy_options_clean_up(&context->options);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_INIT);
    }

    context->endpoint_port = target_port;
    context->endpoint_address_type = aws_socks5_infer_address_type(target_host, address_type);

    if (aws_byte_buf_init(&context->send_buf, allocator, AWS_SOCKS5_SEND_BUFFER_INITIAL_SIZE)) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: Failed to initialize send buffer");
        aws_array_list_clean_up(&context->auth_methods);
        aws_socks5_proxy_options_clean_up(&context->options);
        aws_string_destroy(context->endpoint_host);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_INIT);
    }

    if (aws_byte_buf_init(&context->recv_buf, allocator, AWS_SOCKS5_RECV_BUFFER_INITIAL_SIZE)) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: Failed to initialize receive buffer");
        aws_array_list_clean_up(&context->auth_methods);
        aws_socks5_proxy_options_clean_up(&context->options);
        aws_string_destroy(context->endpoint_host);
        aws_byte_buf_clean_up(&context->send_buf);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_INIT);
    }

    return AWS_OP_SUCCESS;
}

void aws_socks5_context_clean_up(struct aws_socks5_context *context) {
    if (!context) {
        return;
    }

    aws_array_list_clean_up(&context->auth_methods);
    aws_socks5_proxy_options_clean_up(&context->options);
    aws_string_destroy(context->endpoint_host);

    if (context->send_buf.buffer) {
        aws_byte_buf_clean_up(&context->send_buf);
    }

    if (context->recv_buf.buffer) {
        aws_byte_buf_clean_up(&context->recv_buf);
    }

    AWS_ZERO_STRUCT(*context);
}

int aws_socks5_write_greeting(
    struct aws_socks5_context *context,
    struct aws_byte_buf *buffer) {

    if (!context || !buffer) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    size_t num_methods = aws_array_list_length(&context->auth_methods);
    if (num_methods == 0) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: No authentication methods available for SOCKS5 greeting");
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_INIT);
    }

    /* SOCKS5 greeting format:
     * +----+----------+----------+
     * |VER | NMETHODS | METHODS  |
     * +----+----------+----------+
     * | 1  |    1     | 1 to 255 |
     * +----+----------+----------+
     */
    size_t greeting_size = 2 + num_methods; /* VER(1) + NMETHODS(1) + METHODS(n) */

    /* Use the helper function to ensure buffer capacity */
    if (s_ensure_buffer_has_capacity(buffer, greeting_size)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5, "id=static: Failed to allocate buffer for SOCKS5 greeting, size=%zu", greeting_size);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_INIT);
    }

    /* Write SOCKS5 version */
    buffer->buffer[buffer->len++] = AWS_SOCKS5_VERSION;
    
    /* Write number of auth methods */
    buffer->buffer[buffer->len++] = (uint8_t)num_methods;

    /* Write the auth methods */
    for (size_t i = 0; i < num_methods; i++) {
        enum aws_socks5_auth_method method;
        if (aws_array_list_get_at(&context->auth_methods, &method, i)) {
            AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: Failed to get auth method from list at index %zu", i);
            return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_INIT);
        }
        
        buffer->buffer[buffer->len++] = (uint8_t)method;
        
        /* Log which auth methods we're offering */
        struct aws_string *method_str = s_auth_method_to_string(method);
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKS5, 
            "id=static: Offering SOCKS5 auth method %s", 
            method_str ? aws_string_c_str(method_str) : "UNKNOWN");
    }

    /* Update context state */
    context->state = AWS_SOCKS5_STATE_GREETING_SENT;
    
    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKS5, 
        "id=static: Prepared SOCKS5 greeting with %zu auth methods", 
        num_methods);

    return AWS_OP_SUCCESS;
}

int aws_socks5_read_greeting_response(
    struct aws_socks5_context *context,
    struct aws_byte_cursor *data) {

    if (!context || !data || !data->ptr) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (context->state != AWS_SOCKS5_STATE_GREETING_SENT) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Invalid state for reading SOCKS5 greeting response, expected %d, got %d",
            AWS_SOCKS5_STATE_GREETING_SENT,
            context->state);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_BAD_HANDSHAKE);
    }

    if (data->len < AWS_SOCKS5_GREETING_RESP_SIZE) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: SOCKS5 greeting response too short, expected %d bytes, got %zu",
            AWS_SOCKS5_GREETING_RESP_SIZE,
            data->len);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_MALFORMED_RESPONSE);
    }

    /* SOCKS5 greeting response format:
     * +----+--------+
     * |VER | METHOD |
     * +----+--------+
     * | 1  |   1    |
     * +----+--------+
     */
    uint8_t version = data->ptr[0];
    uint8_t method = data->ptr[1];
    
    /* Verify SOCKS version */
    if (version != AWS_SOCKS5_VERSION) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Unexpected SOCKS version in greeting response, expected %d, got %d",
            AWS_SOCKS5_VERSION,
            version);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_MALFORMED_RESPONSE);
    }

    /* Check selected auth method */
    if (method == AWS_SOCKS5_AUTH_NO_ACCEPTABLE) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: SOCKS5 server rejected all authentication methods");
        context->state = AWS_SOCKS5_STATE_ERROR;
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_UNSUPPORTED_AUTH_METHOD);
    }

    /* Store the selected auth method */
    context->selected_auth = (enum aws_socks5_auth_method)method;
    context->state = AWS_SOCKS5_STATE_GREETING_RECEIVED;

    struct aws_string *method_str = s_auth_method_to_string(context->selected_auth);
    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKS5,
        "id=static: SOCKS5 server selected auth method: %s",
        method_str ? aws_string_c_str(method_str) : "UNKNOWN");

    return AWS_OP_SUCCESS;
}

int aws_socks5_write_auth_request(
    struct aws_socks5_context *context,
    struct aws_byte_buf *buffer) {

    if (!context || !buffer) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (context->state != AWS_SOCKS5_STATE_GREETING_RECEIVED) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Invalid state for writing SOCKS5 auth request, expected %d, got %d",
            AWS_SOCKS5_STATE_GREETING_RECEIVED,
            context->state);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_BAD_HANDSHAKE);
    }

    /* Check which auth method was selected */
    switch (context->selected_auth) {
        case AWS_SOCKS5_AUTH_NONE:
            /* No authentication needed, skip to connection phase */
            context->state = AWS_SOCKS5_STATE_AUTH_COMPLETED;
            return AWS_OP_SUCCESS;

        case AWS_SOCKS5_AUTH_USERNAME_PASSWORD:
            /* Continue with username/password authentication */
            break;

        case AWS_SOCKS5_AUTH_GSSAPI:
            /* GSSAPI not supported yet */
            AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: GSSAPI authentication not supported");
            context->state = AWS_SOCKS5_STATE_ERROR;
            return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_UNSUPPORTED_AUTH_METHOD);

        default:
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5, "id=static: Unknown authentication method: %d", context->selected_auth);
            context->state = AWS_SOCKS5_STATE_ERROR;
            return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_UNSUPPORTED_AUTH_METHOD);
    }

    /* Check if we have username/password in options */
    if (context->options.username->len == 0 || context->options.password->len == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Username/password authentication required but credentials not provided");
        context->state = AWS_SOCKS5_STATE_ERROR;
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_AUTH_FAILED);
    }

    /* Username/Password authentication (RFC 1929)
     * +----+------+----------+------+----------+
     * |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
     * +----+------+----------+------+----------+
     * | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
     * +----+------+----------+------+----------+
     */

    /* Check username and password lengths (must be between 1-255 bytes) */
    size_t username_len = s_string_length(context->options.username);
    size_t password_len = s_string_length(context->options.password);
    if (username_len > 255 || password_len > 255) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Username or password too long (max 255 bytes): ulen=%zu, plen=%zu",
            username_len,
            password_len);
        context->state = AWS_SOCKS5_STATE_ERROR;
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_AUTH_FAILED);
    }

    /* Calculate total auth request size */
    size_t auth_size = 3 + username_len + password_len;

    /* Use the helper function to ensure buffer capacity */
    if (s_ensure_buffer_has_capacity(buffer, auth_size)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5, "id=static: Failed to allocate buffer for SOCKS5 auth request, size=%zu", auth_size);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_AUTH_FAILED);
    }

    /* Write sub-negotiation version (0x01 for username/password) */
    buffer->buffer[buffer->len++] = AWS_SOCKS5_AUTH_VERSION;

    /* Write username length and username */
    buffer->buffer[buffer->len++] = (uint8_t)username_len;
    if (username_len > 0) {
        memcpy(buffer->buffer + buffer->len, s_string_bytes(context->options.username), username_len);
        buffer->len += username_len;
    }

    /* Write password length and password */
    buffer->buffer[buffer->len++] = (uint8_t)password_len;
    if (password_len > 0) {
        memcpy(buffer->buffer + buffer->len, s_string_bytes(context->options.password), password_len);
        buffer->len += password_len;
    }

    /* Update state */
    context->state = AWS_SOCKS5_STATE_AUTH_STARTED;

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKS5,
        "id=static: Prepared SOCKS5 username/password auth request with username=%.*s",
        (int)username_len,
        (const char *)s_string_bytes(context->options.username));

    return AWS_OP_SUCCESS;
}

int aws_socks5_read_auth_response(
    struct aws_socks5_context *context,
    struct aws_byte_cursor *data) {

    if (!context || !data || !data->ptr) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    /* If no auth required, we can skip this step */
    if (context->selected_auth == AWS_SOCKS5_AUTH_NONE) {
        context->state = AWS_SOCKS5_STATE_AUTH_COMPLETED;
        return AWS_OP_SUCCESS;
    }

    if (context->state != AWS_SOCKS5_STATE_AUTH_STARTED) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Invalid state for reading SOCKS5 auth response, expected %d, got %d",
            AWS_SOCKS5_STATE_AUTH_STARTED,
            context->state);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_BAD_HANDSHAKE);
    }

    if (data->len < AWS_SOCKS5_AUTH_RESP_SIZE) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: SOCKS5 auth response too short, expected %d bytes, got %zu",
            AWS_SOCKS5_AUTH_RESP_SIZE,
            data->len);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_MALFORMED_RESPONSE);
    }

    /* Username/Password auth response format:
     * +----+--------+
     * |VER | STATUS |
     * +----+--------+
     * | 1  |   1    |
     * +----+--------+
     */
    uint8_t version = data->ptr[0];
    uint8_t status = data->ptr[1];
    
    /* Verify auth version */
    if (version != AWS_SOCKS5_AUTH_VERSION) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Unexpected auth version in SOCKS5 auth response, expected %d, got %d",
            AWS_SOCKS5_AUTH_VERSION,
            version);
        context->state = AWS_SOCKS5_STATE_ERROR;
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_MALFORMED_RESPONSE);
    }

    /* Check auth status (0 = success, anything else = failure) */
    if (status != 0) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5, "id=static: SOCKS5 authentication failed with status code %d", status);
        context->state = AWS_SOCKS5_STATE_ERROR;
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_AUTH_FAILED);
    }

    /* Authentication successful */
    context->state = AWS_SOCKS5_STATE_AUTH_COMPLETED;

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKS5, "id=static: SOCKS5 authentication successful");

    return AWS_OP_SUCCESS;
}

int aws_socks5_write_connect_request(
    struct aws_socks5_context *context,
    struct aws_byte_buf *buffer) {

    if (!context || !buffer) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (context->state != AWS_SOCKS5_STATE_AUTH_COMPLETED &&
        context->state != AWS_SOCKS5_STATE_GREETING_RECEIVED) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Invalid state for writing SOCKS5 connect request, expected %d, got %d",
            AWS_SOCKS5_STATE_AUTH_COMPLETED,
            context->state);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_BAD_HANDSHAKE);
    }

    /* Check if target host and port are set */
    if (s_string_length(context->endpoint_host) == 0) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: Target host not set for SOCKS5 connection");
        context->state = AWS_SOCKS5_STATE_ERROR;
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_BAD_ADDRESS);
    }

    /* Determine the address type and required buffer size */
    enum aws_socks5_address_type addr_type = context->endpoint_address_type;
    size_t addr_size = 0;

    switch (addr_type) {
        case AWS_SOCKS5_ATYP_DOMAIN:
            /* Domain name (1 byte length + domain name) */
            if (s_string_length(context->endpoint_host) > 255) {
                AWS_LOGF_ERROR(
                    AWS_LS_IO_SOCKS5,
                    "id=static: Domain name too long for SOCKS5 (max 255 bytes): %zu",
                    s_string_length(context->endpoint_host));
                context->state = AWS_SOCKS5_STATE_ERROR;
                return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_BAD_ADDRESS);
            }
            addr_size = 1 + s_string_length(context->endpoint_host); /* Length byte + domain */
            break;

        case AWS_SOCKS5_ATYP_IPV4:
            /* IPv4 address (4 bytes) */
            addr_size = 4;
            break;

        case AWS_SOCKS5_ATYP_IPV6:
            /* IPv6 address (16 bytes) */
            addr_size = 16;
            break;

        default:
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKS5, "id=static: Unsupported address type: %d", addr_type);
            context->state = AWS_SOCKS5_STATE_ERROR;
            return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_UNSUPPORTED_ADDRESS_TYPE);
    }

    /* SOCKS5 request format:
     * +----+-----+-------+------+----------+----------+
     * |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
     * +----+-----+-------+------+----------+----------+
     * | 1  |  1  | X'00' |  1   | Variable |    2     |
     * +----+-----+-------+------+----------+----------+
     */
    
    /* Calculate total request size */
    size_t req_size = 6 + addr_size; /* VER(1) + CMD(1) + RSV(1) + ATYP(1) + ADDR(var) + PORT(2) */

    /* Use the helper function to ensure buffer capacity */
    if (s_ensure_buffer_has_capacity(buffer, req_size)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5, "id=static: Failed to allocate buffer for SOCKS5 connect request, size=%zu", req_size);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_REQUEST_FAILED);
    }

    /* Write SOCKS5 version */
    buffer->buffer[buffer->len++] = AWS_SOCKS5_VERSION;
    
    /* Write command (CONNECT) */
    buffer->buffer[buffer->len++] = AWS_SOCKS5_COMMAND_CONNECT;
    
    /* Write reserved byte (0x00) */
    buffer->buffer[buffer->len++] = AWS_SOCKS5_RESERVED;
    
    /* Write address type */
    buffer->buffer[buffer->len++] = (uint8_t)addr_type;

    /* Write destination address */
    switch (addr_type) {
        case AWS_SOCKS5_ATYP_DOMAIN: {
            size_t target_len = s_string_length(context->endpoint_host);
            buffer->buffer[buffer->len++] = (uint8_t)target_len;
            if (target_len > 0) {
                memcpy(buffer->buffer + buffer->len, s_string_bytes(context->endpoint_host), target_len);
                buffer->len += target_len;
            }
            break;
        }

        case AWS_SOCKS5_ATYP_IPV4: {
            uint8_t binary_addr[4];
            size_t target_len = s_string_length(context->endpoint_host);

            if (target_len == 4) {
                memcpy(buffer->buffer + buffer->len, s_string_bytes(context->endpoint_host), 4);
            } else {
                char ip_str[128];
                size_t copy_len = target_len < 127 ? target_len : 127;
                memcpy(ip_str, s_string_bytes(context->endpoint_host), copy_len);
                ip_str[copy_len] = '\0';

                if (inet_pton(AF_INET, ip_str, binary_addr) != 1) {
                    AWS_LOGF_ERROR(
                        AWS_LS_IO_SOCKS5,
                        "id=static: Failed to convert IPv4 address '%s' to binary",
                        ip_str);
                    context->state = AWS_SOCKS5_STATE_ERROR;
                    return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_BAD_ADDRESS);
                }

                memcpy(buffer->buffer + buffer->len, binary_addr, 4);

                AWS_LOGF_DEBUG(
                    AWS_LS_IO_SOCKS5,
                    "id=static: Converted IPv4 '%s' to binary: %d.%d.%d.%d",
                    ip_str,
                    binary_addr[0], binary_addr[1], binary_addr[2], binary_addr[3]);
            }

            buffer->len += 4;
            break;
        }

        case AWS_SOCKS5_ATYP_IPV6: {
            uint8_t binary_addr[16];
            size_t target_len = s_string_length(context->endpoint_host);

            if (target_len == 16) {
                memcpy(buffer->buffer + buffer->len, s_string_bytes(context->endpoint_host), 16);
            } else {
                char ip_str[128];
                size_t copy_len = target_len < 127 ? target_len : 127;
                memcpy(ip_str, s_string_bytes(context->endpoint_host), copy_len);
                ip_str[copy_len] = '\0';

                if (inet_pton(AF_INET6, ip_str, binary_addr) != 1) {
                    AWS_LOGF_ERROR(
                        AWS_LS_IO_SOCKS5,
                        "id=static: Failed to convert IPv6 address '%s' to binary",
                        ip_str);
                    context->state = AWS_SOCKS5_STATE_ERROR;
                    return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_BAD_ADDRESS);
                }

                memcpy(buffer->buffer + buffer->len, binary_addr, 16);

                AWS_LOGF_DEBUG(
                    AWS_LS_IO_SOCKS5,
                    "id=static: Converted IPv6 '%s' to binary format",
                    ip_str);
            }

            buffer->len += 16;
            break;
        }

        default:
            AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: Unsupported address type: %d", addr_type);
            context->state = AWS_SOCKS5_STATE_ERROR;
            return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_UNSUPPORTED_ADDRESS_TYPE);
    }

    /* Write destination port (network byte order) */
    uint16_t port_n = htons(context->endpoint_port);
    memcpy(buffer->buffer + buffer->len, &port_n, sizeof(uint16_t));
    buffer->len += sizeof(uint16_t);

    /* Update state */
    context->state = AWS_SOCKS5_STATE_REQUEST_SENT;

    /* Log the connection attempt */
    switch (addr_type) {
        case AWS_SOCKS5_ATYP_DOMAIN:
            AWS_LOGF_DEBUG(
                AWS_LS_IO_SOCKS5,
                "id=static: Prepared SOCKS5 CONNECT request for domain %.*s:%d",
                (int)s_string_length(context->endpoint_host),
                (const char *)s_string_bytes(context->endpoint_host),
                context->endpoint_port);
            break;

        case AWS_SOCKS5_ATYP_IPV4:
            AWS_LOGF_DEBUG(
                AWS_LS_IO_SOCKS5,
                "id=static: Prepared SOCKS5 CONNECT request for IPv4 address %.*s:%d",
                (int)s_string_length(context->endpoint_host),
                (const char *)s_string_bytes(context->endpoint_host),
                context->endpoint_port);
            break;

        case AWS_SOCKS5_ATYP_IPV6:
            AWS_LOGF_DEBUG(
                AWS_LS_IO_SOCKS5,
                "id=static: Prepared SOCKS5 CONNECT request for IPv6 address %.*s:%d",
                (int)s_string_length(context->endpoint_host),
                (const char *)s_string_bytes(context->endpoint_host),
                context->endpoint_port);
            break;

        default:
            /* This should never happen as we already checked earlier */
            break;
    }

    return AWS_OP_SUCCESS;
}

int aws_socks5_read_connect_response(
    struct aws_socks5_context *context,
    struct aws_byte_cursor *data) {

    if (!context || !data || !data->ptr) {
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    if (context->state != AWS_SOCKS5_STATE_REQUEST_SENT) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Invalid state for reading SOCKS5 connect response, expected %d, got %d",
            AWS_SOCKS5_STATE_REQUEST_SENT,
            context->state);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_BAD_HANDSHAKE);
    }

    /* SOCKS5 response format:
     * +----+-----+-------+------+----------+----------+
     * |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
     * +----+-----+-------+------+----------+----------+
     * | 1  |  1  | X'00' |  1   | Variable |    2     |
     * +----+-----+-------+------+----------+----------+
     */
    
    /* Check minimum response size */
    if (data->len < AWS_SOCKS5_CONN_RESP_MIN_SIZE) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: SOCKS5 connect response too short, expected at least %d bytes, got %zu",
            AWS_SOCKS5_CONN_RESP_MIN_SIZE,
            data->len);
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_MALFORMED_RESPONSE);
    }

    /* Read the fixed response fields */
    uint8_t version = data->ptr[0];
    uint8_t status = data->ptr[1];
    uint8_t reserved = data->ptr[2];
    uint8_t atype = data->ptr[3];

    /* Verify SOCKS version */
    if (version != AWS_SOCKS5_VERSION) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKS5,
            "id=static: Unexpected SOCKS version in connect response, expected %d, got %d",
            AWS_SOCKS5_VERSION,
            version);
        context->state = AWS_SOCKS5_STATE_ERROR;
        return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_MALFORMED_RESPONSE);
    }

    /* Verify reserved byte */
    if (reserved != AWS_SOCKS5_RESERVED) {
        AWS_LOGF_WARN(
            AWS_LS_IO_SOCKS5,
            "id=static: Unexpected reserved byte in SOCKS5 connect response, expected 0, got %d",
            reserved);
        /* Continue anyway, as this isn't critical */
    }

    /* Check status code */
    if (status != AWS_SOCKS5_STATUS_SUCCESS) {
        /* Handle specific error codes */
        context->state = AWS_SOCKS5_STATE_ERROR;
        
        switch (status) {
            case AWS_SOCKS5_STATUS_GENERAL_FAILURE:
                AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: SOCKS5 server reported general failure");
                return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_GENERAL_FAILURE);
                
            case AWS_SOCKS5_STATUS_CONNECTION_NOT_ALLOWED:
                AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: SOCKS5 server rejected connection");
                return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_REJECTED);
                
            case AWS_SOCKS5_STATUS_NETWORK_UNREACHABLE:
                AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: SOCKS5 server reported network unreachable");
                return aws_raise_error(AWS_IO_SOCKET_NO_ROUTE_TO_HOST);
                
            case AWS_SOCKS5_STATUS_HOST_UNREACHABLE:
                AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: SOCKS5 server reported host unreachable");
                return aws_raise_error(AWS_IO_DNS_NO_ADDRESS_FOR_HOST);
                
            case AWS_SOCKS5_STATUS_CONNECTION_REFUSED:
                AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: SOCKS5 server reported connection refused");
                return aws_raise_error(AWS_IO_SOCKET_CONNECTION_REFUSED);
                
            case AWS_SOCKS5_STATUS_TTL_EXPIRED:
                AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: SOCKS5 server reported TTL expired");
                return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_TTL_EXPIRED);
                
            case AWS_SOCKS5_STATUS_COMMAND_NOT_SUPPORTED:
                AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: SOCKS5 server does not support the CONNECT command");
                return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_COMMAND_NOT_SUPPORTED);
                
            case AWS_SOCKS5_STATUS_ADDRESS_TYPE_NOT_SUPPORTED:
                AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: SOCKS5 server does not support the address type");
                return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_UNSUPPORTED_ADDRESS_TYPE);
                
            default:
                AWS_LOGF_ERROR(AWS_LS_IO_SOCKS5, "id=static: SOCKS5 server returned unknown error: %d", status);
                return aws_raise_error(AWS_IO_SOCKS5_PROXY_ERROR_CONNECTION_FAILED);
        }
    }
    
    /* Connection successful */
    context->state = AWS_SOCKS5_STATE_RESPONSE_RECEIVED;

    /* Parse bound address and port if needed (for informational purposes)
     * Note: We don't actually need to use the bound address/port for CONNECT,
     * but we'll log it for debugging purposes.
     */
    size_t addr_offset = 4;
    size_t addr_size = 0;

    switch (atype) {
        case AWS_SOCKS5_ATYP_DOMAIN: {
            /* Domain address format: [len][domain]... */
            uint8_t dom_len = data->ptr[addr_offset];
            addr_offset++;
            addr_size = dom_len;
            
            if (data->len < addr_offset + addr_size + 2) {
                AWS_LOGF_WARN(AWS_LS_IO_SOCKS5, "id=static: Truncated domain address in SOCKS5 response");
                /* Continue anyway, as we've already confirmed success */
            } else {
                AWS_LOGF_DEBUG(
                    AWS_LS_IO_SOCKS5,
                    "id=static: SOCKS5 server bound to domain %.*s",
                    (int)addr_size,
                    (char *)(data->ptr + addr_offset));
            }
            break;
        }
            
        case AWS_SOCKS5_ATYP_IPV4:
            /* IPv4 address (4 bytes) */
            addr_size = 4;
            if (data->len < addr_offset + addr_size + 2) {
                AWS_LOGF_WARN(AWS_LS_IO_SOCKS5, "id=static: Truncated IPv4 address in SOCKS5 response");
            } else {
                AWS_LOGF_DEBUG(
                    AWS_LS_IO_SOCKS5,
                    "id=static: SOCKS5 server bound to IPv4 address %d.%d.%d.%d",
                    data->ptr[addr_offset],
                    data->ptr[addr_offset + 1],
                    data->ptr[addr_offset + 2],
                    data->ptr[addr_offset + 3]);
            }
            break;
            
        case AWS_SOCKS5_ATYP_IPV6:
            /* IPv6 address (16 bytes) */
            addr_size = 16;
            if (data->len < addr_offset + addr_size + 2) {
                AWS_LOGF_WARN(AWS_LS_IO_SOCKS5, "id=static: Truncated IPv6 address in SOCKS5 response");
            }
            break;
            
        default:
            AWS_LOGF_WARN(
                AWS_LS_IO_SOCKS5,
                "id=static: Unknown address type in SOCKS5 connect response: %d",
                atype);
            /* Continue anyway, as we've already confirmed success */
            break;
    }
    
    /* Read port if we have enough data */
    if (data->len >= addr_offset + addr_size + 2) {
        uint16_t port;
        memcpy(&port, data->ptr + addr_offset + addr_size, sizeof(uint16_t));
        port = ntohs(port);
        
        AWS_LOGF_DEBUG(AWS_LS_IO_SOCKS5, "id=static: SOCKS5 server bound to port %d", port);
    }

    context->state = AWS_SOCKS5_STATE_CONNECTED;

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKS5, "id=static: SOCKS5 connection established successfully");

    return AWS_OP_SUCCESS;
}
