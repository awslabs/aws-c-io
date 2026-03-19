#ifndef AWS_IO_TLS_CHANNEL_HANDLER_PRIVATE_H
#define AWS_IO_TLS_CHANNEL_HANDLER_PRIVATE_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/io/io.h>
#include <aws/io/tls_channel_handler.h>

struct aws_tls_vtable {
    void (*init_static_state)(struct aws_allocator *alloc);
    void (*clean_up_static_state)(void);
    const char *(*determine_default_pki_dir)(void);
    const char *(*determine_default_pki_ca_file)(void);
    bool (*is_alpn_available)(void);
    bool (*is_cipher_pref_supported)(enum aws_tls_cipher_pref cipher_pref);
    int (*client_handler_start_negotiation)(struct aws_channel_handler *handler);
    void (*key_operation_complete)(struct aws_tls_key_operation *operation, struct aws_byte_cursor output);
    void (*key_operation_complete_with_error)(struct aws_tls_key_operation *operation, int error_code);
    struct aws_byte_cursor (*key_operation_get_input)(const struct aws_tls_key_operation *operation);
    enum aws_tls_key_operation_type (*key_operation_get_type)(const struct aws_tls_key_operation *operation);
    enum aws_tls_signature_algorithm (*key_operation_get_signature_algorithm)(
        const struct aws_tls_key_operation *operation);
    enum aws_tls_hash_algorithm (*key_operation_get_digest_algorithm)(const struct aws_tls_key_operation *operation);
    struct aws_byte_buf (*handler_protocol)(struct aws_channel_handler *handler);
    struct aws_byte_buf (*handler_server_name)(struct aws_channel_handler *handler);
    struct aws_channel_handler *(*client_handler_new)(
        struct aws_allocator *allocator,
        struct aws_tls_connection_options *options,
        struct aws_channel_slot *slot);
    struct aws_channel_handler *(*server_handler_new)(
        struct aws_allocator *allocator,
        struct aws_tls_connection_options *options,
        struct aws_channel_slot *slot);
    struct aws_tls_ctx *(*server_ctx_new)(struct aws_allocator *alloc, const struct aws_tls_ctx_options *options);
    struct aws_tls_ctx *(*client_ctx_new)(struct aws_allocator *alloc, const struct aws_tls_ctx_options *options);
};

AWS_EXTERN_C_BEGIN

#ifdef _WIN32
/**
 * Force to use schannel creds. Default to false.
 * For windows build above WINDOWS_BUILD_1809, we have deprecated CHANNEL_CREDS.
 * Set the value to true to force to use CHANNEL_CREDS.
 */
AWS_IO_API void aws_windows_force_schannel_creds(bool use_schannel_creds);
#endif

AWS_EXTERN_C_END
#endif /* AWS_IO_TLS_CHANNEL_HANDLER_PRIVATE_H */
