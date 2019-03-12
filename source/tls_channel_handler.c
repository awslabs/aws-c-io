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
#include <aws/io/file_utils.h>
#include <aws/io/tls_channel_handler.h>

void aws_tls_ctx_options_init_default_client(struct aws_tls_ctx_options *options, struct aws_allocator *allocator) {
    AWS_ZERO_STRUCT(*options);
    options->allocator = allocator;
    options->minimum_tls_version = AWS_IO_TLS_VER_SYS_DEFAULTS;
    options->verify_peer = true;
    options->max_fragment_size = g_aws_channel_max_fragment_size;
}

void aws_tls_ctx_options_clean_up(struct aws_tls_ctx_options *options) {
    if (options->ca_file.len) {
        aws_byte_buf_clean_up(&options->ca_file);
    }

    if (options->ca_path) {
        aws_string_destroy(options->ca_path);
    }

    if (options->certificate.len) {
        aws_byte_buf_clean_up(&options->certificate);
    }

    if (options->private_key.len) {
        aws_secure_zero(options->private_key.buffer, options->private_key.len);
        aws_byte_buf_clean_up(&options->private_key);
    }

#ifdef __APPLE__
    if (options->pkcs12.len) {
        aws_secure_zero(options->pkcs12.buffer, options->pkcs12.len);
        aws_byte_buf_clean_up(&options->pkcs12);
    }

    if (options->pkcs12_password.len) {
        aws_secure_zero(options->pkcs12_pwd.buffer, options->pkcs12_pwd.len);
        aws_byte_buf_clean_up(&options->pkcs12_password);
    }
#endif

    if (options->alpn_list) {
        aws_string_destroy(options->alpn_list);
    }

    AWS_ZERO_STRUCT(*options);
}

int aws_tls_ctx_options_init_client_mtls(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cert,
    struct aws_byte_cursor *pkey) {
    AWS_ZERO_STRUCT(*options);
    options->minimum_tls_version = AWS_IO_TLS_VER_SYS_DEFAULTS;
    options->verify_peer = true;
    options->allocator = allocator;
    options->max_fragment_size = g_aws_channel_max_fragment_size;

    if (aws_byte_buf_init_copy_from_cursor(&options->certificate, allocator, *cert)) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_init_copy_from_cursor(&options->private_key, allocator, *pkey)) {
        aws_byte_buf_clean_up(&options->certificate);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_tls_ctx_options_init_client_mtls_from_path(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    const char *cert_path,
    const char *pkey_path) {
    AWS_ZERO_STRUCT(*options);
    options->minimum_tls_version = AWS_IO_TLS_VER_SYS_DEFAULTS;
    options->verify_peer = true;
    options->allocator = allocator;
    options->max_fragment_size = g_aws_channel_max_fragment_size;

    if (aws_byte_buf_init_from_file(&options->certificate, allocator, cert_path)) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_init_from_file(&options->private_key, allocator, pkey_path)) {
        aws_byte_buf_clean_up(&options->certificate);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

#ifdef __APPLE__
int aws_tls_ctx_options_init_client_mtls_pkcs12_from_path(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    const char *pkcs12_path,
    struct aws_byte_cursor *pkcs_pwd) {
    AWS_ZERO_STRUCT(*options);
    options->minimum_tls_version = AWS_IO_TLS_VER_SYS_DEFAULTS;
    options->verify_peer = true;
    options->allocator = allocator;
    options->max_fragment_size = g_aws_channel_max_fragment_size;

    if (aws_byte_buf_init_from_file(&options->pkcs12, allocator, pkcs12_path)) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_init_copy_from_cursor(&options->pkcs12_password, allocator, *pkcs_pwd)) {
        aws_byte_buf_clean_up(&options->pkcs12);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_tls_ctx_options_init_client_mtls_pkcs12(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    struct aws_byte_cursor *pkcs12,
    struct aws_byte_cursor *pkcs_pwd) {
    AWS_ZERO_STRUCT(*options);
    options->minimum_tls_version = AWS_IO_TLS_VER_SYS_DEFAULTS;
    options->verify_peer = true;
    options->allocator = allocator;
    options->max_fragment_size = g_aws_channel_max_fragment_size;

    if (aws_byte_buf_init_copy_from_cursor(&options->pkcs12, allocator, *pkcs12)) {
        return AWS_OP_ERR;
    }

    if (aws_byte_buf_init_copy_from_cursor(&options->pkcs12_password, allocator, *pkcs_pwd)) {
        aws_byte_buf_clean_up(&options->pkcs12);
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_tls_ctx_options_init_server_pkcs12_from_path(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    const char *pkcs12_path,
    struct aws_byte_cursor *pkcs_pwd) {
    if (aws_tls_ctx_options_init_client_mtls_pkcs12_from_path(options, allocator, pkcs12_path, pkcs_pwd)) {
        return AWS_OP_ERR;
    }

    options->verify_peer = false;
    return AWS_OP_SUCCESS;
}

int aws_tls_ctx_options_init_server_pkcs12(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    struct aws_byte_cursor *pkcs12,
    struct aws_byte_cursor *pkcs_pwd) {
    if (aws_tls_ctx_options_init_client_mtls_pkcs12(options, allocator, pkcs12, pkcs_pwd)) {
        return AWS_OP_ERR;
    }

    options->verify_peer = false;
    return AWS_OP_SUCCESS;
}

#endif /* __APPLE__ */

int aws_tls_ctx_options_init_default_server_from_path(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    const char *cert_path,
    const char *pkey_path) {
    if (aws_tls_ctx_options_init_client_mtls_from_path(options, allocator, cert_path, pkey_path)) {
        return AWS_OP_ERR;
    }

    options->verify_peer = false;
    return AWS_OP_SUCCESS;
}

int aws_tls_ctx_options_init_default_server(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cert,
    struct aws_byte_cursor *pkey) {
    if (aws_tls_ctx_options_init_client_mtls(options, allocator, cert, pkey)) {
        return AWS_OP_ERR;
    }

    options->verify_peer = false;
    return AWS_OP_SUCCESS;
}

int aws_tls_ctx_options_set_alpn_list(struct aws_tls_ctx_options *options, const char *alpn_list) {
    options->alpn_list = aws_string_new_from_c_str(options->allocator, alpn_list);
    if (!options->alpn_list) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

void aws_tls_ctx_options_set_verify_peer(struct aws_tls_ctx_options *options, bool verify_peer) {
    options->verify_peer = verify_peer;
}

int aws_tls_ctx_options_override_default_trust_store_from_path(
    struct aws_tls_ctx_options *options,
    const char *ca_path,
    const char *ca_file) {

    if (ca_path) {
        options->ca_path = aws_string_new_from_c_str(options->allocator, ca_path);
        if (!options->ca_path) {
            return AWS_OP_ERR;
        }
    }

    if (ca_file) {
        if (aws_byte_buf_init_from_file(&options->ca_file, options->allocator, ca_file)) {
            return AWS_OP_ERR;
        }
    }

    return AWS_OP_SUCCESS;
}

int aws_tls_ctx_options_override_default_trust_store(
    struct aws_tls_ctx_options *options,
    struct aws_byte_cursor *ca_file) {

    if (aws_byte_buf_init_copy_from_cursor(&options->ca_file, options->allocator, *ca_file)) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

void aws_tls_connection_options_init_from_ctx(
    struct aws_tls_connection_options *conn_options,
    struct aws_tls_ctx *ctx) {
    AWS_ZERO_STRUCT(*conn_options);
    /* the assumption here, is that if it was set in the context, we WANT it to be NULL here unless it's different.
     * so only set verify peer at this point. */
    conn_options->ctx = ctx;
}

void aws_tls_connection_options_clean_up(struct aws_tls_connection_options *connection_options) {
    if (connection_options->alpn_list) {
        aws_string_destroy(connection_options->alpn_list);
    }

    if (connection_options->server_name) {
        aws_string_destroy(connection_options->server_name);
    }

    AWS_ZERO_STRUCT(*connection_options);
}

void aws_tls_connection_options_set_callbacks(
    struct aws_tls_connection_options *conn_options,
    aws_tls_on_negotiation_result_fn *on_negotiation_result,
    aws_tls_on_data_read_fn *on_data_read,
    aws_tls_on_error_fn *on_error,
    void *user_data) {
    conn_options->on_negotiation_result = on_negotiation_result;
    conn_options->on_data_read = on_data_read;
    conn_options->on_error = on_error;
    conn_options->user_data = user_data;
}

int aws_tls_connection_options_set_server_name(
    struct aws_tls_connection_options *conn_options,
    struct aws_allocator *allocator,
    struct aws_byte_cursor *server_name) {
    conn_options->server_name = aws_string_new_from_array(allocator, server_name->ptr, server_name->len);
    if (!conn_options->server_name) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

int aws_tls_connection_options_set_alpn_list(
    struct aws_tls_connection_options *conn_options,
    struct aws_allocator *allocator,
    const char *alpn_list) {

    conn_options->alpn_list = aws_string_new_from_c_str(allocator, alpn_list);
    if (!conn_options->alpn_list) {
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}
