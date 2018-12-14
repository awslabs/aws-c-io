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
#include <aws/io/tls_channel_handler.h>

void aws_tls_ctx_options_init_default_client(struct aws_tls_ctx_options *options) {
    AWS_ZERO_STRUCT(*options);
    options->minimum_tls_version = AWS_IO_TLS_VER_SYS_DEFAULTS;
    options->verify_peer = true;
    options->max_fragment_size = g_aws_channel_max_fragment_size;
}

void aws_tls_ctx_options_init_client_mtls(
    struct aws_tls_ctx_options *options,
    const char *cert_path,
    const char *pkey_path) {
    AWS_ZERO_STRUCT(*options);
    options->minimum_tls_version = AWS_IO_TLS_VER_SYS_DEFAULTS;
    options->verify_peer = true;
    options->certificate_path = cert_path;
    options->private_key_path = pkey_path;
    options->max_fragment_size = g_aws_channel_max_fragment_size;
}

void aws_tls_ctx_options_init_client_mtls_pkcs12(
    struct aws_tls_ctx_options *options,
    const char *pkcs12_path,
    const char *pkcs_pwd) {
    AWS_ZERO_STRUCT(*options);
    options->minimum_tls_version = AWS_IO_TLS_VER_SYS_DEFAULTS;
    options->verify_peer = true;
    options->pkcs12_path = pkcs12_path;
    options->pkcs12_password = pkcs_pwd;
    options->max_fragment_size = g_aws_channel_max_fragment_size;
}

void aws_tls_ctx_options_init_default_server(
    struct aws_tls_ctx_options *options,
    const char *cert_path,
    const char *pkey_path) {
    AWS_ZERO_STRUCT(*options);
    options->minimum_tls_version = AWS_IO_TLS_VER_SYS_DEFAULTS;
    options->verify_peer = false;
    options->certificate_path = cert_path;
    options->private_key_path = pkey_path;
    options->max_fragment_size = g_aws_channel_max_fragment_size;
}

void aws_tls_ctx_options_init_server_pkcs12(
    struct aws_tls_ctx_options *options,
    const char *pkcs12_path,
    const char *pkcs_pwd) {
    AWS_ZERO_STRUCT(*options);
    options->minimum_tls_version = AWS_IO_TLS_VER_SYS_DEFAULTS;
    options->verify_peer = false;
    options->pkcs12_path = pkcs12_path;
    options->pkcs12_password = pkcs_pwd;
    options->max_fragment_size = g_aws_channel_max_fragment_size;
}

void aws_tls_ctx_options_set_alpn_list(struct aws_tls_ctx_options *options, const char *alpn_list) {
    options->alpn_list = alpn_list;
}

void aws_tls_ctx_options_set_verify_peer(struct aws_tls_ctx_options *options, bool verify_peer) {
    options->verify_peer = verify_peer;
}

void aws_tls_ctx_options_override_default_trust_store(
    struct aws_tls_ctx_options *options,
    const char *ca_path,
    const char *ca_file) {
    options->ca_path = ca_path;
    options->ca_file = ca_file;
}

void aws_tls_connection_options_init_from_ctx(
    struct aws_tls_connection_options *conn_options,
    struct aws_tls_ctx *ctx) {
    AWS_ZERO_STRUCT(*conn_options);
    /* the assumption here, is that if it was set in the context, we WANT it to be NULL here unless it's different.
     * so only set verify peer at this point. */
    conn_options->ctx = ctx;
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

void aws_tls_connection_options_set_server_name(
    struct aws_tls_connection_options *conn_options,
    const char *server_name) {
    conn_options->server_name = server_name;
}

void aws_tls_connection_options_set_alpn_list(struct aws_tls_connection_options *conn_options, const char *alpn_list) {
    conn_options->alpn_list = alpn_list;
}
