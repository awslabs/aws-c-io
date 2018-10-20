#ifndef AWS_IO_TLS_HANDLER_H
#define AWS_IO_TLS_HANDLER_H
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
#include <aws/common/byte_buf.h>
#include <aws/io/io.h>

struct aws_channel_slot;
struct aws_channel_handler;

typedef enum aws_tls_versions {
    AWS_IO_SSLv3,
    AWS_IO_TLSv1,
    AWS_IO_TLSv1_1,
    AWS_IO_TLSv1_2,
    AWS_IO_TLSv1_3,
    AWS_IO_TLS_VER_SYS_DEFAULTS = 128,
} aws_tls_versions;

struct aws_tls_ctx {
    struct aws_allocator *alloc;
    void *impl;
};

typedef void(aws_tls_on_negotiation_result_fn)(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    int err_code,
    void *user_data);

typedef void(aws_tls_on_data_read_fn)(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *buffer,
    void *user_data);

typedef void(aws_tls_on_error_fn)(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    int err,
    const char *message,
    void *user_data);

struct aws_tls_connection_options {
    /** semi-colon delimited list of protocols. Example:
     *  h2;http/1.1
     */
    const char *alpn_list;
    /**
     * Serves two purposes. If SNI is supported (hint... it is),
     * this sets the SNI extension.
     *
     * For X.509 validation this also sets the name that will be used
     * for verifying the subj alt name and common name of the peer's certificate.
     */
    const char *server_name;
    aws_tls_on_negotiation_result_fn *on_negotiation_result;
    aws_tls_on_data_read_fn *on_data_read;
    aws_tls_on_error_fn *on_error;
    void *user_data;
    /**
     * default is true for clients and false for servers.
     * You should not change this default for clients unless
     * you're testing and don't want to fool around with CA trust stores.
     * Before you release to production, you'll want to turn this back on
     * and add your custom CA to the aws_tls_ctx_options.
     *
     * If you set this in server mode, it enforces client authentication.
     */
    bool verify_peer;
    bool advertise_alpn_message;
};

struct aws_tls_ctx_options {
    /** minium tls version to use. If you just want us to use the
     *  system defaults, you can set: AWS_IO_TLS_VER_SYS_DEFAULTS. This
     *  has the added benefit of automatically picking up new TLS versions
     *  as your OS or distribution adds support.
     */
    aws_tls_versions minimum_tls_version;
    /**
     * A PEM armored PKCS#7 collection of CAs you want to trust. Only
     * use this if it's a CA not currently installed on your system.
     */
    const char *ca_file;
    /**
     * Only used on Unix systems using an openssl style trust API.
     * this is typically something like /etc/pki/tls/certs/"
     */
    const char *ca_path;
    /**
     * Sets ctx wide alpn string. This is most usefull for servers.
     * This is a semi-colon delimited list. example:
     * h2;http/1.1
     */
    const char *alpn_list;
    /**
     * This is the path to PEM armored PKCS#7
     * certificate file. It is supported on every
     * operating system.
     *
     * Also, on windows, this can be the path to a system
     * installed certficate/private key pair. Example:
     * CurrentUser\\MY\\<thumprint>
     */
    const char *certificate_path;
    /**
     * The path to a PEM armored PKCS#7 private key.
     *
     * On windows, this field should be NULL only if you are
     * using a system installed certficate.
     */
    const char *private_key_path;
    /**
     * Apple Only!
     *
     * On Apple OS you can also use a pkcs#12 file for your certificate
     * and private key. This is the path to that file.
     */
    const char *pkcs12_path;
    /**
     * Password for the pkcs12 file in pkcs12_path.
     */
    const char *pkcs12_password;
    /**
     * default is true for clients and false for servers.
     * You should not change this default for clients unless
     * you're testing and don't want to fool around with CA trust stores.
     * Before you release to production, you'll want to turn this back on
     * and add your custom CA to the aws_tls_ctx_options.
     *
     * If you set this in server mode, it enforces client authentication.
     */
    bool verify_peer;
};

struct aws_tls_negotiated_protocol_message {
    struct aws_byte_buf protocol;
};

static const int AWS_TLS_NEGOTIATED_PROTOCOL_MESSAGE = 0x01;

typedef struct aws_channel_handler *(
    *aws_tls_on_protocol_negotiated)(struct aws_channel_slot *new_slot, struct aws_byte_buf *protocol, void *user_data);

#ifdef __cplusplus
extern "C" {
#endif
/******************************** tls options init stuff ***********************/
AWS_IO_API void aws_tls_ctx_options_init_default_client(struct aws_tls_ctx_options *options);
AWS_IO_API void aws_tls_ctx_options_init_client_mtls(
    struct aws_tls_ctx_options *options,
    const char *cert_path,
    const char *pkey_path);
AWS_IO_API void aws_tls_ctx_options_init_client_mtls_pkcs12(
    struct aws_tls_ctx_options *options,
    const char *pkcs12_path,
    const char *pkcs_pwd);
AWS_IO_API void aws_tls_ctx_options_init_default_server(
    struct aws_tls_ctx_options *options,
    const char *cert_path,
    const char *pkey_path);
AWS_IO_API void aws_tls_ctx_options_init_server_pkcs12(
    struct aws_tls_ctx_options *options,
    const char *pkcs12_path,
    const char *pkcs_pwd);
AWS_IO_API void aws_tls_ctx_options_set_alpn_list(struct aws_tls_ctx_options *options, const char *alpn_list);
AWS_IO_API void aws_tls_ctx_options_set_verify_peer(struct aws_tls_ctx_options *options, bool verify_peer);
AWS_IO_API void aws_tls_ctx_options_override_default_trust_store(
    struct aws_tls_ctx_options *options,
    const char *ca_path,
    const char *ca_file);

AWS_IO_API void aws_tls_connection_options_init_from_ctx_options(
    struct aws_tls_connection_options *conn_options,
    const struct aws_tls_ctx_options *ctx_options);

AWS_IO_API void aws_tls_connection_options_set_callbacks(
    struct aws_tls_connection_options *conn_options,
    aws_tls_on_negotiation_result_fn *on_negotiation_result,
    aws_tls_on_data_read_fn *on_data_read,
    aws_tls_on_error_fn *on_error,
    void *user_data);

AWS_IO_API void aws_tls_connection_options_set_server_name(
    struct aws_tls_connection_options *conn_options,
    const char *server_name);

AWS_IO_API void aws_tls_connection_options_set_alpn_list(
    struct aws_tls_connection_options *conn_options,
    const char *alpn_list);
AWS_IO_API void aws_tls_connection_options_set_verify_peer(
    struct aws_tls_connection_options *conn_options,
    bool verify_peer);

/********************************* stuff that actually does work *********************************/
AWS_IO_API void aws_tls_init_static_state(struct aws_allocator *alloc);
AWS_IO_API void aws_tls_clean_up_static_state(void);
AWS_IO_API void aws_tls_clean_up_tl_state(void);

AWS_IO_API bool aws_tls_is_alpn_available(void);

AWS_IO_API struct aws_channel_handler *aws_tls_client_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_ctx *ctx,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot);

AWS_IO_API struct aws_channel_handler *aws_tls_server_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_ctx *ctx,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot);

AWS_IO_API struct aws_channel_handler *aws_tls_alpn_handler_new(
    struct aws_allocator *allocator,
    aws_tls_on_protocol_negotiated on_protocol_negotiated,
    void *user_data);

AWS_IO_API int aws_tls_client_handler_start_negotiation(struct aws_channel_handler *handler);

AWS_IO_API struct aws_tls_ctx *aws_tls_server_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options);

AWS_IO_API struct aws_tls_ctx *aws_tls_client_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options);

AWS_IO_API void aws_tls_ctx_destroy(struct aws_tls_ctx *ctx);

AWS_IO_API int aws_tls_handler_write(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *buf,
    aws_channel_on_message_write_completed_fn *on_write_completed,
    void *completion_user_data);

AWS_IO_API struct aws_byte_buf aws_tls_handler_protocol(struct aws_channel_handler *handler);
AWS_IO_API struct aws_byte_buf aws_tls_handler_server_name(struct aws_channel_handler *handler);

#ifdef __cplusplus
}
#endif

#endif /*AWS_IO_TLS_HANDLER_H*/
