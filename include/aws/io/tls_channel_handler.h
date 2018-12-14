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

enum aws_tls_versions {
    AWS_IO_SSLv3,
    AWS_IO_TLSv1,
    AWS_IO_TLSv1_1,
    AWS_IO_TLSv1_2,
    AWS_IO_TLSv1_3,
    AWS_IO_TLS_VER_SYS_DEFAULTS = 128,
};

struct aws_tls_ctx {
    struct aws_allocator *alloc;
    void *impl;
};

/**
 * Invoked upon completion of the TLS handshake. If successful error_code will be AWS_OP_SUCCESS, otherwise
 * the negotiation failed and immediately after this function is invoked, the channel will be shutting down.
 */
typedef void(aws_tls_on_negotiation_result_fn)(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    int error_code,
    void *user_data);

/**
 * Only used if the TLS handler is the last handler in the channel. This allows you to read any data that
 * was read and decrypted by the handler. If you have application protocol channel handlers, this function
 * is not necessary and certainly not recommended.
 */
typedef void(aws_tls_on_data_read_fn)(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *buffer,
    void *user_data);

/**
 * Invoked when an error occurs in the TLS state machine AFTER the handshake has completed. This function should only
 * be used in conjunction with the rules of aws_tls_on_data_read_fn.
 */
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
    struct aws_tls_ctx *ctx;
    bool advertise_alpn_message;
};

struct aws_tls_ctx_options {
    /**
     *  minimum tls version to use. If you just want us to use the
     *  system defaults, you can set: AWS_IO_TLS_VER_SYS_DEFAULTS. This
     *  has the added benefit of automatically picking up new TLS versions
     *  as your OS or distribution adds support.
     */
    enum aws_tls_versions minimum_tls_version;
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
     * Sets ctx wide alpn string. This is most useful for servers.
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

    /** max tls fragment size. Default is the value of g_aws_channel_max_fragment_size. */
    size_t max_fragment_size;

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

AWS_IO_API void aws_tls_connection_options_init_from_ctx(
    struct aws_tls_connection_options *conn_options,
    struct aws_tls_ctx *ctx);

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

/********************************* TLS context and state management *********************************/
/**
 * Initializes static state for the tls implementation. This must be called before any attempts
 * to create an aws_tls_ctx or tls handler.
 */
AWS_IO_API void aws_tls_init_static_state(struct aws_allocator *alloc);

/**
 * Cleans up static state for the tls implementation.
 */
AWS_IO_API void aws_tls_clean_up_static_state(void);

/**
 * Cleans up any lazily initialized thread local state for the tls implementation.
 */
AWS_IO_API void aws_tls_clean_up_thread_local_state(void);

/**
 * Returns true if alpn is available in the underlying tls implementation.
 * This function should always be called before setting an alpn list.
 */
AWS_IO_API bool aws_tls_is_alpn_available(void);

/**
 * Creates a new tls channel handler in client mode. Options will be copied.
 * You must call aws_tls_client_handler_start_negotiation and wait on the
 * aws_tls_on_negotiation_result_fn callback before the handler can begin processing
 * application data.
 */
AWS_IO_API struct aws_channel_handler *aws_tls_client_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot);

/**
 * Creates a new tls channel handler in server mode. Options will be copied.
 * You must wait on the aws_tls_on_negotiation_result_fn callback before the handler can begin processing
 * application data.
 */
AWS_IO_API struct aws_channel_handler *aws_tls_server_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot);

/**
 * Creates a channel handler, for client or server mode, that handles alpn. This isn't necessarily required
 * since you can always call aws_tls_handler_protocol in the aws_tls_on_negotiation_result_fn callback, but
 * this makes channel bootstrap easier to handle.
 */
AWS_IO_API struct aws_channel_handler *aws_tls_alpn_handler_new(
    struct aws_allocator *allocator,
    aws_tls_on_protocol_negotiated on_protocol_negotiated,
    void *user_data);

/**
 * Kicks off the negotiation process. This function must be called when in client mode to initiate the
 * TLS handshake. Once the handshake has completed the aws_tls_on_negotiation_result_fn will be invoked.
 */
AWS_IO_API int aws_tls_client_handler_start_negotiation(struct aws_channel_handler *handler);

/**
 * Creates a new server ctx. This ctx can be used for the lifetime of the application assuming you want the same
 * options for every incoming connection. Options will be copied.
 */
AWS_IO_API struct aws_tls_ctx *aws_tls_server_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options);

/**
 * Creates a new client ctx. This ctx can be used for the lifetime of the application assuming you want the same
 * options for every outgoing connection. Options will be copied.
 */
AWS_IO_API struct aws_tls_ctx *aws_tls_client_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options);

/**
 * Destroys the output from aws_tls_server_ctx_new and aws_tls_client_ctx_new.
 */
AWS_IO_API void aws_tls_ctx_destroy(struct aws_tls_ctx *ctx);

/**
 * Not necessary if you are installing more handlers into the channel, but if you just want to have TLS for arbitrary
 * data and use the channel handler directly, this function allows you to write data to the channel and have it
 * encrypted.
 */
AWS_IO_API int aws_tls_handler_write(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_byte_buf *buf,
    aws_channel_on_message_write_completed_fn *on_write_completed,
    void *completion_user_data);

/**
 * Returns a byte buffer by copy of the negotiated protocols. If there is no agreed upon protocol, len will be 0 and
 * buffer will be NULL.
 */
AWS_IO_API struct aws_byte_buf aws_tls_handler_protocol(struct aws_channel_handler *handler);

/**
 * Client mode only. This is the server name that was used for SNI and host name validation.
 */
AWS_IO_API struct aws_byte_buf aws_tls_handler_server_name(struct aws_channel_handler *handler);

#ifdef __cplusplus
}
#endif

#endif /*AWS_IO_TLS_HANDLER_H*/
