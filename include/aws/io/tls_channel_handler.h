#ifndef AWS_IO_TLS_CHANNEL_HANDLER_H
#define AWS_IO_TLS_CHANNEL_HANDLER_H
/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/common/byte_buf.h>
#include <aws/common/ref_count.h>
#include <aws/io/io.h>

struct aws_channel_slot;
struct aws_channel_handler;
struct aws_string;

enum aws_tls_versions {
    AWS_IO_SSLv3,
    AWS_IO_TLSv1,
    AWS_IO_TLSv1_1,
    AWS_IO_TLSv1_2,
    AWS_IO_TLSv1_3,
    AWS_IO_TLS_VER_SYS_DEFAULTS = 128,
};

enum aws_tls_cipher_pref {
    AWS_IO_TLS_CIPHER_PREF_SYSTEM_DEFAULT = 0,
    AWS_IO_TLS_CIPHER_PREF_KMS_PQ_TLSv1_0_2019_06 = 1,
    AWS_IO_TLS_CIPHER_PREF_KMS_PQ_SIKE_TLSv1_0_2019_11 = 2,
    AWS_IO_TLS_CIPHER_PREF_KMS_PQ_TLSv1_0_2020_02 = 3,
    AWS_IO_TLS_CIPHER_PREF_KMS_PQ_SIKE_TLSv1_0_2020_02 = 4,
    AWS_IO_TLS_CIPHER_PREF_KMS_PQ_TLSv1_0_2020_07 = 5,

    AWS_IO_TLS_CIPHER_PREF_END_RANGE = 0xFFFF
};

struct aws_tls_ctx {
    struct aws_allocator *alloc;
    void *impl;
    struct aws_ref_count ref_count;
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
    struct aws_string *alpn_list;
    /**
     * Serves two purposes. If SNI is supported (hint... it is),
     * this sets the SNI extension.
     *
     * For X.509 validation this also sets the name that will be used
     * for verifying the subj alt name and common name of the peer's certificate.
     */
    struct aws_string *server_name;
    aws_tls_on_negotiation_result_fn *on_negotiation_result;
    aws_tls_on_data_read_fn *on_data_read;
    aws_tls_on_error_fn *on_error;
    void *user_data;
    struct aws_tls_ctx *ctx;
    bool advertise_alpn_message;
    uint32_t timeout_ms;
};

struct aws_tls_ctx_options {
    struct aws_allocator *allocator;

    /**
     *  minimum tls version to use. If you just want us to use the
     *  system defaults, you can set: AWS_IO_TLS_VER_SYS_DEFAULTS. This
     *  has the added benefit of automatically picking up new TLS versions
     *  as your OS or distribution adds support.
     */
    enum aws_tls_versions minimum_tls_version;

    /**
     * The Cipher Preference List to use
     */
    enum aws_tls_cipher_pref cipher_pref;

    /**
     * A PEM armored PKCS#7 collection of CAs you want to trust as a string.
     * Only use this if it's a CA not currently installed on your system.
     */
    struct aws_byte_buf ca_file;
    /**
     * Only used on Unix systems using an openssl style trust API.
     * this is typically something like /etc/pki/tls/certs/"
     */
    struct aws_string *ca_path;

    /**
     * If true, the user called a deprecated variant of override_default_trust_store(...)
     * and the legacy behavior should be used. The legacy behavior was inconsistent
     * about "overriding" vs "adding" to the default trust store when a custom CA is set.
     *
     * WINDOWS (Secure Channel): Default trust store IS NOT used.
     *
     * APPLE (Secure Transport): Default trust store IS used.
     *
     * LINUX (s2n / libcrypto): libcrypto's default trust store IS used (configured at build time via --openssldir).
     *      But DO NOT use the default trust store file/directory we found by searching common locations at startup.
     */
    bool legacy_ca_override;

    /**
     * Sets ctx wide alpn string. This is most useful for servers.
     * This is a semi-colon delimited list. example:
     * h2;http/1.1
     */
    struct aws_string *alpn_list;
    /**
     * A PEM armored PKCS#7 certificate as a string.
     * It is supported on every operating system.
     */
    struct aws_byte_buf certificate;

#ifdef _WIN32
    /** The path to a system
     * installed certficate/private key pair. Example:
     * CurrentUser\\MY\\<thumprint>
     */
    const char *system_certificate_path;
#endif

    /**
     * A PEM armored PKCS#7 private key as a string.
     *
     * On windows, this field should be NULL only if you are
     * using a system installed certficate.
     */
    struct aws_byte_buf private_key;

#ifdef __APPLE__
    /**
     * Apple Only!
     *
     * On Apple OS you can also use a pkcs#12 for your certificate
     * and private key. This is the contents the certificate.
     */
    struct aws_byte_buf pkcs12;

    /**
     * Password for the pkcs12 data in pkcs12.
     */
    struct aws_byte_buf pkcs12_password;

#    if !defined(AWS_OS_IOS)
    /**
     * On Apple OS you can also use a custom keychain instead of
     * the default keychain of the account.
     */
    struct aws_string *keychain_path;
#    endif

#endif

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

    /**
     * For use when adding BYO_CRYPTO implementations. You can set extra data in here for use with your TLS
     * implementation.
     */
    void *ctx_options_extension;
};

struct aws_tls_negotiated_protocol_message {
    struct aws_byte_buf protocol;
};

static const int AWS_TLS_NEGOTIATED_PROTOCOL_MESSAGE = 0x01;

typedef struct aws_channel_handler *(
    *aws_tls_on_protocol_negotiated)(struct aws_channel_slot *new_slot, struct aws_byte_buf *protocol, void *user_data);

/**
 * An enum for the current state of tls negotiation within a tls channel handler
 */
enum aws_tls_negotiation_status {
    AWS_TLS_NEGOTIATION_STATUS_NONE,
    AWS_TLS_NEGOTIATION_STATUS_ONGOING,
    AWS_TLS_NEGOTIATION_STATUS_SUCCESS,
    AWS_TLS_NEGOTIATION_STATUS_FAILURE
};

#ifdef BYO_CRYPTO
/**
 * Callback for creating a TLS handler. If you're using this you're using BYO_CRYPTO. This function should return
 * a fully implemented aws_channel_handler instance for TLS. Note: the aws_tls_options passed to your
 * aws_tls_handler_new_fn contains multiple callbacks. Namely: aws_tls_on_negotiation_result_fn. You are responsible for
 * invoking this function when TLs session negotiation has completed.
 */
typedef struct aws_channel_handler *(aws_tls_handler_new_fn)(
    struct aws_allocator *allocator,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot,
    void *user_data);

/**
 * Invoked when it's time to start TLS negotiation. Note: the aws_tls_options passed to your aws_tls_handler_new_fn
 * contains multiple callbacks. Namely: aws_tls_on_negotiation_result_fn. You are responsible for invoking this function
 * when TLS session negotiation has completed.
 */
typedef int(aws_tls_client_handler_start_negotiation_fn)(struct aws_channel_handler *handler, void *user_data);

struct aws_tls_byo_crypto_setup_options {
    aws_tls_handler_new_fn *new_handler_fn;
    /* ignored for server implementations, required for clients. */
    aws_tls_client_handler_start_negotiation_fn *start_negotiation_fn;
    void *user_data;
};

#endif /* BYO_CRYPTO */

AWS_EXTERN_C_BEGIN

/******************************** tls options init stuff ***********************/
/**
 * Initializes options with default client options
 */
AWS_IO_API void aws_tls_ctx_options_init_default_client(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator);
/**
 * Cleans up resources allocated by init_* functions
 */
AWS_IO_API void aws_tls_ctx_options_clean_up(struct aws_tls_ctx_options *options);

#if !defined(AWS_OS_IOS)

/**
 * Initializes options for use with mutual tls in client mode.
 * cert_path and pkey_path are paths to files on disk. cert_path
 * and pkey_path are treated as PKCS#7 PEM armored. They are loaded
 * from disk and stored in buffers internally.
 */
AWS_IO_API int aws_tls_ctx_options_init_client_mtls_from_path(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    const char *cert_path,
    const char *pkey_path);

/**
 * Initializes options for use with mutual tls in client mode.
 * cert and pkey are copied. cert and pkey are treated as PKCS#7 PEM
 * armored.
 */
AWS_IO_API int aws_tls_ctx_options_init_client_mtls(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    const struct aws_byte_cursor *cert,
    const struct aws_byte_cursor *pkey);

#    ifdef __APPLE__
/**
 * Sets a custom keychain path for storing the cert and pkey with mutual tls in client mode.
 */
AWS_IO_API int aws_tls_ctx_options_set_keychain_path(
    struct aws_tls_ctx_options *options,
    struct aws_byte_cursor *keychain_path_cursor);
#    endif

/**
 * Initializes options for use with in server mode.
 * cert_path and pkey_path are paths to files on disk. cert_path
 * and pkey_path are treated as PKCS#7 PEM armored. They are loaded
 * from disk and stored in buffers internally.
 */
AWS_IO_API int aws_tls_ctx_options_init_default_server_from_path(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    const char *cert_path,
    const char *pkey_path);

/**
 * Initializes options for use with in server mode.
 * cert and pkey are copied. cert and pkey are treated as PKCS#7 PEM
 * armored.
 */
AWS_IO_API int aws_tls_ctx_options_init_default_server(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    struct aws_byte_cursor *cert,
    struct aws_byte_cursor *pkey);

#endif /* AWS_OS_IOS */

#ifdef _WIN32
/**
 * Initializes options for use with mutual tls in client mode. This function is only available on
 * windows. cert_reg_path is the path to a system
 * installed certficate/private key pair. Example:
 * CurrentUser\\MY\\<thumprint>
 */
AWS_IO_API void aws_tls_ctx_options_init_client_mtls_from_system_path(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    const char *cert_reg_path);

/**
 * Initializes options for use with server mode. This function is only available on
 * windows. cert_reg_path is the path to a system
 * installed certficate/private key pair. Example:
 * CurrentUser\\MY\\<thumprint>
 */
AWS_IO_API void aws_tls_ctx_options_init_default_server_from_system_path(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    const char *cert_reg_path);
#endif /* _WIN32 */

#ifdef __APPLE__
/**
 * Initializes options for use with mutual tls in client mode. This function is only available on
 * apple machines. pkcs12_path is a path to a file on disk containing a pkcs#12 file. The file is loaded
 * into an internal buffer. pkcs_pwd is the corresponding password for the pkcs#12 file; it is copied.
 */
AWS_IO_API int aws_tls_ctx_options_init_client_mtls_pkcs12_from_path(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    const char *pkcs12_path,
    struct aws_byte_cursor *pkcs_pwd);

/**
 * Initializes options for use with mutual tls in client mode. This function is only available on
 * apple machines. pkcs12 is a buffer containing a pkcs#12 certificate and private key; it is copied.
 * pkcs_pwd is the corresponding password for the pkcs#12 buffer; it is copied.
 */
AWS_IO_API int aws_tls_ctx_options_init_client_mtls_pkcs12(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    struct aws_byte_cursor *pkcs12,
    struct aws_byte_cursor *pkcs_pwd);

/**
 * Initializes options for use in server mode. This function is only available on
 * apple machines. pkcs12_path is a path to a file on disk containing a pkcs#12 file. The file is loaded
 * into an internal buffer. pkcs_pwd is the corresponding password for the pkcs#12 file; it is copied.
 */
AWS_IO_API int aws_tls_ctx_options_init_server_pkcs12_from_path(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    const char *pkcs12_path,
    struct aws_byte_cursor *pkcs_password);

/**
 * Initializes options for use in server mode. This function is only available on
 * apple machines. pkcs12 is a buffer containing a pkcs#12 certificate and private key; it is copied.
 * pkcs_pwd is the corresponding password for the pkcs#12 buffer; it is copied.
 */
AWS_IO_API int aws_tls_ctx_options_init_server_pkcs12(
    struct aws_tls_ctx_options *options,
    struct aws_allocator *allocator,
    struct aws_byte_cursor *pkcs12,
    struct aws_byte_cursor *pkcs_password);
#endif /* __APPLE__ */

/**
 * Sets alpn list in the form <protocol1;protocol2;...>. A maximum of 4 protocols are supported.
 * alpn_list is copied.
 */
AWS_IO_API int aws_tls_ctx_options_set_alpn_list(struct aws_tls_ctx_options *options, const char *alpn_list);

/**
 * Enables or disables x.509 validation. Disable this only for testing. To enable mutual TLS in server mode,
 * set verify_peer to true.
 */
AWS_IO_API void aws_tls_ctx_options_set_verify_peer(struct aws_tls_ctx_options *options, bool verify_peer);

/**
 * Sets the minimum TLS version to allow.
 */
AWS_IO_API void aws_tls_ctx_options_set_minimum_tls_version(
    struct aws_tls_ctx_options *options,
    enum aws_tls_versions minimum_tls_version);

/**
 * Override the default trust store with a CA certificates file.
 * ca_pem_contents is the ASCII/UTF-8 encoded contents of a file containing trusted CA certificates in PEM format.
 * The contents are copied.
 */
AWS_IO_API int aws_tls_ctx_options_override_default_trust_store_with_file_contents(
    struct aws_tls_ctx_options *options,
    const struct aws_byte_cursor *ca_file_contents);

/**
 * Override the default trust store with a CA certificates file.
 * ca_pem_path is the path to an ASCII/UTF-8 encoded file containing trusted CA certificates in PEM format.
 */
AWS_IO_API int aws_tls_ctx_options_override_default_trust_store_with_file(
    struct aws_tls_ctx_options *options,
    const char *ca_file_path);

/**
 * Override the default trust store with a directory of CA certificates.
 * ca_dir_path is the path to a directory of CA certificates in PEM format.
 * This is only supported on Unix systems.
 */
AWS_IO_API int aws_tls_ctx_options_override_default_trust_store_with_directory(
    struct aws_tls_ctx_options *options,
    const char *ca_dir_path);

/* DEPRECATED: use aws_tls_ctx_options_override_default_trust_store_with_file_contents() */
AWS_IO_API int aws_tls_ctx_options_override_default_trust_store(
    struct aws_tls_ctx_options *options,
    const struct aws_byte_cursor *ca_file);

/* DEPRECATED: use aws_tls_ctx_options_override_default_trust_store_with_file()
 * or aws_tls_ctx_options_override_default_trust_store_with_directory */
AWS_IO_API int aws_tls_ctx_options_override_default_trust_store_from_path(
    struct aws_tls_ctx_options *options,
    const char *ca_path,
    const char *ca_file);

/**
 * When implementing BYO_CRYPTO, if you need extra data to pass to your tls implementation, set it here. The lifetime of
 * extension_data must outlive the options object and be cleaned up after options is cleaned up.
 */
AWS_IO_API void aws_tls_ctx_options_set_extension_data(struct aws_tls_ctx_options *options, void *extension_data);

/**
 * Initializes default connection options from an instance ot aws_tls_ctx.
 */
AWS_IO_API void aws_tls_connection_options_init_from_ctx(
    struct aws_tls_connection_options *conn_options,
    struct aws_tls_ctx *ctx);

/**
 * Cleans up resources in aws_tls_connection_options. This can be called immediately after initializing
 * a tls handler, or if using the bootstrap api, immediately after asking for a channel.
 */
AWS_IO_API void aws_tls_connection_options_clean_up(struct aws_tls_connection_options *connection_options);

/**
 * Copies 'from' to 'to'
 */
AWS_IO_API int aws_tls_connection_options_copy(
    struct aws_tls_connection_options *to,
    const struct aws_tls_connection_options *from);

/**
 * Sets callbacks for use with a tls connection.
 */
AWS_IO_API void aws_tls_connection_options_set_callbacks(
    struct aws_tls_connection_options *conn_options,
    aws_tls_on_negotiation_result_fn *on_negotiation_result,
    aws_tls_on_data_read_fn *on_data_read,
    aws_tls_on_error_fn *on_error,
    void *user_data);

/**
 * Sets server name to use for the SNI extension (supported everywhere), as well as x.509 validation. If you don't
 * set this, your x.509 validation will likely fail.
 */
AWS_IO_API int aws_tls_connection_options_set_server_name(
    struct aws_tls_connection_options *conn_options,
    struct aws_allocator *allocator,
    struct aws_byte_cursor *server_name);

/**
 * Sets alpn list in the form <protocol1;protocol2;...>. A maximum of 4 protocols are supported.
 * alpn_list is copied. This value is already inherited from aws_tls_ctx, but the aws_tls_ctx is expensive,
 * and should be used across as many connections as possible. If you want to set this per connection, set it here.
 */
AWS_IO_API int aws_tls_connection_options_set_alpn_list(
    struct aws_tls_connection_options *conn_options,
    struct aws_allocator *allocator,
    const char *alpn_list);

/********************************* TLS context and state management *********************************/

/**
 * Returns true if alpn is available in the underlying tls implementation.
 * This function should always be called before setting an alpn list.
 */
AWS_IO_API bool aws_tls_is_alpn_available(void);

/**
 * Returns true if this Cipher Preference is available in the underlying TLS implementation.
 * This function should always be called before setting a Cipher Preference
 */
AWS_IO_API bool aws_tls_is_cipher_pref_supported(enum aws_tls_cipher_pref cipher_pref);

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

#ifdef BYO_CRYPTO
/**
 * If using BYO_CRYPTO, you need to call this function prior to creating any client channels in the application.
 */
AWS_IO_API void aws_tls_byo_crypto_set_client_setup_options(const struct aws_tls_byo_crypto_setup_options *options);
/**
 * If using BYO_CRYPTO, you need to call this function prior to creating any server channels in the application.
 */
AWS_IO_API void aws_tls_byo_crypto_set_server_setup_options(const struct aws_tls_byo_crypto_setup_options *options);

#endif /* BYO_CRYPTO */

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

#ifndef BYO_CRYPTO
/**
 * Creates a new server ctx. This ctx can be used for the lifetime of the application assuming you want the same
 * options for every incoming connection. Options will be copied.
 */
AWS_IO_API struct aws_tls_ctx *aws_tls_server_ctx_new(
    struct aws_allocator *alloc,
    const struct aws_tls_ctx_options *options);

/**
 * Creates a new client ctx. This ctx can be used for the lifetime of the application assuming you want the same
 * options for every outgoing connection. Options will be copied.
 */
AWS_IO_API struct aws_tls_ctx *aws_tls_client_ctx_new(
    struct aws_allocator *alloc,
    const struct aws_tls_ctx_options *options);
#endif /* BYO_CRYPTO */

/**
 * Increments the reference count on the tls context, allowing the caller to take a reference to it.
 *
 * Returns the same tls context passed in.
 */
AWS_IO_API struct aws_tls_ctx *aws_tls_ctx_acquire(struct aws_tls_ctx *ctx);

/**
 * Decrements a tls context's ref count.  When the ref count drops to zero, the object will be destroyed.
 */
AWS_IO_API void aws_tls_ctx_release(struct aws_tls_ctx *ctx);

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

/********************************* Misc TLS related *********************************/

/*
 * Injects a tls handler/slot into a channel and begins tls negotiation.
 * If desired, ALPN must be handled separately
 *
 * right_of_slot must be an existing slot in a channel
 */
AWS_IO_API int aws_channel_setup_client_tls(
    struct aws_channel_slot *right_of_slot,
    struct aws_tls_connection_options *tls_options);

AWS_EXTERN_C_END

#endif /* AWS_IO_TLS_CHANNEL_HANDLER_H */
