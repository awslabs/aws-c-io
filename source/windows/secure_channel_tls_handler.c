/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#define SECURITY_WIN32

#include <aws/io/tls_channel_handler.h>

#include <aws/common/encoding.h>
#include <aws/common/math.h>
#include <aws/common/string.h>
#include <aws/common/task_scheduler.h>

#include <aws/io/channel.h>
#include <aws/io/file_utils.h>
#include <aws/io/logging.h>
#include <aws/io/private/pki_utils.h>
#include <aws/io/private/tls_channel_handler_shared.h>
#include <aws/io/statistics.h>

#include <Windows.h>

#include <schannel.h>
#include <security.h>

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _MSC_VER
#    pragma warning(disable : 4221) /* aggregate initializer using local variable addresses */
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#    pragma warning(disable : 4306) /* Identifier is type cast to a larger pointer. */
#endif

#define KB_1 1024
#define READ_OUT_SIZE (16 * KB_1)
#define READ_IN_SIZE READ_OUT_SIZE
#define EST_HANDSHAKE_SIZE (7 * KB_1)

#define EST_TLS_RECORD_OVERHEAD 53 /* 5 byte header + 32 + 16 bytes for padding */

void aws_tls_init_static_state(struct aws_allocator *alloc) {
    AWS_LOGF_INFO(AWS_LS_IO_TLS, "static: Initializing TLS using SecureChannel (SSPI).");
    (void)alloc;
}

void aws_tls_clean_up_static_state(void) {}

struct secure_channel_ctx {
    struct aws_tls_ctx ctx;
    struct aws_string *alpn_list;
    SCHANNEL_CRED credentials;
    PCERT_CONTEXT pcerts;
    HCERTSTORE cert_store;
    HCERTSTORE custom_trust_store;
    HCRYPTPROV crypto_provider;
    HCRYPTKEY private_key;
    bool verify_peer;
    bool should_free_pcerts;
};

struct secure_channel_handler {
    struct aws_channel_handler handler;
    struct aws_tls_channel_handler_shared shared_state;
    CtxtHandle sec_handle;
    CredHandle creds;
    /*
     * The SSPI API expects an array of len 1 of these where it's the leaf certificate associated with its private
     * key.
     */
    PCCERT_CONTEXT cert_context[1];
    HCERTSTORE cert_store;
    HCERTSTORE custom_ca_store;
    SecPkgContext_StreamSizes stream_sizes;
    unsigned long ctx_req;
    unsigned long ctx_ret_flags;
    struct aws_channel_slot *slot;
    struct aws_byte_buf protocol;
    struct aws_byte_buf server_name;
    TimeStamp sspi_timestamp;
    int (*s_connection_state_fn)(struct aws_channel_handler *handler);
    /*
     * Give a little bit of extra head room, for split records.
     */
    uint8_t buffered_read_in_data[READ_IN_SIZE + KB_1];
    struct aws_byte_buf buffered_read_in_data_buf;
    size_t estimated_incomplete_size;
    size_t read_extra;
    /* This is to accommodate the extra head room we added above.
       because we're allowing for splits, we may have more data decrypted
       than we can fit in this buffer if we don't make them match. */
    uint8_t buffered_read_out_data[READ_OUT_SIZE + KB_1];
    struct aws_byte_buf buffered_read_out_data_buf;
    struct aws_channel_task sequential_task_storage;
    aws_tls_on_negotiation_result_fn *on_negotiation_result;
    aws_tls_on_data_read_fn *on_data_read;
    aws_tls_on_error_fn *on_error;
    struct aws_string *alpn_list;
    void *user_data;
    bool advertise_alpn_message;
    bool negotiation_finished;
    bool verify_peer;
};

static size_t s_message_overhead(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;

    if (AWS_UNLIKELY(!sc_handler->stream_sizes.cbMaximumMessage)) {
        SECURITY_STATUS status =
            QueryContextAttributes(&sc_handler->sec_handle, SECPKG_ATTR_STREAM_SIZES, &sc_handler->stream_sizes);

        if (status != SEC_E_OK) {
            return EST_TLS_RECORD_OVERHEAD;
        }
    }

    return sc_handler->stream_sizes.cbTrailer + sc_handler->stream_sizes.cbHeader;
}

bool aws_tls_is_alpn_available(void) {
/* if you built on an old version of windows, still no support, but if you did, we still
   want to check the OS version at runtime before agreeing to attempt alpn. */
#ifdef SECBUFFER_APPLICATION_PROTOCOLS
    AWS_LOGF_DEBUG(
        AWS_LS_IO_TLS,
        "static: This library was built with Windows 8.1 or later, "
        "probing OS to see what we're actually running on.");
    /* make sure we're on windows 8.1 or later. */
    OSVERSIONINFOEX os_version;
    DWORDLONG condition_mask = 0;
    VER_SET_CONDITION(condition_mask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(condition_mask, VER_MINORVERSION, VER_GREATER_EQUAL);
    VER_SET_CONDITION(condition_mask, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
    VER_SET_CONDITION(condition_mask, VER_SERVICEPACKMINOR, VER_GREATER_EQUAL);

    AWS_ZERO_STRUCT(os_version);
    os_version.dwMajorVersion = HIBYTE(_WIN32_WINNT_WIN8);
    os_version.dwMinorVersion = LOBYTE(_WIN32_WINNT_WIN8);
    os_version.wServicePackMajor = 0;
    os_version.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (VerifyVersionInfo(
            &os_version,
            VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR | VER_SERVICEPACKMINOR,
            condition_mask)) {
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "static: We're running on Windows 8.1 or later. ALPN is available.");
        return true;
    }

    AWS_LOGF_WARN(
        AWS_LS_IO_TLS,
        "static: Running on older version of windows, ALPN is not supported. "
        "Please update your OS to take advantage of modern features.");
#else
    AWS_LOGF_WARN(
        AWS_LS_IO_TLS,
        "static: This library was built using a Windows SDK prior to 8.1. "
        "Please build with a version of windows >= 8.1 to take advantage modern features. ALPN is not supported.");
#endif /*SECBUFFER_APPLICATION_PROTOCOLS */
    return false;
}

bool aws_tls_is_cipher_pref_supported(enum aws_tls_cipher_pref cipher_pref) {
    switch (cipher_pref) {
        case AWS_IO_TLS_CIPHER_PREF_SYSTEM_DEFAULT:
            return true;

        case AWS_IO_TLS_CIPHER_PREF_KMS_PQ_TLSv1_0_2019_06:
        default:
            return false;
    }
}

/* technically we could lower this, but lets be forgiving */
#define MAX_HOST_LENGTH 255

/* this only gets called if the user specified a custom ca. */
static int s_manually_verify_peer_cert(struct aws_channel_handler *handler) {
    AWS_LOGF_DEBUG(
        AWS_LS_IO_TLS,
        "id=%p: manually verifying certifcate chain because a custom CA is configured.",
        (void *)handler);
    struct secure_channel_handler *sc_handler = handler->impl;

    int result = AWS_OP_ERR;
    CERT_CONTEXT *peer_certificate = NULL;
    HCERTCHAINENGINE engine = NULL;
    CERT_CHAIN_CONTEXT *cert_chain_ctx = NULL;

    /* get the peer's certificate so we can validate it.*/
    SECURITY_STATUS status =
        QueryContextAttributes(&sc_handler->sec_handle, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &peer_certificate);

    if (status != SEC_E_OK || !peer_certificate) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_TLS,
            "id=%p: failed to load peer's certificate with SECURITY_STATUS %d",
            (void *)handler,
            (int)status);
        return AWS_OP_ERR;
    }

    /* this next bit scours the custom trust store to try and load a chain to verify
       the leaf certificate against. */
    CERT_CHAIN_ENGINE_CONFIG engine_config;
    AWS_ZERO_STRUCT(engine_config);
    engine_config.cbSize = sizeof(engine_config);
    engine_config.hExclusiveRoot = sc_handler->custom_ca_store;

    if (!CertCreateCertificateChainEngine(&engine_config, &engine)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_TLS,
            "id=%p: failed to load a certificate chain engine with SECURITY_STATUS %d. "
            "Most likely, the configured CA is corrupted.",
            (void *)handler,
            (int)status);
        goto done;
    }

    /*
     * TODO: Investigate CRL options further on a per-platform basis.  Add control APIs if appropriate.
     */
    DWORD get_chain_flags = 0;

    /* mimic chromium here since we intend for this to be used generally */
    const LPCSTR usage_identifiers[] = {
        szOID_PKIX_KP_SERVER_AUTH,
        szOID_SERVER_GATED_CRYPTO,
        szOID_SGC_NETSCAPE,
    };

    CERT_CHAIN_PARA chain_params;
    AWS_ZERO_STRUCT(chain_params);
    chain_params.cbSize = sizeof(chain_params);
    chain_params.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    chain_params.RequestedUsage.Usage.cUsageIdentifier = AWS_ARRAY_SIZE(usage_identifiers);
    chain_params.RequestedUsage.Usage.rgpszUsageIdentifier = (LPSTR *)usage_identifiers;

    if (!CertGetCertificateChain(
            engine,
            peer_certificate,
            NULL,
            peer_certificate->hCertStore,
            &chain_params,
            get_chain_flags,
            NULL,
            &cert_chain_ctx)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_TLS,
            "id=%p: unable to find certificate in chain with SECURITY_STATUS %d.",
            (void *)handler,
            (int)status);
        goto done;
    }

    struct aws_byte_buf host = aws_tls_handler_server_name(handler);
    if (host.len > MAX_HOST_LENGTH) {
        AWS_LOGF_ERROR(AWS_LS_IO_TLS, "id=%p: host name too long (%d).", (void *)handler, (int)host.len);
        goto done;
    }

    wchar_t whost[MAX_HOST_LENGTH + 1];
    AWS_ZERO_ARRAY(whost);

    int converted = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, (const char *)host.buffer, (int)host.len, whost, AWS_ARRAY_SIZE(whost));
    if ((size_t)converted != host.len) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_TLS,
            "id=%p: unable to convert host to wstr, %d -> %d, with last error 0x%x.",
            (void *)handler,
            (int)host.len,
            (int)converted,
            (int)GetLastError());
        goto done;
    }

    /* check if the chain was trusted */
    LPCSTR policyiod = CERT_CHAIN_POLICY_SSL;

    SSL_EXTRA_CERT_CHAIN_POLICY_PARA sslpolicy;
    AWS_ZERO_STRUCT(sslpolicy);
    sslpolicy.cbSize = sizeof(sslpolicy);
    sslpolicy.dwAuthType = AUTHTYPE_SERVER;
    sslpolicy.fdwChecks = 0;
    sslpolicy.pwszServerName = whost;

    CERT_CHAIN_POLICY_PARA policypara;
    AWS_ZERO_STRUCT(policypara);
    policypara.cbSize = sizeof(policypara);
    policypara.dwFlags = 0;
    policypara.pvExtraPolicyPara = &sslpolicy;

    CERT_CHAIN_POLICY_STATUS policystatus;
    AWS_ZERO_STRUCT(policystatus);
    policystatus.cbSize = sizeof(policystatus);

    if (!CertVerifyCertificateChainPolicy(policyiod, cert_chain_ctx, &policypara, &policystatus)) {
        int error = GetLastError();
        AWS_LOGF_ERROR(
            AWS_LS_IO_TLS, "id=%p: CertVerifyCertificateChainPolicy() failed, error 0x%x", (void *)handler, (int)error);
        goto done;
    }

    if (policystatus.dwError) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_TLS,
            "id=%p: certificate verification failed, error 0x%x",
            (void *)handler,
            (int)policystatus.dwError);
        goto done;
    }

    /* if the chain was trusted, then we're good to go, if it was not
       we bail out. */
    CERT_SIMPLE_CHAIN *simple_chain = cert_chain_ctx->rgpChain[0];
    DWORD trust_mask = ~(DWORD)CERT_TRUST_IS_NOT_TIME_NESTED;
    trust_mask &= simple_chain->TrustStatus.dwErrorStatus;

    if (trust_mask != 0) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_TLS,
            "id=%p: peer certificate is un-trusted with SECURITY_STATUS %d.",
            (void *)handler,
            (int)trust_mask);
        goto done;
    }

    AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "id=%p: peer certificate is trusted.", (void *)handler);
    result = AWS_OP_SUCCESS;

done:

    if (cert_chain_ctx != NULL) {
        CertFreeCertificateChain(cert_chain_ctx);
    }

    if (engine != NULL) {
        CertFreeCertificateChainEngine(engine);
    }

    if (peer_certificate != NULL) {
        CertFreeCertificateContext(peer_certificate);
    }

    return result;
}

static void s_invoke_negotiation_error(struct aws_channel_handler *handler, int err) {
    struct secure_channel_handler *sc_handler = handler->impl;

    aws_on_tls_negotiation_completed(&sc_handler->shared_state, err);

    if (sc_handler->on_negotiation_result) {
        sc_handler->on_negotiation_result(handler, sc_handler->slot, err, sc_handler->user_data);
    }
}

static void s_on_negotiation_success(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;

    /* if the user provided an ALPN handler to the channel, we need to let them know what their protocol is. */
    if (sc_handler->slot->adj_right && sc_handler->advertise_alpn_message && sc_handler->protocol.len) {
        struct aws_io_message *message = aws_channel_acquire_message_from_pool(
            sc_handler->slot->channel,
            AWS_IO_MESSAGE_APPLICATION_DATA,
            sizeof(struct aws_tls_negotiated_protocol_message));
        message->message_tag = AWS_TLS_NEGOTIATED_PROTOCOL_MESSAGE;
        struct aws_tls_negotiated_protocol_message *protocol_message =
            (struct aws_tls_negotiated_protocol_message *)message->message_data.buffer;

        protocol_message->protocol = sc_handler->protocol;
        message->message_data.len = sizeof(struct aws_tls_negotiated_protocol_message);
        if (aws_channel_slot_send_message(sc_handler->slot, message, AWS_CHANNEL_DIR_READ)) {
            aws_mem_release(message->allocator, message);
            aws_channel_shutdown(sc_handler->slot->channel, aws_last_error());
        }
    }

    aws_on_tls_negotiation_completed(&sc_handler->shared_state, AWS_ERROR_SUCCESS);

    if (sc_handler->on_negotiation_result) {
        sc_handler->on_negotiation_result(handler, sc_handler->slot, AWS_OP_SUCCESS, sc_handler->user_data);
    }
}

static int s_determine_sspi_error(int sspi_status) {
    switch (sspi_status) {
        case SEC_E_INSUFFICIENT_MEMORY:
            return AWS_ERROR_OOM;
        case SEC_I_CONTEXT_EXPIRED:
            return AWS_IO_TLS_ALERT_NOT_GRACEFUL;
        case SEC_E_WRONG_PRINCIPAL:
            return AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE;
            /*
            case SEC_E_INVALID_HANDLE:
            case SEC_E_INVALID_TOKEN:
            case SEC_E_LOGON_DENIED:
            case SEC_E_TARGET_UNKNOWN:
            case SEC_E_NO_AUTHENTICATING_AUTHORITY:
            case SEC_E_INTERNAL_ERROR:
            case SEC_E_NO_CREDENTIALS:
            case SEC_E_UNSUPPORTED_FUNCTION:
            case SEC_E_APPLICATION_PROTOCOL_MISMATCH:
            */
        default:
            return AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE;
    }
}

#define CHECK_ALPN_BUFFER_SIZE(s, i, b)                                                                                \
    if (s <= i) {                                                                                                      \
        aws_array_list_clean_up(&b);                                                                                   \
        return aws_raise_error(AWS_ERROR_SHORT_BUFFER);                                                                \
    }

/* construct ALPN extension data... apparently this works on big-endian machines? but I don't believe the docs
   if you're running ARM and you find ALPN isn't working, it's probably because I trusted the documentation
   and your bug is in here. Note, dotnet's corefx also acts like endianness isn't at play so if this is broken
   so is everyone's dotnet code. */
static int s_fillin_alpn_data(
    struct aws_channel_handler *handler,
    unsigned char *alpn_buffer_data,
    size_t buffer_size,
    size_t *written) {
    *written = 0;
    struct secure_channel_handler *sc_handler = handler->impl;
    AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "");

    struct aws_array_list alpn_buffers;
    struct aws_byte_cursor alpn_buffer_array[4];
    aws_array_list_init_static(&alpn_buffers, alpn_buffer_array, 4, sizeof(struct aws_byte_cursor));

    AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "Setting ALPN extension with string %s.", aws_string_c_str(sc_handler->alpn_list));
    struct aws_byte_cursor alpn_str_cur = aws_byte_cursor_from_string(sc_handler->alpn_list);
    if (aws_byte_cursor_split_on_char(&alpn_str_cur, ';', &alpn_buffers)) {
        return AWS_OP_ERR;
    }

    size_t protocols_count = aws_array_list_length(&alpn_buffers);

    size_t index = 0;
    CHECK_ALPN_BUFFER_SIZE(buffer_size, index + sizeof(uint32_t), alpn_buffers)
    uint32_t *extension_length = (uint32_t *)&alpn_buffer_data[index];
    index += sizeof(uint32_t);
    CHECK_ALPN_BUFFER_SIZE(buffer_size, index + sizeof(uint32_t), alpn_buffers)
    uint32_t *extension_name = (uint32_t *)&alpn_buffer_data[index];
    index += sizeof(uint32_t);
    CHECK_ALPN_BUFFER_SIZE(buffer_size, index + sizeof(uint32_t), alpn_buffers)
    uint16_t *protocols_byte_length = (uint16_t *)&alpn_buffer_data[index];
    index += sizeof(uint16_t);
    CHECK_ALPN_BUFFER_SIZE(buffer_size, index + sizeof(uint16_t), alpn_buffers)

    *extension_length += sizeof(uint32_t) + sizeof(uint16_t);

    *extension_name = SecApplicationProtocolNegotiationExt_ALPN;
    /*now add the protocols*/
    for (size_t i = 0; i < protocols_count; ++i) {
        struct aws_byte_cursor *protocol_ptr = NULL;
        aws_array_list_get_at_ptr(&alpn_buffers, (void **)&protocol_ptr, i);
        AWS_ASSERT(protocol_ptr);
        *extension_length += (uint32_t)protocol_ptr->len + 1;
        *protocols_byte_length += (uint16_t)protocol_ptr->len + 1;
        CHECK_ALPN_BUFFER_SIZE(buffer_size, index + 1, alpn_buffers)
        alpn_buffer_data[index++] = (unsigned char)protocol_ptr->len;
        CHECK_ALPN_BUFFER_SIZE(buffer_size, index + protocol_ptr->len, alpn_buffers)
        memcpy(alpn_buffer_data + index, protocol_ptr->ptr, protocol_ptr->len);
        index += protocol_ptr->len;
    }

    aws_array_list_clean_up(&alpn_buffers);
    *written = *extension_length + sizeof(uint32_t);
    return AWS_OP_SUCCESS;
}

static int s_process_connection_state(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;
    return sc_handler->s_connection_state_fn(handler);
}

static int s_do_application_data_decrypt(struct aws_channel_handler *handler);

static int s_do_server_side_negotiation_step_2(struct aws_channel_handler *handler);

/** invoked during the first step of the server's negotiation. It receives the client hello,
    adds its alpn data if available, and if everything is good, sends out the server hello. */
static int s_do_server_side_negotiation_step_1(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;
    AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: server starting negotiation", (void *)handler);

    aws_on_drive_tls_negotiation(&sc_handler->shared_state);

    unsigned char alpn_buffer_data[128] = {0};
    SecBuffer input_bufs[] = {
        {
            .pvBuffer = sc_handler->buffered_read_in_data_buf.buffer,
            .cbBuffer = (unsigned long)sc_handler->buffered_read_in_data_buf.len,
            .BufferType = SECBUFFER_TOKEN,
        },
        {
            .pvBuffer = NULL,
            .cbBuffer = 0,
            .BufferType = SECBUFFER_EMPTY,
        },
    };

    SecBufferDesc input_bufs_desc = {
        .ulVersion = SECBUFFER_VERSION,
        .cBuffers = 2,
        .pBuffers = input_bufs,
    };

#ifdef SECBUFFER_APPLICATION_PROTOCOLS
    if (sc_handler->alpn_list && aws_tls_is_alpn_available()) {
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "id=%p: Setting ALPN to %s", handler, aws_string_c_str(sc_handler->alpn_list));
        size_t extension_length = 0;
        if (s_fillin_alpn_data(handler, alpn_buffer_data, sizeof(alpn_buffer_data), &extension_length)) {
            return AWS_OP_ERR;
        }

        input_bufs[1].pvBuffer = alpn_buffer_data, input_bufs[1].cbBuffer = (unsigned long)extension_length,
        input_bufs[1].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
    }
#endif /* SECBUFFER_APPLICATION_PROTOCOLS*/

    sc_handler->ctx_req = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT | ASC_REQ_CONFIDENTIALITY |
                          ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;

    if (sc_handler->verify_peer) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_TLS,
            "id=%p: server configured to use mutual tls, expecting a certficate from client.",
            (void *)handler);
        sc_handler->ctx_req |= ASC_REQ_MUTUAL_AUTH;
    }

    SecBuffer output_buffer = {
        .pvBuffer = NULL,
        .cbBuffer = 0,
        .BufferType = SECBUFFER_TOKEN,
    };

    SecBufferDesc output_buffer_desc = {
        .ulVersion = SECBUFFER_VERSION,
        .cBuffers = 1,
        .pBuffers = &output_buffer,
    };

    /* process the client hello. */
    SECURITY_STATUS status = AcceptSecurityContext(
        &sc_handler->creds,
        NULL,
        &input_bufs_desc,
        sc_handler->ctx_req,
        0,
        &sc_handler->sec_handle,
        &output_buffer_desc,
        &sc_handler->ctx_ret_flags,
        NULL);

    if (!(status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_TLS,
            "id=%p: error during processing of the ClientHello. SECURITY_STATUS is %d",
            (void *)handler,
            (int)status);
        int error = s_determine_sspi_error(status);
        aws_raise_error(error);
        s_invoke_negotiation_error(handler, error);
        return AWS_OP_ERR;
    }

    size_t data_to_write_len = output_buffer.cbBuffer;

    AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: Sending ServerHello. Data size %zu", (void *)handler, data_to_write_len);
    /* send the server hello. */
    struct aws_io_message *outgoing_message = aws_channel_acquire_message_from_pool(
        sc_handler->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, data_to_write_len);
    if (!outgoing_message) {
        FreeContextBuffer(output_buffer.pvBuffer);
        s_invoke_negotiation_error(handler, aws_last_error());
        return AWS_OP_ERR;
    }

    AWS_ASSERT(outgoing_message->message_data.capacity >= data_to_write_len);
    memcpy(outgoing_message->message_data.buffer, output_buffer.pvBuffer, output_buffer.cbBuffer);
    outgoing_message->message_data.len = output_buffer.cbBuffer;
    FreeContextBuffer(output_buffer.pvBuffer);

    if (aws_channel_slot_send_message(sc_handler->slot, outgoing_message, AWS_CHANNEL_DIR_WRITE)) {
        aws_mem_release(outgoing_message->allocator, outgoing_message);
        s_invoke_negotiation_error(handler, aws_last_error());
        return AWS_OP_ERR;
    }

    sc_handler->s_connection_state_fn = s_do_server_side_negotiation_step_2;

    return AWS_OP_SUCCESS;
}

/* cipher change, key exchange, mutual TLS stuff. */
static int s_do_server_side_negotiation_step_2(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;

    AWS_LOGF_TRACE(
        AWS_LS_IO_TLS, "id=%p: running step 2 of negotiation (cipher change, key exchange etc...)", (void *)handler);
    SecBuffer input_buffers[] = {
        [0] =
            {
                .pvBuffer = sc_handler->buffered_read_in_data_buf.buffer,
                .cbBuffer = (unsigned long)sc_handler->buffered_read_in_data_buf.len,
                .BufferType = SECBUFFER_TOKEN,
            },
        [1] =
            {
                .pvBuffer = NULL,
                .cbBuffer = 0,
                .BufferType = SECBUFFER_EMPTY,
            },
    };

    SecBufferDesc input_buffers_desc = {
        .ulVersion = SECBUFFER_VERSION,
        .cBuffers = 2,
        .pBuffers = input_buffers,
    };

    SecBuffer output_buffers[3];
    AWS_ZERO_ARRAY(output_buffers);
    output_buffers[0].BufferType = SECBUFFER_TOKEN;
    output_buffers[1].BufferType = SECBUFFER_ALERT;

    SecBufferDesc output_buffers_desc = {
        .ulVersion = SECBUFFER_VERSION,
        .cBuffers = 3,
        .pBuffers = output_buffers,
    };

    sc_handler->read_extra = 0;
    sc_handler->estimated_incomplete_size = 0;

    SECURITY_STATUS status = AcceptSecurityContext(
        &sc_handler->creds,
        &sc_handler->sec_handle,
        &input_buffers_desc,
        sc_handler->ctx_req,
        0,
        NULL,
        &output_buffers_desc,
        &sc_handler->ctx_ret_flags,
        &sc_handler->sspi_timestamp);

    if (status != SEC_E_INCOMPLETE_MESSAGE && status != SEC_I_CONTINUE_NEEDED && status != SEC_E_OK) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_TLS, "id=%p: Error during negotiation. SECURITY_STATUS is %d", (void *)handler, (int)status);
        int aws_error = s_determine_sspi_error(status);
        aws_raise_error(aws_error);
        s_invoke_negotiation_error(handler, aws_error);
        return AWS_OP_ERR;
    }

    if (status == SEC_E_INCOMPLETE_MESSAGE) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_TLS, "id=%p: Last processed buffer was incomplete, waiting on more data.", (void *)handler);
        sc_handler->estimated_incomplete_size = input_buffers[1].cbBuffer;
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    };
    /* any output buffers that were filled in with SECBUFFER_TOKEN need to be sent,
       SECBUFFER_EXTRA means we need to account for extra data and shift everything for the next run. */
    if (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK) {
        for (size_t i = 0; i < output_buffers_desc.cBuffers; ++i) {
            SecBuffer *buf_ptr = &output_buffers[i];

            if (buf_ptr->BufferType == SECBUFFER_TOKEN && buf_ptr->cbBuffer) {
                struct aws_io_message *outgoing_message = aws_channel_acquire_message_from_pool(
                    sc_handler->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, buf_ptr->cbBuffer);

                if (!outgoing_message) {
                    FreeContextBuffer(buf_ptr->pvBuffer);
                    s_invoke_negotiation_error(handler, aws_last_error());
                    return AWS_OP_ERR;
                }

                memcpy(outgoing_message->message_data.buffer, buf_ptr->pvBuffer, buf_ptr->cbBuffer);
                outgoing_message->message_data.len = buf_ptr->cbBuffer;
                FreeContextBuffer(buf_ptr->pvBuffer);

                if (aws_channel_slot_send_message(sc_handler->slot, outgoing_message, AWS_CHANNEL_DIR_WRITE)) {
                    aws_mem_release(outgoing_message->allocator, outgoing_message);
                    s_invoke_negotiation_error(handler, aws_last_error());
                    return AWS_OP_ERR;
                }
            }
        }

        if (input_buffers[1].BufferType == SECBUFFER_EXTRA && input_buffers[1].cbBuffer > 0) {
            AWS_LOGF_TRACE(
                AWS_LS_IO_TLS,
                "id=%p: Extra data recieved. Extra size is %lu",
                (void *)handler,
                input_buffers[1].cbBuffer);
            sc_handler->read_extra = input_buffers[1].cbBuffer;
        }
    }

    if (status == SEC_E_OK) {
        AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: handshake completed", (void *)handler);
        /* if a custom CA store was configured, we have to do the verification ourselves. */
        if (sc_handler->custom_ca_store) {
            AWS_LOGF_TRACE(
                AWS_LS_IO_TLS,
                "id=%p: Custom CA was configured, evaluating trust before completing connection",
                (void *)handler);

            if (s_manually_verify_peer_cert(handler)) {
                aws_raise_error(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                s_invoke_negotiation_error(handler, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                return AWS_OP_ERR;
            }
        }
        sc_handler->negotiation_finished = true;

        /* force query of the sizes so future calls to encrypt will be loaded. */
        s_message_overhead(handler);

        /*
           grab the negotiated protocol out of the session.
        */
#ifdef SECBUFFER_APPLICATION_PROTOCOLS
        if (sc_handler->alpn_list && aws_tls_is_alpn_available()) {
            SecPkgContext_ApplicationProtocol alpn_result;
            status = QueryContextAttributes(&sc_handler->sec_handle, SECPKG_ATTR_APPLICATION_PROTOCOL, &alpn_result);
            AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: ALPN is configured. Checking for negotiated protocol", handler);

            if (status == SEC_E_OK && alpn_result.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success) {
                aws_byte_buf_init(&sc_handler->protocol, handler->alloc, alpn_result.ProtocolIdSize + 1);
                memset(sc_handler->protocol.buffer, 0, alpn_result.ProtocolIdSize + 1);
                memcpy(sc_handler->protocol.buffer, alpn_result.ProtocolId, alpn_result.ProtocolIdSize);
                sc_handler->protocol.len = alpn_result.ProtocolIdSize;
                AWS_LOGF_DEBUG(
                    AWS_LS_IO_TLS, "id=%p: negotiated protocol %s", handler, (char *)sc_handler->protocol.buffer);
            } else {
                AWS_LOGF_WARN(
                    AWS_LS_IO_TLS,
                    "id=%p: Error retrieving negotiated protocol. SECURITY_STATUS is %d",
                    handler,
                    (int)status);
                int aws_error = s_determine_sspi_error(status);
                aws_raise_error(aws_error);
            }
        }
#endif
        sc_handler->s_connection_state_fn = s_do_application_data_decrypt;
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "id=%p: TLS handshake completed successfully.", (void *)handler);
        s_on_negotiation_success(handler);
    }

    return AWS_OP_SUCCESS;
}

static int s_do_client_side_negotiation_step_2(struct aws_channel_handler *handler);

/* send the client hello */
static int s_do_client_side_negotiation_step_1(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;
    AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: client starting negotiation", (void *)handler);

    aws_on_drive_tls_negotiation(&sc_handler->shared_state);

    unsigned char alpn_buffer_data[128] = {0};
    SecBuffer input_buf = {
        .pvBuffer = NULL,
        .cbBuffer = 0,
        .BufferType = SECBUFFER_EMPTY,
    };

    SecBufferDesc input_buf_desc = {
        .ulVersion = SECBUFFER_VERSION,
        .cBuffers = 1,
        .pBuffers = &input_buf,
    };

    SecBufferDesc *alpn_sspi_data = NULL;

    /* add alpn data to the client hello if it's supported. */
#ifdef SECBUFFER_APPLICATION_PROTOCOLS
    if (sc_handler->alpn_list && aws_tls_is_alpn_available()) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_TLS, "id=%p: Setting ALPN data as %s", handler, aws_string_c_str(sc_handler->alpn_list));
        size_t extension_length = 0;
        if (s_fillin_alpn_data(handler, alpn_buffer_data, sizeof(alpn_buffer_data), &extension_length)) {
            s_invoke_negotiation_error(handler, aws_last_error());
            return AWS_OP_ERR;
        }

        input_buf.pvBuffer = alpn_buffer_data, input_buf.cbBuffer = (unsigned long)extension_length,
        input_buf.BufferType = SECBUFFER_APPLICATION_PROTOCOLS;

        alpn_sspi_data = &input_buf_desc;
    }
#endif /* SECBUFFER_APPLICATION_PROTOCOLS*/

    sc_handler->ctx_req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | ISC_REQ_CONFIDENTIALITY |
                          ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

    SecBuffer output_buffer = {
        .pvBuffer = NULL,
        .cbBuffer = 0,
        .BufferType = SECBUFFER_EMPTY,
    };

    SecBufferDesc output_buffer_desc = {
        .ulVersion = SECBUFFER_VERSION,
        .cBuffers = 1,
        .pBuffers = &output_buffer,
    };

    char server_name_cstr[256];
    AWS_ZERO_ARRAY(server_name_cstr);
    AWS_ASSERT(sc_handler->server_name.len < 256);
    memcpy(server_name_cstr, sc_handler->server_name.buffer, sc_handler->server_name.len);

    SECURITY_STATUS status = InitializeSecurityContextA(
        &sc_handler->creds,
        NULL,
        (SEC_CHAR *)server_name_cstr,
        sc_handler->ctx_req,
        0,
        0,
        alpn_sspi_data,
        0,
        &sc_handler->sec_handle,
        &output_buffer_desc,
        &sc_handler->ctx_ret_flags,
        &sc_handler->sspi_timestamp);

    if (status != SEC_I_CONTINUE_NEEDED) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_TLS,
            "id=%p: Error sending client/receiving server handshake data. SECURITY_STATUS is %d",
            (void *)handler,
            (int)status);
        int aws_error = s_determine_sspi_error(status);
        aws_raise_error(aws_error);
        s_invoke_negotiation_error(handler, aws_error);
        return AWS_OP_ERR;
    }

    size_t data_to_write_len = output_buffer.cbBuffer;
    AWS_LOGF_TRACE(
        AWS_LS_IO_TLS, "id=%p: Sending client handshake data of size %zu", (void *)handler, data_to_write_len);

    struct aws_io_message *outgoing_message = aws_channel_acquire_message_from_pool(
        sc_handler->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, data_to_write_len);
    if (!outgoing_message) {
        FreeContextBuffer(output_buffer.pvBuffer);
        s_invoke_negotiation_error(handler, aws_last_error());
        return AWS_OP_ERR;
    }

    AWS_ASSERT(outgoing_message->message_data.capacity >= data_to_write_len);
    memcpy(outgoing_message->message_data.buffer, output_buffer.pvBuffer, output_buffer.cbBuffer);
    outgoing_message->message_data.len = output_buffer.cbBuffer;
    FreeContextBuffer(output_buffer.pvBuffer);

    if (aws_channel_slot_send_message(sc_handler->slot, outgoing_message, AWS_CHANNEL_DIR_WRITE)) {
        aws_mem_release(outgoing_message->allocator, outgoing_message);
        s_invoke_negotiation_error(handler, aws_last_error());
        return AWS_OP_ERR;
    }

    sc_handler->s_connection_state_fn = s_do_client_side_negotiation_step_2;

    return AWS_OP_SUCCESS;
}

/* cipher exchange, key exchange etc.... */
static int s_do_client_side_negotiation_step_2(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;
    AWS_LOGF_TRACE(
        AWS_LS_IO_TLS,
        "id=%p: running step 2 of client-side negotiation (cipher change, key exchange etc...)",
        (void *)handler);

    SecBuffer input_buffers[] = {
        [0] =
            {
                .pvBuffer = sc_handler->buffered_read_in_data_buf.buffer,
                .cbBuffer = (unsigned long)sc_handler->buffered_read_in_data_buf.len,
                .BufferType = SECBUFFER_TOKEN,
            },
        [1] =
            {
                .pvBuffer = NULL,
                .cbBuffer = 0,
                .BufferType = SECBUFFER_EMPTY,
            },
    };

    SecBufferDesc input_buffers_desc = {
        .ulVersion = SECBUFFER_VERSION,
        .cBuffers = 2,
        .pBuffers = input_buffers,
    };

    SecBuffer output_buffers[3];
    AWS_ZERO_ARRAY(output_buffers);
    output_buffers[0].BufferType = SECBUFFER_TOKEN;
    output_buffers[1].BufferType = SECBUFFER_ALERT;

    SecBufferDesc output_buffers_desc = {
        .ulVersion = SECBUFFER_VERSION,
        .cBuffers = 3,
        .pBuffers = output_buffers,
    };

    SECURITY_STATUS status = SEC_E_OK;

    sc_handler->read_extra = 0;
    sc_handler->estimated_incomplete_size = 0;

    char server_name_cstr[256];
    AWS_ZERO_ARRAY(server_name_cstr);
    AWS_FATAL_ASSERT(sc_handler->server_name.len < sizeof(server_name_cstr));
    memcpy(server_name_cstr, sc_handler->server_name.buffer, sc_handler->server_name.len);

    status = InitializeSecurityContextA(
        &sc_handler->creds,
        &sc_handler->sec_handle,
        (SEC_CHAR *)server_name_cstr,
        sc_handler->ctx_req,
        0,
        0,
        &input_buffers_desc,
        0,
        NULL,
        &output_buffers_desc,
        &sc_handler->ctx_ret_flags,
        &sc_handler->sspi_timestamp);

    if (status != SEC_E_INCOMPLETE_MESSAGE && status != SEC_I_CONTINUE_NEEDED && status != SEC_E_OK) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_TLS, "id=%p: Error during negotiation. SECURITY_STATUS is %d", (void *)handler, (int)status);
        int aws_error = s_determine_sspi_error(status);
        aws_raise_error(aws_error);
        s_invoke_negotiation_error(handler, aws_error);
        return AWS_OP_ERR;
    }

    if (status == SEC_E_INCOMPLETE_MESSAGE) {
        sc_handler->estimated_incomplete_size = input_buffers[1].cbBuffer;
        AWS_LOGF_TRACE(
            AWS_LS_IO_TLS,
            "id=%p: Incomplete buffer recieved. Incomplete size is %zu. Waiting for more data.",
            (void *)handler,
            sc_handler->estimated_incomplete_size);
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    if (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK) {
        for (size_t i = 0; i < output_buffers_desc.cBuffers; ++i) {
            SecBuffer *buf_ptr = &output_buffers[i];

            if (buf_ptr->BufferType == SECBUFFER_TOKEN && buf_ptr->cbBuffer) {
                struct aws_io_message *outgoing_message = aws_channel_acquire_message_from_pool(
                    sc_handler->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, buf_ptr->cbBuffer);

                if (!outgoing_message) {
                    FreeContextBuffer(buf_ptr->pvBuffer);
                    s_invoke_negotiation_error(handler, aws_last_error());
                    return AWS_OP_ERR;
                }

                memcpy(outgoing_message->message_data.buffer, buf_ptr->pvBuffer, buf_ptr->cbBuffer);
                outgoing_message->message_data.len = buf_ptr->cbBuffer;
                FreeContextBuffer(buf_ptr->pvBuffer);

                if (aws_channel_slot_send_message(sc_handler->slot, outgoing_message, AWS_CHANNEL_DIR_WRITE)) {
                    aws_mem_release(outgoing_message->allocator, outgoing_message);
                    s_invoke_negotiation_error(handler, aws_last_error());
                    return AWS_OP_ERR;
                }
            }
        }

        if (input_buffers[1].BufferType == SECBUFFER_EXTRA && input_buffers[1].cbBuffer > 0) {
            AWS_LOGF_TRACE(
                AWS_LS_IO_TLS,
                "id=%p: Extra data recieved. Extra data size is %lu.",
                (void *)handler,
                input_buffers[1].cbBuffer);
            sc_handler->read_extra = input_buffers[1].cbBuffer;
        }
    }

    if (status == SEC_E_OK) {
        AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: handshake completed", handler);
        /* if a custom CA store was configured, we have to do the verification ourselves. */
        if (sc_handler->custom_ca_store) {
            AWS_LOGF_TRACE(
                AWS_LS_IO_TLS,
                "id=%p: Custom CA was configured, evaluating trust before completing connection",
                (void *)handler);
            if (s_manually_verify_peer_cert(handler)) {
                aws_raise_error(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                s_invoke_negotiation_error(handler, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                return AWS_OP_ERR;
            }
        }
        sc_handler->negotiation_finished = true;
        /* force the sizes query, so future Encrypt message calls work.*/
        s_message_overhead(handler);

#ifdef SECBUFFER_APPLICATION_PROTOCOLS
        if (sc_handler->alpn_list && aws_tls_is_alpn_available()) {
            AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: Retrieving negotiated protocol.", handler);
            SecPkgContext_ApplicationProtocol alpn_result;
            status = QueryContextAttributes(&sc_handler->sec_handle, SECPKG_ATTR_APPLICATION_PROTOCOL, &alpn_result);

            if (status == SEC_E_OK && alpn_result.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success) {
                aws_byte_buf_init(&sc_handler->protocol, handler->alloc, alpn_result.ProtocolIdSize + 1);
                memset(sc_handler->protocol.buffer, 0, alpn_result.ProtocolIdSize + 1);
                memcpy(sc_handler->protocol.buffer, alpn_result.ProtocolId, alpn_result.ProtocolIdSize);
                sc_handler->protocol.len = alpn_result.ProtocolIdSize;
                AWS_LOGF_DEBUG(
                    AWS_LS_IO_TLS, "id=%p: Negotiated protocol %s", handler, (char *)sc_handler->protocol.buffer);
            } else {
                AWS_LOGF_WARN(
                    AWS_LS_IO_TLS,
                    "id=%p: Error retrieving negotiated protocol. SECURITY_STATUS is %d",
                    handler,
                    (int)status);
                int aws_error = s_determine_sspi_error(status);
                aws_raise_error(aws_error);
            }
        }
#endif
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "id=%p: TLS handshake completed successfully.", (void *)handler);
        sc_handler->s_connection_state_fn = s_do_application_data_decrypt;
        s_on_negotiation_success(handler);
    }

    return AWS_OP_SUCCESS;
}

static int s_do_application_data_decrypt(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;

    /* I know this is an unncessary initialization, it's initialized here to make linters happy.*/
    int error = AWS_OP_ERR;
    /* when we get an Extra buffer we have to move the pointer and replay the buffer, so we loop until we don't have
       any extra buffers left over, in the last phase, we then go ahead and send the output. This state function will
       always say BLOCKED_ON_READ, AWS_IO_TLS_ERROR_READ_FAILURE or SUCCESS. There will never be left over reads.*/
    do {
        error = AWS_OP_ERR;
        /* 4 buffers are needed, only one is input, the others get zeroed out for the output operation. */
        SecBuffer input_buffers[4];
        AWS_ZERO_ARRAY(input_buffers);

        size_t read_len = sc_handler->read_extra ? sc_handler->read_extra : sc_handler->buffered_read_in_data_buf.len;
        size_t offset = sc_handler->read_extra ? sc_handler->buffered_read_in_data_buf.len - sc_handler->read_extra : 0;
        sc_handler->read_extra = 0;

        input_buffers[0] = (SecBuffer){
            .cbBuffer = (unsigned long)(read_len),
            .pvBuffer = sc_handler->buffered_read_in_data_buf.buffer + offset,
            .BufferType = SECBUFFER_DATA,
        };

        SecBufferDesc buffer_desc = {
            .ulVersion = SECBUFFER_VERSION,
            .cBuffers = 4,
            .pBuffers = input_buffers,
        };

        SECURITY_STATUS status = DecryptMessage(&sc_handler->sec_handle, &buffer_desc, 0, NULL);

        if (status == SEC_E_OK) {
            error = AWS_OP_SUCCESS;
            /* if SECBUFFER_DATA is the buffer type of the second buffer, we have decrypted data to process.
               If SECBUFFER_DATA is the type for the fourth buffer we need to keep track of it so we can shift
               everything before doing another decrypt operation.
               We don't care what's in the third buffer for TLS usage.*/
            if (input_buffers[1].BufferType == SECBUFFER_DATA) {
                size_t decrypted_length = input_buffers[1].cbBuffer;
                AWS_LOGF_TRACE(
                    AWS_LS_IO_TLS, "id=%p: Decrypted message with length %zu.", (void *)handler, decrypted_length);

                struct aws_byte_cursor to_append =
                    aws_byte_cursor_from_array(input_buffers[1].pvBuffer, decrypted_length);
                int append_failed = aws_byte_buf_append(&sc_handler->buffered_read_out_data_buf, &to_append);
                AWS_ASSERT(!append_failed);
                (void)append_failed;

                /* if we have extra we have to move the pointer and do another Decrypt operation. */
                if (input_buffers[3].BufferType == SECBUFFER_EXTRA) {
                    sc_handler->read_extra = input_buffers[3].cbBuffer;
                    AWS_LOGF_TRACE(
                        AWS_LS_IO_TLS,
                        "id=%p: Extra (incomplete) message received with length %zu.",
                        (void *)handler,
                        sc_handler->read_extra);
                } else {
                    error = AWS_OP_SUCCESS;
                    /* this means we processed everything in the buffer. */
                    sc_handler->buffered_read_in_data_buf.len = 0;
                    AWS_LOGF_TRACE(
                        AWS_LS_IO_TLS,
                        "id=%p: Decrypt ended exactly on the end of the record, resetting buffer.",
                        (void *)handler);
                }
            }
        }
        /* SEC_E_INCOMPLETE_MESSAGE means the message we tried to decrypt isn't a full record and we need to
           append our next read to it and try again. */
        else if (status == SEC_E_INCOMPLETE_MESSAGE) {
            sc_handler->estimated_incomplete_size = input_buffers[1].cbBuffer;
            AWS_LOGF_TRACE(
                AWS_LS_IO_TLS,
                "id=%p: (incomplete) message received. Expecting remaining portion of size %zu.",
                (void *)handler,
                sc_handler->estimated_incomplete_size);
            memmove(
                sc_handler->buffered_read_in_data_buf.buffer,
                sc_handler->buffered_read_in_data_buf.buffer + offset,
                read_len);
            sc_handler->buffered_read_in_data_buf.len = read_len;
            aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
        }
        /* SEC_I_CONTEXT_EXPIRED means that the message sender has shut down the connection.  One such case
           where this can happen is an unaccepted certificate. */
        else if (status == SEC_I_CONTEXT_EXPIRED) {
            AWS_LOGF_TRACE(
                AWS_LS_IO_TLS,
                "id=%p: Alert received. Message sender has shut down the connection. SECURITY_STATUS is %d.",
                (void *)handler,
                (int)status);

            struct aws_channel_slot *slot = handler->slot;
            aws_channel_shutdown(slot->channel, AWS_OP_SUCCESS);
            error = AWS_OP_SUCCESS;
        } else {
            AWS_LOGF_ERROR(
                AWS_LS_IO_TLS, "id=%p: Error decrypting message. SECURITY_STATUS is %d.", (void *)handler, (int)status);
            aws_raise_error(AWS_IO_TLS_ERROR_READ_FAILURE);
        }
    } while (sc_handler->read_extra);

    return error;
}

static int s_process_pending_output_messages(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;

    size_t downstream_window = SIZE_MAX;

    if (sc_handler->slot->adj_right) {
        downstream_window = aws_channel_slot_downstream_read_window(sc_handler->slot);
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_TLS,
        "id=%p: Processing incomming messages. Downstream window is %zu",
        (void *)handler,
        downstream_window);
    while (sc_handler->buffered_read_out_data_buf.len && downstream_window) {
        size_t requested_message_size = sc_handler->buffered_read_out_data_buf.len > downstream_window
                                            ? downstream_window
                                            : sc_handler->buffered_read_out_data_buf.len;
        AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: Requested message size is %zu", (void *)handler, requested_message_size);

        if (sc_handler->slot->adj_right) {
            struct aws_io_message *read_out_msg = aws_channel_acquire_message_from_pool(
                sc_handler->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, requested_message_size);

            if (!read_out_msg) {
                return AWS_OP_ERR;
            }

            size_t copy_size = read_out_msg->message_data.capacity < requested_message_size
                                   ? read_out_msg->message_data.capacity
                                   : requested_message_size;

            memcpy(read_out_msg->message_data.buffer, sc_handler->buffered_read_out_data_buf.buffer, copy_size);
            read_out_msg->message_data.len = copy_size;

            memmove(
                sc_handler->buffered_read_out_data_buf.buffer,
                sc_handler->buffered_read_out_data_buf.buffer + copy_size,
                sc_handler->buffered_read_out_data_buf.len - copy_size);
            sc_handler->buffered_read_out_data_buf.len -= copy_size;

            if (sc_handler->on_data_read) {
                sc_handler->on_data_read(handler, sc_handler->slot, &read_out_msg->message_data, sc_handler->user_data);
            }
            if (aws_channel_slot_send_message(sc_handler->slot, read_out_msg, AWS_CHANNEL_DIR_READ)) {
                aws_mem_release(read_out_msg->allocator, read_out_msg);
                return AWS_OP_ERR;
            }

            if (sc_handler->slot->adj_right) {
                downstream_window = aws_channel_slot_downstream_read_window(sc_handler->slot);
            }
            AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: Downstream window is %zu", (void *)handler, downstream_window);
        } else {
            if (sc_handler->on_data_read) {
                sc_handler->on_data_read(
                    handler, sc_handler->slot, &sc_handler->buffered_read_out_data_buf, sc_handler->user_data);
            }
            sc_handler->buffered_read_out_data_buf.len = 0;
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_process_pending_output_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    struct aws_channel_handler *handler = arg;

    aws_channel_task_init(task, NULL, NULL, "secure_channel_handler_process_pending_output");
    if (status == AWS_TASK_STATUS_RUN_READY) {
        if (s_process_pending_output_messages(handler)) {
            struct secure_channel_handler *sc_handler = arg;
            aws_channel_shutdown(sc_handler->slot->channel, aws_last_error());
        }
    }
}

static int s_process_read_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct secure_channel_handler *sc_handler = handler->impl;

    if (message) {
        /* note, most of these functions log internally, so the log messages in this function are sparse. */
        AWS_LOGF_TRACE(
            AWS_LS_IO_TLS,
            "id=%p: processing incoming message of size %zu",
            (void *)handler,
            message->message_data.len);

        struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&message->message_data);

        /* The SSPI interface forces us to manage incomplete records manually. So when we had extra after
           the previous read, it needs to be shifted to the beginning of the current read, then the current
           read data is appended to it. If we had an incomplete record, we don't need to shift anything but
           we do need to append the current read data to the end of the incomplete record from the previous read.
           Keep going until we've processed everything in the message we were just passed.
         */
        int err = AWS_OP_SUCCESS;
        while (!err && message_cursor.len) {

            size_t available_buffer_space =
                sc_handler->buffered_read_in_data_buf.capacity - sc_handler->buffered_read_in_data_buf.len;
            size_t available_message_len = message_cursor.len;
            size_t amount_to_move_to_buffer =
                available_buffer_space > available_message_len ? available_message_len : available_buffer_space;

            memcpy(
                sc_handler->buffered_read_in_data_buf.buffer + sc_handler->buffered_read_in_data_buf.len,
                message_cursor.ptr,
                amount_to_move_to_buffer);
            sc_handler->buffered_read_in_data_buf.len += amount_to_move_to_buffer;

            err = sc_handler->s_connection_state_fn(handler);

            if (err && aws_last_error() == AWS_IO_READ_WOULD_BLOCK) {
                if (sc_handler->buffered_read_in_data_buf.len == sc_handler->buffered_read_in_data_buf.capacity) {
                    /* throw this one as a protocol error. */
                    aws_raise_error(AWS_IO_TLS_ERROR_WRITE_FAILURE);
                } else {
                    if (sc_handler->buffered_read_out_data_buf.len) {
                        err = s_process_pending_output_messages(handler);
                        if (err) {
                            break;
                        }
                    }
                    /* prevent a deadlock due to downstream handlers wanting more data, but we have an incomplete
                       record, and the amount they're requesting is less than the size of a tls record. */
                    size_t window_size = slot->window_size;
                    if (!window_size &&
                        aws_channel_slot_increment_read_window(slot, sc_handler->estimated_incomplete_size)) {
                        err = AWS_OP_ERR;
                    } else {
                        sc_handler->estimated_incomplete_size = 0;
                        err = AWS_OP_SUCCESS;
                    }
                }
                aws_byte_cursor_advance(&message_cursor, amount_to_move_to_buffer);
                continue;
            } else if (err) {
                break;
            }

            /* handle any left over extra data from the decrypt operation here. */
            if (sc_handler->read_extra) {
                size_t move_pos = sc_handler->buffered_read_in_data_buf.len - sc_handler->read_extra;
                memmove(
                    sc_handler->buffered_read_in_data_buf.buffer,
                    sc_handler->buffered_read_in_data_buf.buffer + move_pos,
                    sc_handler->read_extra);
                sc_handler->buffered_read_in_data_buf.len = sc_handler->read_extra;
                sc_handler->read_extra = 0;
            } else {
                sc_handler->buffered_read_in_data_buf.len = 0;
            }

            if (sc_handler->buffered_read_out_data_buf.len) {
                err = s_process_pending_output_messages(handler);
                if (err) {
                    break;
                }
            }
            aws_byte_cursor_advance(&message_cursor, amount_to_move_to_buffer);
        }

        if (!err) {
            aws_mem_release(message->allocator, message);
            return AWS_OP_SUCCESS;
        }

        aws_channel_shutdown(slot->channel, aws_last_error());
        return AWS_OP_ERR;
    }

    if (sc_handler->buffered_read_out_data_buf.len) {
        if (s_process_pending_output_messages(handler)) {
            return AWS_OP_ERR;
        }
        aws_mem_release(message->allocator, message);
    }

    return AWS_OP_SUCCESS;
}

static int s_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {

    struct secure_channel_handler *sc_handler = (struct secure_channel_handler *)handler->impl;
    AWS_ASSERT(sc_handler->negotiation_finished);
    SECURITY_STATUS status = SEC_E_OK;

    if (message) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_TLS, "id=%p: processing ougoing message of size %zu", (void *)handler, message->message_data.len);

        struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&message->message_data);

        while (message_cursor.len) {
            AWS_LOGF_TRACE(
                AWS_LS_IO_TLS, "id=%p: processing message fragment of size %zu", (void *)handler, message_cursor.len);
            /* message size will be the lesser of either payload + record overhead or the max TLS record size.*/
            size_t upstream_overhead = aws_channel_slot_upstream_message_overhead(sc_handler->slot);
            upstream_overhead += sc_handler->stream_sizes.cbHeader + sc_handler->stream_sizes.cbTrailer;
            size_t requested_length = message_cursor.len + upstream_overhead;
            size_t to_write = sc_handler->stream_sizes.cbMaximumMessage < requested_length
                                  ? sc_handler->stream_sizes.cbMaximumMessage
                                  : requested_length;
            struct aws_io_message *outgoing_message =
                aws_channel_acquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, to_write);

            if (!outgoing_message || outgoing_message->message_data.capacity <= upstream_overhead) {
                return AWS_OP_ERR;
            }

            /* what if message is larger than one record? */
            size_t original_message_fragment_to_process = outgoing_message->message_data.capacity - upstream_overhead;
            memcpy(
                outgoing_message->message_data.buffer + sc_handler->stream_sizes.cbHeader,
                message_cursor.ptr,
                original_message_fragment_to_process);

            if (original_message_fragment_to_process == message_cursor.len) {
                outgoing_message->on_completion = message->on_completion;
                outgoing_message->user_data = message->user_data;
            }

            SecBuffer buffers[4] = {
                [0] =
                    {
                        .BufferType = SECBUFFER_STREAM_HEADER,
                        .pvBuffer = outgoing_message->message_data.buffer,
                        .cbBuffer = sc_handler->stream_sizes.cbHeader,
                    },
                [1] =
                    {
                        .BufferType = SECBUFFER_DATA,
                        .pvBuffer = outgoing_message->message_data.buffer + sc_handler->stream_sizes.cbHeader,
                        .cbBuffer = (unsigned long)original_message_fragment_to_process,
                    },
                [2] =
                    {
                        .BufferType = SECBUFFER_STREAM_TRAILER,
                        .pvBuffer = outgoing_message->message_data.buffer + sc_handler->stream_sizes.cbHeader +
                                    original_message_fragment_to_process,
                        .cbBuffer = sc_handler->stream_sizes.cbTrailer,
                    },
                [3] =
                    {
                        .BufferType = SECBUFFER_EMPTY,
                        .pvBuffer = NULL,
                        .cbBuffer = 0,
                    },
            };

            SecBufferDesc buffer_desc = {
                .ulVersion = SECBUFFER_VERSION,
                .cBuffers = 4,
                .pBuffers = buffers,
            };

            status = EncryptMessage(&sc_handler->sec_handle, 0, &buffer_desc, 0);

            if (status == SEC_E_OK) {
                outgoing_message->message_data.len = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
                AWS_LOGF_TRACE(
                    AWS_LS_IO_TLS,
                    "id=%p:message fragment encrypted successfully: size is %zu",
                    (void *)handler,
                    outgoing_message->message_data.len);

                if (aws_channel_slot_send_message(slot, outgoing_message, AWS_CHANNEL_DIR_WRITE)) {
                    aws_mem_release(outgoing_message->allocator, outgoing_message);
                    return AWS_OP_ERR;
                }

                aws_byte_cursor_advance(&message_cursor, original_message_fragment_to_process);
            } else {
                AWS_LOGF_TRACE(
                    AWS_LS_IO_TLS,
                    "id=%p: Error encrypting message. SECURITY_STATUS is %d",
                    (void *)handler,
                    (int)status);
                return aws_raise_error(AWS_IO_TLS_ERROR_WRITE_FAILURE);
            }
        }

        aws_mem_release(message->allocator, message);
    }

    return AWS_OP_SUCCESS;
}

static int s_increment_read_window(struct aws_channel_handler *handler, struct aws_channel_slot *slot, size_t size) {
    (void)size;
    struct secure_channel_handler *sc_handler = handler->impl;
    AWS_LOGF_TRACE(AWS_LS_IO_TLS, "id=%p: Increment read window message received %zu", (void *)handler, size);

    /* You can't query a context if negotiation isn't completed, since ciphers haven't been negotiated
     * and it couldn't possibly know the overhead size yet. */
    if (sc_handler->negotiation_finished && !sc_handler->stream_sizes.cbMaximumMessage) {
        SECURITY_STATUS status =
            QueryContextAttributes(&sc_handler->sec_handle, SECPKG_ATTR_STREAM_SIZES, &sc_handler->stream_sizes);

        if (status != SEC_E_OK) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_TLS, "id=%p: QueryContextAttributes failed with error %d", (void *)handler, (int)status);
            aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
            aws_channel_shutdown(slot->channel, AWS_ERROR_SYS_CALL_FAILURE);
            return AWS_OP_ERR;
        }
    }

    size_t total_desired_size = size;
    size_t downstream_size = aws_channel_slot_downstream_read_window(slot);
    size_t current_window_size = slot->window_size;

    /* the only time this branch isn't taken is when a window update is propagated during tls negotiation.
     * in that case just pass it through. */
    if (sc_handler->stream_sizes.cbMaximumMessage) {
        size_t likely_records_count = (size_t)ceil((double)(downstream_size) / (double)(READ_IN_SIZE));
        size_t offset_size = aws_mul_size_saturating(
            likely_records_count, sc_handler->stream_sizes.cbTrailer + sc_handler->stream_sizes.cbHeader);
        total_desired_size = aws_add_size_saturating(offset_size, downstream_size);
    }

    if (total_desired_size > current_window_size) {
        size_t window_update_size = total_desired_size - current_window_size;
        AWS_LOGF_TRACE(
            AWS_LS_IO_TLS, "id=%p: Propagating read window increment of size %zu", (void *)handler, window_update_size);
        aws_channel_slot_increment_read_window(slot, window_update_size);
    }

    if (sc_handler->negotiation_finished && !sc_handler->sequential_task_storage.task_fn) {
        aws_channel_task_init(
            &sc_handler->sequential_task_storage,
            s_process_pending_output_task,
            handler,
            "secure_channel_handler_process_pending_output_on_window_increment");
        aws_channel_schedule_task_now(slot->channel, &sc_handler->sequential_task_storage);
    }
    return AWS_OP_SUCCESS;
}

static size_t s_initial_window_size(struct aws_channel_handler *handler) {
    (void)handler;

    /* set this to just enough for the handshake, once the handshake completes, the downstream
       handler will tell us the new window size. */
    return EST_HANDSHAKE_SIZE;
}

static int s_handler_shutdown(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    enum aws_channel_direction dir,
    int error_code,
    bool abort_immediately) {
    struct secure_channel_handler *sc_handler = handler->impl;

    if (dir == AWS_CHANNEL_DIR_WRITE) {
        if (!abort_immediately && error_code != AWS_IO_SOCKET_CLOSED) {
            AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "id=%p: Shutting down the write direction", (void *)handler);

            /* send a TLS alert. */
            SECURITY_STATUS status;

            DWORD shutdown_code = SCHANNEL_SHUTDOWN;
            SecBuffer shutdown_buffer = {
                .pvBuffer = &shutdown_code,
                .cbBuffer = sizeof(shutdown_code),
                .BufferType = SECBUFFER_TOKEN,
            };

            SecBufferDesc shutdown_buffer_desc = {
                .ulVersion = SECBUFFER_VERSION,
                .cBuffers = 1,
                .pBuffers = &shutdown_buffer,
            };

            /* this updates the SSPI internal state machine. */
            status = ApplyControlToken(&sc_handler->sec_handle, &shutdown_buffer_desc);

            if (status != SEC_E_OK) {
                aws_raise_error(AWS_ERROR_SYS_CALL_FAILURE);
                return aws_channel_slot_on_handler_shutdown_complete(
                    slot, dir, AWS_ERROR_SYS_CALL_FAILURE, abort_immediately);
            }

            SecBuffer output_buffer = {
                .pvBuffer = NULL,
                .cbBuffer = 0,
                .BufferType = SECBUFFER_EMPTY,
            };

            SecBufferDesc output_buffer_desc = {
                .ulVersion = SECBUFFER_VERSION,
                .cBuffers = 1,
                .pBuffers = &output_buffer,
            };

            struct aws_byte_buf server_name = aws_tls_handler_server_name(handler);
            char server_name_cstr[256];
            AWS_ZERO_ARRAY(server_name_cstr);
            AWS_FATAL_ASSERT(server_name.len < sizeof(server_name_cstr));
            memcpy(server_name_cstr, server_name.buffer, server_name.len);
            /* this acutally gives us an Alert record to send. */
            status = InitializeSecurityContextA(
                &sc_handler->creds,
                &sc_handler->sec_handle,
                (SEC_CHAR *)server_name_cstr,
                sc_handler->ctx_req,
                0,
                0,
                NULL,
                0,
                NULL,
                &output_buffer_desc,
                &sc_handler->ctx_ret_flags,
                NULL);

            if (status == SEC_E_OK || status == SEC_I_CONTEXT_EXPIRED) {
                struct aws_io_message *outgoing_message = aws_channel_acquire_message_from_pool(
                    slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, output_buffer.cbBuffer);

                if (!outgoing_message || outgoing_message->message_data.capacity < output_buffer.cbBuffer) {
                    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, aws_last_error(), true);
                }
                memcpy(outgoing_message->message_data.buffer, output_buffer.pvBuffer, output_buffer.cbBuffer);
                outgoing_message->message_data.len = output_buffer.cbBuffer;

                /* we don't really care if this succeeds or not, it's just sending the TLS alert. */
                if (aws_channel_slot_send_message(slot, outgoing_message, AWS_CHANNEL_DIR_WRITE)) {
                    aws_mem_release(outgoing_message->allocator, outgoing_message);
                }
            }
        }
    }

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, abort_immediately);
}

static void s_do_negotiation_task(struct aws_channel_task *task, void *arg, enum aws_task_status status) {
    (void)task;

    struct aws_channel_handler *handler = arg;
    struct secure_channel_handler *sc_handler = handler->impl;

    if (status == AWS_TASK_STATUS_RUN_READY) {
        int err = sc_handler->s_connection_state_fn(handler);
        if (err) {
            aws_channel_shutdown(sc_handler->slot->channel, aws_last_error());
        }
    }
}

static void s_secure_channel_handler_destroy(
    struct aws_allocator *allocator,
    struct secure_channel_handler *sc_handler) {

    if (sc_handler == NULL) {
        return;
    }

    if (sc_handler->protocol.buffer) {
        aws_byte_buf_clean_up(&sc_handler->protocol);
    }

    if (sc_handler->alpn_list) {
        aws_string_destroy(sc_handler->alpn_list);
    }

    if (sc_handler->server_name.buffer) {
        aws_byte_buf_clean_up(&sc_handler->server_name);
    }

    if (sc_handler->sec_handle.dwLower || sc_handler->sec_handle.dwUpper) {
        DeleteSecurityContext(&sc_handler->sec_handle);
    }

    if (sc_handler->creds.dwLower || sc_handler->creds.dwUpper) {
        DeleteSecurityContext(&sc_handler->creds);
    }

    aws_tls_channel_handler_shared_clean_up(&sc_handler->shared_state);

    aws_mem_release(allocator, sc_handler);
}

static void s_handler_destroy(struct aws_channel_handler *handler) {
    AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "id=%p: destroying handler", (void *)handler);
    struct secure_channel_handler *sc_handler = handler->impl;

    s_secure_channel_handler_destroy(handler->alloc, sc_handler);
}

static void s_reset_statistics(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;

    aws_crt_statistics_tls_reset(&sc_handler->shared_state.stats);
}

static void s_gather_statistics(struct aws_channel_handler *handler, struct aws_array_list *stats) {
    struct secure_channel_handler *sc_handler = handler->impl;

    void *stats_base = &sc_handler->shared_state.stats;
    aws_array_list_push_back(stats, &stats_base);
}

int aws_tls_client_handler_start_negotiation(struct aws_channel_handler *handler) {
    AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "id=%p: Kicking off TLS negotiation", (void *)handler);

    struct secure_channel_handler *sc_handler = handler->impl;

    if (aws_channel_thread_is_callers_thread(sc_handler->slot->channel)) {
        int err = sc_handler->s_connection_state_fn(handler);
        if (err) {
            aws_channel_shutdown(sc_handler->slot->channel, aws_last_error());
        }
        return err;
    }

    aws_channel_task_init(
        &sc_handler->sequential_task_storage,
        s_do_negotiation_task,
        handler,
        "secure_channel_handler_start_negotation");
    aws_channel_schedule_task_now(sc_handler->slot->channel, &sc_handler->sequential_task_storage);
    return AWS_OP_SUCCESS;
}

struct aws_byte_buf aws_tls_handler_protocol(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;
    return sc_handler->protocol;
}

struct aws_byte_buf aws_tls_handler_server_name(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;
    return sc_handler->server_name;
}

static struct aws_channel_handler_vtable s_handler_vtable = {
    .destroy = s_handler_destroy,
    .process_read_message = s_process_read_message,
    .process_write_message = s_process_write_message,
    .shutdown = s_handler_shutdown,
    .increment_read_window = s_increment_read_window,
    .initial_window_size = s_initial_window_size,
    .message_overhead = s_message_overhead,
    .reset_statistics = s_reset_statistics,
    .gather_statistics = s_gather_statistics,
};

static struct aws_channel_handler *s_tls_handler_new(
    struct aws_allocator *alloc,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot,
    bool is_client_mode) {
    AWS_ASSERT(options->ctx);

    struct secure_channel_handler *sc_handler = aws_mem_calloc(alloc, 1, sizeof(struct secure_channel_handler));
    if (!sc_handler) {
        return NULL;
    }

    sc_handler->handler.alloc = alloc;
    sc_handler->handler.impl = sc_handler;
    sc_handler->handler.vtable = &s_handler_vtable;
    sc_handler->handler.slot = slot;

    aws_tls_channel_handler_shared_init(&sc_handler->shared_state, &sc_handler->handler, options);

    struct secure_channel_ctx *sc_ctx = options->ctx->impl;

    unsigned long credential_use = SECPKG_CRED_INBOUND;
    if (is_client_mode) {
        credential_use = SECPKG_CRED_OUTBOUND;
    }

    SECURITY_STATUS status = AcquireCredentialsHandleA(
        NULL,
        UNISP_NAME,
        credential_use,
        NULL,
        &sc_ctx->credentials,
        NULL,
        NULL,
        &sc_handler->creds,
        &sc_handler->sspi_timestamp);

    if (status != SEC_E_OK) {
        AWS_LOGF_ERROR(AWS_LS_IO_TLS, "Error on AcquireCredentialsHandle. SECURITY_STATUS is %d", (int)status);
        int aws_error = s_determine_sspi_error(status);
        aws_raise_error(aws_error);
        goto on_error;
    }

    sc_handler->advertise_alpn_message = options->advertise_alpn_message;
    sc_handler->on_data_read = options->on_data_read;
    sc_handler->on_error = options->on_error;
    sc_handler->on_negotiation_result = options->on_negotiation_result;
    sc_handler->user_data = options->user_data;

    if (!options->alpn_list && sc_ctx->alpn_list) {
        sc_handler->alpn_list = aws_string_new_from_string(alloc, sc_ctx->alpn_list);
        if (!sc_handler->alpn_list) {
            goto on_error;
        }
    } else if (options->alpn_list) {
        sc_handler->alpn_list = aws_string_new_from_string(alloc, options->alpn_list);
        if (!sc_handler->alpn_list) {
            goto on_error;
        }
    }

    if (options->server_name) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_TLS,
            "id=%p: Setting SNI to %s",
            (void *)&sc_handler->handler,
            aws_string_c_str(options->server_name));
        struct aws_byte_cursor server_name_crsr = aws_byte_cursor_from_string(options->server_name);
        if (aws_byte_buf_init_copy_from_cursor(&sc_handler->server_name, alloc, server_name_crsr)) {
            goto on_error;
        }
    }

    sc_handler->slot = slot;

    if (is_client_mode) {
        sc_handler->s_connection_state_fn = s_do_client_side_negotiation_step_1;
    } else {
        sc_handler->s_connection_state_fn = s_do_server_side_negotiation_step_1;
    }

    sc_handler->custom_ca_store = sc_ctx->custom_trust_store;
    sc_handler->buffered_read_in_data_buf =
        aws_byte_buf_from_array(sc_handler->buffered_read_in_data, sizeof(sc_handler->buffered_read_in_data));
    sc_handler->buffered_read_in_data_buf.len = 0;
    sc_handler->buffered_read_out_data_buf =
        aws_byte_buf_from_array(sc_handler->buffered_read_out_data, sizeof(sc_handler->buffered_read_out_data));
    sc_handler->buffered_read_out_data_buf.len = 0;
    sc_handler->verify_peer = sc_ctx->verify_peer;

    return &sc_handler->handler;

on_error:

    s_secure_channel_handler_destroy(alloc, sc_handler);

    return NULL;
}
struct aws_channel_handler *aws_tls_client_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {

    return s_tls_handler_new(allocator, options, slot, true);
}

struct aws_channel_handler *aws_tls_server_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {

    return s_tls_handler_new(allocator, options, slot, false);
}

static void s_secure_channel_ctx_destroy(struct secure_channel_ctx *secure_channel_ctx) {
    if (secure_channel_ctx == NULL) {
        return;
    }

    if (secure_channel_ctx->private_key) {
        CryptDestroyKey(secure_channel_ctx->private_key);
    }

    if (secure_channel_ctx->crypto_provider) {
        CryptReleaseContext(secure_channel_ctx->crypto_provider, 0);
    }

    if (secure_channel_ctx->custom_trust_store) {
        aws_close_cert_store(secure_channel_ctx->custom_trust_store);
    }

    if (secure_channel_ctx->pcerts) {
        /**
         * Only free the private certificate context if the private key is NOT
         * from the certificate context because freeing the private key
         * using CryptDestroyKey frees the certificate context and then
         * trying to access it leads to a access violation.
         */
        if (secure_channel_ctx->should_free_pcerts == true) {
            CertFreeCertificateContext(secure_channel_ctx->pcerts);
        }
    }

    if (secure_channel_ctx->cert_store) {
        aws_close_cert_store(secure_channel_ctx->cert_store);
    }

    if (secure_channel_ctx->alpn_list) {
        aws_string_destroy(secure_channel_ctx->alpn_list);
    }

    aws_mem_release(secure_channel_ctx->ctx.alloc, secure_channel_ctx);
}

struct aws_tls_ctx *s_ctx_new(
    struct aws_allocator *alloc,
    const struct aws_tls_ctx_options *options,
    bool is_client_mode) {

    if (!aws_tls_is_cipher_pref_supported(options->cipher_pref)) {
        aws_raise_error(AWS_IO_TLS_CIPHER_PREF_UNSUPPORTED);
        AWS_LOGF_ERROR(AWS_LS_IO_TLS, "static: TLS Cipher Preference is not supported: %d.", options->cipher_pref);
        return NULL;
    }

    struct secure_channel_ctx *secure_channel_ctx = aws_mem_calloc(alloc, 1, sizeof(struct secure_channel_ctx));
    if (!secure_channel_ctx) {
        return NULL;
    }

    secure_channel_ctx->ctx.alloc = alloc;
    secure_channel_ctx->ctx.impl = secure_channel_ctx;
    aws_ref_count_init(
        &secure_channel_ctx->ctx.ref_count,
        secure_channel_ctx,
        (aws_simple_completion_callback *)s_secure_channel_ctx_destroy);

    if (options->alpn_list) {
        secure_channel_ctx->alpn_list = aws_string_new_from_string(alloc, options->alpn_list);
        if (!secure_channel_ctx->alpn_list) {
            goto clean_up;
        }
    }

    secure_channel_ctx->verify_peer = options->verify_peer;
    secure_channel_ctx->credentials.dwVersion = SCHANNEL_CRED_VERSION;
    secure_channel_ctx->should_free_pcerts = true;

    secure_channel_ctx->credentials.grbitEnabledProtocols = 0;

    if (is_client_mode) {
        switch (options->minimum_tls_version) {
            case AWS_IO_SSLv3:
                secure_channel_ctx->credentials.grbitEnabledProtocols |= SP_PROT_SSL3_CLIENT;
            case AWS_IO_TLSv1:
                secure_channel_ctx->credentials.grbitEnabledProtocols |= SP_PROT_TLS1_0_CLIENT;
            case AWS_IO_TLSv1_1:
                secure_channel_ctx->credentials.grbitEnabledProtocols |= SP_PROT_TLS1_1_CLIENT;
            case AWS_IO_TLSv1_2:
#if defined(SP_PROT_TLS1_2_CLIENT)
                secure_channel_ctx->credentials.grbitEnabledProtocols |= SP_PROT_TLS1_2_CLIENT;
#endif
            case AWS_IO_TLSv1_3:
#if defined(SP_PROT_TLS1_3_CLIENT)
                secure_channel_ctx->credentials.grbitEnabledProtocols |= SP_PROT_TLS1_3_CLIENT;
#endif
                break;
            case AWS_IO_TLS_VER_SYS_DEFAULTS:
                secure_channel_ctx->credentials.grbitEnabledProtocols = 0;
                break;
        }
    } else {
        switch (options->minimum_tls_version) {
            case AWS_IO_SSLv3:
                secure_channel_ctx->credentials.grbitEnabledProtocols |= SP_PROT_SSL3_SERVER;
            case AWS_IO_TLSv1:
                secure_channel_ctx->credentials.grbitEnabledProtocols |= SP_PROT_TLS1_0_SERVER;
            case AWS_IO_TLSv1_1:
                secure_channel_ctx->credentials.grbitEnabledProtocols |= SP_PROT_TLS1_1_SERVER;
            case AWS_IO_TLSv1_2:
#if defined(SP_PROT_TLS1_2_SERVER)
                secure_channel_ctx->credentials.grbitEnabledProtocols |= SP_PROT_TLS1_2_SERVER;
#endif
            case AWS_IO_TLSv1_3:
#if defined(SP_PROT_TLS1_3_SERVER)
                secure_channel_ctx->credentials.grbitEnabledProtocols |= SP_PROT_TLS1_3_SERVER;
#endif
                break;
            case AWS_IO_TLS_VER_SYS_DEFAULTS:
                secure_channel_ctx->credentials.grbitEnabledProtocols = 0;
                break;
        }
    }

    if (options->verify_peer && aws_tls_options_buf_is_set(&options->ca_file)) {
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "static: loading custom CA file.");
        secure_channel_ctx->credentials.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION;

        struct aws_byte_cursor ca_blob_cur = aws_byte_cursor_from_buf(&options->ca_file);
        int error = aws_import_trusted_certificates(alloc, &ca_blob_cur, &secure_channel_ctx->custom_trust_store);

        if (error) {
            AWS_LOGF_ERROR(AWS_LS_IO_TLS, "static: failed to import custom CA with error %d", aws_last_error());
            goto clean_up;
        }
    } else if (is_client_mode) {
        secure_channel_ctx->credentials.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION;
    }

    if (is_client_mode && !options->verify_peer) {
        AWS_LOGF_WARN(
            AWS_LS_IO_TLS,
            "static: x.509 validation has been disabled. "
            "If this is not running in a test environment, this is likely a security vulnerability.");

        secure_channel_ctx->credentials.dwFlags &= ~(SCH_CRED_AUTO_CRED_VALIDATION);
        secure_channel_ctx->credentials.dwFlags |= SCH_CRED_IGNORE_NO_REVOCATION_CHECK |
                                                   SCH_CRED_IGNORE_REVOCATION_OFFLINE | SCH_CRED_NO_SERVERNAME_CHECK |
                                                   SCH_CRED_MANUAL_CRED_VALIDATION;
    } else if (is_client_mode) {
        secure_channel_ctx->credentials.dwFlags |= SCH_CRED_REVOCATION_CHECK_CHAIN | SCH_CRED_IGNORE_REVOCATION_OFFLINE;
    }

    /* if someone wants to use broken algorithms like rc4/md5/des they'll need to ask for a special control */
    secure_channel_ctx->credentials.dwFlags |= SCH_USE_STRONG_CRYPTO;

    /* if using a system store. */
    if (options->system_certificate_path) {
        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "static: assuming certificate is in a system store, loading now.");

        if (aws_load_cert_from_system_cert_store(
                options->system_certificate_path, &secure_channel_ctx->cert_store, &secure_channel_ctx->pcerts)) {
            AWS_LOGF_ERROR(AWS_LS_IO_TLS, "static: failed to load %s", options->system_certificate_path);
            goto clean_up;
        }

        secure_channel_ctx->credentials.paCred = &secure_channel_ctx->pcerts;
        secure_channel_ctx->credentials.cCreds = 1;
        /* if using traditional PEM armored PKCS#7 and ASN Encoding public/private key pairs */
    } else if (aws_tls_options_buf_is_set(&options->certificate) && aws_tls_options_buf_is_set(&options->private_key)) {

        AWS_LOGF_DEBUG(AWS_LS_IO_TLS, "static: certificate and key have been set, setting them up now.");

        if (!aws_text_is_utf8(options->certificate.buffer, options->certificate.len)) {
            AWS_LOGF_ERROR(AWS_LS_IO_TLS, "static: failed to import certificate, must be ASCII/UTF-8 encoded");
            aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto clean_up;
        }

        if (!aws_text_is_utf8(options->private_key.buffer, options->private_key.len)) {
            AWS_LOGF_ERROR(AWS_LS_IO_TLS, "static: failed to import private key, must be ASCII/UTF-8 encoded");
            aws_raise_error(AWS_IO_FILE_VALIDATION_FAILURE);
            goto clean_up;
        }

        struct aws_byte_cursor cert_chain_cur = aws_byte_cursor_from_buf(&options->certificate);
        struct aws_byte_cursor pk_cur = aws_byte_cursor_from_buf(&options->private_key);
        int err = aws_import_key_pair_to_cert_context(
            alloc,
            &cert_chain_cur,
            &pk_cur,
            is_client_mode,
            &secure_channel_ctx->cert_store,
            &secure_channel_ctx->pcerts,
            &secure_channel_ctx->crypto_provider,
            &secure_channel_ctx->private_key);

        if (err) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_TLS, "static: failed to import certificate and private key with error %d.", aws_last_error());
            goto clean_up;
        }

        secure_channel_ctx->credentials.paCred = &secure_channel_ctx->pcerts;
        secure_channel_ctx->credentials.cCreds = 1;
        secure_channel_ctx->should_free_pcerts = false;
    }

    return &secure_channel_ctx->ctx;

clean_up:
    s_secure_channel_ctx_destroy(secure_channel_ctx);
    return NULL;
}

struct aws_tls_ctx *aws_tls_server_ctx_new(struct aws_allocator *alloc, const struct aws_tls_ctx_options *options) {
    return s_ctx_new(alloc, options, false);
}

struct aws_tls_ctx *aws_tls_client_ctx_new(struct aws_allocator *alloc, const struct aws_tls_ctx_options *options) {
    return s_ctx_new(alloc, options, true);
}
