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
#define SECURITY_WIN32

#include <aws/io/tls_channel_handler.h>

#include <aws/io/channel.h>
#include <aws/io/pki_utils.h>

#include <aws/common/task_scheduler.h>

#include <schannel.h>
#include <security.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#if _MSC_VER
#    pragma warning(disable : 4221) /* aggregate initializer using local variable addresses */
#    pragma warning(disable : 4204) /* non-constant aggregate initializer */
#    pragma warning(disable : 4306) /* msft doesn't trust us to do pointer arithmetic. */
#endif

#define KB_1  1024
#define READ_OUT_SIZE (KB_1 * 16)
#define READ_IN_SIZE READ_OUT_SIZE
#define EST_HANDSHAKE_SIZE (7 * KB_1)

void aws_tls_init_static_state(struct aws_allocator *alloc) {
    (void)alloc;
}

void aws_tls_clean_up_tl_state(void) {}

void aws_tls_clean_up_static_state(void) {}

struct secure_channel_ctx {
    struct aws_tls_ctx_options options;
    SCHANNEL_CRED credentials;
    PCERT_CONTEXT pcerts;
    HCERTSTORE cert_store;
    HCERTSTORE custom_trust_store;
};

struct secure_channel_handler {
    CtxtHandle sec_handle;
    CredHandle creds;
    PCCERT_CONTEXT cert_context[1];
    HCERTSTORE cert_store;
    HCERTSTORE custom_ca_store;
    SecPkgContext_StreamSizes stream_sizes;
    unsigned long ctx_req;
    unsigned long ctx_ret_flags;
    struct aws_channel_slot *slot;
    struct aws_byte_buf protocol;
    struct aws_byte_buf server_name;
    struct aws_tls_connection_options options;
    TimeStamp sspi_timestamp;
    int(*s_connection_state_fn)(struct aws_channel_handler *handler);
    uint8_t buffered_read_in_data[READ_IN_SIZE];
    struct aws_byte_buf buffered_read_in_data_buf;
    size_t estimated_incomplete_size;
    size_t read_extra;
    uint8_t buffered_read_out_data[READ_OUT_SIZE];
    struct aws_byte_buf buffered_read_out_data_buf;
    struct aws_task sequential_task_storage;
    bool negotiation_finished;
    
};

bool aws_tls_is_alpn_available(void) {   
/* if you built on an old version of windows, still no support, but if you did, we still 
   want to check the OS version at runtime before agreeing to attempt alpn. */
#ifdef SECBUFFER_APPLICATION_PROTOCOLS
    /* come back to this later
    OSVERSIONINFOEXA os_version = { sizeof(os_version), 0, 0, 0, 0, {0}, 0, 0 };
    DWORDLONG const condition_mask = VerSetConditionMask(
        VerSetConditionMask(
            VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL),
            VER_MINORVERSION, VER_GREATER_EQUAL),
        VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

    os_version.dwMajorVersion = HIBYTE(_WIN32_WINNT_WIN8);
    os_version.dwMinorVersion = LOBYTE(_WIN32_WINNT_WIN8);
    os_version.wServicePackMajor = 1;
    return VerifyVersionInfoA(&os_version, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, condition_mask);
    */
    return true;
#else
    return false;
#endif /*SECBUFFER_APPLICATION_PROTOCOLS */
}

static int s_manually_verify_peer_cert(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;

    CERT_CONTEXT *peer_certificate = NULL;
    SECURITY_STATUS status = QueryContextAttributes(&sc_handler->sec_handle, 
        SECPKG_ATTR_REMOTE_CERT_CONTEXT, &peer_certificate);

    if (status != SEC_E_OK || !peer_certificate) {
        return AWS_OP_ERR;
    }

    CERT_CHAIN_ENGINE_CONFIG engine_config;
    AWS_ZERO_STRUCT(engine_config);
    engine_config.cbSize = sizeof(engine_config);
    engine_config.hExclusiveRoot = sc_handler->custom_ca_store;

    HCERTCHAINENGINE engine = NULL;
    if (!CertCreateCertificateChainEngine(&engine_config, &engine)) {
        CertFreeCertificateContext(peer_certificate);
        return AWS_OP_ERR;
    }

    CERT_CHAIN_PARA chain_params;
    AWS_ZERO_STRUCT(chain_params);
    chain_params.cbSize = sizeof(chain_params);

    CERT_CHAIN_CONTEXT *cert_chain_ctx = NULL;

    if (!CertGetCertificateChain(engine, peer_certificate, NULL, peer_certificate->hCertStore,
        &chain_params, CERT_CHAIN_REVOCATION_CHECK_CHAIN, NULL, &cert_chain_ctx)) {
        CertFreeCertificateChainEngine(engine);
        CertFreeCertificateContext(peer_certificate);
        return AWS_OP_ERR;
    }

    CERT_SIMPLE_CHAIN *simple_chain = cert_chain_ctx->rgpChain[0];
    DWORD trust_mask = ~(DWORD)CERT_TRUST_IS_NOT_TIME_NESTED;
    trust_mask &= simple_chain->TrustStatus.dwErrorStatus;
    
    CertFreeCertificateChain(cert_chain_ctx);
    CertFreeCertificateChainEngine(engine);
    CertFreeCertificateContext(peer_certificate);

    return trust_mask == 0 ? AWS_OP_SUCCESS : AWS_OP_ERR;
}

static void s_invoke_negotiation_error(struct aws_channel_handler *handler, int err) {
    struct secure_channel_handler *sc_handler = handler->impl;

    if (sc_handler->options.on_negotiation_result) {
        sc_handler->options.on_negotiation_result(
            handler, sc_handler->slot, err, sc_handler->options.user_data);
    }
}

static void s_on_negotiation_success(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;

    if (sc_handler->slot->adj_right && sc_handler->options.advertise_alpn_message && sc_handler->protocol.len) {
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
            aws_channel_release_message_to_pool(sc_handler->slot->channel, message);
            aws_channel_shutdown(sc_handler->slot->channel, aws_last_error());
        }
    }

    if (sc_handler->options.on_negotiation_result) {
        sc_handler->options.on_negotiation_result(
            handler, sc_handler->slot, AWS_OP_SUCCESS, sc_handler->options.user_data);
    }
}

static int s_determine_sspi_error(int sspi_status) {
    switch (sspi_status) {
    case SEC_E_INSUFFICIENT_MEMORY:
        return AWS_ERROR_OOM;
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

static int s_fillin_alpn_data(struct aws_channel_handler *handler, unsigned char*alpn_buffer_data, size_t buffer_size, size_t *written) {
    /* come back and do bounds checking on this later. */
    (void)buffer_size;
    *written = 0;
    struct secure_channel_handler *sc_handler = handler->impl;

    struct aws_array_list alpn_buffers;
    struct aws_byte_cursor alpn_buffer_array[4];
    aws_array_list_init_static(&alpn_buffers, alpn_buffer_array, 4, sizeof(struct aws_byte_cursor));
    struct aws_byte_buf alpn_str_buf = aws_byte_buf_from_c_str(sc_handler->options.alpn_list);
    if (aws_byte_buf_split_on_char(&alpn_str_buf, ';', &alpn_buffers)) {
        return AWS_OP_ERR;
    }

    size_t protocols_count = aws_array_list_length(&alpn_buffers);

    size_t index = 0;
    uint32_t *extension_length = (uint32_t *)&alpn_buffer_data[index];
    index += sizeof(uint32_t);
    uint32_t *extension_name = (uint32_t *)&alpn_buffer_data[index];
    index += sizeof(uint32_t);
    uint16_t *protocols_byte_length = (uint16_t *)&alpn_buffer_data[index];
    index += sizeof(uint16_t);

    *extension_length += sizeof(uint32_t) + sizeof(uint16_t);

    *extension_name = SecApplicationProtocolNegotiationExt_ALPN;
    /*now add the protocols*/
    for (size_t i = 0; i < protocols_count; ++i) {
        struct aws_byte_cursor *protocol_ptr = NULL;
        aws_array_list_get_at_ptr(&alpn_buffers, (void **)&protocol_ptr, i);
        assert(protocol_ptr);
        *extension_length += (uint32_t)protocol_ptr->len + 1;
        *protocols_byte_length += (uint16_t)protocol_ptr->len + 1;
        alpn_buffer_data[index++] = (unsigned char)protocol_ptr->len;
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

static int s_do_server_side_negotiation_step_1(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;

    unsigned char alpn_buffer_data[128] = { 0 };
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
    if (sc_handler->options.alpn_list && aws_tls_is_alpn_available()) {
        size_t extension_length = 0;
        if (s_fillin_alpn_data(handler, alpn_buffer_data, sizeof(alpn_buffer_data), &extension_length)) {
            return AWS_OP_ERR;
        }

        input_bufs[1].pvBuffer = alpn_buffer_data,
        input_bufs[1].cbBuffer = (unsigned long)extension_length,
        input_bufs[1].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
    }
#endif /* SECBUFFER_APPLICATION_PROTOCOLS*/

    sc_handler->ctx_req = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
        ASC_REQ_CONFIDENTIALITY | ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;

    if (sc_handler->options.verify_peer) {
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

    SECURITY_STATUS status = AcceptSecurityContext(&sc_handler->creds, NULL, &input_bufs_desc, 
        sc_handler->ctx_req, 0, &sc_handler->sec_handle, &output_buffer_desc, &sc_handler->ctx_ret_flags, NULL);

    if (!(status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK)) {
        int error = s_determine_sspi_error(status);
        aws_raise_error(error);
        s_invoke_negotiation_error(handler, error);
        return AWS_OP_ERR;
    }

    size_t data_to_write_len = output_buffer.cbBuffer;

    struct aws_io_message *outgoing_message = 
        aws_channel_acquire_message_from_pool(sc_handler->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, data_to_write_len);
    if (!outgoing_message) {
        FreeContextBuffer(output_buffer.pvBuffer);
        s_invoke_negotiation_error(handler, aws_last_error());
        return AWS_OP_ERR;
    }

    assert(outgoing_message->message_data.capacity >= data_to_write_len);
    memcpy(outgoing_message->message_data.buffer, output_buffer.pvBuffer, output_buffer.cbBuffer);
    outgoing_message->message_data.len = output_buffer.cbBuffer;
    FreeContextBuffer(output_buffer.pvBuffer);

    if (aws_channel_slot_send_message(sc_handler->slot, outgoing_message, AWS_CHANNEL_DIR_WRITE)) {
        aws_channel_release_message_to_pool(sc_handler->slot->channel, outgoing_message);
        s_invoke_negotiation_error(handler, aws_last_error());
        return AWS_OP_ERR;
    }

    sc_handler->s_connection_state_fn = s_do_server_side_negotiation_step_2;

    return AWS_OP_SUCCESS;
}

static int s_do_server_side_negotiation_step_2(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;    

    SecBuffer input_buffers[] = {
        [0] = {
        .pvBuffer = sc_handler->buffered_read_in_data_buf.buffer,
        .cbBuffer = (unsigned long)sc_handler->buffered_read_in_data_buf.len,
        .BufferType = SECBUFFER_TOKEN,
    },
    [1] = {
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

    SECURITY_STATUS status = AcceptSecurityContext(&sc_handler->creds, &sc_handler->sec_handle,
        &input_buffers_desc, sc_handler->ctx_req, 0, NULL,
        &output_buffers_desc, &sc_handler->ctx_ret_flags, &sc_handler->sspi_timestamp);
    
    if (status != SEC_E_INCOMPLETE_MESSAGE && status != SEC_I_CONTINUE_NEEDED && status != SEC_E_OK) {
        int aws_error = s_determine_sspi_error(status);
        aws_raise_error(aws_error);
        s_invoke_negotiation_error(handler, aws_error);
        return AWS_OP_ERR;
    }

    if (status == SEC_E_INCOMPLETE_MESSAGE) {
        sc_handler->estimated_incomplete_size = input_buffers[1].cbBuffer;
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    };

    if (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK) {
        for (size_t i = 0; i < output_buffers_desc.cBuffers; ++i) {
            SecBuffer *buf_ptr = &output_buffers[i];

            if (buf_ptr->BufferType == SECBUFFER_TOKEN && buf_ptr->cbBuffer) {
                struct aws_io_message *outgoing_message = aws_channel_acquire_message_from_pool(sc_handler->slot->channel,
                    AWS_IO_MESSAGE_APPLICATION_DATA, buf_ptr->cbBuffer);

                if (!outgoing_message) {
                    FreeContextBuffer(buf_ptr->pvBuffer);
                    s_invoke_negotiation_error(handler, aws_last_error());
                    return AWS_OP_ERR;
                }

                memcpy(outgoing_message->message_data.buffer, buf_ptr->pvBuffer, buf_ptr->cbBuffer);
                outgoing_message->message_data.len = buf_ptr->cbBuffer;
                FreeContextBuffer(buf_ptr->pvBuffer);

                if (aws_channel_slot_send_message(sc_handler->slot, outgoing_message, AWS_CHANNEL_DIR_WRITE)) {
                    aws_channel_release_message_to_pool(sc_handler->slot->channel, outgoing_message);
                    s_invoke_negotiation_error(handler, aws_last_error());
                    return AWS_OP_ERR;
                }
            }
        }

        if (input_buffers[1].BufferType == SECBUFFER_EXTRA && input_buffers[1].cbBuffer > 0) {
            sc_handler->read_extra = input_buffers[1].cbBuffer;
        }
    }    

    if (status == SEC_E_OK) {
        /* do all the negotiation completion callbacks here. also, invoke it in a task so that we don't have a race
        in the next section where we handle any left over data recieved from the server. */
        sc_handler->negotiation_finished = true;

#ifdef SECBUFFER_APPLICATION_PROTOCOLS
        if (sc_handler->options.alpn_list) {
            SecPkgContext_ApplicationProtocol alpn_result;
            status = QueryContextAttributes(&sc_handler->sec_handle, SECPKG_ATTR_APPLICATION_PROTOCOL, &alpn_result);

            if (status == SEC_E_OK && alpn_result.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success) {
                aws_byte_buf_init(handler->alloc, &sc_handler->protocol, alpn_result.ProtocolIdSize + 1);
                memset(sc_handler->protocol.buffer, 0, alpn_result.ProtocolIdSize + 1);
                memcpy(sc_handler->protocol.buffer, alpn_result.ProtocolId, alpn_result.ProtocolIdSize);
                sc_handler->protocol.len = alpn_result.ProtocolIdSize;
            }
            else {
                int aws_error = s_determine_sspi_error(status);
                aws_raise_error(aws_error);
                s_invoke_negotiation_error(handler, aws_error);
                return AWS_OP_ERR;
            }
        }
#endif 
        sc_handler->s_connection_state_fn = s_do_application_data_decrypt;
        s_on_negotiation_success(handler);
    }

    return AWS_OP_SUCCESS;
}

static int s_do_client_side_negotiation_step_2(struct aws_channel_handler *handler);

static int s_do_client_side_negotiation_step_1(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;

    unsigned char alpn_buffer_data[128] = { 0 };
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

#ifdef SECBUFFER_APPLICATION_PROTOCOLS
    if (sc_handler->options.alpn_list && aws_tls_is_alpn_available()) {
        size_t extension_length = 0;
        if (s_fillin_alpn_data(handler, alpn_buffer_data, sizeof(alpn_buffer_data), &extension_length)) {
            s_invoke_negotiation_error(handler, aws_last_error());
            return AWS_OP_ERR;
        }

        input_buf.pvBuffer = alpn_buffer_data,
        input_buf.cbBuffer = (unsigned long)extension_length,
        input_buf.BufferType = SECBUFFER_APPLICATION_PROTOCOLS;

        alpn_sspi_data = &input_buf_desc;
    }
#endif /* SECBUFFER_APPLICATION_PROTOCOLS*/

    sc_handler->ctx_req = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT | 
        ISC_REQ_CONFIDENTIALITY | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;

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

    SECURITY_STATUS status = InitializeSecurityContextA(&sc_handler->creds, NULL, (SEC_CHAR *)sc_handler->options.server_name, sc_handler->ctx_req, 0, 0,
        alpn_sspi_data, 0, &sc_handler->sec_handle, &output_buffer_desc, &sc_handler->ctx_ret_flags, &sc_handler->sspi_timestamp);

    if (status != SEC_I_CONTINUE_NEEDED) {
        int aws_error = s_determine_sspi_error(status);
        aws_raise_error(aws_error);
        s_invoke_negotiation_error(handler, aws_error);
        return AWS_OP_ERR;
    }

    size_t data_to_write_len = output_buffer.cbBuffer;

    struct aws_io_message *outgoing_message = aws_channel_acquire_message_from_pool(sc_handler->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, data_to_write_len);
    if (!outgoing_message) {
        FreeContextBuffer(output_buffer.pvBuffer);
        s_invoke_negotiation_error(handler, aws_last_error());
        return AWS_OP_ERR;
    }

    assert(outgoing_message->message_data.capacity >= data_to_write_len);
    memcpy(outgoing_message->message_data.buffer, output_buffer.pvBuffer, output_buffer.cbBuffer);
    outgoing_message->message_data.len = output_buffer.cbBuffer;
    FreeContextBuffer(output_buffer.pvBuffer);

    if (aws_channel_slot_send_message(sc_handler->slot, outgoing_message, AWS_CHANNEL_DIR_WRITE)) {
        aws_channel_release_message_to_pool(sc_handler->slot->channel, outgoing_message);

        s_invoke_negotiation_error(handler, aws_last_error());
        return AWS_OP_ERR;
    }

    sc_handler->s_connection_state_fn = s_do_client_side_negotiation_step_2;

    return AWS_OP_SUCCESS;
}

static int s_do_client_side_negotiation_step_2(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;   
    SecBuffer input_buffers[] = {
        [0] = {
            .pvBuffer = sc_handler->buffered_read_in_data_buf.buffer,
            .cbBuffer = (unsigned long)sc_handler->buffered_read_in_data_buf.len,
            .BufferType = SECBUFFER_TOKEN,
        },
        [1] = {
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

    status = InitializeSecurityContextA(&sc_handler->creds, &sc_handler->sec_handle,
        (SEC_CHAR *)sc_handler->options.server_name, sc_handler->ctx_req, 0, 0, &input_buffers_desc, 0, NULL,
        &output_buffers_desc, &sc_handler->ctx_ret_flags, &sc_handler->sspi_timestamp);

    if (status != SEC_E_INCOMPLETE_MESSAGE && status != SEC_I_CONTINUE_NEEDED && status != SEC_E_OK) {
        int aws_error = s_determine_sspi_error(status);
        aws_raise_error(aws_error);
        s_invoke_negotiation_error(handler, aws_error);
        return AWS_OP_ERR;
    }

    if (status == SEC_E_INCOMPLETE_MESSAGE) {
        sc_handler->estimated_incomplete_size = input_buffers[1].cbBuffer;
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }    

    if (status == SEC_I_CONTINUE_NEEDED || status == SEC_E_OK) {
        for (size_t i = 0; i < output_buffers_desc.cBuffers; ++i) {
            SecBuffer *buf_ptr = &output_buffers[i];

            if (buf_ptr->BufferType == SECBUFFER_TOKEN && buf_ptr->cbBuffer) {
                struct aws_io_message *outgoing_message = aws_channel_acquire_message_from_pool(sc_handler->slot->channel,
                    AWS_IO_MESSAGE_APPLICATION_DATA, buf_ptr->cbBuffer);

                if (!outgoing_message) {
                    FreeContextBuffer(buf_ptr->pvBuffer);
                    s_invoke_negotiation_error(handler, aws_last_error());
                    return AWS_OP_ERR;
                }

                memcpy(outgoing_message->message_data.buffer, buf_ptr->pvBuffer, buf_ptr->cbBuffer);
                outgoing_message->message_data.len = buf_ptr->cbBuffer;
                FreeContextBuffer(buf_ptr->pvBuffer);

                if (aws_channel_slot_send_message(sc_handler->slot, outgoing_message, AWS_CHANNEL_DIR_WRITE)) {
                    aws_channel_release_message_to_pool(sc_handler->slot->channel, outgoing_message);
                    s_invoke_negotiation_error(handler, aws_last_error());
                    return AWS_OP_ERR;
                }
            }
        }

        if (input_buffers[1].BufferType == SECBUFFER_EXTRA && input_buffers[1].cbBuffer > 0) {
            sc_handler->read_extra = input_buffers[1].cbBuffer;
        }
    }

    if (status == SEC_E_OK) {
        if (sc_handler->custom_ca_store) {
            if (s_manually_verify_peer_cert(handler)) {
                aws_raise_error(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                s_invoke_negotiation_error(handler, AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
                return AWS_OP_ERR;
            }
        }
        sc_handler->negotiation_finished = true;

#ifdef SECBUFFER_APPLICATION_PROTOCOLS
        SecPkgContext_ApplicationProtocol alpn_result;
        status = QueryContextAttributes(&sc_handler->sec_handle, SECPKG_ATTR_APPLICATION_PROTOCOL, &alpn_result);

        if (status == SEC_E_OK && alpn_result.ProtoNegoStatus == SecApplicationProtocolNegotiationStatus_Success) {
            aws_byte_buf_init(handler->alloc, &sc_handler->protocol, alpn_result.ProtocolIdSize + 1);
            memset(sc_handler->protocol.buffer, 0, alpn_result.ProtocolIdSize + 1);
            memcpy(sc_handler->protocol.buffer, alpn_result.ProtocolId, alpn_result.ProtocolIdSize);
            sc_handler->protocol.len = alpn_result.ProtocolIdSize;
        }
        else {
            int aws_error = s_determine_sspi_error(status);
            aws_raise_error(aws_error);
            s_invoke_negotiation_error(handler, aws_error);
            return AWS_OP_ERR;
        }
#endif 
        sc_handler->s_connection_state_fn = s_do_application_data_decrypt;
        s_on_negotiation_success(handler);
    }

    return AWS_OP_SUCCESS;
}

static int s_do_application_data_decrypt(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;
    /* 4 buffers are needed, only one is input, the others get zeroed out for the output operation. */
    SecBuffer input_buffers[4];
    AWS_ZERO_ARRAY(input_buffers);
    input_buffers[0] = (SecBuffer) {
        .cbBuffer = (unsigned long)sc_handler->buffered_read_in_data_buf.len,
        .pvBuffer = sc_handler->buffered_read_in_data_buf.buffer,
        .BufferType = SECBUFFER_DATA,
    };

    SecBufferDesc buffer_desc = {
        .ulVersion = SECBUFFER_VERSION,
        .cBuffers = 4,
        .pBuffers = input_buffers,
    };

    SECURITY_STATUS status = DecryptMessage(&sc_handler->sec_handle, &buffer_desc, 0, NULL);

    if (status == SEC_E_OK) {
        if (input_buffers[1].BufferType == SECBUFFER_DATA) {
            size_t decrypted_length = input_buffers[1].cbBuffer;

            if (input_buffers[3].BufferType == SECBUFFER_EXTRA) {
                sc_handler->read_extra = input_buffers[3].cbBuffer;
            }
            
            assert(decrypted_length <= sc_handler->buffered_read_out_data_buf.capacity - sc_handler->buffered_read_out_data_buf.len);
            memcpy(sc_handler->buffered_read_out_data_buf.buffer + sc_handler->buffered_read_out_data_buf.len,
                    (uint8_t *)input_buffers[1].pvBuffer, decrypted_length);
            sc_handler->buffered_read_out_data_buf.len += decrypted_length;
        }

        return AWS_OP_SUCCESS;
    }
    else if (status == SEC_E_INCOMPLETE_MESSAGE) {
        sc_handler->estimated_incomplete_size = input_buffers[1].cbBuffer;
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }
    else {
        int aws_error = s_determine_sspi_error(status);
        aws_raise_error(aws_error);
        return AWS_OP_ERR;
    }
}

static int s_process_pending_output_messages(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;

    size_t downstream_window = SIZE_MAX;
    
    if (sc_handler->slot->adj_right) {
        downstream_window = aws_channel_slot_downstream_read_window(sc_handler->slot);
    }

    while (sc_handler->buffered_read_out_data_buf.len && downstream_window) {
        size_t requested_message_size = sc_handler->buffered_read_out_data_buf.len > downstream_window ?
            downstream_window : sc_handler->buffered_read_out_data_buf.len;

        if (sc_handler->slot->adj_right) {
            struct aws_io_message *read_out_msg =
                aws_channel_acquire_message_from_pool(sc_handler->slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, requested_message_size);

            if (!read_out_msg) {
                return AWS_OP_ERR;
            }

            size_t copy_size = read_out_msg->message_data.capacity < requested_message_size ?
                read_out_msg->message_data.len : requested_message_size;

            memcpy(read_out_msg->message_data.buffer, sc_handler->buffered_read_out_data_buf.buffer, copy_size);
            read_out_msg->message_data.len = copy_size;

            memmove(sc_handler->buffered_read_out_data_buf.buffer,
                sc_handler->buffered_read_out_data_buf.buffer + copy_size,
                sc_handler->buffered_read_out_data_buf.len - copy_size);
            sc_handler->buffered_read_out_data_buf.len -= copy_size;

            if (aws_channel_slot_send_message(sc_handler->slot, read_out_msg, AWS_CHANNEL_DIR_READ)) {
                aws_channel_release_message_to_pool(sc_handler->slot->channel, read_out_msg);
                return AWS_OP_ERR;
            }

            downstream_window = aws_channel_slot_downstream_read_window(sc_handler->slot);
        }
        else {
            /* TODO: invoke the on read callback here.*/
            sc_handler->buffered_read_out_data_buf.len = 0;
        }
    }

    return AWS_OP_SUCCESS;
}

static void s_process_pending_output_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    struct aws_channel_handler *handler = arg;

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
        struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&message->message_data);

        int err = AWS_OP_SUCCESS;
        while (!err && message_cursor.len) {

            size_t available_buffer_space = sc_handler->buffered_read_in_data_buf.capacity -
                sc_handler->buffered_read_in_data_buf.len;
            size_t available_message_len = message_cursor.len;
            size_t amount_to_move_to_buffer = available_buffer_space > available_message_len ?
                available_message_len : available_buffer_space;

            memcpy(sc_handler->buffered_read_in_data_buf.buffer + sc_handler->buffered_read_in_data_buf.len,
                message_cursor.ptr, amount_to_move_to_buffer);
            sc_handler->buffered_read_in_data_buf.len += amount_to_move_to_buffer;
            
            err = sc_handler->s_connection_state_fn(handler);

            if (err && aws_last_error() == AWS_IO_READ_WOULD_BLOCK) {
                if (sc_handler->buffered_read_in_data_buf.len == sc_handler->buffered_read_in_data_buf.capacity) {
                    /* throw this one as a protocol error. */
                    aws_raise_error(AWS_IO_TLS_ERROR_WRITE_FAILURE);
                }
                else {
                    size_t window_size = slot->window_size;
                    if (!window_size && aws_channel_slot_increment_read_window(slot, sc_handler->estimated_incomplete_size)) {
                        err = AWS_OP_ERR;
                    }
                    else {
                        sc_handler->estimated_incomplete_size = 0;
                        err = AWS_OP_SUCCESS;
                    }
                }
                aws_byte_cursor_advance(&message_cursor, amount_to_move_to_buffer);
                continue;
            }
            else if (err) {
                break;
            }
            
            if (sc_handler->read_extra) {
                size_t move_pos = sc_handler->buffered_read_in_data_buf.len - sc_handler->read_extra;
                memmove(sc_handler->buffered_read_in_data_buf.buffer,
                    sc_handler->buffered_read_in_data_buf.buffer + move_pos,
                    sc_handler->read_extra);
                sc_handler->buffered_read_in_data_buf.len = sc_handler->read_extra;
            }
            else {
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
            aws_channel_release_message_to_pool(slot->channel, message);
            return AWS_OP_SUCCESS;
        }

        aws_channel_shutdown(slot->channel, err);
        return AWS_OP_ERR;
    }

    if (sc_handler->buffered_read_out_data_buf.len) {
        if (s_process_pending_output_messages(handler)) {
            return AWS_OP_ERR;
        }
        aws_channel_release_message_to_pool(slot->channel, message);        
    }

    return AWS_OP_SUCCESS;
}

static int s_process_write_message(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    struct aws_io_message *message) {
    
    struct secure_channel_handler *sc_handler = (struct secure_channel_handler *)handler->impl;
    assert(sc_handler->negotiation_finished);
    SECURITY_STATUS status = SEC_E_OK;    
    
    if (message) {
        struct aws_byte_cursor message_cursor = aws_byte_cursor_from_buf(&message->message_data);

        while (message_cursor.len) {
            size_t requested_length = message_cursor.len + sc_handler->stream_sizes.cbHeader + sc_handler->stream_sizes.cbTrailer;
            size_t to_write = sc_handler->stream_sizes.cbMaximumMessage < requested_length ? sc_handler->stream_sizes.cbMaximumMessage : requested_length;
            struct aws_io_message *outgoing_message = aws_channel_acquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, to_write);

            if (!outgoing_message) {
                return AWS_OP_ERR;
            }

            /* what if message is larger than one record? */
            size_t original_message_fragment_to_process = outgoing_message->message_data.capacity - (sc_handler->stream_sizes.cbHeader + sc_handler->stream_sizes.cbTrailer);
            memcpy(outgoing_message->message_data.buffer + sc_handler->stream_sizes.cbHeader, message_cursor.ptr, original_message_fragment_to_process);

            if (original_message_fragment_to_process == message_cursor.len) {
                outgoing_message->on_completion = message->on_completion;
                outgoing_message->user_data = message->user_data;
            }

            SecBuffer buffers[4] = {
                [0] = {
                    .BufferType = SECBUFFER_STREAM_HEADER,
                    .pvBuffer = outgoing_message->message_data.buffer,
                    .cbBuffer = sc_handler->stream_sizes.cbHeader,
                },
                [1] = {
                    .BufferType = SECBUFFER_DATA,
                    .pvBuffer = outgoing_message->message_data.buffer + sc_handler->stream_sizes.cbHeader,
                    .cbBuffer = (unsigned long)original_message_fragment_to_process,
                },
                [2] = {
                    .BufferType = SECBUFFER_STREAM_TRAILER,
                    .pvBuffer = outgoing_message->message_data.buffer + sc_handler->stream_sizes.cbHeader + original_message_fragment_to_process,
                    .cbBuffer = sc_handler->stream_sizes.cbTrailer,
                },
                [3] = {
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
                outgoing_message->message_data.len = original_message_fragment_to_process + sc_handler->stream_sizes.cbHeader + sc_handler->stream_sizes.cbTrailer;
                if (aws_channel_slot_send_message(slot, outgoing_message, AWS_CHANNEL_DIR_WRITE)) {
                    aws_channel_release_message_to_pool(slot->channel, outgoing_message);
                    return AWS_OP_ERR;
                }

                aws_byte_cursor_advance(&message_cursor, original_message_fragment_to_process);
            }
            else {
                return AWS_OP_ERR;
            }
        }

        aws_channel_release_message_to_pool(slot->channel, message);
    }

    return AWS_OP_SUCCESS;
}

static int s_increment_read_window(
    struct aws_channel_handler *handler,
    struct aws_channel_slot *slot,
    size_t size) {
    (void)size;
    struct secure_channel_handler *sc_handler = (struct secure_channel_handler *)handler->impl;

    if (!sc_handler->stream_sizes.cbMaximumMessage) {
        SECURITY_STATUS status = QueryContextAttributes(&sc_handler->sec_handle, SECPKG_ATTR_STREAM_SIZES, &sc_handler->stream_sizes);

        if (status != SEC_E_OK) {
            aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
            aws_channel_shutdown(slot->channel, AWS_IO_SYS_CALL_FAILURE);
            return AWS_OP_ERR;
        }
    }

    size_t downstream_size = aws_channel_slot_downstream_read_window(slot);
    size_t current_window_size = slot->window_size;

    if (downstream_size <= current_window_size) {
        size_t window_update_size = (downstream_size - current_window_size) + sc_handler->stream_sizes.cbHeader + sc_handler->stream_sizes.cbTrailer;
        aws_channel_slot_increment_read_window(slot, window_update_size);
    }

    if (sc_handler->negotiation_finished) {
        sc_handler->sequential_task_storage.fn = s_process_pending_output_task;
        sc_handler->sequential_task_storage.arg = handler;

        aws_channel_schedule_task_now(slot->channel, &sc_handler->sequential_task_storage);
    }
    return AWS_OP_SUCCESS;
}

static size_t s_get_current_window_size(struct aws_channel_handler *handler) {
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

    if (dir == AWS_CHANNEL_DIR_WRITE && !error_code) {
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

        status = ApplyControlToken(&sc_handler->sec_handle, &shutdown_buffer_desc);

        if (status != SEC_E_OK) {
            aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
            return aws_channel_slot_on_handler_shutdown_complete(slot, dir, AWS_IO_SYS_CALL_FAILURE, true);
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
        status = InitializeSecurityContextA(&sc_handler->creds,
            &sc_handler->sec_handle,
            (SEC_CHAR *)server_name.buffer,
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
            struct aws_io_message *outgoing_message = 
                aws_channel_acquire_message_from_pool(slot->channel, AWS_IO_MESSAGE_APPLICATION_DATA, output_buffer.cbBuffer);

            if (!outgoing_message || outgoing_message->message_data.capacity < output_buffer.cbBuffer) {
                aws_raise_error(AWS_IO_SYS_CALL_FAILURE);
                return aws_channel_slot_on_handler_shutdown_complete(slot, dir, AWS_IO_SYS_CALL_FAILURE, true);
            }
            memcpy(outgoing_message->message_data.buffer, output_buffer.pvBuffer, output_buffer.cbBuffer);
            
            /* we don't really care if this succeeds or not, it's just sending the TLS alert. */
            if (aws_channel_slot_send_message(slot, outgoing_message, AWS_CHANNEL_DIR_WRITE)) {
                aws_channel_release_message_to_pool(slot->channel, outgoing_message);
            }
        }
    }   

    return aws_channel_slot_on_handler_shutdown_complete(slot, dir, error_code, abort_immediately);
}

static void s_do_negotiation_task(struct aws_task *task, void *arg, enum aws_task_status status) {
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

static void s_handler_destroy(struct aws_channel_handler *handler) {
    (void)handler;
    struct secure_channel_handler *sc_handler = handler->impl;

    if (sc_handler->protocol.buffer) {
        aws_byte_buf_clean_up(&sc_handler->protocol);
    }

    if (sc_handler->sec_handle.dwLower || sc_handler->sec_handle.dwUpper) {
        DeleteSecurityContext(&sc_handler->sec_handle);
    }

    if (sc_handler->creds.dwLower || sc_handler->creds.dwUpper) {        
        DeleteSecurityContext(&sc_handler->creds);
    }

    aws_mem_release(handler->alloc, sc_handler);
    aws_mem_release(handler->alloc, handler);
}

int aws_tls_client_handler_start_negotiation(struct aws_channel_handler *handler) {
    struct secure_channel_handler *sc_handler = handler->impl;

    if (aws_channel_thread_is_callers_thread(sc_handler->slot->channel)) {
        int err = sc_handler->s_connection_state_fn(handler);
        if (err) {
            aws_channel_shutdown(sc_handler->slot->channel, aws_last_error());
        }
        return err;
    }
    
    sc_handler->sequential_task_storage.fn = s_do_negotiation_task;
    sc_handler->sequential_task_storage.arg = handler;

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
    .initial_window_size = s_get_current_window_size,
};

struct aws_channel_handler *aws_tls_client_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_ctx *ctx,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {

    struct secure_channel_handler *sc_handler = aws_mem_acquire(allocator, sizeof(struct secure_channel_handler));

    if (!sc_handler) {
        return NULL;
    }

    struct aws_channel_handler *handler = aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));

    if (!handler) {
        aws_mem_release(allocator, sc_handler);
        return NULL;
    }

    AWS_ZERO_STRUCT(*sc_handler);
    AWS_ZERO_STRUCT(*handler);

    handler->alloc = allocator;
    handler->impl = sc_handler;
    handler->vtable = s_handler_vtable;

    struct secure_channel_ctx *sc_ctx = ctx->impl;

    SECURITY_STATUS status = AcquireCredentialsHandleA(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND,
        NULL, &sc_ctx->credentials, NULL, NULL, &sc_handler->creds, &sc_handler->sspi_timestamp);
    (void)status;
    sc_handler->options = *options;

    if (!sc_handler->options.alpn_list) {
        sc_handler->options.alpn_list = sc_ctx->options.alpn_list;
    }

    sc_handler->server_name = aws_byte_buf_from_c_str(options->server_name);
    sc_handler->slot = slot;
    sc_handler->s_connection_state_fn = s_do_client_side_negotiation_step_1;
    sc_handler->custom_ca_store = sc_ctx->custom_trust_store;
    sc_handler->buffered_read_in_data_buf = aws_byte_buf_from_array(sc_handler->buffered_read_in_data, 
        sizeof(sc_handler->buffered_read_in_data));
    sc_handler->buffered_read_in_data_buf.len = 0;
    sc_handler->buffered_read_out_data_buf = aws_byte_buf_from_array(sc_handler->buffered_read_out_data,
        sizeof(sc_handler->buffered_read_out_data));
    sc_handler->buffered_read_out_data_buf.len = 0;

    return handler;
}

struct aws_channel_handler *aws_tls_server_handler_new(
    struct aws_allocator *allocator,
    struct aws_tls_ctx *ctx,
    struct aws_tls_connection_options *options,
    struct aws_channel_slot *slot) {

    struct secure_channel_handler *sc_handler = aws_mem_acquire(allocator, sizeof(struct secure_channel_handler));

    if (!sc_handler) {
        return NULL;
    }

    struct aws_channel_handler *handler = aws_mem_acquire(allocator, sizeof(struct aws_channel_handler));

    if (!handler) {
        aws_mem_release(allocator, sc_handler);
        return NULL;
    }

    AWS_ZERO_STRUCT(*sc_handler);
    AWS_ZERO_STRUCT(*handler);

    handler->alloc = allocator;
    handler->impl = sc_handler;
    handler->vtable = s_handler_vtable;

    struct secure_channel_ctx *sc_ctx = ctx->impl;

    SECURITY_STATUS status = AcquireCredentialsHandleA(NULL, UNISP_NAME, SECPKG_CRED_INBOUND,
        NULL, &sc_ctx->credentials, NULL, NULL, &sc_handler->creds, &sc_handler->sspi_timestamp);
    (void)status;
    sc_handler->options = *options;

    if (!sc_handler->options.alpn_list) {
        sc_handler->options.alpn_list = sc_ctx->options.alpn_list;
    }

    sc_handler->slot = slot;
    sc_handler->s_connection_state_fn = s_do_server_side_negotiation_step_1;
    sc_handler->buffered_read_in_data_buf = aws_byte_buf_from_array(sc_handler->buffered_read_in_data,
        sizeof(sc_handler->buffered_read_in_data));
    sc_handler->buffered_read_in_data_buf.len = 0;

    sc_handler->buffered_read_out_data_buf = aws_byte_buf_from_array(sc_handler->buffered_read_out_data,
        sizeof(sc_handler->buffered_read_out_data));
    sc_handler->buffered_read_out_data_buf.len = 0;

    return handler;
}

void aws_tls_ctx_destroy(struct aws_tls_ctx *ctx) {
    struct secure_channel_ctx *secure_channel_ctx = ctx->impl;

    if (secure_channel_ctx->custom_trust_store) {
        aws_close_cert_store(secure_channel_ctx->custom_trust_store);
    }

    if (secure_channel_ctx->pcerts) {
        CertFreeCertificateContext(secure_channel_ctx->pcerts);
    }

    if (secure_channel_ctx->cert_store) {
        aws_close_cert_store(secure_channel_ctx->cert_store);
    }
    
    aws_mem_release(ctx->alloc, secure_channel_ctx);
    aws_mem_release(ctx->alloc, ctx);
}

struct aws_tls_ctx *aws_tls_server_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    struct aws_tls_ctx *tls_ctx = aws_mem_acquire(alloc, sizeof(struct aws_tls_ctx));

    if (!tls_ctx) {
        return NULL;
    }

    struct secure_channel_ctx *secure_channel_ctx = aws_mem_acquire(alloc, sizeof(struct secure_channel_ctx));

    if (!secure_channel_ctx) {
        aws_mem_release(alloc, tls_ctx);
        return NULL;
    }

    AWS_ZERO_STRUCT(*secure_channel_ctx);
    secure_channel_ctx->options = *options;
    secure_channel_ctx->credentials.dwVersion = SCHANNEL_CRED_VERSION;
    //secure_channel_ctx->credentials.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION;
    secure_channel_ctx->credentials.grbitEnabledProtocols = SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_1_SERVER | SP_PROT_TLS1_2_SERVER;
    tls_ctx->alloc = alloc;
    tls_ctx->impl = secure_channel_ctx;

    if (options->certificate_path && options->private_key_path) {
        struct aws_byte_buf certificate_chain, private_key;

        if (aws_byte_buf_init_from_file(&certificate_chain, alloc, options->certificate_path)) {
            goto clean_up;
        }

        if (aws_byte_buf_init_from_file(&private_key, alloc, options->private_key_path)) {
            aws_secure_zero(certificate_chain.buffer, certificate_chain.len);
            aws_byte_buf_clean_up(&certificate_chain);
            goto clean_up;
        }

        int err = aws_import_key_pair_to_cert_context(alloc, &certificate_chain, &private_key, 
            &secure_channel_ctx->cert_store, &secure_channel_ctx->pcerts);

        aws_secure_zero(certificate_chain.buffer, certificate_chain.len);
        aws_byte_buf_clean_up(&certificate_chain);
        aws_secure_zero(private_key.buffer, private_key.len);
        aws_byte_buf_clean_up(&private_key);
        
        if (err) goto clean_up;

        secure_channel_ctx->credentials.paCred = &secure_channel_ctx->pcerts;
        secure_channel_ctx->credentials.cCreds = 1;
    }

    return tls_ctx;

clean_up:
    aws_mem_release(alloc, secure_channel_ctx);
    aws_mem_release(alloc, tls_ctx);
    return NULL;
}

struct aws_tls_ctx *aws_tls_client_ctx_new(struct aws_allocator *alloc, struct aws_tls_ctx_options *options) {
    struct aws_tls_ctx *tls_ctx = aws_mem_acquire(alloc, sizeof(struct aws_tls_ctx));

    if (!tls_ctx) {
        return NULL;
    }

    struct secure_channel_ctx *secure_channel_ctx = aws_mem_acquire(alloc, sizeof(struct secure_channel_ctx));

    if (!secure_channel_ctx) {
        aws_mem_release(alloc, tls_ctx);
        return NULL;
    }

    AWS_ZERO_STRUCT(*secure_channel_ctx);
    secure_channel_ctx->options = *options;

    if (options->certificate_path && options->private_key_path) {
        struct aws_byte_buf certificate_chain, private_key;

        if (aws_byte_buf_init_from_file(&certificate_chain, alloc, options->certificate_path)) {
            goto clean_up;
        }

        if (aws_byte_buf_init_from_file(&private_key, alloc, options->private_key_path)) {
            aws_secure_zero(certificate_chain.buffer, certificate_chain.len);
            aws_byte_buf_clean_up(&certificate_chain);
            goto clean_up;
        }

        int error = aws_import_key_pair_to_cert_context(alloc, &certificate_chain, &private_key, 
            &secure_channel_ctx->cert_store, &secure_channel_ctx->pcerts);
       
        aws_secure_zero(certificate_chain.buffer, certificate_chain.len);
        aws_byte_buf_clean_up(&certificate_chain);
        aws_secure_zero(private_key.buffer, private_key.len);
        aws_byte_buf_clean_up(&private_key);

        if (error) {
            goto clean_up;
        }

        secure_channel_ctx->credentials.paCred = &secure_channel_ctx->pcerts;
        secure_channel_ctx->credentials.cCreds = 1;
    }

    if (options->verify_peer && options->ca_file) {
        secure_channel_ctx->credentials.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION;

        struct aws_byte_buf ca_blob;

        if (aws_byte_buf_init_from_file(&ca_blob, alloc, options->ca_file)) {
            goto clean_up;
        }

        int error = aws_import_trusted_certificates(alloc, &ca_blob, &secure_channel_ctx->custom_trust_store);

        aws_secure_zero(ca_blob.buffer, ca_blob.len);
        aws_byte_buf_clean_up(&ca_blob);

        if (error) {
            goto clean_up;
        }
    }
    else {
        secure_channel_ctx->credentials.dwFlags = SCH_CRED_AUTO_CRED_VALIDATION;
    }

    if (!options->verify_peer) {
        secure_channel_ctx->credentials.dwFlags |= SCH_CRED_IGNORE_NO_REVOCATION_CHECK 
            | SCH_CRED_IGNORE_REVOCATION_OFFLINE | SCH_CRED_NO_SERVERNAME_CHECK | SCH_CRED_MANUAL_CRED_VALIDATION;
    } else {
        secure_channel_ctx->credentials.dwFlags |= SCH_CRED_REVOCATION_CHECK_CHAIN;

    }

    secure_channel_ctx->credentials.dwVersion = SCHANNEL_CRED_VERSION;
    secure_channel_ctx->credentials.grbitEnabledProtocols = SP_PROT_TLS1_0_CLIENT 
        | SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT;
    tls_ctx->alloc = alloc;
    tls_ctx->impl = secure_channel_ctx;
    return tls_ctx;

clean_up:
    aws_mem_release(alloc, secure_channel_ctx);
    aws_mem_release(alloc, tls_ctx);
    return NULL;
}
