/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#ifdef AWS_USE_DISPATCH_QUEUE

#include <aws/io/private/socket.h>
#include <aws/io/socket.h>

#include <aws/common/clock.h>
#include <aws/common/string.h>
#include <aws/common/uuid.h>
#include <aws/io/logging.h>

#include <Network/Network.h>
#include <aws/io/private/aws_apple_network_framework.h>
#include <aws/io/private/tls_channel_handler_shared.h>

#include <arpa/inet.h>
#include <sys/socket.h>

const char *aws_sec_trust_result_type_to_string(SecTrustResultType trust_result) {
    switch (trust_result) {
        case kSecTrustResultInvalid:
            return "kSecTrustResultInvalid";
        case kSecTrustResultProceed:
            return "kSecTrustResultProceed";
        case kSecTrustResultConfirm:
            return "kSecTrustResultConfirm";
        case kSecTrustResultDeny:
            return "kSecTrustResultDeny";
        case kSecTrustResultUnspecified:
            return "kSecTrustResultUnspecified";
        case kSecTrustResultRecoverableTrustFailure:
            return "kSecTrustResultRecoverableTrustFailure";
        case kSecTrustResultFatalTrustFailure:
            return "kSecTrustResultFatalTrustFailure";
        case kSecTrustResultOtherError:
            return "kSecTrustResultOtherError";
        default:
            return "Unknown SecTrustResultType";
    }
}

static int s_determine_socket_error(int error) {
    switch (error) {
        /* POSIX Errors */
        case ECONNREFUSED:
            return AWS_IO_SOCKET_CONNECTION_REFUSED;
        case ETIMEDOUT:
            return AWS_IO_SOCKET_TIMEOUT;
        case EHOSTUNREACH:
        case ENETUNREACH:
            return AWS_IO_SOCKET_NO_ROUTE_TO_HOST;
        case EADDRNOTAVAIL:
            return AWS_IO_SOCKET_INVALID_ADDRESS;
        case ENETDOWN:
            return AWS_IO_SOCKET_NETWORK_DOWN;
        case ECONNABORTED:
            return AWS_IO_SOCKET_CONNECT_ABORTED;
        case EADDRINUSE:
            return AWS_IO_SOCKET_ADDRESS_IN_USE;
        case ENOBUFS:
        case ENOMEM:
            return AWS_ERROR_OOM;
        case EAGAIN:
            return AWS_IO_READ_WOULD_BLOCK;
        case EMFILE:
        case ENFILE:
            return AWS_ERROR_MAX_FDS_EXCEEDED;
        case ENOENT:
        case EINVAL:
            return AWS_ERROR_FILE_INVALID_PATH;
        case EAFNOSUPPORT:
            return AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY;
        case EACCES:
            return AWS_ERROR_NO_PERMISSION;

        /* SSL/TLS Errors */
        case errSSLUnknownRootCert:
            return AWS_IO_TLS_UNKNOWN_ROOT_CERTIFICATE;
        case errSSLNoRootCert:
            return AWS_IO_TLS_NO_ROOT_CERTIFICATE_FOUND;
        case errSSLCertExpired:
            return AWS_IO_TLS_CERTIFICATE_EXPIRED;
        case errSSLCertNotYetValid:
            return AWS_IO_TLS_CERTIFICATE_NOT_YET_VALID;
        case errSSLPeerHandshakeFail:
            return AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE;
        case errSSLBadCert:
            return AWS_IO_TLS_BAD_CERTIFICATE;
        case errSSLPeerCertExpired:
            return AWS_IO_TLS_PEER_CERTIFICATE_EXPIRED;
        case errSSLPeerBadCert:
            return AWS_IO_TLS_BAD_PEER_CERTIFICATE;
        case errSSLPeerCertRevoked:
            return AWS_IO_TLS_PEER_CERTIFICATE_REVOKED;
        case errSSLPeerCertUnknown:
            return AWS_IO_TLS_PEER_CERTIFICATE_UNKNOWN;
        case errSSLInternal:
            return AWS_IO_TLS_INTERNAL_ERROR;
        case errSSLClosedGraceful:
            return AWS_IO_TLS_CLOSED_GRACEFUL;
        case errSSLClosedAbort:
            return AWS_IO_TLS_CLOSED_ABORT;
        case errSSLXCertChainInvalid:
            return AWS_IO_TLS_INVALID_CERTIFICATE_CHAIN;
        case errSSLHostNameMismatch:
            return AWS_IO_TLS_HOST_NAME_MISSMATCH;

        default:
            return AWS_IO_SOCKET_NOT_CONNECTED;
    }
}

static inline int s_convert_pton_error(int pton_code) {
    if (pton_code == 0) {
        return AWS_IO_SOCKET_INVALID_ADDRESS;
    }

    return s_determine_socket_error(errno);
}

/* other than CONNECTED_READ | CONNECTED_WRITE
 * a socket is only in one of these states at a time. */
enum socket_state {
    INIT = 0x01,
    CONNECTING = 0x02,
    CONNECTED_READ = 0x04,
    CONNECTED_WRITE = 0x08,
    BOUND = 0x10,
    LISTENING = 0x20,
    TIMEDOUT = 0x40,
    ERROR = 0x80,
    CLOSED,
};

struct nw_socket_listener_args {
    int error_code;
    struct aws_allocator *allocator;
    struct aws_socket *socket;
    struct aws_socket *new_socket;
    void *user_data;
};

struct nw_socket_timeout_args {
    struct aws_task task;
    struct aws_allocator *allocator;
    struct aws_socket *socket;
};

struct nw_socket_readable_args {
    int error_code;
    struct aws_allocator *allocator;
    struct aws_socket *socket;
};

struct nw_socket_written_args {
    int error_code;
    struct aws_allocator *allocator;
    struct aws_socket *socket;
    aws_socket_on_write_completed_fn *written_fn;
    void *user_data;
    size_t bytes_written;
};

struct nw_socket_cancel_task_args {
    struct aws_allocator *allocator;
    struct aws_socket *socket;
    struct aws_task *task_to_cancel;
};

struct nw_socket {
    struct aws_allocator *allocator;
    struct aws_ref_count ref_count;
    nw_connection_t nw_connection;
    nw_parameters_t nw_parameters;
    nw_listener_t nw_listener;
    struct aws_linked_list read_queue;
    int last_error;
    aws_socket_on_readable_fn *on_readable;
    void *on_readable_user_data;
    bool setup_run;
    bool currently_connected; // If the io port is connected. Similar to posix_socket->currently_subscribed.
    bool read_queued;
    bool is_listener;
    struct nw_socket_timeout_args *timeout_args;
    aws_socket_on_connection_result_fn *on_connection_result_fn;
    void *connect_accept_user_data;
    struct aws_event_loop *event_loop;
    struct aws_string *host_name;
    struct aws_tls_ctx *tls_ctx;
};

struct socket_address {
    union sock_addr_types {
        struct sockaddr_in addr_in;
        struct sockaddr_in6 addr_in6;
        struct sockaddr_un un_addr;
    } sock_addr_types;
};

static size_t KB_16 = 16 * 1024;

/* setup the TCP options Block for use in socket parameters */
static void s_setup_tcp_options(nw_protocol_options_t tcp_options, const struct aws_socket_options *options) {
    if (options->connect_timeout_ms) {
        /* this value gets set in seconds. */
        nw_tcp_options_set_connection_timeout(tcp_options, options->connect_timeout_ms / AWS_TIMESTAMP_MILLIS);
    }

    /* Only change default keepalive values if keepalive is true and both interval and timeout
     * are not zero. */
    if (options->keepalive && options->keep_alive_interval_sec != 0 && options->keep_alive_timeout_sec != 0) {
        nw_tcp_options_set_enable_keepalive(tcp_options, options->keepalive);
        nw_tcp_options_set_keepalive_idle_time(tcp_options, options->keep_alive_timeout_sec);
        nw_tcp_options_set_keepalive_interval(tcp_options, options->keep_alive_interval_sec);
    }

    if (options->keep_alive_max_failed_probes) {
        nw_tcp_options_set_keepalive_count(tcp_options, options->keep_alive_max_failed_probes);
    }

    if (g_aws_channel_max_fragment_size < KB_16) {
        nw_tcp_options_set_maximum_segment_size(tcp_options, g_aws_channel_max_fragment_size);
    }
}

static int s_setup_socket_params(
    struct nw_socket *nw_socket,
    const struct aws_socket_options *options,
    struct aws_tls_connection_options *tls_ctx_options) {

    /* If we already have parameters set, release them before re-establishing new parameters */
    if (nw_socket->nw_parameters != NULL) {
        nw_release(nw_socket->nw_parameters);
        nw_socket->nw_parameters = NULL;
    }

    if (options->type == AWS_SOCKET_STREAM) {
        if (options->domain == AWS_SOCKET_IPV4 || options->domain == AWS_SOCKET_IPV6) {
            /* options->user_data will contain the tls_ctx if tls_ctx was initialized */
            if (nw_socket->tls_ctx) {
                struct secure_transport_ctx *transport_ctx = nw_socket->tls_ctx->impl;
                struct dispatch_loop *dispatch_loop = nw_socket->event_loop->impl_data;

                /* This check cannot be done within the TLS options block and must be handled here. */
                if (transport_ctx->minimum_tls_version == AWS_IO_SSLv3) {
                    AWS_LOGF_ERROR(
                        AWS_LS_IO_SOCKET,
                        "id=%p options=%p: Apple Network Framework does not support SSLv3 due to its "
                        "deprecated status and known security flaws.",
                        (void *)nw_socket,
                        (void *)options);
                    return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
                }

                nw_socket->nw_parameters = nw_parameters_create_secure_tcp(
                    // TLS options block
                    ^(nw_protocol_options_t tls_options) {
                      /* Obtain the security protocol options from the tls_options. Changes made directly
                       * to the copy will impact the protocol options within the tls_options */
                      sec_protocol_options_t sec_options = nw_tls_copy_sec_protocol_options(tls_options);

                      sec_protocol_options_set_local_identity(sec_options, transport_ctx->secitem_identity);

                      // Set the minimum TLS version
                      switch (transport_ctx->minimum_tls_version) {
                          case AWS_IO_TLSv1:
                              sec_protocol_options_set_min_tls_protocol_version(
                                  sec_options, tls_protocol_version_TLSv10);
                              break;
                          case AWS_IO_TLSv1_1:
                              sec_protocol_options_set_min_tls_protocol_version(
                                  sec_options, tls_protocol_version_TLSv11);
                              break;
                          case AWS_IO_TLSv1_2:
                              sec_protocol_options_set_min_tls_protocol_version(
                                  sec_options, tls_protocol_version_TLSv12);
                              break;
                          case AWS_IO_TLSv1_3:
                              sec_protocol_options_set_min_tls_protocol_version(
                                  sec_options, tls_protocol_version_TLSv13);
                              break;
                          case AWS_IO_TLS_VER_SYS_DEFAULTS:
                              /* not assigning a min tls protocol version automatically uses the
                               * system default version. */
                              break;
                          default:
                              AWS_LOGF_ERROR(
                                  AWS_LS_IO_SOCKET,
                                  "id=%p options=%p: Unrecognized minimum TLS version used for parameter creation. "
                                  "System default minimum TLS version will be used.",
                                  (void *)nw_socket,
                                  (void *)options);
                              break;
                      }

                      /* Enable/Disable peer authentication. This setting is ignored by network framework due to our
                       * implementation of the verification block below but we set it in case anything else checks this
                       * value and/or in case we decide to remove the verify block in the future. */
                      sec_protocol_options_set_peer_authentication_required(sec_options, transport_ctx->verify_peer);

                      /* We handle the verification of the remote end here. */
                      sec_protocol_options_set_verify_block(
                          sec_options,
                          ^(sec_protocol_metadata_t metadata,
                            sec_trust_t trust,
                            sec_protocol_verify_complete_t complete) {
                            /* Since we manually handle the verification of the peer, the value set using
                             * sec_protocol_options_set_peer_authentication_required is ignored and this block is
                             * run instead. We must manually skip the verification at this point if verify_peer is
                             * false. */
                            if (!transport_ctx->verify_peer) {
                                AWS_LOGF_DEBUG(
                                    AWS_LS_IO_TLS,
                                    "id=%p: nw_socket instructed not to verify peer. Accepting peer credentials "
                                    "without evaluation against CA.",
                                    (void *)nw_socket);
                                complete(true);
                            }

                            SecTrustRef trust_ref = sec_trust_copy_ref(trust);
                            OSStatus status;

                            /* Use root ca if provided. */
                            if (transport_ctx->ca_cert != NULL) {
                                AWS_LOGF_DEBUG(
                                    AWS_LS_IO_TLS,
                                    "id=%p: nw_socket verify block applying provided root CA for remote verification.",
                                    (void *)nw_socket);
                                // We add the ca certificate as a anchor certificate in the trust_ref
                                status = SecTrustSetAnchorCertificates(trust_ref, transport_ctx->ca_cert);
                                if (status != errSecSuccess) {
                                    AWS_LOGF_DEBUG(
                                        AWS_LS_IO_TLS,
                                        "id=%p: nw_socket verify block SecTrustSetAnchorCertificates failed with "
                                        "OSStatus: %d",
                                        (void *)nw_socket,
                                        (int)status);
                                    goto verification_done;
                                }
                            }

                            /* Add the host name to be checked against the available Certificate Authorities */
                            if (nw_socket->host_name != NULL) {
                                SecPolicyRef policy = NULL;
                                CFStringRef server_name = CFStringCreateWithBytes(
                                    transport_ctx->wrapped_allocator,
                                    nw_socket->host_name->bytes,
                                    (CFIndex)nw_socket->host_name->len,
                                    kCFStringEncodingUTF8,
                                    false);
                                policy = SecPolicyCreateSSL(true, server_name);
                                CFRelease(server_name);
                                status = SecTrustSetPolicies(trust_ref, policy);
                            }

                            SecTrustResultType trust_result;
                            status = SecTrustEvaluate(trust_ref, &trust_result);
                            if (status == errSecSuccess) {
                                AWS_LOGF_DEBUG(
                                    AWS_LS_IO_TLS,
                                    "id=%p: nw_socket verify block SecTrustEvaluate trust result: %s",
                                    (void *)nw_socket,
                                    aws_sec_trust_result_type_to_string(trust_result));

                                if (trust_result == kSecTrustResultProceed ||
                                    trust_result == kSecTrustResultUnspecified) {
                                    complete(true);
                                } else {
                                    complete(false);
                                }
                            } else {
                                AWS_LOGF_DEBUG(
                                    AWS_LS_IO_TLS,
                                    "id=%p: nw_socket SecTrustEvaluate failed with OSStatus: %d",
                                    (void *)nw_socket,
                                    (int)status);
                                complete(false);
                            }
                        verification_done:
                            CFRelease(trust_ref);
                          },
                          dispatch_loop->dispatch_queue);
                    },

                    // TCP options block
                    ^(nw_protocol_options_t tcp_options) {
                      s_setup_tcp_options(tcp_options, options);
                    });
            } else {
                // TLS options are not set and the TLS options block should be disabled.
                nw_socket->nw_parameters = nw_parameters_create_secure_tcp(
                    // TLS options Block disabled
                    NW_PARAMETERS_DISABLE_PROTOCOL,
                    // TCP options Block
                    ^(nw_protocol_options_t tcp_options) {
                      s_setup_tcp_options(tcp_options, options);
                    });
            }
        } else if (options->domain == AWS_SOCKET_LOCAL) {
#if defined(TARGET_OS_OSX) && TARGET_OS_OSX
            nw_socket->nw_parameters = nw_parameters_create_custom_ip(AF_LOCAL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
#else  /* TARGET_OS_OSX */
            /* AF_LOCAL is not supported on iOS with Network Framework. TCP or UDP should be used instead. */
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p options=%p: failed to create nw_parameters_t for nw_socket. AF_LOCAL is not supported on iOS.",
                (void *)nw_socket,
                (void *)options);
            return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
#endif /* !TARGET_OS_OSX */
        }
    } else if (options->type == AWS_SOCKET_DGRAM) {
        nw_socket->nw_parameters = nw_parameters_create_secure_udp(
            NW_PARAMETERS_DISABLE_PROTOCOL,
            // TCP options Block
            ^(nw_protocol_options_t tcp_options) {
              s_setup_tcp_options(tcp_options, options);
            });
    }

    if (!nw_socket->nw_parameters) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p options=%p: failed to create nw_parameters_t for nw_socket.",
            (void *)nw_socket,
            (void *)options);
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
    }
    /* allow a local address to be used by multiple parameters. */
    nw_parameters_set_reuse_local_address(nw_socket->nw_parameters, true);

    return AWS_OP_SUCCESS;
}

static void s_socket_cleanup_fn(struct aws_socket *socket);
static int s_socket_connect_fn(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *event_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    aws_socket_retrieve_tls_options_fn *retrieve_tls_options,
    void *user_data);
static int s_socket_bind_fn(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint);
static int s_socket_listen_fn(struct aws_socket *socket, int backlog_size);
static int s_socket_start_accept_fn(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    aws_socket_on_accept_result_fn *on_accept_result,
    void *user_data);
static int s_socket_stop_accept_fn(struct aws_socket *socket);
static int s_socket_close_fn(struct aws_socket *socket);
static int s_socket_shutdown_dir_fn(struct aws_socket *socket, enum aws_channel_direction dir);
static int s_socket_set_options_fn(struct aws_socket *socket, const struct aws_socket_options *options);
static int s_socket_assign_to_event_loop_fn(struct aws_socket *socket, struct aws_event_loop *event_loop);
static int s_socket_subscribe_to_readable_events_fn(
    struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable,
    void *user_data);
static int s_socket_read_fn(struct aws_socket *socket, struct aws_byte_buf *buffer, size_t *amount_read);
static int s_socket_write_fn(
    struct aws_socket *socket,
    const struct aws_byte_cursor *cursor,
    aws_socket_on_write_completed_fn *written_fn,
    void *user_data);
static int s_socket_get_error_fn(struct aws_socket *socket);
static bool s_socket_is_open_fn(struct aws_socket *socket);

static struct aws_socket_vtable s_vtable = {
    .socket_cleanup_fn = s_socket_cleanup_fn,
    .socket_connect_fn = s_socket_connect_fn,
    .socket_bind_fn = s_socket_bind_fn,
    .socket_listen_fn = s_socket_listen_fn,
    .socket_start_accept_fn = s_socket_start_accept_fn,
    .socket_stop_accept_fn = s_socket_stop_accept_fn,
    .socket_close_fn = s_socket_close_fn,
    .socket_shutdown_dir_fn = s_socket_shutdown_dir_fn,
    .socket_set_options_fn = s_socket_set_options_fn,
    .socket_assign_to_event_loop_fn = s_socket_assign_to_event_loop_fn,
    .socket_subscribe_to_readable_events_fn = s_socket_subscribe_to_readable_events_fn,
    .socket_read_fn = s_socket_read_fn,
    .socket_write_fn = s_socket_write_fn,
    .socket_get_error_fn = s_socket_get_error_fn,
    .socket_is_open_fn = s_socket_is_open_fn,
};

static void s_socket_cleanup_fn(struct aws_socket *socket) {
    if (!socket->impl) {
        /* protect from double clean */
        return;
    }

    if (aws_socket_is_open(socket)) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET, "id=%p nw_socket=%p: is still open, closing...", (void *)socket, (void *)socket->impl);
        aws_socket_close(socket);
    }

    struct nw_socket *nw_socket = socket->impl;

    // The cleanup of nw_connection_t will be handled in the nw_socket destroy
    aws_ref_count_release(&nw_socket->ref_count);

    AWS_ZERO_STRUCT(*socket);
}

struct read_queue_node {
    struct aws_allocator *allocator;
    dispatch_data_t received_data;
    struct aws_linked_list_node node;
    size_t current_offset;
};

static void s_clean_up_read_queue_node(struct read_queue_node *node) {
    /* releases reference count on dispatch_data_t that was increased during creation of read_queue_node */
    dispatch_release(node->received_data);
    aws_mem_release(node->allocator, node);
}

static void s_socket_impl_destroy(void *sock_ptr) {
    struct nw_socket *nw_socket = sock_ptr;

    /* we might have leftovers from the read queue, clean them up. */
    // Todo check if this is disposing data that needs to be processed already received on the socket.
    // When the socket is being closed from the remote endpoint, we need to insure all received data
    // already received is processed and not thrown away before fully tearing down the socket. I'm relatively
    // certain that should take place before we reach this point of nw_socket destroy.
    while (!aws_linked_list_empty(&nw_socket->read_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&nw_socket->read_queue);
        struct read_queue_node *read_queue_node = AWS_CONTAINER_OF(node, struct read_queue_node, node);
        s_clean_up_read_queue_node(read_queue_node);
    }

    /* Network Framework cleanup */
    if (nw_socket->nw_parameters) {
        nw_release(nw_socket->nw_parameters);
        nw_socket->nw_parameters = NULL;
    }

    if (nw_socket->nw_connection) {
        nw_release(nw_socket->nw_connection);
        nw_socket->nw_connection = NULL;
    }

    if (nw_socket->host_name) {
        aws_string_destroy(nw_socket->host_name);
    }

    if (nw_socket->tls_ctx) {
        aws_tls_ctx_release(nw_socket->tls_ctx);
        nw_socket->tls_ctx = NULL;
    }

    if (nw_socket->nw_listener) {
        nw_release(nw_socket->nw_listener);
        nw_socket->nw_listener = NULL;
    }

    if (nw_socket->timeout_args) {
        aws_mem_release(nw_socket->allocator, nw_socket->timeout_args);
    }

    aws_mem_release(nw_socket->allocator, nw_socket);
    nw_socket = NULL;
}

int aws_socket_init(struct aws_socket *socket, struct aws_allocator *alloc, const struct aws_socket_options *options) {
    AWS_ASSERT(options);
    AWS_ZERO_STRUCT(*socket);

    struct nw_socket *nw_socket = aws_mem_calloc(alloc, 1, sizeof(struct nw_socket));
    nw_socket->allocator = alloc;

    socket->allocator = alloc;
    socket->state = INIT;
    socket->options = *options;
    socket->impl = nw_socket;
    socket->vtable = &s_vtable;
    socket->event_loop_style = AWS_EVENT_LOOP_STYLE_COMPLETION_PORT_BASED;

    aws_ref_count_init(&nw_socket->ref_count, nw_socket, s_socket_impl_destroy);

    nw_socket->allocator = alloc;
    aws_linked_list_init(&nw_socket->read_queue);

    return AWS_OP_SUCCESS;
}

static void s_client_set_dispatch_queue(struct aws_io_handle *handle, void *queue) {
    nw_connection_set_queue(handle->data.handle, queue);
}

static void s_client_clear_dispatch_queue(struct aws_io_handle *handle) {
    /* Setting to NULL removes previously set handler from nw_connection_t */
    nw_connection_set_state_changed_handler(handle->data.handle, NULL);
}

static void s_handle_socket_timeout(struct aws_task *task, void *args, aws_task_status status) {
    (void)task;
    (void)status;

    if (status == AWS_TASK_STATUS_CANCELED) {
        // We will clean up the task and args on socket destory.
        return;
    }
    struct nw_socket_timeout_args *timeout_args = args;

    AWS_LOGF_TRACE(AWS_LS_IO_SOCKET, "task_id=%p: timeout task triggered, evaluating timeouts.", (void *)task);
    /* successful connection will have nulled out timeout_args->socket */
    if (timeout_args->socket) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: timed out, shutting down.",
            (void *)timeout_args->socket,
            timeout_args->socket->io_handle.data.handle);

        timeout_args->socket->state = TIMEDOUT;
        int error_code = AWS_IO_SOCKET_TIMEOUT;

        struct nw_socket *socket_impl = timeout_args->socket->impl;

        aws_raise_error(error_code);
        struct aws_socket *socket = timeout_args->socket;
        aws_socket_close(socket);
        socket_impl->on_connection_result_fn(socket, error_code, socket_impl->connect_accept_user_data);
    }
}

static void s_process_readable_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    // TODO: WAHT IF THE TASK IS CANCELED???

    (void)status;
    struct nw_socket_readable_args *args = arg;

    struct nw_socket *nw_socket = args->socket->impl;
    if (nw_socket->on_readable)
        nw_socket->on_readable(args->socket, args->error_code, nw_socket->on_readable_user_data);

    aws_mem_release(args->allocator, task);
    aws_mem_release(args->allocator, args);
}

static void s_schedule_on_readable(struct aws_socket *socket, int error_code) {
    struct aws_task *task = aws_mem_calloc(socket->allocator, 1, sizeof(struct aws_task));
    ;
    struct nw_socket_readable_args *args = aws_mem_calloc(socket->allocator, 1, sizeof(struct nw_socket_readable_args));

    args->socket = socket;
    args->allocator = socket->allocator;
    args->error_code = error_code;

    aws_task_init(task, s_process_readable_task, args, "readableTask");

    aws_event_loop_schedule_task_now(socket->event_loop, task);
}

static void s_process_connection_success_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    // TODO: WAHT IF THE TASK IS CANCELED???

    (void)status;
    struct nw_socket_readable_args *args = arg;

    struct nw_socket *nw_socket = args->socket->impl;
    if (nw_socket->on_connection_result_fn)
        nw_socket->on_connection_result_fn(args->socket, args->error_code, nw_socket->connect_accept_user_data);

    aws_mem_release(args->allocator, task);
    aws_mem_release(args->allocator, args);
}

static void s_schedule_on_connection_success(struct aws_socket *socket, int error_code) {

    struct aws_task *task = aws_mem_calloc(socket->allocator, 1, sizeof(struct aws_task));
    ;
    struct nw_socket_readable_args *args = aws_mem_calloc(socket->allocator, 1, sizeof(struct nw_socket_readable_args));

    args->socket = socket;
    args->allocator = socket->allocator;
    args->error_code = error_code;

    aws_task_init(task, s_process_connection_success_task, args, "connectionSuccessTask");
    aws_event_loop_schedule_task_now(socket->event_loop, task);
}

static void s_process_listener_success_task(struct aws_task *task, void *args, enum aws_task_status status) {
    // TODO: WAHT IF THE TASK IS CANCELED???

    (void)status;
    struct nw_socket_listener_args *listener_args = args;

    if (listener_args->socket->accept_result_fn)
        listener_args->socket->accept_result_fn(
            listener_args->socket, listener_args->error_code, listener_args->new_socket, listener_args->user_data);

    aws_mem_release(listener_args->allocator, task);
    aws_mem_release(listener_args->allocator, listener_args);
}

static void s_schedule_on_listener_success(
    struct aws_socket *socket,
    int error_code,
    struct aws_socket *new_socket,
    void *user_data) {

    struct aws_task *task = aws_mem_calloc(socket->allocator, 1, sizeof(struct aws_task));
    ;
    struct nw_socket_listener_args *args = aws_mem_calloc(socket->allocator, 1, sizeof(struct nw_socket_readable_args));

    args->socket = socket;
    args->allocator = socket->allocator;
    args->error_code = error_code;
    args->new_socket = new_socket;
    args->user_data = user_data;

    aws_task_init(task, s_process_listener_success_task, args, "listenerSuccessTask");
    aws_event_loop_schedule_task_now(socket->event_loop, task);
}

static void s_process_cancel_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    // TODO: WAHT IF THE TASK IS CANCELED???

    (void)status;
    struct nw_socket_cancel_task_args *args = arg;

    if (status == AWS_TASK_STATUS_RUN_READY)
        aws_event_loop_cancel_task(args->socket->event_loop, args->task_to_cancel);

    aws_mem_release(args->allocator, task);
    aws_mem_release(args->allocator, args);
}

// As cancel task has to run on the same thread & we dont have control on dispatch queue thread,
// we always schedule the cancel task on event loop
static void s_schedule_cancel_task(struct aws_socket *socket, struct aws_task *task_to_cancel) {

    struct aws_task *task = aws_mem_calloc(socket->allocator, 1, sizeof(struct aws_task));
    ;
    struct nw_socket_cancel_task_args *args =
        aws_mem_calloc(socket->allocator, 1, sizeof(struct nw_socket_cancel_task_args));

    args->socket = socket;
    args->allocator = socket->allocator;
    args->task_to_cancel = task_to_cancel;

    aws_task_init(task, s_process_cancel_task, args, "cancelTaskTask");
    aws_event_loop_schedule_task_now(socket->event_loop, task);
}

static void s_process_write_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    // TODO: WAHT IF THE TASK IS CANCELED???

    (void)status;
    struct nw_socket_written_args *args = arg;

    if (args->written_fn)
        args->written_fn(args->socket, args->error_code, args->bytes_written, args->user_data);

    aws_mem_release(args->allocator, task);
    aws_mem_release(args->allocator, args);
}

static void s_schedule_write_fn(
    struct aws_socket *socket,
    int error_code,
    size_t bytes_written,
    void *user_data,
    aws_socket_on_write_completed_fn *written_fn) {

    struct aws_task *task = aws_mem_calloc(socket->allocator, 1, sizeof(struct aws_task));
    ;
    struct nw_socket_written_args *args = aws_mem_calloc(socket->allocator, 1, sizeof(struct nw_socket_written_args));

    args->socket = socket;
    args->allocator = socket->allocator;
    args->error_code = error_code;
    args->written_fn = written_fn;
    args->user_data = user_data;
    args->bytes_written = bytes_written;

    aws_task_init(task, s_process_write_task, args, "writtenTask");
    aws_event_loop_schedule_task_now(socket->event_loop, task);
}

static int s_socket_connect_fn(
    struct aws_socket *socket,
    const struct aws_socket_endpoint *remote_endpoint,
    struct aws_event_loop *event_loop,
    aws_socket_on_connection_result_fn *on_connection_result,
    aws_socket_retrieve_tls_options_fn *retrieve_tls_options,
    void *user_data) {
    struct nw_socket *nw_socket = socket->impl;

    AWS_ASSERT(event_loop);
    AWS_ASSERT(!socket->event_loop);

    struct aws_tls_connection_options *tls_connection_options = NULL;
    retrieve_tls_options(&tls_connection_options, user_data);

    if (tls_connection_options->server_name) {
        if (nw_socket->host_name != NULL) {
            aws_string_destroy(nw_socket->host_name);
            nw_socket->host_name = NULL;
        }
        nw_socket->host_name = aws_string_new_from_string(
            tls_connection_options->server_name->allocator, tls_connection_options->server_name);
        if (nw_socket->host_name == NULL) {
            return AWS_OP_ERR;
        }
    }

    if (tls_connection_options->ctx) {
        if (nw_socket->tls_ctx) {
            aws_tls_ctx_release(nw_socket->tls_ctx);
            nw_socket->tls_ctx = NULL;
        }
        nw_socket->tls_ctx = tls_connection_options->ctx;
        aws_tls_ctx_acquire(nw_socket->tls_ctx);
    }

    nw_socket->event_loop = event_loop;

    if (s_setup_socket_params(nw_socket, &socket->options, tls_connection_options)) {
        return AWS_OP_ERR;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p handle=%p: beginning connect.", (void *)socket, socket->io_handle.data.handle);

    if (socket->event_loop) {
        return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
    }

    if (socket->options.type != AWS_SOCKET_DGRAM) {
        AWS_ASSERT(on_connection_result);
        if (socket->state != INIT) {
            return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
        }
    } else { /* UDP socket */
        /* UDP sockets jump to CONNECT_READ if bind is called first */
        if (socket->state != CONNECTED_READ && socket->state != INIT) {
            return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
        }
    }

    /* fill in posix sock addr, and then let Network framework sort it out. */
    size_t address_strlen;
    if (aws_secure_strlen(remote_endpoint->address, AWS_ADDRESS_MAX_LEN, &address_strlen)) {
        return AWS_OP_ERR;
    }

    struct socket_address address;
    AWS_ZERO_STRUCT(address);
    int pton_err = 1;
    if (socket->options.domain == AWS_SOCKET_IPV4) {
        pton_err = inet_pton(AF_INET, remote_endpoint->address, &address.sock_addr_types.addr_in.sin_addr);
        address.sock_addr_types.addr_in.sin_port = htons(remote_endpoint->port);
        address.sock_addr_types.addr_in.sin_family = AF_INET;
        address.sock_addr_types.addr_in.sin_len = sizeof(struct sockaddr_in);
    } else if (socket->options.domain == AWS_SOCKET_IPV6) {
        pton_err = inet_pton(AF_INET6, remote_endpoint->address, &address.sock_addr_types.addr_in6.sin6_addr);
        address.sock_addr_types.addr_in6.sin6_port = htons(remote_endpoint->port);
        address.sock_addr_types.addr_in6.sin6_family = AF_INET6;
        address.sock_addr_types.addr_in6.sin6_len = sizeof(struct sockaddr_in6);
    } else if (socket->options.domain == AWS_SOCKET_LOCAL) {
        address.sock_addr_types.un_addr.sun_family = AF_UNIX;
        strncpy(address.sock_addr_types.un_addr.sun_path, remote_endpoint->address, AWS_ADDRESS_MAX_LEN);
        address.sock_addr_types.un_addr.sun_len = sizeof(struct sockaddr_un);

    } else {
        AWS_ASSERT(0);
        return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
    }

    if (pton_err != 1) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to parse address %s:%d.",
            (void *)socket,
            socket->io_handle.data.handle,
            remote_endpoint->address,
            (int)remote_endpoint->port);
        return aws_raise_error(s_convert_pton_error(pton_err));
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: connecting to endpoint %s:%d.",
        (void *)socket,
        socket->io_handle.data.handle,
        remote_endpoint->address,
        (int)remote_endpoint->port);

    socket->state = CONNECTING;
    socket->remote_endpoint = *remote_endpoint;
    socket->connect_accept_user_data = user_data;
    socket->connection_result_fn = on_connection_result;

    nw_endpoint_t endpoint = nw_endpoint_create_address((struct sockaddr *)&address.sock_addr_types);

    if (!endpoint) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to create remote address %s:%d.",
            (void *)socket,
            socket->io_handle.data.handle,
            remote_endpoint->address,
            (int)remote_endpoint->port);
        return aws_raise_error(AWS_IO_SOCKET_INVALID_ADDRESS);
    }

    socket->io_handle.data.handle = nw_connection_create(endpoint, nw_socket->nw_parameters);
    nw_socket->nw_connection = socket->io_handle.data.handle;
    nw_release(endpoint);

    if (!socket->io_handle.data.handle) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: connection creation failed, presumably due to a bad network path.",
            (void *)socket,
            socket->io_handle.data.handle);
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    socket->io_handle.set_queue = s_client_set_dispatch_queue;
    socket->io_handle.clear_queue = s_client_clear_dispatch_queue;

    aws_event_loop_connect_handle_to_completion_port(event_loop, &socket->io_handle);
    socket->event_loop = event_loop;

    nw_socket->on_connection_result_fn = on_connection_result;
    nw_socket->connect_accept_user_data = user_data;
    nw_socket->timeout_args = aws_mem_calloc(socket->allocator, 1, sizeof(struct nw_socket_timeout_args));
    nw_socket->timeout_args->socket = socket;
    nw_socket->timeout_args->allocator = socket->allocator;

    aws_task_init(
        &nw_socket->timeout_args->task,
        s_handle_socket_timeout,
        nw_socket->timeout_args,
        "NWSocketConnectionTimeoutTask");

    /* set a handler for socket state changes. This is where we find out if the connection timed out, was successful,
     * was disconnected etc .... */
    nw_connection_set_state_changed_handler(
        socket->io_handle.data.handle, ^(nw_connection_state_t state, nw_error_t error) {
          /* we're connected! */
          if (state == nw_connection_state_ready) {
              AWS_LOGF_INFO(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: connection success",
                  (void *)socket,
                  socket->io_handle.data.handle);
              nw_socket->currently_connected = true;
              nw_path_t path = nw_connection_copy_current_path(socket->io_handle.data.handle);
              nw_endpoint_t local_endpoint = nw_path_copy_effective_local_endpoint(path);
              nw_release(path);
              const char *hostname = nw_endpoint_get_hostname(local_endpoint);
              uint16_t port = nw_endpoint_get_port(local_endpoint);

              if (hostname != NULL) {
                  size_t hostname_len = strlen(hostname);
                  size_t buffer_size = AWS_ARRAY_SIZE(socket->local_endpoint.address);
                  size_t to_copy = aws_min_size(hostname_len, buffer_size);
                  memcpy(socket->local_endpoint.address, hostname, to_copy);
                  socket->local_endpoint.port = port;
              }
              nw_release(local_endpoint);

              AWS_LOGF_DEBUG(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: local endpoint %s:%d",
                  (void *)socket,
                  socket->io_handle.data.handle,
                  socket->local_endpoint.address,
                  port);
              // Cancel the connection timeout task
              s_schedule_cancel_task(socket, &nw_socket->timeout_args->task);
              socket->state = CONNECTED_WRITE | CONNECTED_READ;
              nw_socket->setup_run = true;
              aws_ref_count_acquire(&nw_socket->ref_count);
              s_schedule_on_connection_success(socket, AWS_OP_SUCCESS);
              aws_ref_count_release(&nw_socket->ref_count);

          } else if (error) {
              /* any error, including if closed remotely in error */
              int error_code = nw_error_get_error_code(error);
              AWS_LOGF_ERROR(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: connection error %d",
                  (void *)socket,
                  socket->io_handle.data.handle,
                  error_code);
              // Cancel the connection timeout task
              s_schedule_cancel_task(socket, &nw_socket->timeout_args->task);
              /* we don't let this thing do DNS or TLS. Everything had better be a posix error. */
              //   AWS_ASSERT(nw_error_get_error_domain(error) == nw_error_domain_posix);
              // DEBUG WIP we do in fact allow this to do TLS
              error_code = s_determine_socket_error(error_code);
              nw_socket->last_error = error_code;
              aws_raise_error(error_code);
              socket->state = ERROR;
              aws_ref_count_acquire(&nw_socket->ref_count);
              if (!nw_socket->setup_run) {
                  s_schedule_on_connection_success(socket, error_code);
                  nw_socket->setup_run = true;
              } else if (socket->readable_fn) {
                  s_schedule_on_readable(socket, nw_socket->last_error);
              }

              aws_ref_count_release(&nw_socket->ref_count);
          } else if (state == nw_connection_state_cancelled || state == nw_connection_state_failed) {
              /* this should only hit when the socket was closed by not us. Note,
               * we uninstall this handler right before calling close on the socket so this shouldn't
               * get hit unless it was triggered remotely */
              // Cancel the connection timeout task
              s_schedule_cancel_task(socket, &nw_socket->timeout_args->task);
              AWS_LOGF_DEBUG(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: socket closed remotely.",
                  (void *)socket,
                  socket->io_handle.data.handle);
              socket->state = CLOSED;
              aws_ref_count_acquire(&nw_socket->ref_count);
              aws_raise_error(AWS_IO_SOCKET_CLOSED);
              if (!nw_socket->setup_run) {
                  s_schedule_on_connection_success(socket, AWS_IO_SOCKET_CLOSED);
                  nw_socket->setup_run = true;
              } else if (socket->readable_fn) {
                  s_schedule_on_readable(socket, AWS_IO_SOCKET_CLOSED);
              }
              aws_ref_count_release(&nw_socket->ref_count);
          } else if (state == nw_connection_state_waiting) {
              AWS_LOGF_DEBUG(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: socket connection is waiting for a usable network before re-attempting.",
                  (void *)socket,
                  socket->io_handle.data.handle);
          } else if (state == nw_connection_state_preparing) {
              AWS_LOGF_DEBUG(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: socket connection is in the process of establishing.",
                  (void *)socket,
                  socket->io_handle.data.handle);
          }
        });

    nw_connection_start(socket->io_handle.data.handle);
    nw_retain(socket->io_handle.data.handle);

    /* schedule a task to run at the connect timeout interval, if this task runs before the connect
     * happens, we consider that a timeout. */

    uint64_t timeout = 0;
    aws_event_loop_current_clock_time(event_loop, &timeout);
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: start connection at %llu.",
        (void *)socket,
        socket->io_handle.data.handle,
        (unsigned long long)timeout);
    timeout +=
        aws_timestamp_convert(socket->options.connect_timeout_ms, AWS_TIMESTAMP_MILLIS, AWS_TIMESTAMP_NANOS, NULL);
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p hanlde=%p: scheduling timeout task for %llu.",
        (void *)socket,
        socket->io_handle.data.handle,
        (unsigned long long)timeout);
    nw_socket->timeout_args->task.timestamp = timeout;
    aws_event_loop_schedule_task_future(event_loop, &nw_socket->timeout_args->task, timeout);

    return AWS_OP_SUCCESS;
}

static int s_socket_bind_fn(struct aws_socket *socket, const struct aws_socket_endpoint *local_endpoint) {
    struct nw_socket *nw_socket = socket->impl;

    if (socket->state != INIT) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKET, "id=%p: invalid state for bind operation.", (void *)socket);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    socket->local_endpoint = *local_endpoint;
    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET,
        "id=%p: binding to %s:%d.",
        (void *)socket,
        local_endpoint->address,
        (int)local_endpoint->port);

    struct socket_address address;
    AWS_ZERO_STRUCT(address);
    int pton_err = 1;
    if (socket->options.domain == AWS_SOCKET_IPV4) {
        pton_err = inet_pton(AF_INET, local_endpoint->address, &address.sock_addr_types.addr_in.sin_addr);
        address.sock_addr_types.addr_in.sin_port = htons(local_endpoint->port);
        address.sock_addr_types.addr_in.sin_family = AF_INET;
        address.sock_addr_types.addr_in.sin_len = sizeof(struct sockaddr_in);
    } else if (socket->options.domain == AWS_SOCKET_IPV6) {
        pton_err = inet_pton(AF_INET6, local_endpoint->address, &address.sock_addr_types.addr_in6.sin6_addr);
        address.sock_addr_types.addr_in6.sin6_port = htons(local_endpoint->port);
        address.sock_addr_types.addr_in6.sin6_family = AF_INET6;
        address.sock_addr_types.addr_in6.sin6_len = sizeof(struct sockaddr_in6);
    } else if (socket->options.domain == AWS_SOCKET_LOCAL) {
        address.sock_addr_types.un_addr.sun_family = AF_UNIX;
        address.sock_addr_types.un_addr.sun_len = sizeof(struct sockaddr_un);

        strncpy(address.sock_addr_types.un_addr.sun_path, local_endpoint->address, AWS_ADDRESS_MAX_LEN);
    } else {
        AWS_ASSERT(0);
        return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
    }

    if (pton_err != 1) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p: failed to parse address %s:%d.",
            (void *)socket,
            local_endpoint->address,
            (int)local_endpoint->port);
        return aws_raise_error(s_convert_pton_error(pton_err));
    }

    nw_endpoint_t endpoint = nw_endpoint_create_address((struct sockaddr *)&address.sock_addr_types);

    if (!endpoint) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_ADDRESS);
    }

    nw_parameters_set_local_endpoint(nw_socket->nw_parameters, endpoint);
    nw_release(endpoint);

    // DEBUG WIP:
    // Though UDP is a connectionless transport, but the network framework uses a connection based abstraction on top of the UDP layer. 
    // We should always do an abatract "connection" action for Apple Network Framework
    socket->state = BOUND;

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p: successfully bound", (void *)socket);

    return AWS_OP_SUCCESS;
}

static void s_listener_set_dispatch_queue(struct aws_io_handle *handle, void *queue) {
    nw_listener_set_queue(handle->data.handle, queue);
}

static void s_listener_clear_dispatch_queue(struct aws_io_handle *handle) {
    /* we can't actually clear the queue out, but we can cancel the handlers which is effectively what we want */
    nw_listener_set_state_changed_handler(handle->data.handle, NULL);
    nw_listener_set_new_connection_handler(handle->data.handle, NULL);
}

static int s_socket_listen_fn(struct aws_socket *socket, int backlog_size) {
    (void)backlog_size;

    struct nw_socket *nw_socket = socket->impl;

    if (socket->state != BOUND) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET, "id=%p: invalid state for listen operation. You must call bind first.", (void *)socket);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    socket->io_handle.data.handle = nw_listener_create(nw_socket->nw_parameters);
    nw_socket->nw_listener = socket->io_handle.data.handle;
    nw_retain(socket->io_handle.data.handle);
    nw_socket->is_listener = true;

    if (!socket->io_handle.data.handle) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKET, "id=%p:  listen failed with error code %d", (void *)socket, aws_last_error());
        socket->state = ERROR;
        return aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
    }

    socket->io_handle.set_queue = s_listener_set_dispatch_queue;
    socket->io_handle.clear_queue = s_listener_clear_dispatch_queue;

    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET, "id=%p handle=%p: successfully listening", (void *)socket, socket->io_handle.data.handle);
    socket->state = LISTENING;
    return AWS_OP_SUCCESS;
}

static int s_socket_start_accept_fn(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    aws_socket_on_accept_result_fn *on_accept_result,
    void *user_data) {
    AWS_ASSERT(on_accept_result);
    AWS_ASSERT(accept_loop);

    if (socket->event_loop) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: is already assigned to event-loop %p.",
            (void *)socket,
            socket->io_handle.data.handle,
            (void *)socket->event_loop);
        return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
    }

    if (socket->state != LISTENING) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: invalid state for start_accept operation. You must call listen first.",
            (void *)socket,
            socket->io_handle.data.handle);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    aws_event_loop_connect_handle_to_completion_port(accept_loop, &socket->io_handle);
    socket->event_loop = accept_loop;
    socket->accept_result_fn = on_accept_result;
    socket->connect_accept_user_data = user_data;
    struct aws_allocator *allocator = socket->allocator;

    nw_listener_set_state_changed_handler(
        socket->io_handle.data.handle, ^(nw_listener_state_t state, nw_error_t error) {
          errno = error ? nw_error_get_error_code(error) : 0;
          if (state == nw_listener_state_waiting) {
              AWS_LOGF_DEBUG(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: lisnter on port waiting ",
                  (void *)socket,
                  socket->io_handle.data.handle);

          } else if (state == nw_listener_state_failed) {
              AWS_LOGF_DEBUG(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: lisnter on port failed ",
                  (void *)socket,
                  socket->io_handle.data.handle);
              /* any error, including if closed remotely in error */
              int error_code = nw_error_get_error_code(error);
              AWS_LOGF_ERROR(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: connection error %d",
                  (void *)socket,
                  socket->io_handle.data.handle,
                  error_code);
          } else if (state == nw_listener_state_ready) {
              AWS_LOGF_DEBUG(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: lisnter on port ready ",
                  (void *)socket,
                  socket->io_handle.data.handle);
          } else if (state == nw_listener_state_cancelled) {
              AWS_LOGF_DEBUG(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: lisnter on port cancelled ",
                  (void *)socket,
                  socket->io_handle.data.handle);
          }
        });

    nw_listener_set_new_connection_handler(socket->io_handle.data.handle, ^(nw_connection_t connection) {
      /* invoked upon an incoming connection. In BSD/Posix land this is the result of an
       * accept() call. */

      AWS_LOGF_DEBUG(
          AWS_LS_IO_SOCKET, "id=%p handle=%p: incoming connection", (void *)socket, socket->io_handle.data.handle);

      struct aws_socket *new_socket = aws_mem_calloc(allocator, 1, sizeof(struct aws_socket));

      struct aws_socket_options options = socket->options;
      int error = aws_socket_init(new_socket, allocator, &options);
      if(error)
      {
        aws_mem_release(allocator, new_socket);
        s_schedule_on_listener_success(socket, aws_last_error(), NULL, user_data);
        return;
      }
      new_socket->state = CONNECTED_READ | CONNECTED_WRITE;
      new_socket->io_handle.data.handle = connection;
      // The connection would be released in socket destroy.
      nw_retain(connection);
      new_socket->io_handle.set_queue = s_client_set_dispatch_queue;
      new_socket->io_handle.clear_queue = s_client_clear_dispatch_queue;

      nw_endpoint_t endpoint = nw_connection_copy_endpoint(connection);
      const char *hostname = nw_endpoint_get_hostname(endpoint);
      uint16_t port = nw_endpoint_get_port(endpoint);

      if (hostname != NULL) {
          size_t hostname_len = strlen(hostname);
          size_t buffer_size = AWS_ARRAY_SIZE(new_socket->remote_endpoint.address);
          size_t to_copy = aws_min_size(hostname_len, buffer_size);
          memcpy(new_socket->remote_endpoint.address, hostname, to_copy);
          new_socket->remote_endpoint.port = port;
      }
      nw_release(endpoint);

      // Setup socket state to start read/write operations.
      new_socket->state = CONNECTED_READ | CONNECTED_WRITE;
      struct nw_socket *new_nw_socket = new_socket->impl;
      new_nw_socket->nw_connection = connection;
      new_nw_socket->setup_run = true;
      new_nw_socket->currently_connected = true;

      AWS_LOGF_INFO(
          AWS_LS_IO_SOCKET,
          "id=%p handle=%p: connected to %s:%d, incoming handle %p",
          (void *)socket,
          socket->io_handle.data.handle,
          new_socket->remote_endpoint.address,
          new_socket->remote_endpoint.port,
          new_socket->io_handle.data.handle);
      s_schedule_on_listener_success(socket, AWS_OP_SUCCESS, new_socket, user_data);
    });
    nw_listener_start(socket->io_handle.data.handle);
    return AWS_OP_SUCCESS;
}

static int s_socket_stop_accept_fn(struct aws_socket *socket) {
    if (socket->state != LISTENING) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: is not in a listening state, can't stop_accept.",
            (void *)socket,
            socket->io_handle.data.handle);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    AWS_LOGF_INFO(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: stopping accepting new connections",
        (void *)socket,
        socket->io_handle.data.handle);
    nw_listener_cancel(socket->io_handle.data.handle);
    aws_event_loop_unsubscribe_from_io_events(socket->event_loop, &socket->io_handle);
    socket->state = CLOSED;
    return AWS_OP_SUCCESS;
}

static int s_socket_close_fn(struct aws_socket *socket) {
    struct nw_socket *nw_socket = socket->impl;
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p handle=%p: closing", (void *)socket, socket->io_handle.data.handle);

    /* disable the handlers. We already know it closed and don't need pointless use-after-free event/async hell*/
    if (nw_socket->is_listener) {
        nw_listener_set_state_changed_handler(socket->io_handle.data.handle, NULL);
        nw_listener_cancel(socket->io_handle.data.handle);
    } else {
        /* Setting to NULL removes previously set handler from nw_connection_t */
        nw_connection_set_state_changed_handler(socket->io_handle.data.handle, NULL);
        nw_connection_cancel(socket->io_handle.data.handle);
    }
    nw_socket->currently_connected = false;

    return AWS_OP_SUCCESS;
}

static int s_socket_shutdown_dir_fn(struct aws_socket *socket, enum aws_channel_direction dir) {
    (void)dir;
    return s_socket_close_fn(socket);
}

static int s_socket_set_options_fn(struct aws_socket *socket, const struct aws_socket_options *options) {
    if (socket->options.domain != options->domain || socket->options.type != options->type) {
        aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
        return AWS_OP_ERR;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: setting socket options to: keep-alive %d, keep idle %d, keep-alive interval %d, keep-alive "
        "probe "
        "count %d.",
        (void *)socket,
        socket->io_handle.data.handle,
        (int)options->keepalive,
        (int)options->keep_alive_timeout_sec,
        (int)options->keep_alive_interval_sec,
        (int)options->keep_alive_max_failed_probes);

    socket->options = *options;

    struct nw_socket *nw_socket = socket->impl;

    return AWS_OP_SUCCESS;
}

static int s_socket_assign_to_event_loop_fn(struct aws_socket *socket, struct aws_event_loop *event_loop) {
    if (!socket->event_loop) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: assigning to event loop %p",
            (void *)socket,
            socket->io_handle.data.handle,
            (void *)event_loop);
        socket->event_loop = event_loop;
        if (!aws_event_loop_connect_handle_to_completion_port(event_loop, &socket->io_handle)) {
            nw_connection_start(socket->io_handle.data.handle);
            return AWS_OP_SUCCESS;
        }
        return AWS_OP_ERR;
    }

    return AWS_OP_SUCCESS;
}

/* sockets need to emulate edge-triggering. When we find that we've read all of our buffers or we preemptively know
 * we're going to want more notifications, we schedule a read. That read, upon occuring gets queued into an internal
 * buffer to then be vended upon a call to aws_socket_read() */
static void s_schedule_next_read(struct aws_socket *socket) {
    struct nw_socket *nw_socket = socket->impl;

    struct aws_allocator *allocator = socket->allocator;
    struct aws_linked_list *list = &nw_socket->read_queue;

    if (!(socket->state & CONNECTED_READ)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot read to because it is not connected",
            (void *)socket,
            socket->io_handle.data.handle);
        aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
        return;
    }

    // Acquire nw_socket after we call connection receive, and released it when handler is called.
    aws_ref_count_acquire(&nw_socket->ref_count);

    /* read and let me know when you've done it. */
    nw_connection_receive(
        socket->io_handle.data.handle,
        1,
        UINT32_MAX,
        ^(dispatch_data_t data, nw_content_context_t context, bool is_complete, nw_error_t error) {
          (void)context;
          AWS_LOGF_TRACE(
              AWS_LS_IO_SOCKET, "id=%p handle=%p: read cb invoked", (void *)socket, socket->io_handle.data.handle);

          if (!nw_socket->currently_connected) {
              AWS_LOGF_TRACE(
                  AWS_LS_IO_SOCKET, "id=%p handle=%p: socket closed", (void *)socket, socket->io_handle.data.handle);
              aws_raise_error(AWS_IO_SOCKET_CLOSED);
          } else if (!error || nw_error_get_error_code(error) == 0) {
              if (data) {
                  struct read_queue_node *node = aws_mem_calloc(allocator, 1, sizeof(struct read_queue_node));
                  node->allocator = allocator;
                  node->received_data = data;
                  dispatch_retain(data);
                  aws_linked_list_push_back(list, &node->node);
                  AWS_LOGF_TRACE(
                      AWS_LS_IO_SOCKET,
                      "id=%p handle=%p: queued read buffer of size %d",
                      (void *)socket,
                      socket->io_handle.data.handle,
                      (int)dispatch_data_get_size(data));

                  s_schedule_on_readable(socket, AWS_ERROR_SUCCESS);
              }
              if (!is_complete) {
                  s_schedule_next_read(socket);
              }
          } else {
              int error_code = s_determine_socket_error(nw_error_get_error_code(error));
              aws_raise_error(error_code);

              AWS_LOGF_TRACE(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: error in read callback %d",
                  (void *)socket,
                  socket->io_handle.data.handle,
                  error_code);

              s_schedule_on_readable(socket, error_code);
          }
          aws_ref_count_release(&nw_socket->ref_count);
        });
}

static int s_socket_subscribe_to_readable_events_fn(
    struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable,
    void *user_data) {
    struct nw_socket *nw_socket = socket->impl;

    nw_socket->on_readable = on_readable;
    nw_socket->on_readable_user_data = user_data;

    s_schedule_next_read(socket);
    return AWS_OP_SUCCESS;
}

static int s_socket_read_fn(struct aws_socket *socket, struct aws_byte_buf *read_buffer, size_t *amount_read) {
    struct nw_socket *nw_socket = socket->impl;

    AWS_ASSERT(amount_read);

    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot read from a different thread than event loop %p",
            (void *)socket,
            socket->io_handle.data.handle,
            (void *)socket->event_loop);
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (!(socket->state & CONNECTED_READ)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot read because it is not connected",
            (void *)socket,
            socket->io_handle.data.handle);
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    __block size_t max_to_read = read_buffer->capacity - read_buffer->len;

    /* if empty, schedule a read and return WOULD_BLOCK */
    if (aws_linked_list_empty(&nw_socket->read_queue)) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read queue is empty, scheduling another read",
            (void *)socket,
            socket->io_handle.data.handle);
        if (!nw_socket->read_queued) {
            s_schedule_next_read(socket);
            nw_socket->read_queued = true;
        }
        *amount_read = 0;
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    nw_socket->read_queued = false;

    /* loop over the read queue, take the data and copy it over, and do so til we're either out of data
     * and need to schedule another read, or we've read entirely into the requested buffer. */
    while (!aws_linked_list_empty(&nw_socket->read_queue) && max_to_read) {
        struct aws_linked_list_node *node = aws_linked_list_front(&nw_socket->read_queue);
        struct read_queue_node *read_node = AWS_CONTAINER_OF(node, struct read_queue_node, node);

        bool read_completed = dispatch_data_apply(
            read_node->received_data,
            (dispatch_data_applier_t) ^ (dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
                (void)offset;
                size_t to_copy = aws_min_size(max_to_read, size - read_node->current_offset);
                aws_byte_buf_write(read_buffer, (const uint8_t *)buffer, to_copy);
                if (to_copy < size) {
                    dispatch_retain(region);
                    read_node->current_offset = size - to_copy;
                    return false;
                }

                max_to_read -= to_copy;
                *amount_read += to_copy;
                read_node->current_offset = 0;
                return true;
            });

        if (read_completed) {
            aws_linked_list_remove(node);
            s_clean_up_read_queue_node(read_node);
        }

        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read of %d",
            (void *)socket,
            socket->io_handle.data.handle,
            (int)*amount_read);
    }

    /* keep replacing buffers */
    s_schedule_next_read(socket);
    return AWS_OP_SUCCESS;
}

static int s_socket_write_fn(
    struct aws_socket *socket,
    const struct aws_byte_cursor *cursor,
    aws_socket_on_write_completed_fn *written_fn,
    void *user_data) {
    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    if (!(socket->state & CONNECTED_WRITE)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot write to because it is not connected",
            (void *)socket,
            socket->io_handle.data.handle);
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    struct nw_socket *nw_socket = socket->impl;
    aws_ref_count_acquire(&nw_socket->ref_count);

    AWS_ASSERT(written_fn);

    dispatch_data_t data = dispatch_data_create(cursor->ptr, cursor->len, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    nw_connection_send(
        socket->io_handle.data.handle, data, _nw_content_context_default_message, true, ^(nw_error_t error) {
          AWS_LOGF_TRACE(
              AWS_LS_IO_SOCKET,
              "id=%p handle=%p: processing write requests, called from aws_socket_write",
              (void *)socket,
              socket->io_handle.data.handle);

          if (!nw_socket->currently_connected) {
              AWS_LOGF_TRACE(
                  AWS_LS_IO_SOCKET, "id=%p handle=%p: socket closed", (void *)socket, socket->io_handle.data.handle);
              // As the socket is not open, we no longer have access to the event loop to schedule tasks
              // directly execute the written callback instead of scheduling a task.
              written_fn(socket, 0, 0, user_data);
              goto nw_socket_release;
          }

          AWS_LOGF_ERROR(
              AWS_LS_IO_SOCKET,
              "id=%p handle=%p: DEBUG:: callback writing message: %p",
              (void *)socket,
              socket->io_handle.data.handle,
              user_data);
          int error_code = !error || nw_error_get_error_code(error) == 0
                               ? AWS_OP_SUCCESS
                               : s_determine_socket_error(nw_error_get_error_code(error));

          if (error_code) {
              nw_socket->last_error = error_code;
              aws_raise_error(error_code);
              AWS_LOGF_ERROR(
                  AWS_LS_IO_SOCKET,
                  "id=%p handle=%p: error during write %d",
                  (void *)socket,
                  socket->io_handle.data.handle,
                  error_code);
          }

          size_t written_size = dispatch_data_get_size(data);
          AWS_LOGF_TRACE(
              AWS_LS_IO_SOCKET,
              "id=%p handle=%p: send written size %d",
              (void *)socket,
              socket->io_handle.data.handle,
              (int)written_size);
          s_schedule_write_fn(socket, error_code, !error_code ? written_size : 0, user_data, written_fn);
      nw_socket_release:
          aws_ref_count_release(&nw_socket->ref_count);
        });

    return AWS_OP_SUCCESS;
}

static int s_socket_get_error_fn(struct aws_socket *socket) {
    struct nw_socket *nw_socket = socket->impl;

    return nw_socket->last_error;
}

static bool s_socket_is_open_fn(struct aws_socket *socket) {
    struct nw_socket *nw_socket = socket->impl;
    if (!socket->io_handle.data.handle) {
        return false;
    }

    return nw_socket->last_error == AWS_OP_SUCCESS;
}

void aws_socket_endpoint_init_local_address_for_test(struct aws_socket_endpoint *endpoint) {
    struct aws_uuid uuid;
    AWS_FATAL_ASSERT(aws_uuid_init(&uuid) == AWS_OP_SUCCESS);
    char uuid_str[AWS_UUID_STR_LEN] = {0};
    struct aws_byte_buf uuid_buf = aws_byte_buf_from_empty_array(uuid_str, sizeof(uuid_str));
    AWS_FATAL_ASSERT(aws_uuid_to_str(&uuid, &uuid_buf) == AWS_OP_SUCCESS);
    snprintf(endpoint->address, sizeof(endpoint->address), "testsock" PRInSTR ".local", AWS_BYTE_BUF_PRI(uuid_buf));
}
int aws_socket_get_bound_address(const struct aws_socket *socket, struct aws_socket_endpoint *out_address) {
    if (socket->local_endpoint.address[0] == 0) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p fd=%d: Socket has no local address. Socket must be bound first.",
            (void *)socket,
            socket->io_handle.data.fd);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }
    *out_address = socket->local_endpoint;
    return AWS_OP_SUCCESS;
}

#endif /* AWS_USE_DISPATCH_QUEUE */
