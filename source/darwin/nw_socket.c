/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

#include <aws/io/private/socket_impl.h>
#include <aws/io/socket.h>

#include <aws/common/clock.h>
#include <aws/common/mutex.h>
#include <aws/common/string.h>
#include <aws/common/uuid.h>
#include <aws/io/logging.h>

#include "./dispatch_queue_event_loop_private.h" // private header
#include <Network/Network.h>
#include <aws/io/private/event_loop_impl.h>
#include <aws/io/private/tls_channel_handler_shared.h>

#include <arpa/inet.h>
#include <sys/socket.h>

static const char *s_aws_sec_trust_result_type_to_string(SecTrustResultType trust_result) {
    switch (trust_result) {
        case kSecTrustResultInvalid:
            return "kSecTrustResultInvalid";
        case kSecTrustResultProceed:
            return "kSecTrustResultProceed";
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
        case errSecNotTrusted:
        case errSSLPeerProtocolVersion:
            return AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE;

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
        default:
            return AWS_IO_SOCKET_NOT_CONNECTED;
    }
}

static int s_convert_nw_error(nw_error_t nw_error) {
    int nw_error_code = nw_error ? nw_error_get_error_code(nw_error) : 0;
    int crt_error_code = nw_error_code ? s_determine_socket_error(nw_error_code) : AWS_OP_SUCCESS;
    return crt_error_code;
}

static inline int s_convert_pton_error(int pton_code) {
    if (pton_code == 0) {
        return AWS_IO_SOCKET_INVALID_ADDRESS;
    }

    return s_determine_socket_error(errno);
}

/*
 * Helper function that gets the available human readable error description from Core Foundation.
 */
static void s_get_error_description(CFErrorRef error, char *description_buffer, size_t buffer_size) {
    if (error == NULL) {
        snprintf(description_buffer, buffer_size, "No error provided");
        return;
    }

    CFStringRef error_description = CFErrorCopyDescription(error);
    if (error_description) {
        CFStringGetCString(error_description, description_buffer, buffer_size, kCFStringEncodingUTF8);
        CFRelease(error_description);
    } else {
        snprintf(description_buffer, buffer_size, "Unable to retrieve error description");
    }
}

/*
 * A socket is only in one of these states at a time, except for CONNECTED_READ | CONNECTED_WRITE.
 *
 * The state can only go increasing, except for the following cases
 *      1. LISTENING and STOPPED: They can switch between each other.
 *      2. CLOSING -> ERROR: It is a valid case where socket state tries to transfer from CLOSING to ERROR, but we never
 *      actually set it to ERROR if we are already in CLOSING state. This happened in the following scenario: After we
 *      called aws_socket_close(), the socket state is set to CLOSING. And if a read callback invoked at this time, it
 *      is possible that the socket reads an ERROR and tries to set the socket state to ERROR, which makes the socket
 * state goes backwards. Though this is a valid case, we don't actually set it back to ERROR as we are shutting down the
 * socket.
 *      3. CONNECT_WRITE and CONNECT_READ: you are allow to flip the flags for these two state, while not going
 * backwards to `CONNECTING` and `INIT` state.
 */
enum aws_nw_socket_state {
    INVALID = 0x000,
    INIT = 0x001,
    CONNECTING = 0x002,
    CONNECTED_READ = 0x004,
    CONNECTED_WRITE = 0x008,
    BOUND = 0x010,
    LISTENING = 0x020,
    STOPPED = 0x040, // Stop the io events, while we could restart it later
    ERROR = 0x080,
    CLOSING = 0X100, // Only set when aws_socket_close() is called.
    CLOSED = 0x200,
};

static const char *aws_socket_state_to_c_string(enum aws_nw_socket_state state) {
    switch (state) {
        case INVALID:
            return "INVALID";
        case CONNECTING:
            return "CONNECTING";
        case CONNECTED_READ:
            return "CONNECTED_READ";
        case CONNECTED_WRITE:
            return "CONNECTED_WRITE";
        case BOUND:
            return "BOUND";
        case LISTENING:
            return "LISTENING";
        case STOPPED:
            return "STOPPED";
        case ERROR:
            return "ERROR";
        case CLOSING:
            return "CLOSING";
        case CLOSED:
            return "CLOSED";
        default:
            return "UNKNOWN";
    }
}

enum aws_nw_socket_mode {
    NWSM_CONNECTION,
    NWSM_LISTENER,
};

struct nw_listener_connection_args {
    struct aws_task task;
    int error_code;
    struct aws_allocator *allocator;
    struct nw_socket *nw_socket;
    nw_connection_t new_connection;
    void *user_data;
};

struct nw_socket_timeout_args {
    struct aws_task task;
    struct aws_allocator *allocator;
    struct nw_socket *nw_socket;
};

struct nw_socket_scheduled_task_args {
    struct aws_task task;
    int error_code;
    struct aws_allocator *allocator;
    struct nw_socket *nw_socket;
    dispatch_data_t data;
    bool is_complete;
};

struct nw_socket_written_args {
    struct aws_task task;
    int error_code;
    struct aws_allocator *allocator;
    struct nw_socket *nw_socket;
    aws_socket_on_write_completed_fn *written_fn;
    void *user_data;
    size_t bytes_written;
};

struct nw_socket_cancel_task_args {
    struct aws_allocator *allocator;
    struct nw_socket *nw_socket;
    struct aws_task task;
};

struct nw_socket {
    struct aws_allocator *allocator;

    /* The `nw_socket_ref_count` that keeps the nw_socket alive. The `nw_socket_ref_count` initalized on
     * aws_socket_init() and decreased on aws_socket_clean_up() called. The `internal_ref_count` will also keep a
     * reference of the `nw_socket_ref_count` so that the nw_socket would alive until all system callbacks and tasks are
     * handled. On `nw_socket_ref_count` drops to 0, it invokes s_socket_impl_destroy, which cleanup the nw_socket
     * memory and invoke on_socket_cleanup_complete_fn.
     */
    struct aws_ref_count nw_socket_ref_count;

    /* The `internal_ref_count` is used to track any in-flight socket operations. It would be init on socket init, and
     * acquired on aws_socket_connect()/aws_socket_listen() called. The reference will be decreased on
     * nw_connection/listener_state_changed_handler is invoked with a "nw_connection/listener_state_cancelled" state.
     * Besides this, each network framework system call or each scheduled task in event loop would also acquire an
     * internal reference, and release when the callback invoked or the task executed.
     */
    struct aws_ref_count internal_ref_count;

    /* The `write_ref_count` is used to track any in-flight write operations. It would be init on aws_socket_init() and
     * dropped on aws_socket_close() call. Each aws_socket_write() function call will acquire a ref-count, and released
     * the ref-count on nw_connection_send handler is invoked.
     * When the reference is dropped to 0, it invoked the destroy function `s_nw_socket_canceled()`, and start to cancel
     * and close the Apple nw_connection/nw_listener.
     */
    struct aws_ref_count write_ref_count;

    int last_error;

    /* Apple's native structs for connection and listener. */
    union {
        nw_connection_t nw_connection;
        nw_listener_t nw_listener;
    } os_handle;
    nw_parameters_t nw_parameters;
    /* The socket would be either setup as nw_connection or nw_listener. */
    enum aws_nw_socket_mode mode;

    /* The linked list of `read_queue_node`. The read queue to store read data from io events. aws_socket_read()
     * function would read data from the queue.

     * WARNING: The read_queue is not lock protected so far, as we always access it on event loop thread. */
    struct aws_linked_list read_queue;

    /*
     * nw_socket is ref counted. It is possible that the aws_socket object is released while nw_socket is still alive
     * and processing events. We keep the callbacks and parameters on nw_socket to avoid bad access after the aws_socket
     * is released.
     */
    aws_socket_on_readable_fn *on_readable;
    void *on_readable_user_data;
    aws_socket_on_connection_result_fn *on_connection_result_fn;
    void *connect_result_user_data;
    aws_socket_on_accept_started_fn *on_accept_started_fn;
    void *listen_accept_started_user_data;
    aws_socket_on_shutdown_complete_fn *on_socket_close_complete_fn;
    void *close_user_data;
    aws_socket_on_shutdown_complete_fn *on_socket_cleanup_complete_fn;
    void *cleanup_user_data;

    /* nw_socket had to be assigned to an event loop to process events. The nw_socket will acquire a reference of the
     * event_loop's base event group to kept the event loop alive.
     *
     *  For client socket (nw_connection): setup on aws_socket_connect()
     *  For listener (nw_listener) : setup on aws_socket_start_accept()
     *  For incoming socket / server socket (nw_connection accepted on a listener): setup by calling
     * aws_socket_assign_event_loop()
     */
    struct aws_event_loop *event_loop;

    /* Indicate the connection result is updated. This argument is used to cancel the timeout task. The argument should
     * be only set on socket event loop. The value will be set to true if:
     *      1. nw_connection returned with state=`nw_connection_state_ready`, indicating the connection succeed
     *      2. nw_connection returned with state=`nw_connection_state_failed`, indicating the connection failed
     *      3. directly set to true for the incoming socket, as the incoming socket is already connected
     */
    bool connection_setup;

    /* Timeout task that is created on aws_socket_connect(). The task will be flagged to be canceled if the connection
     * succeed or failed. */
    struct nw_socket_timeout_args *timeout_args;

    struct aws_string *host_name;
    struct aws_string *alpn_list;
    struct aws_tls_ctx *tls_ctx;
    struct aws_byte_buf protocol_buf;

    /* synced_data and the lock to protect the synced data. */
    struct {
        /* Used to avoid scheduling a duplicate read call. We would like to wait for the read call complete back before
         * we schedule another one. */
        bool read_scheduled;
        /* The aws_nw_socket_state. aws_socket also has a field `state` which should be represent the same parameter,
         * however, as it is possible that the aws_socket object is released while nw_socket is still alive, we will use
         * nw_socket->state instead of socket->state to verify the socket_state.
         */
        enum aws_nw_socket_state state;
        struct aws_mutex lock;
    } synced_data;

    /*
     * The synced data to protect base_socket access. As aws_socket is not ref-counted. It is possible that the user
     * called aws_socket_cleanup() to release the aws_socket(base_socket), while the nw_socket is still alive and the
     * underlying system calls are still processing the data.  Therefore, here nw_socket kept a point to base_socket to
     * avoid bad access after aws_socket is cleaned up. The lock is acquired before we do any callback that might access
     * the base_socket.
     * We put aws_socket in a different base_socket_synced_data struct to avoid the lock contention between other
     * cross-thread data, especially when we do a socket operation in a callback when the socket lock is acquired.
     *
     * As all the callbacks will hold the lock to make sure the base_socket is alive, we should avoid to use the lock in
     * user API calls. So far we used it only in aws_socket_cleanup. And handle it in this way to avoid deadlock: if we
     * are on the assigned event loop, we assume we are fired on the event loop thread, and we don't need to acquire the
     * lock, otherwise, we acquire the lock.
     */
    struct {
        struct aws_mutex lock;
        struct aws_socket *base_socket;
    } base_socket_synced_data;
};

static size_t KB_16 = 16 * 1024;

static void *s_socket_acquire_internal_ref(struct nw_socket *nw_socket) {
    return aws_ref_count_acquire(&nw_socket->internal_ref_count);
}

static size_t s_socket_release_internal_ref(struct nw_socket *nw_socket) {
    return aws_ref_count_release(&nw_socket->internal_ref_count);
}

static void *s_socket_acquire_write_ref(struct nw_socket *nw_socket) {
    return aws_ref_count_acquire(&nw_socket->write_ref_count);
}

static size_t s_socket_release_write_ref(struct nw_socket *nw_socket) {
    return aws_ref_count_release(&nw_socket->write_ref_count);
}

static int s_lock_base_socket(struct nw_socket *nw_socket) {
    return aws_mutex_lock(&nw_socket->base_socket_synced_data.lock);
}

static int s_unlock_base_socket(struct nw_socket *nw_socket) {
    return aws_mutex_unlock(&nw_socket->base_socket_synced_data.lock);
}

static int s_lock_socket_synced_data(struct nw_socket *nw_socket) {
    return aws_mutex_lock(&nw_socket->synced_data.lock);
}

static int s_unlock_socket_synced_data(struct nw_socket *nw_socket) {
    return aws_mutex_unlock(&nw_socket->synced_data.lock);
}

static bool s_validate_event_loop(struct aws_event_loop *event_loop) {
    return event_loop && event_loop->vtable && event_loop->impl_data;
}

static void s_set_event_loop(struct aws_socket *aws_socket, struct aws_event_loop *event_loop) {
    aws_socket->event_loop = event_loop;
    struct nw_socket *nw_socket = aws_socket->impl;
    // Never re-assign an event loop
    AWS_FATAL_ASSERT(nw_socket->event_loop == NULL);
    nw_socket->event_loop = event_loop;

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p: s_set_event_loop: socket acquire event loop group.", (void *)nw_socket);
    aws_event_loop_group_acquire(get_base_event_loop_group(event_loop));
}

static void s_release_event_loop(struct nw_socket *nw_socket) {
    if (nw_socket->event_loop == NULL) {
        AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p: s_release_event_loop: socket has not event loop.", (void *)nw_socket);
        return;
    }
    aws_event_loop_group_release(get_base_event_loop_group(nw_socket->event_loop));
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p: s_release_event_loop: socket release event loop group.", (void *)nw_socket);
    nw_socket->event_loop = NULL;
}

/* The help function to update the socket state. The function must be called with synced_data locked (use
 * s_lock_socket_synced_data() / s_unlock_socket_synced_data()), as the function touches the synced_data.state. */
static void s_set_socket_state(struct nw_socket *nw_socket, enum aws_nw_socket_state state) {

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p: s_set_socket_state: socket state set from %s to %s.",
        (void *)nw_socket,
        aws_socket_state_to_c_string(nw_socket->synced_data.state),
        aws_socket_state_to_c_string(state));
    enum aws_nw_socket_state result_state = nw_socket->synced_data.state;

    // clip the read/write bits
    enum aws_nw_socket_state read_write_bits = state & (CONNECTED_WRITE | CONNECTED_READ);
    result_state = result_state & ~CONNECTED_WRITE & ~CONNECTED_READ;

    // If the caller would like simply flip the read/write bits, set the state to invalid, as we dont have further
    // information there.
    if (~CONNECTED_WRITE == (int)state || ~CONNECTED_READ == (int)state) {
        state = INVALID;
    }

    // The state can only go increasing, except for the following cases
    //  1. LISTENING and STOPPED: They can switch between each other.
    //  2. CLOSING -> ERROR: It is a valid case where socket state tries to transfer from CLOSING to ERROR. This
    //  happened in the following scenario: After we called aws_socket_close(), the socket state is set to CLOSING. And
    //  if a read callback invoked at this time, it is possible that the socket reads an ERROR and tries to set the
    //  socket state to ERROR, which makes the socket state goes backwards. Though this is a valid case, we don't
    //  actually set it back to ERROR as we are shutting down the socket.
    //  3. CONNECT_WRITE and CONNECT_READ: you are allow to flip the flags for these two state, while not going
    //  backwards to `CONNECTING` and `INIT` state.
    if (result_state < state || (state == LISTENING && result_state == STOPPED)) {
        result_state = state;
    }

    // Set CONNECTED_WRITE and CONNECTED_READ
    result_state = result_state | read_write_bits;

    nw_socket->synced_data.state = result_state;

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p: s_set_socket_state: socket state set to %s.",
        (void *)nw_socket,
        aws_socket_state_to_c_string(nw_socket->synced_data.state));
}

/* setup the TCP options Block for use in socket parameters */
static void s_setup_tcp_options(nw_protocol_options_t tcp_options, const struct aws_socket_options *options) {
    if (options->domain == AWS_SOCKET_LOCAL) {
        /*
         * TCP options for a local connection should use system defaults and not be modified. We have this function in
         * case we need to support the setting of local connection options in the future during the creation of
         * nw_parameters.
         */
        return;
    }

    if (options->connect_timeout_ms) {
        /* this value gets set in seconds. */
        nw_tcp_options_set_connection_timeout(tcp_options, options->connect_timeout_ms / AWS_TIMESTAMP_MILLIS);
    }

    /* Only change default keepalive values if keepalive is true and both interval and timeout
     * are not zero. */
    if (options->keepalive && options->keep_alive_interval_sec != 0 && options->keep_alive_timeout_sec != 0) {
        nw_tcp_options_set_enable_keepalive(tcp_options, options->keepalive);
        nw_tcp_options_set_keepalive_idle_time(tcp_options, options->keep_alive_interval_sec);
        nw_tcp_options_set_keepalive_interval(tcp_options, options->keep_alive_timeout_sec);
    }

    if (options->keep_alive_max_failed_probes) {
        nw_tcp_options_set_keepalive_count(tcp_options, options->keep_alive_max_failed_probes);
    }

    if (g_aws_channel_max_fragment_size < KB_16) {
        nw_tcp_options_set_maximum_segment_size(tcp_options, g_aws_channel_max_fragment_size);
    }
}

static void s_tls_verification_block(
    sec_protocol_metadata_t metadata,
    sec_trust_t trust,
    sec_protocol_verify_complete_t complete,
    struct nw_socket *nw_socket,
    struct secure_transport_ctx *transport_ctx) {
    (void)metadata;

    CFErrorRef error = NULL;
    SecPolicyRef policy = NULL;
    SecTrustRef trust_ref = NULL;
    OSStatus status;
    bool verification_successful = false;

    /*
     * Because we manually handle the verification of the peer, the value set using
     * sec_protocol_options_set_peer_authentication_required is ignored and this block is run instead. We force
     * successful verification if verify_peer is false.
     */
    if (!transport_ctx->verify_peer) {
        AWS_LOGF_WARN(
            AWS_LS_IO_TLS,
            "id=%p: x.509 validation has been disabled. If this is not running in a test environment, this is "
            "likely a security vulnerability.",
            (void *)nw_socket);
        verification_successful = true;
        goto verification_done;
    }

    trust_ref = sec_trust_copy_ref(trust);

    /* Use root ca if provided. */
    if (transport_ctx->ca_cert != NULL) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_TLS,
            "id=%p: nw_socket verify block applying provided root CA for remote verification.",
            (void *)nw_socket);
        // We add the ca certificate as a anchor certificate in the trust_ref
        status = SecTrustSetAnchorCertificates(trust_ref, transport_ctx->ca_cert);
        if (status != errSecSuccess) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_TLS,
                "id=%p: nw_socket verify block SecTrustSetAnchorCertificates failed with "
                "OSStatus: %d",
                (void *)nw_socket,
                (int)status);
            aws_raise_error(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
            goto verification_done;
        }
    }

    /* Add the host name to be checked against the available Certificate Authorities */
    if (nw_socket->host_name != NULL) {
        CFStringRef server_name = CFStringCreateWithCString(
            transport_ctx->wrapped_allocator, aws_string_c_str(nw_socket->host_name), kCFStringEncodingUTF8);
        policy = SecPolicyCreateSSL(true, server_name);
        CFRelease(server_name);
    } else {
        policy = SecPolicyCreateBasicX509();
    }

    status = SecTrustSetPolicies(trust_ref, policy);
    if (status != errSecSuccess) {
        AWS_LOGF_ERROR(AWS_LS_IO_TLS, "id=%p: Failed to set trust policy %d\n", (void *)nw_socket, (int)status);
        aws_raise_error(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE);
        goto verification_done;
    }

    SecTrustResultType trust_result;

    /* verify peer */
    bool success = SecTrustEvaluateWithError(trust_ref, &error);
    if (success) {
        status = SecTrustGetTrustResult(trust_ref, &trust_result);
        if (status == errSecSuccess) {
            AWS_LOGF_DEBUG(
                AWS_LS_IO_TLS,
                "id=%p: nw_socket verify block trust result: %s",
                (void *)nw_socket,
                s_aws_sec_trust_result_type_to_string(trust_result));

            // Proceed based on the trust_result if necessary
            if (trust_result == kSecTrustResultProceed || trust_result == kSecTrustResultUnspecified) {
                verification_successful = true;
            }
        } else {
            AWS_LOGF_DEBUG(
                AWS_LS_IO_TLS,
                "id=%p: nw_socket SecTrustGetTrustResult failed with OSStatus: %d",
                (void *)nw_socket,
                (int)status);
        }
    } else {
        char description_buffer[256];
        s_get_error_description(error, description_buffer, sizeof(description_buffer));
        int crt_error_code = s_determine_socket_error(CFErrorGetCode(error));
        AWS_LOGF_DEBUG(
            AWS_LS_IO_TLS,
            "id=%p: nw_socket SecTrustEvaluateWithError failed with error code: %d CF error "
            "code: %ld : %s",
            (void *)nw_socket,
            crt_error_code,
            (long)CFErrorGetCode(error),
            description_buffer);
    }

verification_done:
    if (policy) {
        CFRelease(policy);
    }
    if (trust_ref) {
        CFRelease(trust_ref);
    }
    if (error) {
        CFRelease(error);
    }
    complete(verification_successful);
}

static void s_setup_tls_options(
    nw_protocol_options_t tls_options,
    struct nw_socket *nw_socket,
    struct secure_transport_ctx *transport_ctx) {
    /*
     * Obtain the security protocol options from tls_options. Changes made to the copy will impact the protocol options
     * within the tls_options
     */
    sec_protocol_options_t sec_options = nw_tls_copy_sec_protocol_options(tls_options);

    sec_protocol_options_set_local_identity(sec_options, transport_ctx->secitem_identity);

    // Set the minimum TLS version
    switch (transport_ctx->minimum_tls_version) {
        case AWS_IO_TLSv1_2:
            sec_protocol_options_set_min_tls_protocol_version(sec_options, tls_protocol_version_TLSv12);
            break;
        case AWS_IO_TLSv1_3:
            sec_protocol_options_set_min_tls_protocol_version(sec_options, tls_protocol_version_TLSv13);
            break;
        case AWS_IO_TLS_VER_SYS_DEFAULTS:
            /* not assigning a min tls protocol version automatically uses the system default version. */
            break;
        default:
            /* Already validated with error thrown in s_setup_socket_params prior to this block being called. */
            AWS_FATAL_ASSERT(false);
            break;
    }

    /*
     * Enable/Disable peer authentication. This setting is ignored by network framework due to our implementation of the
     * verification block below but we set it in case anything else checks this value and/or in case we decide to remove
     * the verify block in the future.
     */
    sec_protocol_options_set_peer_authentication_required(sec_options, transport_ctx->verify_peer);

    if (nw_socket->host_name != NULL) {
        sec_protocol_options_set_tls_server_name(sec_options, (const char *)nw_socket->host_name->bytes);
    }

    // Add alpn protocols
    if (nw_socket->alpn_list != NULL) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_TLS, "id=%p: Setting ALPN list %s", (void *)nw_socket, aws_string_c_str(nw_socket->alpn_list));

        struct aws_byte_cursor alpn_data = aws_byte_cursor_from_string(nw_socket->alpn_list);
        struct aws_array_list alpn_list_array;
        if (aws_array_list_init_dynamic(&alpn_list_array, nw_socket->allocator, 2, sizeof(struct aws_byte_cursor)) ||
            aws_byte_cursor_split_on_char(&alpn_data, ';', &alpn_list_array)) {
            /*
             * We cannot throw or fail from within a tls options block. We will log the error and in the event an ALPN
             * was required for this connection to succeeed, the connection's state change handler will catch the
             * connection failure.
             */
            AWS_LOGF_ERROR(AWS_LS_IO_TLS, "id=%p: Failed to setup array list for ALPN setup.", (void *)nw_socket);
        } else {
            for (size_t i = 0; i < aws_array_list_length(&alpn_list_array); ++i) {
                struct aws_byte_cursor protocol_cursor;
                aws_array_list_get_at(&alpn_list_array, &protocol_cursor, i);
                struct aws_string *protocol_string = aws_string_new_from_cursor(nw_socket->allocator, &protocol_cursor);
                sec_protocol_options_add_tls_application_protocol(sec_options, aws_string_c_str(protocol_string));
                aws_string_destroy(protocol_string);
            }
        }
        aws_array_list_clean_up(&alpn_list_array);
    }

    /*
     * We handle the verification of the remote end here. The verify block requires a dispatch queue to execute on.
     */
    struct aws_dispatch_loop *dispatch_loop = nw_socket->event_loop->impl_data;
    sec_protocol_options_set_verify_block(
        sec_options,
        ^(sec_protocol_metadata_t metadata, sec_trust_t trust, sec_protocol_verify_complete_t complete) {
          s_tls_verification_block(metadata, trust, complete, nw_socket, transport_ctx);
        },
        dispatch_loop->dispatch_queue);
}

static int s_setup_socket_params(struct nw_socket *nw_socket, const struct aws_socket_options *options) {

    /* If we already have parameters set, release them before re-establishing new parameters */
    if (nw_socket->nw_parameters != NULL) {
        nw_release(nw_socket->nw_parameters);
        nw_socket->nw_parameters = NULL;
    }
    bool setup_tls = false;

    if (aws_is_use_secitem()) {
        /* If SecItem isn't being used then the nw_parameters should not be setup to handle the TLS Negotiation. */
        if (nw_socket->tls_ctx) {
            setup_tls = true;
        }
    }

    if (options->type == AWS_SOCKET_STREAM) {
        if (setup_tls) {
            /* The verification block of the Network Framework TLS handshake requires a dispatch queue to run on. */
            if (nw_socket->event_loop == NULL) {
                AWS_LOGF_ERROR(
                    AWS_LS_IO_SOCKET,
                    "id=%p Apple Network Framework setup of TLS parameters requires the nw_socket to have a valid "
                    "event_loop.",
                    (void *)nw_socket);
                return aws_raise_error(AWS_IO_SOCKET_MISSING_EVENT_LOOP);
            }

            struct secure_transport_ctx *transport_ctx = nw_socket->tls_ctx->impl;

            /* This check cannot be done within the TLS options block and must be handled here. */
            if (transport_ctx->minimum_tls_version == AWS_IO_SSLv3 ||
                transport_ctx->minimum_tls_version == AWS_IO_TLSv1 ||
                transport_ctx->minimum_tls_version == AWS_IO_TLSv1_1) {
                AWS_LOGF_ERROR(
                    AWS_LS_IO_SOCKET,
                    "id=%p options=%p: Selected minimum tls version not supported by Apple Network Framework due "
                    "to deprecated status and known security flaws.",
                    (void *)nw_socket,
                    (void *)options);
                return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
            }

            switch (options->domain) {
                case AWS_SOCKET_IPV4:
                case AWS_SOCKET_IPV6:
                case AWS_SOCKET_LOCAL:
                    nw_socket->nw_parameters = nw_parameters_create_secure_tcp(
                        // TLS options block
                        ^(nw_protocol_options_t tls_options) {
                          s_setup_tls_options(tls_options, nw_socket, transport_ctx);
                        },
                        // TCP options block
                        ^(nw_protocol_options_t tcp_options) {
                          s_setup_tcp_options(tcp_options, options);
                        });
                    break;
                default:
                    AWS_LOGF_ERROR(
                        AWS_LS_IO_SOCKET,
                        "id=%p options=%p: AWS_SOCKET_VSOCK is not supported on nw_socket.",
                        (void *)nw_socket,
                        (void *)options);
                    return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
            }
        } else {
            switch (options->domain) {
                case AWS_SOCKET_IPV4:
                case AWS_SOCKET_IPV6:
                case AWS_SOCKET_LOCAL:
                    // TLS options are not set and the TLS options block should be disabled.
                    nw_socket->nw_parameters = nw_parameters_create_secure_tcp(
                        // TLS options Block disabled
                        NW_PARAMETERS_DISABLE_PROTOCOL,
                        // TCP options Block
                        ^(nw_protocol_options_t tcp_options) {
                          s_setup_tcp_options(tcp_options, options);
                        });
                    break;
                default:
                    AWS_LOGF_ERROR(
                        AWS_LS_IO_SOCKET,
                        "id=%p options=%p: AWS_SOCKET_VSOCK is not supported on nw_socket.",
                        (void *)nw_socket,
                        (void *)options);
                    return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
            }
        }

        /* allow a local address to be used by multiple parameters. */
        if (options->domain == AWS_SOCKET_LOCAL) {
            nw_parameters_set_reuse_local_address(nw_socket->nw_parameters, true);
        }
    } else if (options->type == AWS_SOCKET_DGRAM) {
        if (setup_tls) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET, "id=%p options=%p: Cannot use TLS with UDP.", (void *)nw_socket, (void *)options);
            return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
        } else {
            nw_socket->nw_parameters = nw_parameters_create_secure_udp(
                NW_PARAMETERS_DISABLE_PROTOCOL,
                // TCP options Block
                ^(nw_protocol_options_t tcp_options) {
                  s_setup_tcp_options(tcp_options, options);
                });
        }
    }

    if (!nw_socket->nw_parameters) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p options=%p: failed to create nw_parameters_t for nw_socket.",
            (void *)nw_socket,
            (void *)options);
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
    }

    return AWS_OP_SUCCESS;
}

static void s_socket_cleanup_fn(struct aws_socket *socket);
static int s_socket_connect_fn(
    struct aws_socket *socket,
    struct aws_socket_connect_options *socket_connect_options,
    void *user_data);
static int s_socket_bind_fn(
    struct aws_socket *socket,
    struct aws_socket_bind_options *socket_bind_options,
    void *user_data);
static int s_socket_listen_fn(struct aws_socket *socket, int backlog_size);
static int s_socket_start_accept_fn(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    struct aws_socket_listener_options options);
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
static int s_set_close_callback(struct aws_socket *socket, aws_socket_on_shutdown_complete_fn fn, void *user_data);
static int s_set_cleanup_callback(struct aws_socket *socket, aws_socket_on_shutdown_complete_fn fn, void *user_data);
static struct aws_byte_buf s_socket_get_protocol_fn(const struct aws_socket *socket);
static struct aws_string *s_socket_get_server_name_fn(const struct aws_socket *socket);

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
    .socket_set_close_callback = s_set_close_callback,
    .socket_set_cleanup_callback = s_set_cleanup_callback,
    .socket_get_protocol_fn = s_socket_get_protocol_fn,
    .socket_get_server_name_fn = s_socket_get_server_name_fn,
};

static int s_schedule_next_read(struct nw_socket *socket);

static void s_socket_cleanup_fn(struct aws_socket *socket) {
    if (!socket->impl) {
        /* protect from double clean */
        return;
    }

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p nw_socket=%p: is cleanup...", (void *)socket, (void *)socket->impl);
    if (aws_socket_is_open(socket)) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET, "id=%p nw_socket=%p: is still open, closing...", (void *)socket, (void *)socket->impl);
        aws_socket_close(socket);
    }

    struct nw_socket *nw_socket = socket->impl;

    if (s_validate_event_loop(socket->event_loop) && !aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        s_lock_base_socket(nw_socket);
        nw_socket->base_socket_synced_data.base_socket = NULL;
        s_unlock_base_socket(nw_socket);
    } else {
        // If we are already on event loop or event loop is unavailable, we should already acquire the lock for base
        // socket access
        nw_socket->base_socket_synced_data.base_socket = NULL;
    }

    aws_ref_count_release(&nw_socket->nw_socket_ref_count);
    socket->impl = NULL;
    AWS_ZERO_STRUCT(*socket);
}

struct read_queue_node {
    struct aws_allocator *allocator;
    dispatch_data_t received_data;
    struct aws_linked_list_node node;
    size_t region_offset;
    // If we didn't finish reading the received_data, we need to keep track of the region offset that we would
    // like to resume with
    size_t resume_region;
};

static void s_read_queue_node_destroy(struct read_queue_node *node) {
    /* releases reference count on dispatch_data_t that was increased during creation of read_queue_node */
    dispatch_release(node->received_data);
    aws_mem_release(node->allocator, node);
}

struct socket_close_complete_args {
    struct aws_task task;
    struct aws_allocator *allocator;
    aws_socket_on_shutdown_complete_fn *shutdown_complete_fn;
    void *user_data;
    struct nw_socket *nw_socket;
};

static void s_close_complete_callback(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)status;
    (void)task;
    struct socket_close_complete_args *task_arg = arg;
    struct aws_allocator *allocator = task_arg->allocator;
    if (task_arg->shutdown_complete_fn) {
        task_arg->shutdown_complete_fn(task_arg->user_data);
    }
    aws_ref_count_release(&task_arg->nw_socket->nw_socket_ref_count);
    aws_mem_release(allocator, task_arg);
}

static void s_socket_impl_destroy(void *sock_ptr) {
    struct nw_socket *nw_socket = sock_ptr;
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p : start s_socket_impl_destroy", (void *)sock_ptr);
    /* In case we have leftovers from the read queue, clean them up. */
    while (!aws_linked_list_empty(&nw_socket->read_queue)) {
        struct aws_linked_list_node *node = aws_linked_list_pop_front(&nw_socket->read_queue);
        struct read_queue_node *read_queue_node = AWS_CONTAINER_OF(node, struct read_queue_node, node);
        s_read_queue_node_destroy(read_queue_node);
    }

    /* Network Framework cleanup */
    if (nw_socket->nw_parameters) {
        nw_release(nw_socket->nw_parameters);
        nw_socket->nw_parameters = NULL;
    }

    aws_string_destroy(nw_socket->host_name);

    aws_string_destroy(nw_socket->alpn_list);

    aws_byte_buf_clean_up(&nw_socket->protocol_buf);

    if (nw_socket->tls_ctx) {
        aws_tls_ctx_release(nw_socket->tls_ctx);
        nw_socket->tls_ctx = NULL;
    }

    aws_socket_on_shutdown_complete_fn *on_cleanup_complete = nw_socket->on_socket_cleanup_complete_fn;
    void *cleanup_user_data = nw_socket->cleanup_user_data;

    aws_mutex_clean_up(&nw_socket->synced_data.lock);
    aws_mutex_clean_up(&nw_socket->base_socket_synced_data.lock);
    aws_mem_release(nw_socket->allocator, nw_socket);

    nw_socket = NULL;

    if (on_cleanup_complete) {
        on_cleanup_complete(cleanup_user_data);
    }
}

static void s_process_socket_cancel_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct nw_socket_cancel_task_args *args = arg;
    struct nw_socket *nw_socket = args->nw_socket;

    AWS_LOGF_TRACE(AWS_LS_IO_SOCKET, "id=%p: start to process socket cancel task.", (void *)nw_socket);

    // The task should always run event when status == AWS_TASK_STATUS_CANCELLED. We rely on the task to clean up the
    // system connection/listener. And release the socket memory.

    if ((nw_socket->mode == NWSM_CONNECTION && nw_socket->os_handle.nw_connection != NULL) ||
        (nw_socket->mode == NWSM_LISTENER && nw_socket->os_handle.nw_listener != NULL)) {
        // The timeout_args only setup for connected client connections.
        if (nw_socket->mode == NWSM_CONNECTION && nw_socket->timeout_args && !nw_socket->connection_setup) {
            // if the connection setup is not set, the timeout task has not yet triggered, cancel it.
            aws_event_loop_cancel_task(nw_socket->event_loop, &nw_socket->timeout_args->task);
        }

        if (nw_socket->mode == NWSM_LISTENER) {
            nw_listener_cancel(nw_socket->os_handle.nw_listener);
            nw_release(nw_socket->os_handle.nw_listener);
            nw_socket->os_handle.nw_listener = NULL;
        } else if (nw_socket->mode == NWSM_CONNECTION) {
            nw_connection_cancel(nw_socket->os_handle.nw_connection);
            nw_release(nw_socket->os_handle.nw_connection);
            nw_socket->os_handle.nw_connection = NULL;
        }
    }

    s_socket_release_internal_ref(nw_socket);
    aws_mem_release(args->allocator, args);
}

// Cancel the socket and close the connection. The cancel should happened on the event loop.
static void s_handle_socket_canceled(void *socket_ptr) {
    struct nw_socket *nw_socket = socket_ptr;

    struct nw_socket_cancel_task_args *args =
        aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct nw_socket_cancel_task_args));

    args->allocator = nw_socket->allocator;
    args->nw_socket = nw_socket;

    /* The socket cancel should happened on the event loop if possible. The event loop will not set
     * in the case where the socket is never connected/ listener is never started accept.
     */
    if (s_validate_event_loop(nw_socket->event_loop)) {

        aws_task_init(&args->task, s_process_socket_cancel_task, args, "SocketCanceledTask");

        aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
    } else {
        s_process_socket_cancel_task(&args->task, args, AWS_TASK_STATUS_RUN_READY);
    }
}

static void s_socket_internal_destroy(void *sock_ptr) {
    struct nw_socket *nw_socket = sock_ptr;
    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p : start s_socket_internal_destroy", (void *)sock_ptr);

    if (s_validate_event_loop(nw_socket->event_loop)) {
        struct socket_close_complete_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct socket_close_complete_args));

        args->shutdown_complete_fn = nw_socket->on_socket_close_complete_fn;
        args->user_data = nw_socket->close_user_data;
        args->allocator = nw_socket->allocator;
        args->nw_socket = nw_socket;
        // At this point the internal ref count has been dropped to 0, and we are about to release the external ref
        // count.
        // However, we would still keep the external ref count alive until the s_close_complete_callback callback is
        // invoked. Acquire another external ref count to keep the socket alive. It will be released in
        // s_close_complete_callback.
        aws_ref_count_acquire(&nw_socket->nw_socket_ref_count);
        aws_task_init(&args->task, s_close_complete_callback, args, "SocketShutdownCompleteTask");

        aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
    } else {
        // If we are not on the event loop
        if (nw_socket->on_socket_close_complete_fn) {
            nw_socket->on_socket_close_complete_fn(nw_socket->close_user_data);
        }
    }
    s_release_event_loop(nw_socket);
    aws_ref_count_release(&nw_socket->nw_socket_ref_count);
}

int aws_socket_init_apple_nw_socket(
    struct aws_socket *socket,
    struct aws_allocator *alloc,
    const struct aws_socket_options *options) {
    AWS_FATAL_ASSERT(options);
    AWS_ZERO_STRUCT(*socket);

    // Network Interface is not supported with Apple Network Framework yet
    if (options->network_interface_name[0] != 0) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p fd=%d: network_interface_name is not supported on this platform.",
            (void *)socket,
            socket->io_handle.data.fd);
        return aws_raise_error(AWS_ERROR_PLATFORM_NOT_SUPPORTED);
    }

    struct nw_socket *nw_socket = aws_mem_calloc(alloc, 1, sizeof(struct nw_socket));
    nw_socket->allocator = alloc;

    socket->allocator = alloc;
    socket->options = *options;
    socket->impl = nw_socket;
    socket->vtable = &s_vtable;

    aws_mutex_init(&nw_socket->synced_data.lock);
    aws_mutex_init(&nw_socket->base_socket_synced_data.lock);
    nw_socket->base_socket_synced_data.base_socket = socket;

    nw_socket->synced_data.state = INIT;
    socket->state = INIT;

    aws_ref_count_init(&nw_socket->nw_socket_ref_count, nw_socket, s_socket_impl_destroy);
    aws_ref_count_init(&nw_socket->internal_ref_count, nw_socket, s_socket_internal_destroy);
    // The internal_ref_count should keep a reference of the nw_socket_ref_count. When the internal_ref_count
    // drop to 0, it would release the nw_socket_ref_count.
    aws_ref_count_acquire(&nw_socket->nw_socket_ref_count);
    aws_ref_count_init(&nw_socket->write_ref_count, nw_socket, s_handle_socket_canceled);

    aws_linked_list_init(&nw_socket->read_queue);

    AWS_LOGF_DEBUG(AWS_LS_IO_SOCKET, "id=%p fd=%d: socket created.", (void *)nw_socket, socket->io_handle.data.fd);

    return AWS_OP_SUCCESS;
}

static void s_client_set_dispatch_queue(struct aws_io_handle *handle, void *queue) {
    nw_connection_set_queue(handle->data.handle, queue);
}

static void s_handle_socket_timeout(struct aws_task *task, void *args, aws_task_status status) {
    (void)task;
    (void)status;

    struct nw_socket_timeout_args *timeout_args = args;
    struct nw_socket *nw_socket = timeout_args->nw_socket;

    AWS_LOGF_TRACE(AWS_LS_IO_SOCKET, "task_id=%p: timeout task triggered, evaluating timeouts.", (void *)task);

    s_lock_base_socket(nw_socket);
    struct aws_socket *socket = nw_socket->base_socket_synced_data.base_socket;
    if (!nw_socket->connection_setup && socket) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: timed out, shutting down.",
            (void *)socket,
            (void *)nw_socket->os_handle.nw_connection);

        int error_code = AWS_IO_SOCKET_TIMEOUT;

        // Must set timeout_args to NULL to avoid double cancel. Clean up the timeout task
        aws_mem_release(nw_socket->allocator, nw_socket->timeout_args);
        nw_socket->timeout_args = NULL;
        aws_socket_close(socket);
        nw_socket->on_connection_result_fn(socket, error_code, nw_socket->connect_result_user_data);
    } else {
        // If the socket is already setup (either succeed or failed), we have already invoked the callback to notify the
        // connection result. No need to invoke again. If the aws_socket is NULL (cleaned up by user), there is no
        // meaning to invoke the callback anymore. Simply release the memory in these two cases.
        aws_mem_release(nw_socket->allocator, nw_socket->timeout_args);
        nw_socket->timeout_args = NULL;
    }

    s_unlock_base_socket(nw_socket);

    s_socket_release_internal_ref(nw_socket);
    // No need to release task, as task lives on timeout_args on nw_socket.
}

static void s_process_incoming_data_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)task;
    (void)status;
    struct nw_socket_scheduled_task_args *readable_args = arg;
    struct nw_socket *nw_socket = readable_args->nw_socket;
    int crt_error = readable_args->error_code;

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: start to process read data.",
        (void *)nw_socket,
        (void *)nw_socket->os_handle.nw_connection);

    // If data is valid, push it in read_queue. The read_queue should be only accessed in event loop, as the
    // task is scheduled in event loop, it is fine to directly access it.
    if (readable_args->data) {
        // We directly store the dispatch_data returned from kernel. This could potentially be performance concern.
        // Another option is to read the data out into heap buffer and store the heap buffer in read_queue. However,
        // this would introduce extra memory copy. We would like to keep the dispatch_data_t in read_queue for now.
        struct read_queue_node *node = aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct read_queue_node));
        node->allocator = nw_socket->allocator;
        node->received_data = readable_args->data;
        aws_linked_list_push_back(&nw_socket->read_queue, &node->node);
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read data is not empty, push data to read_queue",
            (void *)nw_socket,
            (void *)nw_socket->os_handle.nw_connection);
    }

    if (status != AWS_TASK_STATUS_CANCELED) {
        s_lock_base_socket(nw_socket);
        struct aws_socket *socket = nw_socket->base_socket_synced_data.base_socket;

        // If the protocol is TCP, `is_complete` means the connection is closed, raise the
        // AWS_IO_SOCKET_CLOSED error
        if (socket && socket->options.type != AWS_SOCKET_DGRAM && readable_args->is_complete) {
            crt_error = AWS_IO_SOCKET_CLOSED;
            s_lock_socket_synced_data(nw_socket);
            s_set_socket_state(nw_socket, ~CONNECTED_READ);
            s_unlock_socket_synced_data(nw_socket);
            AWS_LOGF_TRACE(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: socket is complete, flip read flag",
                (void *)nw_socket,
                (void *)nw_socket->os_handle.nw_connection);
        }

        if (nw_socket->on_readable) {
            nw_socket->on_readable(socket, crt_error, nw_socket->on_readable_user_data);
        }
        s_unlock_base_socket(nw_socket);
    }

    s_socket_release_internal_ref(nw_socket);

    aws_mem_release(readable_args->allocator, readable_args);
}

static void s_handle_incoming_data(
    struct nw_socket *nw_socket,
    int error_code,
    dispatch_data_t data,
    bool is_complete) {

    if (s_validate_event_loop(nw_socket->event_loop)) {
        struct nw_socket_scheduled_task_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct nw_socket_scheduled_task_args));

        args->is_complete = is_complete;
        args->nw_socket = nw_socket;
        args->allocator = nw_socket->allocator;
        args->error_code = error_code;

        if (data) {
            dispatch_retain(data);
            args->data = data;
        }
        s_socket_acquire_internal_ref(nw_socket);
        aws_task_init(&args->task, s_process_incoming_data_task, args, "readableTask");

        aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
    }
}

static void s_process_connection_result_task(struct aws_task *task, void *arg, enum aws_task_status status) {
    (void)status;
    (void)task;

    struct nw_socket_scheduled_task_args *task_args = arg;
    struct nw_socket *nw_socket = task_args->nw_socket;

    AWS_LOGF_TRACE(AWS_LS_IO_SOCKET, "id=%p: start to process connection result task.", (void *)nw_socket);

    if (status != AWS_TASK_STATUS_CANCELED) {
        s_lock_base_socket(nw_socket);
        struct aws_socket *socket = nw_socket->base_socket_synced_data.base_socket;
        if (socket && nw_socket->on_connection_result_fn)
            nw_socket->on_connection_result_fn(socket, task_args->error_code, nw_socket->connect_result_user_data);
        s_unlock_base_socket(nw_socket);
    }

    s_socket_release_internal_ref(nw_socket);

    aws_mem_release(task_args->allocator, task_args);
}

static void s_handle_on_connection_result(struct nw_socket *nw_socket, int error_code) {

    if (s_validate_event_loop(nw_socket->event_loop)) {
        struct nw_socket_scheduled_task_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct nw_socket_scheduled_task_args));

        args->nw_socket = s_socket_acquire_internal_ref(nw_socket);
        args->allocator = nw_socket->allocator;
        args->error_code = error_code;

        aws_task_init(&args->task, s_process_connection_result_task, args, "connectionSuccessTask");
        aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
    }
}

struct connection_state_change_args {
    struct aws_task task;
    struct aws_allocator *allocator;
    struct nw_socket *nw_socket;
    nw_connection_t nw_connection;
    nw_connection_state_t state;
    int error;
};

static void s_process_connection_state_changed_ready(struct nw_socket *nw_socket, nw_connection_t nw_connection) {
    s_lock_base_socket(nw_socket);
    struct aws_socket *socket = nw_socket->base_socket_synced_data.base_socket;
    if (socket) {
        nw_path_t path = nw_connection_copy_current_path(nw_connection);
        nw_endpoint_t local_endpoint = nw_path_copy_effective_local_endpoint(path);
        nw_release(path);
        const char *hostname = nw_endpoint_get_hostname(local_endpoint);
        uint16_t port = nw_endpoint_get_port(local_endpoint);
        nw_release(local_endpoint);

        if (hostname != NULL) {
            size_t hostname_len = strlen(hostname);
            size_t buffer_size = AWS_ARRAY_SIZE(socket->local_endpoint.address);
            size_t to_copy = aws_min_size(hostname_len, buffer_size);
            memcpy(socket->local_endpoint.address, hostname, to_copy);
            socket->local_endpoint.port = port;
        }

        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: set local endpoint %s:%d",
            (void *)socket,
            socket->io_handle.data.handle,
            socket->local_endpoint.address,
            port);

        /* Check and store protocol for connection */
        if (nw_socket->tls_ctx) {
            nw_protocol_metadata_t metadata =
                nw_connection_copy_protocol_metadata(socket->io_handle.data.handle, nw_protocol_copy_tls_definition());
            if (metadata != NULL) {
                sec_protocol_metadata_t sec_metadata = (sec_protocol_metadata_t)metadata;

                const char *negotiated_protocol = sec_protocol_metadata_get_negotiated_protocol(sec_metadata);
                if (negotiated_protocol) {
                    nw_socket->protocol_buf = aws_byte_buf_from_c_str(negotiated_protocol);
                    AWS_LOGF_DEBUG(
                        AWS_LS_IO_TLS,
                        "id=%p handle=%p: ALPN protocol set to: '%s'",
                        (void *)socket,
                        socket->io_handle.data.handle,
                        nw_socket->protocol_buf.buffer);
                }
                nw_release(metadata);
            }
        }
    } else {
        /*
         * This happens when the aws_socket_clean_up() is called before the nw_connection_state_ready is
         * returned. We still want to set the socket to write/read state and fire the connection succeed
         * callback until we get the "nw_connection_state_cancelled" status.
         */
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: connection succeed, however, the base socket has been cleaned up.",
            (void *)nw_socket,
            (void *)nw_socket->os_handle.nw_connection);
    }
    s_lock_socket_synced_data(nw_socket);
    s_set_socket_state(nw_socket, socket, CONNECTED_WRITE | CONNECTED_READ);
    s_unlock_socket_synced_data(nw_socket);
    s_unlock_base_socket(nw_socket);

    nw_socket->connection_setup = true;
    // Cancel the connection timeout task
    if (nw_socket->timeout_args) {
        aws_event_loop_cancel_task(nw_socket->event_loop, &nw_socket->timeout_args->task);
    }
    aws_ref_count_acquire(&nw_socket->nw_socket_ref_count);
    s_handle_on_connection_result(nw_socket, AWS_OP_SUCCESS);
    aws_ref_count_release(&nw_socket->nw_socket_ref_count);
}

static void s_process_connection_state_changed_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)status;
    (void)task;

    struct connection_state_change_args *connection_args = args;

    struct nw_socket *nw_socket = connection_args->nw_socket;
    nw_connection_t nw_connection = connection_args->nw_connection;
    nw_connection_state_t state = connection_args->state;

    /* Ideally we should not have a canceled task here, as nw_socket keeps a reference to event loop, therefore the
     * event loop should never be destroyed before the nw_socket get destroyed. If we manually cancel the task, we
     * should make sure we carefully handled the state change eventually, as the socket relies on this task to release
     * and cleanup.
     */
    if (status != AWS_TASK_STATUS_CANCELED) {
        switch (state) {
            case nw_connection_state_cancelled: {
                AWS_LOGF_INFO(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: Apple network framework socket connection state changed to cancelled, nw error "
                    "code : %d",
                    (void *)nw_socket,
                    (void *)nw_socket->os_handle.nw_connection,
                    connection_args->error);
                s_lock_base_socket(nw_socket);
                struct aws_socket *socket = nw_socket->base_socket_synced_data.base_socket;
                s_unlock_base_socket(nw_socket);

                s_lock_socket_synced_data(nw_socket);
                s_set_socket_state(nw_socket, socket, CLOSED);
                s_unlock_socket_synced_data(nw_socket);

                s_socket_release_internal_ref(nw_socket);
            } break;
            case nw_connection_state_ready: {
                AWS_LOGF_INFO(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: Apple network framework socket connection state changed to ready, nw error "
                    "code : %d",
                    (void *)nw_socket,
                    (void *)nw_socket->os_handle.nw_connection,
                    connection_args->error);
                s_process_connection_state_changed_ready(nw_socket, nw_connection);
            } break;
            case nw_connection_state_waiting:
            case nw_connection_state_preparing:
            case nw_connection_state_failed:
            default:
                break;
        }

        int crt_error_code = connection_args->error;
        if (crt_error_code) {
            /* any error, including if closed remotely in error */
            AWS_LOGF_DEBUG(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: socket connection got error: %d",
                (void *)nw_socket,
                (void *)nw_socket->os_handle.nw_connection,
                crt_error_code);

            nw_socket->last_error = crt_error_code;
            s_lock_socket_synced_data(nw_socket);
            s_set_socket_state(nw_socket, ERROR);
            s_unlock_socket_synced_data(nw_socket);

            if (!nw_socket->connection_setup) {
                s_handle_on_connection_result(nw_socket, crt_error_code);
                nw_socket->connection_setup = true;
                // Cancel the connection timeout task
                if (nw_socket->timeout_args) {
                    aws_event_loop_cancel_task(nw_socket->event_loop, &nw_socket->timeout_args->task);
                }
            } else {
                s_handle_incoming_data(nw_socket, nw_socket->last_error, NULL, false);
            }
        }
    }

    s_socket_release_internal_ref(nw_socket);
    aws_mem_release(connection_args->allocator, connection_args);
}

static void s_handle_connection_state_changed_fn(
    struct nw_socket *nw_socket,
    nw_connection_t nw_connection,
    nw_connection_state_t state,
    nw_error_t error) {

    AWS_LOGF_TRACE(AWS_LS_IO_SOCKET, "id=%p: s_handle_connection_state_changed_fn start...", (void *)nw_socket);

    int crt_error_code = s_convert_nw_error(error);
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: nw_connection_set_state_changed_handler invoked with nw_error_code %d, maps to CRT "
        "error code %d",
        (void *)nw_socket,
        (void *)nw_socket->os_handle.nw_connection,
        nw_error_get_error_code(error),
        crt_error_code);

    if (s_validate_event_loop(nw_socket->event_loop)) {
        struct connection_state_change_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct connection_state_change_args));

        args->nw_socket = nw_socket;
        args->allocator = nw_socket->allocator;
        args->error = crt_error_code;
        args->state = state;
        args->nw_connection = nw_connection;

        s_socket_acquire_internal_ref(nw_socket);

        aws_task_init(&args->task, s_process_connection_state_changed_task, args, "ConnectionStateChangedTask");

        aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);

    } else if (state == nw_connection_state_cancelled) {
        s_socket_release_internal_ref(nw_socket);
    }
}

static void s_process_listener_success_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)task;
    struct nw_listener_connection_args *task_args = args;
    struct aws_allocator *allocator = task_args->allocator;
    struct nw_socket *listener_nw_socket = task_args->nw_socket;
    int error = task_args->error_code;

    AWS_FATAL_ASSERT(listener_nw_socket && listener_nw_socket->mode == NWSM_LISTENER);

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: start to process incoming connection.",
        (void *)listener_nw_socket,
        (void *)listener_nw_socket->os_handle.nw_listener);

    if (status == AWS_TASK_STATUS_RUN_READY) {
        s_lock_base_socket(listener_nw_socket);
        struct aws_socket *listener = listener_nw_socket->base_socket_synced_data.base_socket;
        AWS_FATAL_ASSERT(listener && listener->accept_result_fn);
        struct aws_socket *new_socket = NULL;

        if (error) {
            goto incoming_listener_error_cleanup;
        }

        new_socket = aws_mem_calloc(allocator, 1, sizeof(struct aws_socket));
        struct aws_socket_options options = listener->options;
        error = aws_socket_init(new_socket, allocator, &options);
        if (error) {
            goto incoming_listener_error_cleanup;
        }

        nw_endpoint_t endpoint = nw_connection_copy_endpoint(task_args->new_connection);
        const char *hostname = nw_endpoint_get_hostname(endpoint);
        uint16_t port = nw_endpoint_get_port(endpoint);

        if (hostname != NULL) {
            size_t address_strlen;
            if (aws_secure_strlen(hostname, AWS_ADDRESS_MAX_LEN, &address_strlen)) {
                nw_release(endpoint);
                goto incoming_listener_error_cleanup;
            }
            memcpy(new_socket->remote_endpoint.address, hostname, address_strlen);
            new_socket->remote_endpoint.port = port;
        }
        nw_release(endpoint);

        new_socket->io_handle.data.handle = task_args->new_connection;
        new_socket->io_handle.set_queue = s_client_set_dispatch_queue;

        struct nw_socket *new_nw_socket = new_socket->impl;
        new_nw_socket->os_handle.nw_connection = task_args->new_connection;
        new_nw_socket->connection_setup = true;

        // Setup socket state to start read/write operations. We didn't lock here as we are in initializing process, no
        // other process will touch the socket state.
        s_set_socket_state(new_nw_socket, CONNECTED_READ | CONNECTED_WRITE);

        // this internal ref will be released when the connection canceled ( connection state changed to
        // nw_connection_state_cancelled)
        s_socket_acquire_internal_ref(new_nw_socket);

        nw_connection_set_state_changed_handler(
            new_socket->io_handle.data.handle, ^(nw_connection_state_t state, nw_error_t error) {
              s_handle_connection_state_changed_fn(
                new_nw_socket, new_nw_socket->os_handle.nw_connection, state, error);
            });

        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: incoming connection has been successfully connected to %s:%d, the incoming "
            "handle is %p",
            (void *)listener,
            listener->io_handle.data.handle,
            new_socket->remote_endpoint.address,
            new_socket->remote_endpoint.port,
            new_socket->io_handle.data.handle);

        goto incoming_listener_finalize;

    incoming_listener_error_cleanup:
        if (new_socket) {
            aws_socket_clean_up(new_socket);
            aws_mem_release(allocator, new_socket);
            new_socket = NULL;
        }
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to setup new socket for incoming connection with error code %d.",
            (void *)listener,
            listener->io_handle.data.handle,
            error);
        nw_release(task_args->new_connection);

    incoming_listener_finalize:
        listener->accept_result_fn(listener, error, new_socket, task_args->user_data);

        s_unlock_base_socket(listener_nw_socket);

    } else {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: process incoming listener task canceled .",
            (void *)listener_nw_socket,
            (void *)listener_nw_socket->os_handle.nw_listener);
        // If the task is not scheduled, release the connection.
        nw_release(task_args->new_connection);
    }

    s_socket_release_internal_ref(listener_nw_socket);
    aws_mem_release(task_args->allocator, task_args);
}

static void s_handle_on_listener_success(
    struct nw_socket *nw_socket,
    int error_code,
    nw_connection_t new_connection,
    void *user_data) {

    if (s_validate_event_loop(nw_socket->event_loop)) {

        struct nw_listener_connection_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct nw_listener_connection_args));

        args->nw_socket = nw_socket;
        args->allocator = nw_socket->allocator;
        args->error_code = error_code;
        args->new_connection = new_connection;
        args->user_data = user_data;

        s_socket_acquire_internal_ref(nw_socket);
        nw_retain(new_connection);

        aws_task_init(&args->task, s_process_listener_success_task, args, "listenerSuccessTask");
        aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
    }
}

static void s_process_write_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)task;
    struct nw_socket_written_args *task_args = args;
    struct aws_allocator *allocator = task_args->allocator;
    struct nw_socket *nw_socket = task_args->nw_socket;

    AWS_LOGF_TRACE(AWS_LS_IO_SOCKET, "id=%p: start to process write task.", (void *)nw_socket);

    if (status != AWS_TASK_STATUS_CANCELED) {
        s_lock_base_socket(nw_socket);
        struct aws_socket *socket = nw_socket->base_socket_synced_data.base_socket;
        if (task_args->written_fn) {
            task_args->written_fn(socket, task_args->error_code, task_args->bytes_written, task_args->user_data);
        }
        s_unlock_base_socket(nw_socket);
    }

    s_socket_release_internal_ref(nw_socket);

    aws_mem_release(allocator, task_args);
}

static void s_handle_write_fn(
    struct nw_socket *nw_socket,
    int error_code,
    size_t bytes_written,
    void *user_data,
    aws_socket_on_write_completed_fn *written_fn) {
    AWS_FATAL_ASSERT(s_validate_event_loop(nw_socket->event_loop));

    struct nw_socket_written_args *args =
        aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct nw_socket_written_args));

    args->nw_socket = nw_socket;
    args->allocator = nw_socket->allocator;
    args->error_code = error_code;
    args->written_fn = written_fn;
    args->user_data = user_data;
    args->bytes_written = bytes_written;
    s_socket_acquire_internal_ref(nw_socket);

    aws_task_init(&args->task, s_process_write_task, args, "writtenTask");

    aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
}

/*
 * Because TLS negotiation is handled by Apple Network Framework connection using its parameters, we need access to a
 * number of items typically not needed until the TLS slot and handler are being initialized. This function along with
 * aws_socket_retrieve_tls_options_fn() are used to gain access to those items.
 */
static int s_setup_tls_options_from_context(
    struct nw_socket *nw_socket,
    struct aws_tls_connection_context *tls_connection_context) {

    if (nw_socket->tls_ctx != NULL || nw_socket->host_name != NULL || nw_socket->alpn_list != NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET, "id=%p: Socket cannot have TLS options set more than once.", (void *)nw_socket);
        return AWS_OP_ERR;
    }

    /* The host name is needed during the setup of the verification block */
    if (tls_connection_context->host_name != NULL) {
        nw_socket->host_name =
            aws_string_new_from_string(tls_connection_context->host_name->allocator, tls_connection_context->host_name);
        if (nw_socket->host_name == NULL) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p: Error encounterd during setup of host name from tls context.",
                (void *)nw_socket);
            return AWS_OP_ERR;
        }
    }

    /* The tls_ctx is needed to setup TLS negotiation options in the Apple Network Framework connection's parameters */
    if (tls_connection_context->tls_ctx != NULL) {
        nw_socket->tls_ctx = tls_connection_context->tls_ctx;
        aws_tls_ctx_acquire(nw_socket->tls_ctx);

        /* TLS negotiation needs the alpn list if one is present for use. */
        struct aws_string *alpn_list = NULL;
        struct secure_transport_ctx *transport_ctx = tls_connection_context->tls_ctx->impl;
        if (tls_connection_context->alpn_list != NULL) {
            alpn_list = tls_connection_context->alpn_list;
        } else if (transport_ctx->alpn_list != NULL) {
            alpn_list = transport_ctx->alpn_list;
        }

        if (alpn_list != NULL) {
            nw_socket->alpn_list = aws_string_new_from_string(alpn_list->allocator, alpn_list);
            if (nw_socket->alpn_list == NULL) {
                AWS_LOGF_ERROR(
                    AWS_LS_IO_SOCKET,
                    "id=%p: Error encounterd during setup of alpn list from tls context.",
                    (void *)nw_socket);
                return AWS_OP_ERR;
            }
        }
    }

    return AWS_OP_SUCCESS;
}

static int s_socket_connect_fn(
    struct aws_socket *socket,
    struct aws_socket_connect_options *socket_connect_options,
    void *user_data) {
    struct nw_socket *nw_socket = socket->impl;

    const struct aws_socket_endpoint *remote_endpoint = socket_connect_options->remote_endpoint;
    struct aws_event_loop *event_loop = socket_connect_options->event_loop;
    aws_socket_on_connection_result_fn *on_connection_result = socket_connect_options->on_connection_result;
    aws_socket_retrieve_tls_options_fn *retrieve_tls_options = socket_connect_options->retrieve_tls_options;

    AWS_ASSERT(event_loop);
    AWS_FATAL_ASSERT(on_connection_result);

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET, "id=%p handle=%p: beginning connect.", (void *)socket, socket->io_handle.data.handle);

    if (socket->event_loop) {
        return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
    }

    if (retrieve_tls_options != NULL) {
        struct aws_tls_connection_context tls_connection_context;
        AWS_ZERO_STRUCT(tls_connection_context);
        retrieve_tls_options(&tls_connection_context, user_data);

        if (s_setup_tls_options_from_context(nw_socket, &tls_connection_context)) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET, "id=%p: Error encounterd during setup of tls options from context.", (void *)socket);
            return AWS_OP_ERR;
        }
    }

    /* event_loop must be set prior to setup of socket parameters. */
    s_set_event_loop(socket, event_loop);
    if (s_setup_socket_params(nw_socket, &socket->options)) {
        goto error;
    }

    s_lock_socket_synced_data(nw_socket);
    if (nw_socket->synced_data.state != INIT) {
        s_unlock_socket_synced_data(nw_socket);
        aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
        goto error;
    }

    /* fill in posix sock addr, and then let Network framework sort it out. */
    size_t address_strlen;
    if (aws_secure_strlen(remote_endpoint->address, AWS_ADDRESS_MAX_LEN, &address_strlen)) {
        s_unlock_socket_synced_data(nw_socket);
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to parse address %s:%d.",
            (void *)socket,
            socket->io_handle.data.handle,
            remote_endpoint->address,
            (int)remote_endpoint->port);
        aws_raise_error(AWS_IO_SOCKET_INVALID_ADDRESS);
        goto error;
    }

    struct socket_address address;
    AWS_ZERO_STRUCT(address);
    int pton_err = 1;

    switch (socket->options.domain) {
        case AWS_SOCKET_IPV4: {
            pton_err = inet_pton(AF_INET, remote_endpoint->address, &address.sock_addr_types.addr_in.sin_addr);
            address.sock_addr_types.addr_in.sin_port = htons((uint16_t)remote_endpoint->port);
            address.sock_addr_types.addr_in.sin_family = AF_INET;
            address.sock_addr_types.addr_in.sin_len = sizeof(struct sockaddr_in);
            break;
        }
        case AWS_SOCKET_IPV6: {
            pton_err = inet_pton(AF_INET6, remote_endpoint->address, &address.sock_addr_types.addr_in6.sin6_addr);
            address.sock_addr_types.addr_in6.sin6_port = htons((uint16_t)remote_endpoint->port);
            address.sock_addr_types.addr_in6.sin6_family = AF_INET6;
            address.sock_addr_types.addr_in6.sin6_len = sizeof(struct sockaddr_in6);
            break;
        }
        case AWS_SOCKET_LOCAL: {
            address.sock_addr_types.un_addr.sun_family = AF_UNIX;
            strncpy(address.sock_addr_types.un_addr.sun_path, remote_endpoint->address, AWS_ADDRESS_MAX_LEN);
            address.sock_addr_types.un_addr.sun_len = sizeof(struct sockaddr_un);
            break;
        }
        default: {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: socket tried to bind to an unknow domain.",
                (void *)socket,
                socket->io_handle.data.handle);
            s_unlock_socket_synced_data(nw_socket);
            aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);

            goto error;
        }
    }

    if (pton_err != 1) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to parse address %s:%d.",
            (void *)socket,
            socket->io_handle.data.handle,
            remote_endpoint->address,
            (int)remote_endpoint->port);
        s_unlock_socket_synced_data(nw_socket);
        aws_raise_error(s_convert_pton_error(pton_err));
        goto error;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: connecting to endpoint %s:%d.",
        (void *)socket,
        socket->io_handle.data.handle,
        remote_endpoint->address,
        (int)remote_endpoint->port);

    nw_endpoint_t endpoint = nw_endpoint_create_address(&address.sock_addr_types.addr_base);

    if (!endpoint) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to create remote address %s:%d.",
            (void *)socket,
            socket->io_handle.data.handle,
            remote_endpoint->address,
            (int)remote_endpoint->port);
        s_unlock_socket_synced_data(nw_socket);
        aws_raise_error(AWS_IO_SOCKET_INVALID_ADDRESS);
        goto error;
    }

    socket->io_handle.data.handle = nw_connection_create(endpoint, nw_socket->nw_parameters);
    nw_release(endpoint);

    if (!socket->io_handle.data.handle) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: connection creation failed, please verify the socket options are setup properly.",
            (void *)socket,
            socket->io_handle.data.handle);
        s_unlock_socket_synced_data(nw_socket);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto error;
    }

    socket->remote_endpoint = *remote_endpoint;
    nw_socket->os_handle.nw_connection = socket->io_handle.data.handle;

    socket->io_handle.set_queue = s_client_set_dispatch_queue;
    aws_event_loop_connect_handle_to_io_completion_port(event_loop, &socket->io_handle);

    nw_socket->on_connection_result_fn = on_connection_result;
    nw_socket->connect_result_user_data = user_data;

    nw_socket->timeout_args = aws_mem_calloc(socket->allocator, 1, sizeof(struct nw_socket_timeout_args));

    nw_socket->timeout_args->nw_socket = nw_socket;
    nw_socket->timeout_args->allocator = socket->allocator;

    aws_task_init(
        &nw_socket->timeout_args->task,
        s_handle_socket_timeout,
        nw_socket->timeout_args,
        "NWSocketConnectionTimeoutTask");

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
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: scheduling timeout task for %llu.",
        (void *)socket,
        socket->io_handle.data.handle,
        (unsigned long long)timeout);
    nw_socket->timeout_args->task.timestamp = timeout;
    // Acquire a nw_socket for the timeout task
    s_socket_acquire_internal_ref(nw_socket);

    // The timeout task must schedule before we start the system connection. We will release the timeout args when
    // we finished a connection. If we start the system connection first, then it is possible that the connection
    // finished before timeout task scheduled, and the timeout args is already released by the time we schedule it.
    aws_event_loop_schedule_task_future(event_loop, &nw_socket->timeout_args->task, timeout);

    /* set a handler for socket state changes. This is where we find out if the connection timed out, was
     * successful, was disconnected etc .... */
    nw_connection_set_state_changed_handler(
        socket->io_handle.data.handle, ^(nw_connection_state_t state, nw_error_t error) {
          s_handle_connection_state_changed_fn(nw_socket, nw_socket->os_handle.nw_connection, state, error);
        });

    s_set_socket_state(nw_socket, CONNECTING);

    socket->connect_accept_user_data = user_data;
    socket->connection_result_fn = on_connection_result;

    // released when the connection state changed to nw_connection_state_cancelled
    s_socket_acquire_internal_ref(nw_socket);
    nw_retain(socket->io_handle.data.handle);
    nw_connection_start(socket->io_handle.data.handle);
    s_unlock_socket_synced_data(nw_socket);

    return AWS_OP_SUCCESS;

error:
    s_release_event_loop(nw_socket);
    return AWS_OP_ERR;
}

static int s_socket_bind_fn(
    struct aws_socket *socket,
    struct aws_socket_bind_options *socket_bind_options,
    void *user_data) {
    struct nw_socket *nw_socket = socket->impl;

    const struct aws_socket_endpoint *local_endpoint = socket_bind_options->local_endpoint;
    aws_socket_retrieve_tls_options_fn *retrieve_tls_options = socket_bind_options->retrieve_tls_options;

    s_lock_socket_synced_data(nw_socket);
    if (nw_socket->synced_data.state != INIT) {
        AWS_LOGF_ERROR(AWS_LS_IO_SOCKET, "id=%p: invalid state for bind operation.", (void *)socket);
        s_unlock_socket_synced_data(nw_socket);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    socket->local_endpoint = *local_endpoint;
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p: binding to %s:%d.",
        (void *)socket,
        local_endpoint->address,
        (int)local_endpoint->port);

    if (nw_socket->nw_parameters == NULL) {

        if (retrieve_tls_options) {
            struct aws_tls_connection_context tls_connection_context;
            AWS_ZERO_STRUCT(tls_connection_context);
            retrieve_tls_options(&tls_connection_context, user_data);

            if (s_setup_tls_options_from_context(nw_socket, &tls_connection_context)) {
                AWS_LOGF_ERROR(
                    AWS_LS_IO_SOCKET,
                    "id=%p: Error encounterd during setup of tls options from context.",
                    (void *)socket);
                return AWS_OP_ERR;
            }
            nw_socket->event_loop = tls_connection_context.event_loop;
        }
        s_setup_socket_params(nw_socket, &socket->options);
        /* Because a refcount wasn't acquired, we NULL the event_loop right after its use in creating socket params. */
        nw_socket->event_loop = NULL;
    }

    struct socket_address address;
    AWS_ZERO_STRUCT(address);
    int pton_err = 1;
    switch (socket->options.domain) {
        case AWS_SOCKET_IPV4: {
            pton_err = inet_pton(AF_INET, local_endpoint->address, &address.sock_addr_types.addr_in.sin_addr);
            address.sock_addr_types.addr_in.sin_port = htons((uint16_t)local_endpoint->port);
            address.sock_addr_types.addr_in.sin_family = AF_INET;
            address.sock_addr_types.addr_in.sin_len = sizeof(struct sockaddr_in);
            break;
        }
        case AWS_SOCKET_IPV6: {
            pton_err = inet_pton(AF_INET6, local_endpoint->address, &address.sock_addr_types.addr_in6.sin6_addr);
            address.sock_addr_types.addr_in6.sin6_port = htons((uint16_t)local_endpoint->port);
            address.sock_addr_types.addr_in6.sin6_family = AF_INET6;
            address.sock_addr_types.addr_in6.sin6_len = sizeof(struct sockaddr_in6);
            break;
        }
        case AWS_SOCKET_LOCAL: {
            address.sock_addr_types.un_addr.sun_family = AF_UNIX;
            address.sock_addr_types.un_addr.sun_len = sizeof(struct sockaddr_un);

            strncpy(address.sock_addr_types.un_addr.sun_path, local_endpoint->address, AWS_ADDRESS_MAX_LEN);
            break;
        }
        default: {
            s_unlock_socket_synced_data(nw_socket);
            return aws_raise_error(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY);
        }
    }

    if (pton_err != 1) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p: failed to parse address %s:%d.",
            (void *)socket,
            local_endpoint->address,
            (int)local_endpoint->port);
        s_unlock_socket_synced_data(nw_socket);
        return aws_raise_error(s_convert_pton_error(pton_err));
    }

    nw_endpoint_t endpoint = nw_endpoint_create_address(&address.sock_addr_types.addr_base);

    if (!endpoint) {
        s_unlock_socket_synced_data(nw_socket);
        return aws_raise_error(AWS_IO_SOCKET_INVALID_ADDRESS);
    }

    nw_parameters_set_local_endpoint(nw_socket->nw_parameters, endpoint);
    nw_release(endpoint);

    // Apple network framework requires connection besides bind.
    s_set_socket_state(nw_socket, BOUND);
    s_unlock_socket_synced_data(nw_socket);

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p fd=%d: successfully bound to %s:%u",
        (void *)socket,
        socket->io_handle.data.fd,
        socket->local_endpoint.address,
        socket->local_endpoint.port);

    return AWS_OP_SUCCESS;
}

static void s_listener_set_dispatch_queue(struct aws_io_handle *handle, void *queue) {
    nw_listener_set_queue(handle->data.handle, queue);
}

static int s_socket_listen_fn(struct aws_socket *socket, int backlog_size) {
    (void)backlog_size;

    struct nw_socket *nw_socket = socket->impl;

    s_lock_socket_synced_data(nw_socket);
    if (nw_socket->synced_data.state != BOUND) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET, "id=%p: invalid state for listen operation. You must call bind first.", (void *)socket);
        aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
        goto done;
    }

    if (nw_socket->nw_parameters == NULL) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p: socket nw_parameters needs to be set before creating a listener from socket.",
            (void *)socket);
        aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
        goto done;
    }

    socket->io_handle.data.handle = nw_listener_create(nw_socket->nw_parameters);
    if (!socket->io_handle.data.handle) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p:  listener creation failed, please verify the socket options are setup properly.",
            (void *)socket);
        aws_raise_error(AWS_ERROR_INVALID_ARGUMENT);
        goto done;
    }

    socket->io_handle.set_queue = s_listener_set_dispatch_queue;
    nw_socket->os_handle.nw_listener = socket->io_handle.data.handle;
    nw_retain(socket->io_handle.data.handle);
    nw_socket->mode = NWSM_LISTENER;

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: nw_socket successfully listening",
        (void *)socket,
        socket->io_handle.data.handle);

    s_set_socket_state(nw_socket, LISTENING);
    s_unlock_socket_synced_data(nw_socket);
    return AWS_OP_SUCCESS;

done:
    s_unlock_socket_synced_data(nw_socket);
    return AWS_OP_ERR;
}

struct listener_state_changed_args {
    struct aws_task task;
    struct aws_allocator *allocator;
    struct nw_socket *nw_socket;
    nw_listener_state_t state;
    int error;
};

static void s_process_listener_state_changed_task(struct aws_task *task, void *args, enum aws_task_status status) {
    (void)status;
    (void)task;

    struct listener_state_changed_args *listener_state_changed_args = args;

    struct nw_socket *nw_socket = listener_state_changed_args->nw_socket;
    nw_listener_t nw_listener = nw_socket->os_handle.nw_listener;
    nw_listener_state_t state = listener_state_changed_args->state;
    int crt_error_code = listener_state_changed_args->error;

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: start to process listener state change task.",
        (void *)nw_socket,
        (void *)nw_listener);

    /* Ideally we should not have a task with AWS_TASK_STATUS_CANCELED here, as the event loop should never be destroyed
     * before the nw_socket get destroyed. If we manually cancel the task, we should make sure we carefully handled the
     * state change eventually, as the socket relies on this task to release and cleanup.
     */
    if (status != AWS_TASK_STATUS_CANCELED) {

        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: listener state changed to %d ",
            (void *)nw_socket,
            (void *)nw_listener,
            state);

        switch (state) {
            case nw_listener_state_failed: {
                AWS_LOGF_DEBUG(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: listener failed with error %d",
                    (void *)nw_socket,
                    (void *)nw_listener,
                    crt_error_code);

                s_lock_base_socket(nw_socket);
                struct aws_socket *aws_socket = nw_socket->base_socket_synced_data.base_socket;
                s_lock_socket_synced_data(nw_socket);
                s_set_socket_state(nw_socket, ERROR);
                s_unlock_socket_synced_data(nw_socket);
                if (nw_socket->on_accept_started_fn) {
                    nw_socket->on_accept_started_fn(
                        aws_socket, crt_error_code, nw_socket->listen_accept_started_user_data);
                }
                s_unlock_base_socket(nw_socket);
                break;
            }
            case nw_listener_state_ready: {
                s_lock_base_socket(nw_socket);
                struct aws_socket *aws_socket = nw_socket->base_socket_synced_data.base_socket;
                if (aws_socket) {
                    AWS_FATAL_ASSERT(nw_socket->mode == NWSM_LISTENER);
                    aws_socket->local_endpoint.port = nw_listener_get_port(nw_socket->os_handle.nw_listener);
                    if (nw_socket->on_accept_started_fn) {
                        nw_socket->on_accept_started_fn(
                            aws_socket, AWS_OP_SUCCESS, nw_socket->listen_accept_started_user_data);
                    }
                    AWS_LOGF_DEBUG(
                        AWS_LS_IO_SOCKET,
                        "id=%p handle=%p: listener on port %d ready ",
                        (void *)nw_socket,
                        (void *)nw_listener,
                        aws_socket->local_endpoint.port);
                }

                s_unlock_base_socket(nw_socket);
                break;
            }
            case nw_listener_state_cancelled: {
                AWS_LOGF_DEBUG(
                    AWS_LS_IO_SOCKET, "id=%p handle=%p: listener cancelled.", (void *)nw_socket, (void *)nw_listener);
                s_lock_socket_synced_data(nw_socket);
                s_set_socket_state(nw_socket, CLOSED);
                s_unlock_socket_synced_data(nw_socket);
                s_socket_release_internal_ref(nw_socket);
                break;
            }
            default:
                break;
        }
    }

    // Release the internal ref for the task
    s_socket_release_internal_ref(nw_socket);
    aws_mem_release(listener_state_changed_args->allocator, listener_state_changed_args);
}

static void s_handle_listener_state_changed_fn(
    struct nw_socket *nw_socket,
    nw_listener_state_t state,
    nw_error_t error) {

    AWS_LOGF_TRACE(AWS_LS_IO_SOCKET, "id=%p: s_handle_listener_state_changed_fn start...", (void *)nw_socket);

    int crt_error_code = s_convert_nw_error(error);
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: nw_listener_set_state_changed_handler invoked with nw_error_code %d, maps to CRT "
        "error code %d",
        (void *)nw_socket,
        (void *)nw_socket->os_handle.nw_connection,
        nw_error_get_error_code(error),
        crt_error_code);

    if (s_validate_event_loop(nw_socket->event_loop)) {
        struct listener_state_changed_args *args =
            aws_mem_calloc(nw_socket->allocator, 1, sizeof(struct listener_state_changed_args));

        args->nw_socket = nw_socket;
        args->allocator = nw_socket->allocator;
        args->error = crt_error_code;
        args->state = state;

        s_socket_acquire_internal_ref(nw_socket);
        aws_task_init(&args->task, s_process_listener_state_changed_task, args, "ListenerStateChangedTask");
        aws_event_loop_schedule_task_now(nw_socket->event_loop, &args->task);
    } else {
        AWS_FATAL_ASSERT(false && "The nw_socket should be always attached to a valid event loop.");
    }
}

static int s_socket_start_accept_fn(
    struct aws_socket *socket,
    struct aws_event_loop *accept_loop,
    struct aws_socket_listener_options options) {
    AWS_FATAL_ASSERT(options.on_accept_result);
    AWS_FATAL_ASSERT(accept_loop);

    struct nw_socket *nw_socket = socket->impl;
    s_lock_socket_synced_data(nw_socket);
    if (nw_socket->synced_data.state != LISTENING) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: invalid state for start_accept operation. You must call listen first.",
            (void *)socket,
            socket->io_handle.data.handle);
        s_unlock_socket_synced_data(nw_socket);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    if (socket->event_loop) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: is already assigned to event-loop %p.",
            (void *)socket,
            socket->io_handle.data.handle,
            (void *)socket->event_loop);
        s_unlock_socket_synced_data(nw_socket);
        return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
    }

    aws_event_loop_connect_handle_to_io_completion_port(accept_loop, &socket->io_handle);
    socket->accept_result_fn = options.on_accept_result;
    socket->connect_accept_user_data = options.on_accept_result_user_data;

    nw_socket->on_accept_started_fn = options.on_accept_start;
    nw_socket->listen_accept_started_user_data = options.on_accept_start_user_data;

    s_set_event_loop(socket, accept_loop);

    nw_listener_set_state_changed_handler(
        socket->io_handle.data.handle, ^(nw_listener_state_t state, nw_error_t error) {
          s_handle_listener_state_changed_fn(nw_socket, state, error);
        });

    nw_listener_set_new_connection_handler(socket->io_handle.data.handle, ^(nw_connection_t connection) {
      s_handle_on_listener_success(nw_socket, AWS_OP_SUCCESS, connection, socket->connect_accept_user_data);
    });
    // this ref should be released in nw_listener_set_state_changed_handler where get state ==
    // nw_listener_state_cancelled
    s_socket_acquire_internal_ref(nw_socket);
    nw_listener_start(socket->io_handle.data.handle);
    s_unlock_socket_synced_data(nw_socket);
    return AWS_OP_SUCCESS;
}

static int s_socket_stop_accept_fn(struct aws_socket *socket) {
    struct nw_socket *nw_socket = socket->impl;
    s_lock_socket_synced_data(nw_socket);
    if (nw_socket->synced_data.state != LISTENING) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: is not in a listening state, can't stop_accept.",
            (void *)socket,
            socket->io_handle.data.handle);
        s_unlock_socket_synced_data(nw_socket);
        return aws_raise_error(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE);
    }

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: stopping accepting new connections",
        (void *)socket,
        socket->io_handle.data.handle);

    nw_listener_cancel(socket->io_handle.data.handle);

    s_set_socket_state(nw_socket, STOPPED);
    s_unlock_socket_synced_data(nw_socket);

    return AWS_OP_SUCCESS;
}

// Close should always be run on event loop
static int s_socket_close_fn(struct aws_socket *socket) {

    struct nw_socket *nw_socket = socket->impl;
    s_lock_socket_synced_data(nw_socket);

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: socket is closing with current state %d",
        (void *)socket,
        socket->io_handle.data.handle,
        socket->state);

    if (nw_socket->synced_data.state < CLOSING) {
        // We would like to keep CONNECTED_READ so that we could continue processing any received data until the we
        // got the system callback indicates that the system connection has been closed in the receiving direction.
        s_set_socket_state(nw_socket, nw_socket->base_socket_synced_data.base_socket, CLOSING | CONNECTED_READ);
        s_socket_release_write_ref(nw_socket);
    }
    s_unlock_socket_synced_data(nw_socket);
    return AWS_OP_SUCCESS;
}

static int s_socket_shutdown_dir_fn(struct aws_socket *socket, enum aws_channel_direction dir) {
    (void)dir;
    AWS_ASSERT(false);
    AWS_LOGF_ERROR(
        AWS_LS_IO_SOCKET, "id=%p: shutdown by direction is not support for Apple network framework.", (void *)socket);
    return aws_raise_error(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE);
}

static int s_socket_set_options_fn(struct aws_socket *socket, const struct aws_socket_options *options) {
    if (socket->options.domain != options->domain || socket->options.type != options->type) {
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPTIONS);
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: setting socket options to: keep-alive %d, keep idle %d, keep-alive interval %d, "
        "keep-alive "
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

    return s_setup_socket_params(nw_socket, options);
}

static int s_socket_assign_to_event_loop_fn(struct aws_socket *socket, struct aws_event_loop *event_loop) {
    if (!socket->event_loop) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: assigning to event loop %p",
            (void *)socket,
            socket->io_handle.data.handle,
            (void *)event_loop);

        if (aws_event_loop_connect_handle_to_io_completion_port(event_loop, &socket->io_handle)) {

            AWS_LOGF_DEBUG(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: assigning event loop %p failed",
                (void *)socket,
                socket->io_handle.data.handle,
                (void *)event_loop);
            return AWS_OP_ERR;
        }

        s_set_event_loop(socket, event_loop);
        nw_connection_start(socket->io_handle.data.handle);
        return AWS_OP_SUCCESS;
    }

    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: the socket is already assigned with an event loop %p",
        (void *)socket,
        socket->io_handle.data.handle,
        (void *)event_loop);
    return aws_raise_error(AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED);
}

static void s_handle_nw_connection_receive_completion_fn(
    dispatch_data_t data,
    nw_content_context_t context,
    bool is_complete,
    nw_error_t error,
    struct nw_socket *nw_socket) {
    s_lock_socket_synced_data(nw_socket);
    nw_socket->synced_data.read_scheduled = false;
    s_unlock_socket_synced_data(nw_socket);

    bool complete = is_complete;
    int crt_error_code = s_convert_nw_error(error);
    AWS_LOGF_DEBUG(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: nw_connection_receive invoked with nw_error_code %d, CRT error code %d",
        (void *)nw_socket,
        (void *)nw_socket->os_handle.nw_connection,
        nw_error_get_error_code(error),
        crt_error_code);

    if (!crt_error_code) {
        /* For protocols such as TCP, `is_complete` will be marked when the entire stream has be closed in the
         * reading direction. For protocols such as UDP, this will be marked when the end of a datagram has
         * been reached. */

        complete = is_complete && nw_content_context_get_is_final(context);

        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: queued read buffer of size %d",
            (void *)nw_socket,
            (void *)nw_socket->os_handle.nw_connection,
            data ? (int)dispatch_data_get_size(data) : 0);
    }

    // The callback should be fired before schedule next read, so that if the socket is closed, we could
    // prevent schedule next read earlier.
    s_handle_incoming_data(nw_socket, crt_error_code, data, complete);

    // keep reading from the system socket
    s_schedule_next_read(nw_socket);

    s_socket_release_internal_ref(nw_socket);
}

/* s_schedule_next_read() will setup the nw_connection_receive_completion_t and start a read request to the system
 * socket. The handler will get invoked when the system socket has data to read.
 * The function is initially fired on the following conditions, and recursively call itself on handler invocation:
 *   1. on function call `aws_socket_read()`
 *   2. on function call `aws_socket_subscribe_to_readable_events`
 */
static int s_schedule_next_read(struct nw_socket *nw_socket) {
    s_lock_socket_synced_data(nw_socket);

    // Once a read operation is scheduled, we should not schedule another one until the current one is
    // completed.
    if (nw_socket->synced_data.read_scheduled) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: there is already read queued, do not queue further read",
            (void *)nw_socket,
            (void *)nw_socket->os_handle.nw_connection);
        s_unlock_socket_synced_data(nw_socket);
        return AWS_OP_SUCCESS;
    }

    if (nw_socket->synced_data.state & CLOSING || !(nw_socket->synced_data.state & CONNECTED_READ)) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot read to because socket is not connected",
            (void *)nw_socket,
            (void *)nw_socket->os_handle.nw_connection);
        s_unlock_socket_synced_data(nw_socket);
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    nw_socket->synced_data.read_scheduled = true;

    // Acquire nw_socket as we called nw_connection_receive, and the ref will be released when the handler is
    // called.
    s_socket_acquire_internal_ref(nw_socket);

    /* read and let me know when you've done it. */
    nw_connection_receive(
        nw_socket->os_handle.nw_connection,
        1,
        UINT32_MAX,
        ^(dispatch_data_t data, nw_content_context_t context, bool is_complete, nw_error_t error) {
          s_handle_nw_connection_receive_completion_fn(data, context, is_complete, error, nw_socket);
        });

    s_unlock_socket_synced_data(nw_socket);
    return AWS_OP_SUCCESS;
}

static int s_socket_subscribe_to_readable_events_fn(
    struct aws_socket *socket,
    aws_socket_on_readable_fn *on_readable,
    void *user_data) {
    struct nw_socket *nw_socket = socket->impl;

    if (nw_socket->mode == NWSM_LISTENER) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: Apple Network Framework does not support read/write on a listener. Please use the "
            "incoming socket to track the read/write operation.",
            (void *)nw_socket,
            (void *)nw_socket->os_handle.nw_listener);
        return aws_raise_error(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE);
    }

    socket->readable_user_data = user_data;
    socket->readable_fn = on_readable;

    nw_socket->on_readable = on_readable;
    nw_socket->on_readable_user_data = user_data;

    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: socket_subscribe_to_readable_events: start to schedule read request.",
        (void *)nw_socket,
        (void *)nw_socket->os_handle.nw_connection);

    return s_schedule_next_read(nw_socket);
}

// WARNING: This function should handle the locks carefully. aws_socket_read()&aws_socket_write() should always
// called on event loop thread.
static int s_socket_read_fn(struct aws_socket *socket, struct aws_byte_buf *read_buffer, size_t *amount_read) {
    struct nw_socket *nw_socket = socket->impl;

    AWS_FATAL_ASSERT(amount_read);

    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot read from a different thread than event loop %p",
            (void *)socket,
            socket->io_handle.data.handle,
            (void *)socket->event_loop);
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    __block size_t max_to_read = read_buffer->capacity - read_buffer->len;

    /* As the function is always called on event loop, we didn't lock protect the read_queue. */
    if (aws_linked_list_empty(&nw_socket->read_queue)) {
        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read queue is empty, scheduling another read",
            (void *)socket,
            socket->io_handle.data.handle);
        s_lock_socket_synced_data(nw_socket);
        if (!(nw_socket->synced_data.state & CONNECTED_READ)) {
            AWS_LOGF_DEBUG(
                AWS_LS_IO_SOCKET,
                "id=%p handle=%p: socket is not connected to read.",
                (void *)socket,
                socket->io_handle.data.handle);
            s_unlock_socket_synced_data(nw_socket);

            return aws_raise_error(AWS_IO_SOCKET_CLOSED);
        }

        *amount_read = 0;
        s_unlock_socket_synced_data(nw_socket);
        s_schedule_next_read(nw_socket);
        return aws_raise_error(AWS_IO_READ_WOULD_BLOCK);
    }

    /* loop over the read queue, take the data and copy it over, and do so til we're either out of data
     * and need to schedule another read, or we've read entirely into the requested buffer. */
    while (!aws_linked_list_empty(&nw_socket->read_queue) && max_to_read) {
        struct aws_linked_list_node *node = aws_linked_list_front(&nw_socket->read_queue);
        struct read_queue_node *read_node = AWS_CONTAINER_OF(node, struct read_queue_node, node);

        bool buffer_processed = dispatch_data_apply(
            read_node->received_data,
            (dispatch_data_applier_t) ^ (dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
                (void)region;
                (void)offset;

                AWS_LOGF_TRACE(
                    AWS_LS_IO_SOCKET,
                    "id=%p handle=%p: Starting read dispatch data region offset: %lu, buffer %p, with size %lu.",
                    (void *)socket,
                    socket->io_handle.data.handle,
                    offset,
                    buffer,
                    size);

                if (read_node->resume_region && offset < read_node->resume_region) {
                    AWS_LOGF_TRACE(
                        AWS_LS_IO_SOCKET,
                        "id=%p handle=%p: Skipped dispatch data region region : %lu, looking for region: %lu",
                        (void *)socket,
                        socket->io_handle.data.handle,
                        offset,
                        read_node->resume_region);
                    return true;
                }
                size_t to_copy = aws_min_size(max_to_read, size - read_node->region_offset);
                aws_byte_buf_write(read_buffer, (const uint8_t *)buffer + read_node->region_offset, to_copy);
                max_to_read -= to_copy;
                *amount_read += to_copy;
                read_node->region_offset += to_copy;
                if (read_node->region_offset == size) {
                    read_node->region_offset = 0;
                    return true;
                }
                read_node->resume_region = offset;
                return false;
            });

        if (buffer_processed) {
            aws_linked_list_remove(node);
            s_read_queue_node_destroy(read_node);
        }

        AWS_LOGF_TRACE(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: read of %d",
            (void *)socket,
            socket->io_handle.data.handle,
            (int)*amount_read);
    }

    return AWS_OP_SUCCESS;
}

static void s_handle_nw_connection_send_completion_fn(
    nw_error_t error,
    dispatch_data_t data,
    struct nw_socket *nw_socket,
    aws_socket_on_write_completed_fn *written_fn,
    void *user_data) {

    int crt_error_code = s_convert_nw_error(error);
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: nw_connection_send invoked with nw_error_code %d, maps to CRT "
        "error code %d",
        (void *)nw_socket,
        (void *)nw_socket->os_handle.nw_connection,
        nw_error_get_error_code(error),
        crt_error_code);

    if (crt_error_code) {
        nw_socket->last_error = crt_error_code;
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: error during write %d",
            (void *)nw_socket,
            (void *)nw_socket->os_handle.nw_connection,
            crt_error_code);
    }

    size_t written_size = dispatch_data_get_size(data);
    AWS_LOGF_TRACE(
        AWS_LS_IO_SOCKET,
        "id=%p handle=%p: send written size %d",
        (void *)nw_socket,
        (void *)nw_socket->os_handle.nw_connection,
        (int)written_size);
    s_handle_write_fn(nw_socket, crt_error_code, data ? written_size : 0, user_data, written_fn);
    s_socket_release_write_ref(nw_socket);
    s_socket_release_internal_ref(nw_socket);
}

// WARNING: This function should be careful with locks. aws_socket_read()&aws_socket_write() should always called on
// event loop thread.
static int s_socket_write_fn(
    struct aws_socket *socket,
    const struct aws_byte_cursor *cursor,
    aws_socket_on_write_completed_fn *written_fn,
    void *user_data) {
    AWS_FATAL_ASSERT(written_fn);
    if (!aws_event_loop_thread_is_callers_thread(socket->event_loop)) {
        return aws_raise_error(AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY);
    }

    struct nw_socket *nw_socket = socket->impl;
    s_lock_socket_synced_data(nw_socket);
    if (!(nw_socket->synced_data.state & CONNECTED_WRITE)) {
        AWS_LOGF_DEBUG(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: cannot write to because it is not connected",
            (void *)socket,
            socket->io_handle.data.handle);
        s_unlock_socket_synced_data(nw_socket);
        return aws_raise_error(AWS_IO_SOCKET_NOT_CONNECTED);
    }

    dispatch_data_t data = dispatch_data_create(cursor->ptr, cursor->len, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    if (!data) {
        AWS_LOGF_ERROR(
            AWS_LS_IO_SOCKET,
            "id=%p handle=%p: failed to process write data.",
            (void *)socket,
            socket->io_handle.data.handle);
        return AWS_OP_ERR;
    }
    s_socket_acquire_internal_ref(nw_socket);
    s_socket_acquire_write_ref(nw_socket);

    nw_connection_send(
        socket->io_handle.data.handle, data, _nw_content_context_default_message, true, ^(nw_error_t error) {
          s_handle_nw_connection_send_completion_fn(error, data, nw_socket, written_fn, user_data);
        });

    s_unlock_socket_synced_data(nw_socket);

    return AWS_OP_SUCCESS;
}

static int s_socket_get_error_fn(struct aws_socket *socket) {
    struct nw_socket *nw_socket = socket->impl;

    return nw_socket->last_error;
}

static bool s_socket_is_open_fn(struct aws_socket *socket) {
    struct nw_socket *nw_socket = socket->impl;
    s_lock_socket_synced_data(nw_socket);
    bool is_open = nw_socket->synced_data.state < CLOSING;
    s_unlock_socket_synced_data(nw_socket);
    return is_open;
}

static int s_set_close_callback(struct aws_socket *socket, aws_socket_on_shutdown_complete_fn fn, void *user_data) {
    struct nw_socket *nw_socket = socket->impl;
    nw_socket->close_user_data = user_data;
    nw_socket->on_socket_close_complete_fn = fn;
    return 0;
}

static int s_set_cleanup_callback(struct aws_socket *socket, aws_socket_on_shutdown_complete_fn fn, void *user_data) {
    struct nw_socket *nw_socket = socket->impl;
    nw_socket->cleanup_user_data = user_data;
    nw_socket->on_socket_cleanup_complete_fn = fn;
    return 0;
}

static struct aws_byte_buf s_socket_get_protocol_fn(const struct aws_socket *socket) {
    struct nw_socket *nw_socket = socket->impl;
    return nw_socket->protocol_buf;
}

static struct aws_string *s_socket_get_server_name_fn(const struct aws_socket *socket) {
    struct nw_socket *nw_socket = socket->impl;
    return nw_socket->host_name;
}
