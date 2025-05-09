#ifndef AWS_IO_IO_H
#define AWS_IO_IO_H

/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */
#include <aws/common/byte_buf.h>
#include <aws/common/common.h>
#include <aws/common/linked_list.h>
#include <aws/io/exports.h>

AWS_PUSH_SANE_WARNING_LEVEL

#define AWS_C_IO_PACKAGE_ID 1

struct aws_io_handle;
typedef void aws_io_set_queue_on_handle_fn(struct aws_io_handle *handle, void *queue);

struct aws_io_handle {
    union {
        int fd;
        /* on Apple systems, handle is of type nw_connection_t. On Windows, it's a SOCKET handle. */
        void *handle;
    } data;
    void *additional_data;
    aws_io_set_queue_on_handle_fn *set_queue;
};

enum aws_io_message_type {
    AWS_IO_MESSAGE_APPLICATION_DATA,
};

struct aws_io_message;
struct aws_channel;

typedef void(aws_channel_on_message_write_completed_fn)(
    struct aws_channel *channel,
    struct aws_io_message *message,
    int err_code,
    void *user_data);

struct aws_io_message {
    /**
     * Allocator used for the message and message data. If this is null, the message belongs to a pool or some other
     * message manager.
     */
    struct aws_allocator *allocator;

    /**
     * Buffer containing the data for message
     */
    struct aws_byte_buf message_data;

    /**
     * type of the message. This is used for framework control messages. Currently the only type is
     * AWS_IO_MESSAGE_APPLICATION_DATA
     */
    enum aws_io_message_type message_type;

    /**
     * Conveys information about the contents of message_data (e.g. cast the ptr to some type). If 0, it's just opaque
     * data.
     */
    int message_tag;

    /**
     * In order to avoid excess allocations/copies, on a partial read or write, the copy mark is set to indicate how
     * much of this message has already been processed or copied.
     */
    size_t copy_mark;

    /**
     * The channel that the message is bound to.
     */
    struct aws_channel *owning_channel;

    /**
     * Invoked by the channel once the entire message has been written to the data sink.
     */
    aws_channel_on_message_write_completed_fn *on_completion;

    /**
     * arbitrary user data for the on_completion callback
     */
    void *user_data;

    /** it's incredibly likely something is going to need to queue this,
     * go ahead and make sure the list info is part of the original allocation.
     */
    struct aws_linked_list_node queueing_handle;
};

typedef int(aws_io_clock_fn)(uint64_t *timestamp);

enum aws_io_errors {
    AWS_IO_CHANNEL_ERROR_ERROR_CANT_ACCEPT_INPUT = AWS_ERROR_ENUM_BEGIN_RANGE(AWS_C_IO_PACKAGE_ID),
    AWS_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE,
    AWS_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW,
    AWS_IO_EVENT_LOOP_ALREADY_ASSIGNED,
    AWS_IO_EVENT_LOOP_SHUTDOWN,
    AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE,
    AWS_IO_TLS_ERROR_NOT_NEGOTIATED,
    AWS_IO_TLS_ERROR_WRITE_FAILURE,
    AWS_IO_TLS_ERROR_ALERT_RECEIVED,
    AWS_IO_TLS_CTX_ERROR,
    AWS_IO_TLS_VERSION_UNSUPPORTED,
    AWS_IO_TLS_CIPHER_PREF_UNSUPPORTED,
    AWS_IO_MISSING_ALPN_MESSAGE,
    AWS_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE,
    AWS_IO_FILE_VALIDATION_FAILURE,
    AWS_ERROR_IO_EVENT_LOOP_THREAD_ONLY,
    AWS_ERROR_IO_ALREADY_SUBSCRIBED,
    AWS_ERROR_IO_NOT_SUBSCRIBED,
    AWS_ERROR_IO_OPERATION_CANCELLED,
    AWS_IO_READ_WOULD_BLOCK,
    AWS_IO_BROKEN_PIPE,
    AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY,
    AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE,
    AWS_IO_SOCKET_CONNECTION_REFUSED,
    AWS_IO_SOCKET_TIMEOUT,
    AWS_IO_SOCKET_NO_ROUTE_TO_HOST,
    AWS_IO_SOCKET_NETWORK_DOWN,
    AWS_IO_SOCKET_CLOSED,
    AWS_IO_SOCKET_NOT_CONNECTED,
    AWS_IO_SOCKET_INVALID_OPTIONS,
    AWS_IO_SOCKET_ADDRESS_IN_USE,
    AWS_IO_SOCKET_INVALID_ADDRESS,
    AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE,
    AWS_IO_SOCKET_CONNECT_ABORTED,
    AWS_IO_DNS_QUERY_FAILED,
    AWS_IO_DNS_INVALID_NAME,
    AWS_IO_DNS_NO_ADDRESS_FOR_HOST,
    AWS_IO_DNS_HOST_REMOVED_FROM_CACHE,
    AWS_IO_STREAM_INVALID_SEEK_POSITION,
    AWS_IO_STREAM_READ_FAILED,
    DEPRECATED_AWS_IO_INVALID_FILE_HANDLE,
    AWS_IO_SHARED_LIBRARY_LOAD_FAILURE,
    AWS_IO_SHARED_LIBRARY_FIND_SYMBOL_FAILURE,
    AWS_IO_TLS_NEGOTIATION_TIMEOUT,
    AWS_IO_TLS_ALERT_NOT_GRACEFUL,
    AWS_IO_MAX_RETRIES_EXCEEDED,
    AWS_IO_RETRY_PERMISSION_DENIED,
    AWS_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED,
    AWS_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED,

    AWS_ERROR_PKCS11_VERSION_UNSUPPORTED,
    AWS_ERROR_PKCS11_TOKEN_NOT_FOUND,
    AWS_ERROR_PKCS11_KEY_NOT_FOUND,
    AWS_ERROR_PKCS11_KEY_TYPE_UNSUPPORTED,
    AWS_ERROR_PKCS11_UNKNOWN_CRYPTOKI_RETURN_VALUE,

    /* PKCS#11 "CKR_" (Cryptoki Return Value) as AWS error-codes */
    AWS_ERROR_PKCS11_CKR_CANCEL,
    AWS_ERROR_PKCS11_CKR_HOST_MEMORY,
    AWS_ERROR_PKCS11_CKR_SLOT_ID_INVALID,
    AWS_ERROR_PKCS11_CKR_GENERAL_ERROR,
    AWS_ERROR_PKCS11_CKR_FUNCTION_FAILED,
    AWS_ERROR_PKCS11_CKR_ARGUMENTS_BAD,
    AWS_ERROR_PKCS11_CKR_NO_EVENT,
    AWS_ERROR_PKCS11_CKR_NEED_TO_CREATE_THREADS,
    AWS_ERROR_PKCS11_CKR_CANT_LOCK,
    AWS_ERROR_PKCS11_CKR_ATTRIBUTE_READ_ONLY,
    AWS_ERROR_PKCS11_CKR_ATTRIBUTE_SENSITIVE,
    AWS_ERROR_PKCS11_CKR_ATTRIBUTE_TYPE_INVALID,
    AWS_ERROR_PKCS11_CKR_ATTRIBUTE_VALUE_INVALID,
    AWS_ERROR_PKCS11_CKR_ACTION_PROHIBITED,
    AWS_ERROR_PKCS11_CKR_DATA_INVALID,
    AWS_ERROR_PKCS11_CKR_DATA_LEN_RANGE,
    AWS_ERROR_PKCS11_CKR_DEVICE_ERROR,
    AWS_ERROR_PKCS11_CKR_DEVICE_MEMORY,
    AWS_ERROR_PKCS11_CKR_DEVICE_REMOVED,
    AWS_ERROR_PKCS11_CKR_ENCRYPTED_DATA_INVALID,
    AWS_ERROR_PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE,
    AWS_ERROR_PKCS11_CKR_FUNCTION_CANCELED,
    AWS_ERROR_PKCS11_CKR_FUNCTION_NOT_PARALLEL,
    AWS_ERROR_PKCS11_CKR_FUNCTION_NOT_SUPPORTED,
    AWS_ERROR_PKCS11_CKR_KEY_HANDLE_INVALID,
    AWS_ERROR_PKCS11_CKR_KEY_SIZE_RANGE,
    AWS_ERROR_PKCS11_CKR_KEY_TYPE_INCONSISTENT,
    AWS_ERROR_PKCS11_CKR_KEY_NOT_NEEDED,
    AWS_ERROR_PKCS11_CKR_KEY_CHANGED,
    AWS_ERROR_PKCS11_CKR_KEY_NEEDED,
    AWS_ERROR_PKCS11_CKR_KEY_INDIGESTIBLE,
    AWS_ERROR_PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED,
    AWS_ERROR_PKCS11_CKR_KEY_NOT_WRAPPABLE,
    AWS_ERROR_PKCS11_CKR_KEY_UNEXTRACTABLE,
    AWS_ERROR_PKCS11_CKR_MECHANISM_INVALID,
    AWS_ERROR_PKCS11_CKR_MECHANISM_PARAM_INVALID,
    AWS_ERROR_PKCS11_CKR_OBJECT_HANDLE_INVALID,
    AWS_ERROR_PKCS11_CKR_OPERATION_ACTIVE,
    AWS_ERROR_PKCS11_CKR_OPERATION_NOT_INITIALIZED,
    AWS_ERROR_PKCS11_CKR_PIN_INCORRECT,
    AWS_ERROR_PKCS11_CKR_PIN_INVALID,
    AWS_ERROR_PKCS11_CKR_PIN_LEN_RANGE,
    AWS_ERROR_PKCS11_CKR_PIN_EXPIRED,
    AWS_ERROR_PKCS11_CKR_PIN_LOCKED,
    AWS_ERROR_PKCS11_CKR_SESSION_CLOSED,
    AWS_ERROR_PKCS11_CKR_SESSION_COUNT,
    AWS_ERROR_PKCS11_CKR_SESSION_HANDLE_INVALID,
    AWS_ERROR_PKCS11_CKR_SESSION_PARALLEL_NOT_SUPPORTED,
    AWS_ERROR_PKCS11_CKR_SESSION_READ_ONLY,
    AWS_ERROR_PKCS11_CKR_SESSION_EXISTS,
    AWS_ERROR_PKCS11_CKR_SESSION_READ_ONLY_EXISTS,
    AWS_ERROR_PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS,
    AWS_ERROR_PKCS11_CKR_SIGNATURE_INVALID,
    AWS_ERROR_PKCS11_CKR_SIGNATURE_LEN_RANGE,
    AWS_ERROR_PKCS11_CKR_TEMPLATE_INCOMPLETE,
    AWS_ERROR_PKCS11_CKR_TEMPLATE_INCONSISTENT,
    AWS_ERROR_PKCS11_CKR_TOKEN_NOT_PRESENT,
    AWS_ERROR_PKCS11_CKR_TOKEN_NOT_RECOGNIZED,
    AWS_ERROR_PKCS11_CKR_TOKEN_WRITE_PROTECTED,
    AWS_ERROR_PKCS11_CKR_UNWRAPPING_KEY_HANDLE_INVALID,
    AWS_ERROR_PKCS11_CKR_UNWRAPPING_KEY_SIZE_RANGE,
    AWS_ERROR_PKCS11_CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    AWS_ERROR_PKCS11_CKR_USER_ALREADY_LOGGED_IN,
    AWS_ERROR_PKCS11_CKR_USER_NOT_LOGGED_IN,
    AWS_ERROR_PKCS11_CKR_USER_PIN_NOT_INITIALIZED,
    AWS_ERROR_PKCS11_CKR_USER_TYPE_INVALID,
    AWS_ERROR_PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
    AWS_ERROR_PKCS11_CKR_USER_TOO_MANY_TYPES,
    AWS_ERROR_PKCS11_CKR_WRAPPED_KEY_INVALID,
    AWS_ERROR_PKCS11_CKR_WRAPPED_KEY_LEN_RANGE,
    AWS_ERROR_PKCS11_CKR_WRAPPING_KEY_HANDLE_INVALID,
    AWS_ERROR_PKCS11_CKR_WRAPPING_KEY_SIZE_RANGE,
    AWS_ERROR_PKCS11_CKR_WRAPPING_KEY_TYPE_INCONSISTENT,
    AWS_ERROR_PKCS11_CKR_RANDOM_SEED_NOT_SUPPORTED,
    AWS_ERROR_PKCS11_CKR_RANDOM_NO_RNG,
    AWS_ERROR_PKCS11_CKR_DOMAIN_PARAMS_INVALID,
    AWS_ERROR_PKCS11_CKR_CURVE_NOT_SUPPORTED,
    AWS_ERROR_PKCS11_CKR_BUFFER_TOO_SMALL,
    AWS_ERROR_PKCS11_CKR_SAVED_STATE_INVALID,
    AWS_ERROR_PKCS11_CKR_INFORMATION_SENSITIVE,
    AWS_ERROR_PKCS11_CKR_STATE_UNSAVEABLE,
    AWS_ERROR_PKCS11_CKR_CRYPTOKI_NOT_INITIALIZED,
    AWS_ERROR_PKCS11_CKR_CRYPTOKI_ALREADY_INITIALIZED,
    AWS_ERROR_PKCS11_CKR_MUTEX_BAD,
    AWS_ERROR_PKCS11_CKR_MUTEX_NOT_LOCKED,
    AWS_ERROR_PKCS11_CKR_NEW_PIN_MODE,
    AWS_ERROR_PKCS11_CKR_NEXT_OTP,
    AWS_ERROR_PKCS11_CKR_EXCEEDED_MAX_ITERATIONS,
    AWS_ERROR_PKCS11_CKR_FIPS_SELF_TEST_FAILED,
    AWS_ERROR_PKCS11_CKR_LIBRARY_LOAD_FAILED,
    AWS_ERROR_PKCS11_CKR_PIN_TOO_WEAK,
    AWS_ERROR_PKCS11_CKR_PUBLIC_KEY_INVALID,
    AWS_ERROR_PKCS11_CKR_FUNCTION_REJECTED,

    AWS_ERROR_IO_PINNED_EVENT_LOOP_MISMATCH,

    AWS_ERROR_PKCS11_ENCODING_ERROR,
    AWS_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND,

    AWS_IO_STREAM_SEEK_FAILED,
    AWS_IO_STREAM_GET_LENGTH_FAILED,
    AWS_IO_STREAM_SEEK_UNSUPPORTED,
    AWS_IO_STREAM_GET_LENGTH_UNSUPPORTED,
    AWS_IO_TLS_ERROR_READ_FAILURE,

    AWS_ERROR_PEM_MALFORMED,

    AWS_IO_SOCKET_MISSING_EVENT_LOOP,
    AWS_IO_TLS_UNKNOWN_ROOT_CERTIFICATE,
    AWS_IO_TLS_NO_ROOT_CERTIFICATE_FOUND,
    AWS_IO_TLS_CERTIFICATE_EXPIRED,
    AWS_IO_TLS_CERTIFICATE_NOT_YET_VALID,
    AWS_IO_TLS_BAD_CERTIFICATE,
    AWS_IO_TLS_PEER_CERTIFICATE_EXPIRED,
    AWS_IO_TLS_BAD_PEER_CERTIFICATE,
    AWS_IO_TLS_PEER_CERTIFICATE_REVOKED,
    AWS_IO_TLS_PEER_CERTIFICATE_UNKNOWN,
    AWS_IO_TLS_INTERNAL_ERROR,
    AWS_IO_TLS_CLOSED_GRACEFUL,
    AWS_IO_TLS_CLOSED_ABORT,
    AWS_IO_TLS_INVALID_CERTIFICATE_CHAIN,
    AWS_IO_TLS_HOST_NAME_MISMATCH,

    AWS_IO_ERROR_END_RANGE = AWS_ERROR_ENUM_END_RANGE(AWS_C_IO_PACKAGE_ID),
    AWS_IO_INVALID_FILE_HANDLE = AWS_ERROR_INVALID_FILE_HANDLE,
};

AWS_EXTERN_C_BEGIN

/**
 * Initializes internal datastructures used by aws-c-io.
 * Must be called before using any functionality in aws-c-io.
 */
AWS_IO_API
void aws_io_library_init(struct aws_allocator *allocator);

/**
 * Shuts down the internal datastructures used by aws-c-io.
 */
AWS_IO_API
void aws_io_library_clean_up(void);

AWS_IO_API
void aws_io_fatal_assert_library_initialized(void);

AWS_EXTERN_C_END
AWS_POP_SANE_WARNING_LEVEL

#endif /* AWS_IO_IO_H */
