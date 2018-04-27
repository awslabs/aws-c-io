#ifndef AWS_IO_H
#define AWS_IO_H

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
#include <aws/io/exports.h>
#include <aws/common/common.h>
#include <aws/common/byte_buf.h>
#include <aws/common/linked_list.h>
#include <stdint.h>

struct aws_io_handle {
#ifdef _WIN32
    HANDLE handle;
#else
    int handle;
#endif
    void *private_event_loop_data;
};

typedef enum aws_io_message_type {
    AWS_IO_MESSAGE_APPLICATION_DATA,
} aws_io_message_type;

struct aws_io_message;
struct aws_channel;

typedef void(*aws_channel_on_message_write_completed)(struct aws_channel *, struct aws_io_message *, int err_code, void *ctx);

struct aws_io_message {
    struct aws_allocator *allocator;
    struct aws_byte_buf message_data;
    aws_io_message_type message_type;
    int message_tag;
    size_t copy_mark;
    aws_channel_on_message_write_completed on_completion;
    void *ctx;
};

typedef int (*aws_io_clock)(uint64_t *timestamp);

typedef enum aws_io_errors {
    AWS_IO_CHANNEL_ERROR_ERROR_CANT_ACCEPT_INPUT = 0x0400,
    AWS_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE,
    AWS_IO_SYS_CALL_FAILURE,
    AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE,
    AWS_IO_TLS_ERROR_NOT_NEGOTIATED,
    AWS_IO_TLS_ERROR_WRITE_FAILURE,
    AWS_IO_TLS_CTX_ERROR,
    AWS_IO_FILE_NOT_FOUND,
    AWS_IO_FILE_VALIDATION_FAILURE,
    AWS_IO_WRITE_WOULD_BLOCK,
    AWS_IO_READ_WOULD_BLOCK,
    AWS_IO_BROKEN_PIPE,
    AWS_IO_MAX_FDS_EXCEEDED,
    AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY,
    AWS_IO_NO_PERMISSION,
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

    AWS_IO_ERROR_END_RANGE =  0x07FF
} aws_io_errors;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Loads error strings for this API so that aws_last_error_str etc... will return useful debug strings.
 */
AWS_IO_API void aws_io_load_error_strings(void);

#ifdef __cplusplus
}
#endif

#endif /* AWS_IO_H */
