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
#include <aws/io/io.h>

#define LIB_NAME  "aws-c-io"

static struct aws_error_info errors[] = {
        AWS_DEFINE_ERROR_INFO(AWS_IO_CHANNEL_ERROR_ERROR_CANT_ACCEPT_INPUT,
                              "Channel cannot accept input", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE,
                              "Channel unknown message type", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW,
                              "A channel handler attempted to propagate a read larger than the upstream window", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SYS_CALL_FAILURE,
                              "System call failure", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_TLS_ERROR_NEGOTIATION_FAILURE,
                              "TLS (SSL) negotiation failed", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_TLS_ERROR_NOT_NEGOTIATED,
                              "Attempt to read/write, but TLS (SSL) hasn't been negotiated", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_TLS_ERROR_WRITE_FAILURE,
                              "Failed to write to TLS handler", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_TLS_CTX_ERROR,
                              "Failed to create tls context", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_MISSING_ALPN_MESSAGE,
                              "An ALPN message was expected but not received", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE,
                              "An ALPN message was received but a handler was not created by the user", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_FILE_NOT_FOUND,
                              "Unable to open file", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_FILE_VALIDATION_FAILURE,
                              "A file was read and the input did not match the expected value", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_WRITE_WOULD_BLOCK,
                              "Write operation would block, try again later", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_READ_WOULD_BLOCK,
                              "Read operation would block, try again later", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_BROKEN_PIPE,
                              "Attempt to read or write to io handle that has already been closed.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_MAX_FDS_EXCEEDED,
                              "The maximum number of fds has been exceeded.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY,
                              "Socket, unsupported address family.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_NO_PERMISSION,
                              "User does not have permission to perform the requested action.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SOCKET_INVALID_OPERATION_FOR_TYPE,
                              "Invalid socket operation for socket type.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SOCKET_CONNECTION_REFUSED,
                              "socket connection refused.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SOCKET_TIMEOUT,
                              "socket operation timed out.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SOCKET_NO_ROUTE_TO_HOST,
                              "socket connect failure, no route to host.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SOCKET_NETWORK_DOWN,
                              "network is down.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SOCKET_CLOSED,
                              "socket is closed.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SOCKET_NOT_CONNECTED,
                              "socket not connected.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SOCKET_INVALID_OPTIONS,
                              "Invalid socket options.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SOCKET_ADDRESS_IN_USE,
                              "Socket address already in use.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SOCKET_INVALID_ADDRESS,
                              "Invalid socket address.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE,
                              "Illegal operation for socket state.", LIB_NAME),
        AWS_DEFINE_ERROR_INFO(AWS_IO_SOCKET_CONNECT_ABORTED,
                              "Incoming connection was aborted.", LIB_NAME),

};

static struct aws_error_info_list list = {
        .error_list = errors,
        .count = sizeof(errors) / sizeof(struct aws_error_info),
};

static int8_t error_strings_loaded = 0;

void aws_io_load_error_strings(void) {
    if (!error_strings_loaded) {
        error_strings_loaded = 1;
        aws_register_error_info(&list);
    }
}
