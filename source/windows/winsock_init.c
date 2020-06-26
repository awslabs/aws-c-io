/**
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

/* clang is just a naive little idealist and doesn't understand that it can't just
go around re-ordering windows header files. Also, sorry about the C++ style comments
below, clang-format doesn't work (at least on my version) with the c-style comments. */

// clang-format off
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>
// clang-format on

#include <aws/io/logging.h>
#include <aws/io/socket.h>

#include <stdlib.h>

static LPFN_CONNECTEX s_connect_ex_fn = NULL;
static LPFN_ACCEPTEX s_accept_ex_fn = NULL;
static bool s_winsock_init = false;

void aws_check_and_init_winsock(void) {

    if (!s_winsock_init) {
        AWS_LOGF_INFO(AWS_LS_IO_SOCKET, "static: initializing WinSock");
        WORD requested_version = MAKEWORD(2, 2);
        WSADATA wsa_data;
        if (WSAStartup(requested_version, &wsa_data)) {
            AWS_LOGF_FATAL(
                AWS_LS_IO_SOCKET, "static: WinSock initialization failed with error %d", (int)GetLastError());
            AWS_ASSERT(0);
            exit(-1);
        }

        SOCKET dummy_socket = socket(AF_INET, SOCK_STREAM, 0);
        AWS_ASSERT(dummy_socket != INVALID_SOCKET);

        AWS_LOGF_INFO(AWS_LS_IO_SOCKET, "static: loading WSAID_CONNECTEX function");
        GUID connect_ex_guid = WSAID_CONNECTEX;
        DWORD bytes_written = 0;
        int rc = WSAIoctl(
            dummy_socket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &connect_ex_guid,
            sizeof(connect_ex_guid),
            &s_connect_ex_fn,
            sizeof(s_connect_ex_fn),
            &bytes_written,
            NULL,
            NULL);

        if (rc) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET, "static: failed to load WSAID_CONNECTEX function with error %d", (int)GetLastError());
            AWS_ASSERT(0);
            exit(-1);
        }

        AWS_LOGF_INFO(AWS_LS_IO_SOCKET, "static: loading WSAID_ACCEPTEX function");
        GUID accept_ex_guid = WSAID_ACCEPTEX;
        bytes_written = 0;
        rc = WSAIoctl(
            dummy_socket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &accept_ex_guid,
            sizeof(accept_ex_guid),
            &s_accept_ex_fn,
            sizeof(s_accept_ex_fn),
            &bytes_written,
            NULL,
            NULL);

        if (rc) {
            AWS_LOGF_ERROR(
                AWS_LS_IO_SOCKET, "static: failed to load WSAID_ACCEPTEX function with error %d", (int)GetLastError());
            AWS_ASSERT(0);
            exit(-1);
        }

        closesocket(dummy_socket);
        s_winsock_init = true;
    }
}

aws_ms_fn_ptr aws_winsock_get_connectex_fn(void) {
    aws_check_and_init_winsock();
    return (aws_ms_fn_ptr)s_connect_ex_fn;
}

aws_ms_fn_ptr aws_winsock_get_acceptex_fn(void) {
    aws_check_and_init_winsock();
    return (aws_ms_fn_ptr)s_accept_ex_fn;
}
