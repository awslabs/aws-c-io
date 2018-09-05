
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>

#include <aws/io/socket.h>

#include <stdlib.h>


static LPFN_CONNECTEX s_connect_ex_fn = NULL;
static LPFN_ACCEPTEX s_accept_ex_fn = NULL;
static bool s_winsock_init = false;

void aws_check_and_init_winsock(void) {

    if (!s_winsock_init) {
        WORD requested_version = MAKEWORD(2, 2);
        WSADATA wsa_data;
        if (WSAStartup(requested_version, &wsa_data)) {
            assert(0);
            exit(-1);
        }

        SOCKET dummy_socket = socket(AF_INET, SOCK_STREAM, 0);
        assert(dummy_socket != INVALID_SOCKET);

        GUID connect_ex_guid = WSAID_CONNECTEX;
        DWORD bytes_written = 0;
        int rc = WSAIoctl(dummy_socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &connect_ex_guid, sizeof(connect_ex_guid), 
            &s_connect_ex_fn, sizeof(s_connect_ex_fn), &bytes_written, NULL, NULL);

        if (rc) {
            assert(0);
            exit(-1);
        }

        GUID accept_ex_guoid = WSAID_ACCEPTEX;
        bytes_written = 0;
        rc = WSAIoctl(dummy_socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &accept_ex_guoid, sizeof(accept_ex_guoid),
            &s_accept_ex_fn, sizeof(s_accept_ex_fn), &bytes_written, NULL, NULL);

        if (rc) {
            assert(0);
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