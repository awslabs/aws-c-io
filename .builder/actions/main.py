import socket
import ssl
import os

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
cwd = os.getcwd()
print("Current dir is {}".format(cwd))
context.load_cert_chain('tls13.pem.crt', 'tls13.key')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind(('127.0.0.1', 59443))
    sock.listen(5)
    with context.wrap_socket(sock, server_side=True) as ssock:
        conn, addr = ssock.accept()
        print("accepted new conn: {}".format(addr))
