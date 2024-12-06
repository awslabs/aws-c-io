import socket
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain('tls13.pem.crt', 'tls13.key')

cnt = 0
while cnt < 2:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(('127.0.0.1', 59443))
        sock.listen(5)
        with context.wrap_socket(sock, server_side=True) as ssock:
            conn, addr = ssock.accept()
            print("accepted new conn: {}".format(addr))
            cnt = cnt + 1
