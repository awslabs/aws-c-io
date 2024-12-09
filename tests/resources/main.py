import socket
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.maximum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain('tls13_server.pem.crt', 'tls13_server.key')
context.load_verify_locations('tls13_device_root_ca.pem.crt')
context.verify_mode = ssl.CERT_REQUIRED

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.bind(('127.0.0.1', 59443))
    sock.listen(1)
    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            try:
                conn, addr = ssock.accept()
                print("Accepted new connection: {}".format(addr))
            except Exceptions as e:
                print("accept failed: {}".format(e))
