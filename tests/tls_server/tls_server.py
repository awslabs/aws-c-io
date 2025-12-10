# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0.

import argparse
import pathlib
import signal
import socket
import ssl
import sys


def parse_tls(tls_str):
    if tls_str == '1.1':
        return ssl.TLSVersion.TLSv1_1
    elif tls_str == '1.2':
        return ssl.TLSVersion.TLSv1_2
    elif tls_str == '1.3':
        return ssl.TLSVersion.TLSv1_3
    raise ValueError('Unknown TLS version')


print(f"Starting TLS server")

parser = argparse.ArgumentParser(
    description="TLS test server",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)

optional = parser.add_argument_group("optional arguments")

optional.add_argument("--host", dest="host", default="127.0.0.1", help="Listening host")
optional.add_argument("--port", type=int, dest="port", default=59443, help="Listening port")
optional.add_argument("--min-tls", choices=['1.1', '1.2', '1.3'], dest="min_tls", default='1.2',
                      help="Minimum acceptable TLS version")
optional.add_argument("--max-tls", choices=['1.1', '1.2', '1.3'], dest="max_tls", default='1.3',
                      help="Maximum acceptable TLS version")
optional.add_argument("--resource-dir", type=pathlib.Path, dest="resource_dir", default='./tests/resources/',
                      help="Path to keys and certificates")

args = parser.parse_args()

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = parse_tls(args.min_tls)
context.maximum_version = parse_tls(args.max_tls)
context.load_cert_chain(args.resource_dir / 'mtls_server.pem.crt', args.resource_dir / 'mtls_server.key')
context.load_verify_locations(args.resource_dir / 'mtls_device_root_ca.pem.crt')
context.verify_mode = ssl.CERT_REQUIRED


def signal_handler(signum, frame):
    sys.stdout.flush()
    sys.exit(0)


signal.signal(signal.SIGTERM, signal_handler)

print(f"Running TLS server on {args.host}:{args.port}")
print(f"Minimum TLS version: {context.minimum_version.name}")
print(f"Maximum TLS version: {context.maximum_version.name}")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(1)
    with context.wrap_socket(sock, server_side=True) as ssock:
        while True:
            try:
                conn, addr = ssock.accept()
                print("Accepted new connection: {}".format(addr))
            except Exception as e:
                print(f"Accept failed: {e}")
