import http.server
import ssl
server = http.server.HTTPServer(('localhost', 42337), http.server.SimpleHTTPRequestHandler)
server.socket = ssl.wrap_socket(server.socket, keyfile='certchain.key', certfile='certchained.pem', server_side=True)
print(server.server_address)
server.serve_forever()
