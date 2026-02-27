#!/bin/bash
# WinRM module test using Docker
# Requires: docker
# WinRM is Windows-only natively, but we can test against a mock HTTP server

set -e

CONTAINER_NAME="bruter-test-winrm"
PORT=5985

echo "[*] Starting WinRM mock server..."
# Use a simple Python HTTP server that mimics WinRM Basic auth
docker run -d --name "$CONTAINER_NAME" -p "$PORT:$PORT" python:3-alpine \
  python3 -c "
import http.server, base64, socketserver

class WinRMHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != '/wsman':
            self.send_response(404)
            self.end_headers()
            return
        auth = self.headers.get('Authorization', '')
        expected = 'Basic ' + base64.b64encode(b'admin:P@ssw0rd').decode()
        if auth == expected:
            self.send_response(200)
            self.send_header('Content-Type', 'application/soap+xml')
            self.end_headers()
            self.wfile.write(b'<IdentifyResponse/>')
        else:
            self.send_response(401)
            self.end_headers()
    def log_message(self, *args): pass

with socketserver.TCPServer(('0.0.0.0', $PORT), WinRMHandler) as s:
    s.serve_forever()
" > /dev/null 2>&1

sleep 2

echo "[*] Testing WinRM brute-force..."
../bruter -m winrm -t 127.0.0.1 -p "$PORT" -u admin -w /dev/stdin <<< "wrong
P@ssw0rd
also_wrong"

echo ""
echo "[*] Cleaning up..."
docker rm -f "$CONTAINER_NAME" > /dev/null 2>&1
echo "[+] Done"
