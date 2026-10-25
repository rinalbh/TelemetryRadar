"""Real local HTTPS interception/key logging without UAC or trusted-root changes."""
import http.server
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

from mitmproxy.certs import CertStore
from cryptography import x509


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"fixture":"decrypted"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class KeyLoggingTests(unittest.TestCase):
    def test_real_proxy_logs_both_tls_legs_to_capture_private_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            origin = directory / "origin"
            origin.mkdir()
            store = CertStore.from_store(origin, "mitmproxy", 2048)
            leaf = store.get_cert("localhost", [x509.DNSName("localhost")])
            chain = origin / "server.pem"
            chain.write_bytes(leaf.cert.to_pem() + (origin / "mitmproxy-ca.pem").read_bytes())
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(chain)
            server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                self.check_proxy(directory, server.server_port)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def check_proxy(self, directory, origin_port):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        confdir = directory / "proxy"
        keylog = directory / "capture.keys"
        env = dict(os.environ, MITMPROXY_SSLKEYLOGFILE=str(keylog))
        with (directory / "proxy.log").open("wb") as log:
            # Trust the fixture CA only in this proxy, never in the OS store.
            proxy = subprocess.Popen([
                sys.executable, "-c", "from mitmproxy.tools.main import mitmdump; mitmdump()",
                "--mode", "regular", "--listen-host", "127.0.0.1", "--listen-port", str(port),
                "--set", f"confdir={confdir}", "--set",
                f"ssl_verify_upstream_trusted_ca={directory / 'origin' / 'mitmproxy-ca-cert.pem'}",
            ], env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            try:
                deadline = time.monotonic() + 20
                while True:
                    self.assertIsNone(proxy.poll(), "proxy exited before readiness")
                    try:
                        connection = socket.create_connection(("127.0.0.1", port), timeout=1)
                        break
                    except OSError:
                        self.assertLess(time.monotonic(), deadline, "proxy startup timed out")
                        time.sleep(0.05)
                with connection:
                    connection.settimeout(10)
                    connection.sendall(f"CONNECT localhost:{origin_port} HTTP/1.1\r\nHost: localhost:{origin_port}\r\n\r\n".encode())
                    headers = bytearray()
                    while not headers.endswith(b"\r\n\r\n"):
                        byte = connection.recv(1)
                        self.assertTrue(byte, "proxy closed CONNECT")
                        headers.extend(byte)
                        self.assertLess(len(headers), 8192)
                    self.assertIn(b" 200 ", headers)
                    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    client_context.load_verify_locations(confdir / "mitmproxy-ca-cert.pem")
                    with client_context.wrap_socket(connection, server_hostname="localhost") as tls:
                        tls.sendall(b"GET /fixture HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                        response = bytearray()
                        while chunk := tls.recv(8192):
                            response.extend(chunk)
                        self.assertIn(b'{"fixture":"decrypted"}', response)
                entries = [line.split() for line in keylog.read_text().splitlines() if line and not line.startswith("#")]
                # Each TLS leg has a different ClientHello random. Do not print secrets.
                randoms = {fields[1] for fields in entries if len(fields) == 3}
                self.assertGreaterEqual(len(randoms), 2)
            finally:
                proxy.terminate()
                try:
                    proxy.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proxy.kill()
                    proxy.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
