"""
src/workload/server_app.py
--------------------------
Simple HTTP/TCP service listening on port 8080.
Logs all incoming connections and request details.
Runs inside the target-server container (172.28.0.20).
"""

import http.server
import logging
import os
import socket
import socketserver
import time
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SERVER] %(message)s",
)
logger = logging.getLogger(__name__)

HOST = "0.0.0.0"
PORT = int(os.environ.get("SERVER_PORT", 8080))


class AegisRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP request handler that logs every connection and responds 200 OK."""

    def log_message(self, format: str, *args: Any) -> None:  # type: ignore[override]
        """Override to route logs through Python logging."""
        logger.info(
            "Connection from %s — %s",
            self.client_address[0],
            format % args,
        )

    def do_GET(self) -> None:
        """Handle GET requests — used by the client heartbeat."""
        body = b"AegisNet Target Server - OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        """Handle POST requests — used by the client workload."""
        content_length = int(self.headers.get("Content-Length", 0))
        body_in = self.rfile.read(content_length) if content_length > 0 else b""
        logger.info("POST body (%d bytes): %r", len(body_in), body_in[:80])
        response = b"ACK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def main() -> None:
    logger.info("AegisNet target-server starting on %s:%d", HOST, PORT)
    # Allow address reuse so the container can restart cleanly
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer((HOST, PORT), AegisRequestHandler) as httpd:
        logger.info("Listening — ready for client workload and health probes")
        httpd.serve_forever()


if __name__ == "__main__":
    main()
