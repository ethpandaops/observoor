#!/usr/bin/env python3
"""Minimal mock HTTP sink for observoor CPU overhead benchmark.

Accepts POST/PUT requests to any path and returns 200 immediately, discarding
the body. Used so the bench config can enable observoor's HTTP exporter and
exercise the full aggregation pipeline without measuring real network I/O.

Binds to 127.0.0.1:18999 by default. No dependencies beyond stdlib.
"""

import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18999


class Handler(BaseHTTPRequestHandler):
    def _accept(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length:
            # Drain the body without storing it.
            remaining = length
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        self._accept()

    def do_PUT(self):
        self._accept()

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress request logging.


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"mock-sink: listening on 127.0.0.1:{PORT}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
