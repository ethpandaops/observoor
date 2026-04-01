#!/usr/bin/env python3
"""Minimal mock beacon node for observoor CPU overhead benchmark.

Serves the three endpoints that observoor requires at startup:
  - GET /eth/v1/beacon/genesis
  - GET /eth/v1/config/spec
  - GET /eth/v1/node/syncing

Binds to 127.0.0.1:15999 by default. No dependencies beyond stdlib.
"""

import json
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 15999

RESPONSES = {
    "/eth/v1/beacon/genesis": {
        "data": {
            "genesis_time": "1695902400",
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "genesis_fork_version": "0x00000000",
        }
    },
    "/eth/v1/config/spec": {
        "data": {
            "SECONDS_PER_SLOT": "12",
            "SLOTS_PER_EPOCH": "32",
            "PRESET_BASE": "mainnet",
        }
    },
    "/eth/v1/node/syncing": {
        "data": {
            "head_slot": "0",
            "sync_distance": "0",
            "is_syncing": False,
            "is_optimistic": False,
            "el_offline": False,
        }
    },
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = RESPONSES.get(self.path)
        if body is None:
            self.send_error(404)
            return
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        pass  # Suppress request logging.


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", PORT), Handler)
    print(f"mock-beacon: listening on 127.0.0.1:{PORT}", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
