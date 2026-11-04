"""Mock Lumia policy endpoint for tests.

Usage: python3 mock_server.py <state_dir>

Writes the chosen port to <state_dir>/port. For each POST /policy/<hook_type>
it records the request to <state_dir>/last_request.json and replies with
<state_dir>/response.json (default {"decision":"allow"}) and the status code
in <state_dir>/status (default 200). <state_dir>/delay makes it sleep N seconds.
"""

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

STATE = sys.argv[1]


def read(name, default):
    try:
        with open(os.path.join(STATE, name), encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return default


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length).decode("utf-8")
        if self.path.startswith("/oidc/"):
            # Devin OIDC token exchange: record the form and answer <state_dir>/oidc_response.json.
            with open(os.path.join(STATE, "oidc_request.txt"), "a", encoding="utf-8") as f:
                f.write(body + "\n")
            payload = read("oidc_response.json", '{"access_token":"aud.scoped.token","token_type":"Bearer"}').encode()
            self.send_response(int(read("oidc_status", "200").strip() or 200))
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        record = {
            "path": self.path,
            "headers": {k.lower(): v for k, v in self.headers.items()},
            "raw_body": body,
        }
        try:
            record["body"] = json.loads(body)
        except ValueError:
            record["body"] = None
        with open(os.path.join(STATE, "last_request.json"), "w", encoding="utf-8") as f:
            json.dump(record, f)

        delay = float(read("delay", "0") or 0)
        if delay:
            time.sleep(delay)
        payload = read("response.json", '{"decision":"allow"}').encode("utf-8")
        self.send_response(int(read("status", "200").strip() or 200))
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except ConnectionError:  # client gave up (timeout test)
            pass

    def log_message(self, *args):
        pass


server = HTTPServer(("127.0.0.1", 0), Handler)
with open(os.path.join(STATE, "port"), "w", encoding="utf-8") as f:
    f.write(str(server.server_address[1]))
server.serve_forever()
