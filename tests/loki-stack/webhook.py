"""Minimal Alertmanager webhook receiver for the Loki smoke test.

Runs inside the compose network (the Docker host firewall blocks
container-to-host connections), appending every received payload to
``/received/alerts.jsonl`` for tools/loki_check.py to read.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer

OUTPUT = "/received/alerts.jsonl"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        with open(OUTPUT, "ab") as handle:
            handle.write(body + b"\n")
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
