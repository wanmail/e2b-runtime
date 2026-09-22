#!/usr/bin/env python3
"""Dump every HTTP request (method, path, headers, body) then echo a 200."""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class CaptureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:
        sys.stdout.write("[capture] " + (fmt % args) + "\n")
        sys.stdout.flush()

    def _dump(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        sys.stdout.write("\n========== CAPTURED REQUEST ==========\n")
        sys.stdout.write(f"{self.command} {self.path} {self.request_version}\n")
        for k, v in self.headers.items():
            sys.stdout.write(f"{k}: {v}\n")
        if body:
            sys.stdout.write("--- body ---\n")
            sys.stdout.write(body.decode("utf-8", errors="replace"))
            sys.stdout.write("\n")
        sys.stdout.write("======================================\n\n")
        sys.stdout.flush()
        return body

    def do_GET(self) -> None:
        self._reply(self._dump())

    def do_POST(self) -> None:
        self._reply(self._dump())

    def do_PUT(self) -> None:
        self._reply(self._dump())

    def do_HEAD(self) -> None:
        self._dump()
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _reply(self, body: bytes) -> None:
        msg = b"ok: request captured\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(msg)))
        self.send_header("X-Captured-Path", self.path)
        self.end_headers()
        self.wfile.write(msg)


def main() -> None:
    host, port = "0.0.0.0", 8080
    httpd = ThreadingHTTPServer((host, port), CaptureHandler)
    print(f"[capture] listening on {host}:{port}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
