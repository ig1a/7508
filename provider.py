"""Local external-provider wrapper with an independent ingress log.

Run a separate Ollama process on 11437, then `python provider.py` on 11436.
Only synthetic experiment data belongs in these full-body logs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from urllib.parse import urlsplit

from relay7508.conversation import conversation_key


class IngressLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self.lock = Lock()

    def append(self, record):
        with self.lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")


def make_provider(*, upstream="http://127.0.0.1:11437/api/chat", port=11436,
                  log_path="reports/provider_ingress.jsonl", timeout=120):
    parts = urlsplit(upstream)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        raise ValueError("Provider upstream must be an HTTP(S) endpoint without credentials")
    internal = urlsplit(os.environ.get("BRANDAI_INTERNAL_URL", "http://127.0.0.1:11434/api/chat"))
    def endpoint(p):
        host = "loopback" if p.hostname in {"localhost", "127.0.0.1", "::1"} else p.hostname
        return host, p.port or (443 if p.scheme == "https" else 80)
    if endpoint(parts) == endpoint(internal) or endpoint(parts) == ("loopback", port):
        raise ValueError("External provider needs a separate model endpoint")
    ingress = IngressLog(log_path)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, raw):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path == "/health":
                self.reply(200, b'{"status":"ok","service":"external-provider"}')
            else:
                self.send_error(404)

        def do_POST(self):
            if self.path != "/api/chat":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 131072 or self.headers.get("Transfer-Encoding"):
                    self.send_error(413)
                    return
                raw = self.rfile.read(length)
                body = json.loads(raw)
                if not isinstance(body, dict) or body.get("stream") is not False or not isinstance(body.get("messages"), list):
                    self.send_error(400, "Non-streaming chat JSON required")
                    return
            except (ValueError, UnicodeError):
                self.send_error(400)
                return
            conv_id, turn = conversation_key(body)
            trial_id = self.headers.get("X-Trial-Id")
            mode = self.headers.get("X-Relay-Mode", "passive")
            # Log receipt BEFORE invoking the model: even an upstream failure is exposure.
            record = {"recipient": "provider", "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                      "trial_id": trial_id, "task_id": trial_id or "unknown-task", "conv_id": conv_id,
                      "turn": turn, "condition": "C2" if mode == "active" else "C1",
                      "request": {"body": body, "body_sha256": hashlib.sha256(raw).hexdigest(),
                                  "headers": {"content-type": self.headers.get("Content-Type"),
                                              "x-trial-id": trial_id, "x-relay-mode": mode}}}
            try:
                ingress.append(record)
            except OSError:
                self.reply(503, b'{"error":"provider ingress log unavailable"}')
                return
            connection_type = HTTPSConnection if parts.scheme == "https" else HTTPConnection
            connection = connection_type(parts.hostname, parts.port or (443 if parts.scheme == "https" else 80), timeout=timeout)
            try:
                target = parts.path or "/api/chat"
                if parts.query:
                    target += "?" + parts.query
                connection.request("POST", target, body=raw, headers={"Content-Type": "application/json"})
                response = connection.getresponse()
                payload = response.read()
                # Redirects never initiate a second request.
                self.reply(response.status, payload)
            except (OSError, ValueError, HTTPException):
                self.reply(502, b'{"error":"external model unavailable"}')
            finally:
                connection.close()

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", default="http://127.0.0.1:11437/api/chat")
    parser.add_argument("--port", type=int, default=11436)
    parser.add_argument("--log", default="reports/provider_ingress.jsonl")
    args = parser.parse_args()
    server = make_provider(upstream=args.upstream, port=args.port, log_path=args.log)
    print(f"External provider: http://127.0.0.1:{server.server_port}/api/chat", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
