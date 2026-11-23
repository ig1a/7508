"""Temporary local API -> gate -> relay -> provider stack for integration checks.

Model servers are supplied separately; all wrapper ports are allocated dynamically.
Use in a dedicated process (the assistant's single-process store is shared).
"""
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
import os
import secrets
import socket
from threading import Thread
import time

import uvicorn

from provider import make_provider
from relay7508.config import ActivePolicy, RelayConfig
from relay7508.relay import make_server
from security_gateway.audit import SecurityAuditLogger
from security_gateway.engine import SecurityForwardingGate


@dataclass
class Stack:
    url: str
    token: str
    output: Path


@contextmanager
def local_stack(output, *, internal_url, external_url, append_text):
    import main
    import model_backend
    import routing
    from sessions import store

    if store.histories:
        raise RuntimeError("Run integration in a dedicated process with an empty session store")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    old_env = {k: os.environ.get(k) for k in ("BRANDAI_RUNNER_TOKEN", "BRANDAI_INTERNAL_URL")}
    old_values = model_backend.OLLAMA_CHAT_URL, routing.EXTERNAL_CHAT_URL, routing.gate, store.provenance_audit_path
    token = secrets.token_urlsafe(32)
    os.environ["BRANDAI_RUNNER_TOKEN"] = token
    os.environ["BRANDAI_INTERNAL_URL"] = internal_url
    model_backend.OLLAMA_CHAT_URL = internal_url
    store.provenance_audit_path = output / "provenance.jsonl"
    routing.gate = SecurityForwardingGate(audit=SecurityAuditLogger(output / "gate.jsonl"))
    servers = []
    threads = []
    api = api_thread = sock = None
    try:
        provider = make_provider(upstream=external_url, port=0, log_path=output / "provider.jsonl")
        servers.append(provider)
        relay = make_server(RelayConfig(port=0, upstream=f"http://127.0.0.1:{provider.server_port}/api/chat",
                                       log=str(output / "relay.jsonl"),
                                       active=ActivePolicy(append_text=append_text)))
        servers.append(relay)
        routing.EXTERNAL_CHAT_URL = f"http://127.0.0.1:{relay.server_port}/api/chat"
        for server in servers:
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            threads.append(thread)
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        api_port = sock.getsockname()[1]
        api = uvicorn.Server(uvicorn.Config(main.app, log_level="error", access_log=False))
        api_thread = Thread(target=api.run, kwargs={"sockets": [sock]}, daemon=True)
        api_thread.start()
        deadline = time.monotonic() + 15
        while not api.started:
            if not api_thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("Integration API did not start")
            time.sleep(0.05)
        yield Stack(f"http://127.0.0.1:{api_port}", token, output)
    finally:
        if api:
            api.should_exit = True
        if api_thread:
            api_thread.join(timeout=10)
        if sock:
            sock.close()
        for server, thread in reversed(list(zip(servers, threads))):
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
        for server in servers[len(threads):]:
            server.server_close()
        with store.lock:
            for sid in list(store.histories):
                store.delete(sid)
        model_backend.OLLAMA_CHAT_URL, routing.EXTERNAL_CHAT_URL, routing.gate, store.provenance_audit_path = old_values
        for name, value in old_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
