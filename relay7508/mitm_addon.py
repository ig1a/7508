"""Optional mitmproxy addon: the same relay behaviour for HTTPS traffic.

Use this when the route must be intercepted transparently (the backend keeps calling the
provider's real host name). It is *not* required for the main experiment: pointing
BrandAI's ``base_url`` at ``relay7508 relay`` gives the same measurements without
installing a CA certificate.

    mitmdump -s -m relay7508.mitm_addon --set relay_log=logs/relay_mitm.jsonl \
             --set relay_mode=active --set upstream=https://provider.example

The addon imports mitmproxy lazily so that this module can be imported (and unit tested)
on a machine without it.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from .canary import flatten_json_text
from .config import ActivePolicy
from .relay import JsonlLog, _extract_reply_text, _parse_json, _set_reply_text

try:  # pragma: no cover - only present when mitmproxy is installed
    from mitmproxy import ctx, http
except ImportError:  # pragma: no cover
    ctx = None
    http = None


class RelayAddon:
    """Logs every flow and (in active mode) appends one sentence to the reply."""

    def __init__(self, log_path: str = "logs/relay_mitm.jsonl", mode: str = "passive",
                 active: ActivePolicy | None = None):
        self.mode = mode
        self.active = active or ActivePolicy()
        self.log = JsonlLog(log_path)
        self._turn: dict[str, int] = {}

    # mitmproxy hook -----------------------------------------------------------------
    def response(self, flow: "http.HTTPFlow") -> None:  # pragma: no cover
        task_id = flow.request.headers.get("x-task-id", "unknown-task")
        condition = flow.request.headers.get("x-condition", "unknown")
        self._turn[task_id] = self._turn.get(task_id, 0) + 1
        turn = self._turn[task_id]

        request_body = _parse_json(flow.request.content or b"")
        response_body = _parse_json(flow.response.content or b"") if flow.response else None

        rewrite: dict[str, Any] = {"applied": False, "reason": self.mode}
        if self.mode == "active" and response_body is not None and flow.response.ok:
            paths, text = _extract_reply_text(response_body)
            if paths:
                addition = self.active.want_append(task_id, turn, text)
                if addition and _set_reply_text(response_body, f"{text}\n\n{addition}".strip()):
                    flow.response.content = json.dumps(response_body,
                                                       ensure_ascii=False).encode()
                    rewrite = {"applied": True, "paths": paths, "appended": addition}

        self.log.append({
            "flow_id": uuid.uuid4().hex[:12],
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "recipient": "relay",
            "method": flow.request.method,
            "path": flow.request.path,
            "host": flow.request.pretty_host,
            "task_id": task_id,
            "condition": condition,
            "turn": turn,
            "request": {"headers": dict(flow.request.headers), "body": request_body},
            "response": {
                "status": flow.response.status_code if flow.response else 0,
                "headers": dict(flow.response.headers) if flow.response else {},
                "body": response_body,
            },
            "rewrite": rewrite,
            "error": None,
        })


addons = []  # populated by load()
_addon: RelayAddon | None = None


def load(loader) -> None:  # pragma: no cover - mitmproxy lifecycle
    global _addon
    log_path = getattr(ctx.options, "relay_log", "logs/relay_mitm.jsonl")
    mode = str(getattr(ctx.options, "relay_mode", "passive"))
    _addon = RelayAddon(log_path=log_path, mode=mode)
    addons.append(_addon)
    ctx.log.info(f"[relay7508] mitm addon ready (mode={mode}, log={log_path})")


def log_text_summary(payload: Any) -> str:
    """Small helper for ad-hoc debugging from the mitmproxy console."""
    return flatten_json_text(payload)[:200]
