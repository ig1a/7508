"""Single-process in-memory sessions with atomic monotonic provenance state."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from uuid import uuid4

from fastapi import HTTPException

from security_gateway.models import SecurityLabel
from security_gateway.provenance import merge_labels, parse_label

MAX_TURNS = 4
MAX_SESSIONS = 128
MAX_CONTEXT_BYTES = 12000


class SessionStore:
    def __init__(self, provenance_audit_path: str | Path | None = "reports/provenance_audit.jsonl"):
        self.histories: dict[str, list[dict[str, str]]] = {}
        self.security_labels: dict[str, SecurityLabel | None] = {}
        self.lock = RLock()
        self.provenance_audit_path = Path(provenance_audit_path) if provenance_audit_path else None

    def _audit_transition(self, session_id: str, old: SecurityLabel | None,
                          incoming: SecurityLabel, new: SecurityLabel,
                          source: str) -> None:
        # Metadata only: never write message text, payloads, canaries or credentials.
        if self.provenance_audit_path is None:
            return
        record = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "previous_label": old.value if old is not None else None,
            "incoming_label": incoming.value,
            "resulting_label": new.value,
            "source": source,
        }
        self.provenance_audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self.provenance_audit_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")

    def get_or_create(self, session_id: str | None):
        with self.lock:
            if session_id is not None:
                if session_id not in self.histories:
                    raise HTTPException(404, "会话不存在或已重置，请不带 session_id 开始新会话。")
                return session_id, self.histories[session_id]
            if len(self.histories) >= MAX_SESSIONS:
                raise HTTPException(503, "会话数量已达上限，请删除不用的会话。")
            session_id = str(uuid4())
            self.histories[session_id] = []
            self.security_labels[session_id] = None
            return session_id, self.histories[session_id]

    def update_security_label(self, session_id: str, incoming_label: str | None,
                              *, source: str = "trusted_runner") -> SecurityLabel:
        with self.lock:
            if session_id not in self.histories:
                raise HTTPException(404, "会话不存在或已重置。")
            current = self.security_labels.get(session_id)
            incoming = parse_label(incoming_label)
            updated = merge_labels(current, incoming)
            self.security_labels[session_id] = updated
            if updated != current or current is None:
                self._audit_transition(session_id, current, incoming, updated, source)
            return updated

    def get_security_label(self, session_id: str) -> SecurityLabel:
        with self.lock:
            if session_id not in self.histories:
                return SecurityLabel.UNKNOWN
            current = self.security_labels.get(session_id)
            return current if current is not None else SecurityLabel.UNKNOWN

    def append_turns(self, session_id: str, turns: list[dict[str, str]]) -> None:
        with self.lock:
            if session_id not in self.histories:
                raise HTTPException(404, "会话不存在或已重置。")
            self.histories[session_id].extend(turns)

    def delete(self, session_id: str) -> None:
        with self.lock:
            self.histories.pop(session_id, None)
            self.security_labels.pop(session_id, None)


store = SessionStore()
