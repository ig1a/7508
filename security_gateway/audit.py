"""Append-only security decision audit; never stores payload or secret values."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock


class SecurityAuditLogger:
    def __init__(self, path: str | Path = "reports/security_audit.jsonl"):
        self.path = Path(path)
        self._lock = Lock()

    def write(self, *, session_id: str, trial_id: str | None, mode: str,
              decision: str, reason_code: str, session_label: str,
              detector_names: tuple[str, ...] = (), entity_types: tuple[str, ...] = (),
              inspection_complete: bool = True, payload_bytes: int = 0,
              latency_ms: float = 0.0) -> None:
        record = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "session_id": session_id,
            "trial_id": trial_id,
            "mode": mode,
            "decision": decision,
            "reason_code": reason_code,
            "session_label": session_label,
            "detectors": list(detector_names),
            "entity_types": list(entity_types),
            "inspection_complete": inspection_complete,
            "payload_bytes": payload_bytes,
            "latency_ms": round(latency_ms, 3),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
