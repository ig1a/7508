"""Concrete ForwardingGate implementation for the existing BrandAI interface."""

from __future__ import annotations

from time import perf_counter
from urllib.parse import urlsplit

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gate import OutboundRequest
from security_gateway.audit import SecurityAuditLogger
from security_gateway.detection import HybridPayloadScanner
from security_gateway.models import DecisionMode, DetectionReport, SecurityLabel
from security_gateway.policy import evaluate_policy


class SecurityForwardingGate:
    def __init__(self, *, scanner: HybridPayloadScanner | None = None,
                 audit: SecurityAuditLogger | None = None):
        self.scanner = scanner or HybridPayloadScanner()
        self.audit = audit or SecurityAuditLogger()

    def inspect(self, request: OutboundRequest, *, session_id: str):
        from gate import GateDecision

        started = perf_counter()
        mode = getattr(request, "gate_mode", DecisionMode.M1_M2.value)
        trial_id = getattr(request, "trial_id", None)
        try:
            # Imported here to avoid a module-level dependency cycle.
            from sessions import store
            label = store.get_security_label(session_id)
            try:
                mode_enum = DecisionMode(mode)
            except (ValueError, TypeError):
                latency_ms = (perf_counter() - started) * 1000
                self.audit.write(
                    session_id=session_id, trial_id=trial_id, mode=str(mode),
                    decision="DENY", reason_code="INVALID_GATE_MODE",
                    session_label=label.value, inspection_complete=False,
                    payload_bytes=len(request.body), latency_ms=latency_ms,
                )
                return GateDecision(
                    allowed=False, reason_code="INVALID_GATE_MODE",
                    session_label=label.value, inspection_complete=False,
                    latency_ms=round(latency_ms, 3),
                )

            detection = DetectionReport()
            if mode_enum in (DecisionMode.M1, DecisionMode.M1_M2):
                # Do not classify fixed transport metadata (loopback address,
                # model tag, Trial ID, Relay mode, content type) as user secrets.
                # Scan unknown header values and any URL userinfo/query instead.
                # The complete JSON body remains strictly validated and scanned.
                url = urlsplit(request.url)
                metadata = []
                if url.username or url.password:
                    metadata.append(f"URL_AUTH={url.username or ''}:{url.password or ''}")
                if url.query:
                    metadata.append(url.query)
                for key, value in request.headers:
                    if key.lower() not in {"content-type", "x-trial-id", "x-relay-mode"}:
                        metadata.append(f"{key}: {value}")
                detection = self.scanner.scan(request.body, additional_texts=tuple(metadata))

            result = evaluate_policy(mode=mode_enum, session_label=label, detection=detection)
            latency_ms = (perf_counter() - started) * 1000
            self.audit.write(
                session_id=session_id,
                trial_id=trial_id,
                mode=mode_enum.value,
                decision="ALLOW" if result.allowed else "DENY",
                reason_code=result.reason_code,
                session_label=result.session_label.value,
                detector_names=result.detection.detector_names,
                entity_types=result.detection.entity_types,
                inspection_complete=result.detection.inspection_complete,
                payload_bytes=len(request.body),
                latency_ms=latency_ms,
            )
            return GateDecision(
                allowed=result.allowed,
                reason_code=result.reason_code,
                session_label=result.session_label.value,
                detection_types=result.detection.entity_types,
                inspection_complete=result.detection.inspection_complete,
                latency_ms=round(latency_ms, 3),
            )
        except Exception:
            # Gate exceptions must never permit forwarding.
            latency_ms = (perf_counter() - started) * 1000
            try:
                self.audit.write(
                    session_id=session_id, trial_id=trial_id, mode=str(mode),
                    decision="DENY", reason_code="GATE_FAILURE",
                    session_label="UNKNOWN", inspection_complete=False,
                    payload_bytes=len(request.body), latency_ms=latency_ms,
                )
            except Exception:
                pass
            return GateDecision(
                allowed=False, reason_code="GATE_FAILURE", session_label="UNKNOWN",
                inspection_complete=False, latency_ms=round(latency_ms, 3),
            )
