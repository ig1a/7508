"""Concrete ForwardingGate implementation for the existing BrandAI interface."""

from __future__ import annotations

from queue import Empty, Queue
from threading import Lock, Thread
from time import perf_counter
from urllib.parse import urlsplit

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from gate import OutboundRequest
from security_gateway.audit import SecurityAuditLogger
from security_gateway.detection import HybridPayloadScanner
from security_gateway.models import DecisionMode, DetectionReport, SecurityLabel
from security_gateway.policy import evaluate_policy
from security_gateway.trial import is_valid_trial_id


class SecurityForwardingGate:
    def __init__(self, *, scanner: HybridPayloadScanner | None = None,
                 audit: SecurityAuditLogger | None = None,
                 inspection_timeout_s: float = 30.0):
        if inspection_timeout_s <= 0:
            raise ValueError("inspection_timeout_s must be positive")
        self.scanner = scanner or HybridPayloadScanner()
        self.audit = audit or SecurityAuditLogger()
        self.inspection_timeout_s = inspection_timeout_s
        self._timeout_lock = Lock()
        self._scanner_timed_out = False

    def _scan_with_timeout(self, body: bytes, metadata: tuple[str, ...]) -> DetectionReport:
        with self._timeout_lock:
            if self._scanner_timed_out:
                return DetectionReport(
                    inspection_complete=False,
                    error_code="DETECTOR_DISABLED_AFTER_TIMEOUT",
                )

        outcome: Queue[tuple[str, object]] = Queue(maxsize=1)

        def scan() -> None:
            try:
                outcome.put(("result", self.scanner.scan(body, additional_texts=metadata)))
            except Exception as exc:
                outcome.put(("error", exc))

        worker = Thread(target=scan, name="security-gateway-scan", daemon=True)
        worker.start()
        worker.join(self.inspection_timeout_s)
        if worker.is_alive():
            # Python cannot safely terminate a detector thread. Permanently fail
            # this gate instance closed so repeated requests cannot accumulate
            # additional blocked detector workers.
            with self._timeout_lock:
                self._scanner_timed_out = True
            return DetectionReport(inspection_complete=False, error_code="DETECTOR_TIMEOUT")

        try:
            kind, value = outcome.get_nowait()
        except Empty:
            return DetectionReport(inspection_complete=False, error_code="DETECTOR_NO_RESULT")
        if kind == "error":
            if isinstance(value, BaseException):
                raise value
            return DetectionReport(inspection_complete=False, error_code="DETECTOR_FAILURE")
        if not isinstance(value, DetectionReport):
            return DetectionReport(inspection_complete=False, error_code="INVALID_DETECTOR_RESULT")
        return value

    def inspect(self, request: OutboundRequest, *, session_id: str):
        from gate import GateDecision

        started = perf_counter()
        mode = getattr(request, "gate_mode", DecisionMode.M1_M2.value)
        raw_trial_id = getattr(request, "trial_id", None)
        trial_headers = [
            value for key, value in request.headers if key.lower() == "x-trial-id"
        ]
        trial_id = raw_trial_id if is_valid_trial_id(raw_trial_id) else None
        try:
            # Imported here to avoid a module-level dependency cycle.
            from sessions import store
            label = store.get_security_label(session_id)
            trial_metadata_valid = (
                (raw_trial_id is None and not trial_headers)
                or (
                    trial_id is not None
                    and trial_headers == [trial_id]
                )
            )
            if not trial_metadata_valid:
                latency_ms = (perf_counter() - started) * 1000
                self.audit.write(
                    session_id=session_id, trial_id=None, mode=str(mode),
                    decision="DENY", reason_code="INVALID_TRIAL_ID",
                    session_label=label.value, inspection_complete=False,
                    payload_bytes=len(request.body), latency_ms=latency_ms,
                )
                return GateDecision(
                    allowed=False, reason_code="INVALID_TRIAL_ID",
                    session_label=label.value, inspection_complete=False,
                    latency_ms=round(latency_ms, 3),
                )
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
                detection = self._scan_with_timeout(request.body, tuple(metadata))

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
