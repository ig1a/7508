"""Deterministic policy decision logic."""

from security_gateway.models import DecisionMode, DetectionReport, PolicyResult, SecurityLabel


def evaluate_policy(
    *,
    mode: str | DecisionMode,
    session_label: SecurityLabel,
    detection: DetectionReport | None = None,
) -> PolicyResult:
    mode = mode if isinstance(mode, DecisionMode) else DecisionMode(mode)
    detection = detection or DetectionReport()

    if mode is DecisionMode.NONE:
        return PolicyResult(True, "GATE_DISABLED_FOR_CONTROL", session_label, detection)

    if mode in (DecisionMode.M1, DecisionMode.M1_M2):
        if not detection.inspection_complete:
            return PolicyResult(False, detection.error_code or "INSPECTION_INCOMPLETE", session_label, detection)
        if detection.has_sensitive_data:
            return PolicyResult(False, "SENSITIVE_CONTENT", session_label, detection)

    if mode in (DecisionMode.M2, DecisionMode.M1_M2):
        if session_label is SecurityLabel.CONFIDENTIAL:
            return PolicyResult(False, "CONFIDENTIAL_SESSION", session_label, detection)
        if session_label is not SecurityLabel.PUBLIC:
            return PolicyResult(False, "UNKNOWN_SESSION", session_label, detection)

    return PolicyResult(True, "PUBLIC_AND_CLEAN", session_label, detection)
