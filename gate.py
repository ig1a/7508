"""Outbound gate contract and default security implementation."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class OutboundRequest:
    # The exact immutable bytes checked by the gate are the bytes sent by routing.py.
    url: str
    body: bytes
    method: str = "POST"
    headers: tuple[tuple[str, str], ...] = (("Content-Type", "application/json"),)
    gate_mode: str = "M1_M2"
    trial_id: str | None = None
    relay_mode: str = "passive"


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    reason_code: str = "UNSPECIFIED"
    session_label: str = "UNKNOWN"
    detection_types: tuple[str, ...] = ()
    inspection_complete: bool = True
    latency_ms: float = 0.0


class ForwardingGate(Protocol):
    def inspect(self, request: OutboundRequest, *, session_id: str) -> GateDecision:
        ...


class PlaceholderGate:
    """Legacy fail-closed placeholder retained for tests and compatibility."""

    def inspect(self, request: OutboundRequest, *, session_id: str) -> GateDecision:
        return GateDecision(allowed=False, reason_code="PLACEHOLDER_DENY")


# Imported after the protocol definitions to avoid a circular import.
from security_gateway.engine import SecurityForwardingGate  # noqa: E402
