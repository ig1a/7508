"""Shared, dependency-light data models for the security gateway."""

from enum import Enum
from dataclasses import dataclass, field


class SecurityLabel(str, Enum):
    PUBLIC = "PUBLIC"
    CONFIDENTIAL = "CONFIDENTIAL"
    UNKNOWN = "UNKNOWN"


class DecisionMode(str, Enum):
    NONE = "none"
    M1 = "M1"
    M2 = "M2"
    M1_M2 = "M1_M2"


@dataclass(frozen=True)
class DetectionFinding:
    detector: str
    entity_type: str
    source_variant: str = "raw"
    score: float | None = None


@dataclass(frozen=True)
class DetectionReport:
    findings: tuple[DetectionFinding, ...] = ()
    inspection_complete: bool = True
    error_code: str | None = None

    @property
    def has_sensitive_data(self) -> bool:
        return bool(self.findings)

    @property
    def detector_names(self) -> tuple[str, ...]:
        return tuple(sorted({item.detector for item in self.findings}))

    @property
    def entity_types(self) -> tuple[str, ...]:
        return tuple(sorted({item.entity_type for item in self.findings}))


@dataclass(frozen=True)
class PolicyResult:
    allowed: bool
    reason_code: str
    session_label: SecurityLabel
    detection: DetectionReport = field(default_factory=DetectionReport)
