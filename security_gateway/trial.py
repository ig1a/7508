"""Validation for experiment correlation identifiers crossing trust boundaries."""

from __future__ import annotations

import re


MAX_TRIAL_ID_LENGTH = 160
# Relay attack state and log attribution are keyed by the full trial ID and outlive a runner
# invocation, so every ID carries the batch that produced it.
_BATCH_ID = r"b[0-9]{8}T[0-9]{6}-[0-9a-f]{6}"
_BATCH_ID_RE = re.compile(_BATCH_ID)
_TRIAL_ID_RE = re.compile(
    r"^(?:C0|C[12]-(?:none|M1|M2|M1_M2)):"
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}:"
    r"r[1-9][0-9]{0,5}:"
    + _BATCH_ID + r"$"
)


def is_valid_batch_id(value: str | None) -> bool:
    return isinstance(value, str) and _BATCH_ID_RE.fullmatch(value) is not None


def is_valid_trial_id(value: str | None) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= MAX_TRIAL_ID_LENGTH
        and _TRIAL_ID_RE.fullmatch(value) is not None
    )
