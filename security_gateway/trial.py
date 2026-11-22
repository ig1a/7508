"""Validation for experiment correlation identifiers crossing trust boundaries."""

from __future__ import annotations

import re


MAX_TRIAL_ID_LENGTH = 128
_TRIAL_ID_RE = re.compile(
    r"^(?:C0|C[12]-(?:none|M1|M2|M1_M2)):"
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}:"
    r"r[1-9][0-9]{0,5}$"
)


def is_valid_trial_id(value: str | None) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= MAX_TRIAL_ID_LENGTH
        and _TRIAL_ID_RE.fullmatch(value) is not None
    )
