"""Authentication boundary for trusted local experiment-label ingestion."""

from __future__ import annotations

import hmac
import os

RUNNER_TOKEN_ENV = "BRANDAI_RUNNER_TOKEN"
RUNNER_TOKEN_HEADER = "X-Experiment-Token"


def configured_runner_token() -> str | None:
    value = os.environ.get(RUNNER_TOKEN_ENV)
    return value if value and value.strip() else None


def is_trusted_runner(provided_token: str | None, expected_token: str | None = None) -> bool:
    """Constant-time comparison; missing server/client token is never trusted."""
    expected = expected_token if expected_token is not None else configured_runner_token()
    if not expected or not provided_token:
        return False
    return hmac.compare_digest(provided_token, expected)
