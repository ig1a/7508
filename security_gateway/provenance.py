"""Session-level, monotonic provenance labels.

Labels must originate from the trusted local task runner / corpus labeller.
This module never reads the canary registry.
"""

from security_gateway.models import SecurityLabel


def parse_label(value: str | SecurityLabel | None) -> SecurityLabel:
    if value is None:
        return SecurityLabel.UNKNOWN
    try:
        return value if isinstance(value, SecurityLabel) else SecurityLabel(value)
    except (TypeError, ValueError):
        return SecurityLabel.UNKNOWN


def merge_labels(current: SecurityLabel | None, incoming: str | SecurityLabel | None) -> SecurityLabel:
    """Merge one trusted turn label into a session label.

    First turn establishes the session label. Thereafter UNKNOWN and
    CONFIDENTIAL are sticky; PUBLIC cannot downgrade either state.
    """
    new = parse_label(incoming)
    if current is None:
        return new
    old = parse_label(current)
    if old is SecurityLabel.CONFIDENTIAL or new is SecurityLabel.CONFIDENTIAL:
        return SecurityLabel.CONFIDENTIAL
    if old is SecurityLabel.UNKNOWN or new is SecurityLabel.UNKNOWN:
        return SecurityLabel.UNKNOWN
    return SecurityLabel.PUBLIC
