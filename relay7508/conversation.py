"""Conversation identity derived from the request body.

BrandAI's ``routing.py`` posts Ollama-style chat JSON and sends no task metadata headers,
so the relay cannot rely on ``X-Task-Id``. Two values are recoverable from the payload
alone and are enough to attribute leak evidence to a task:

* ``turn``     - the number of user messages in the history (BrandAI resends the whole
                 conversation every turn, so this counts turns exactly and is stateless);
* ``conv_id``  - a short hash of the *first* user message, stable for every turn of one
                 conversation.

``scan`` recomputes ``conv_id`` from the task manifest's opening prompt, so a recorded
conversation can be mapped back to its task without touching the assistant's code. If a
harness *does* send ``X-Task-Id``, the relay prefers it and this module is not used.
"""

from __future__ import annotations

import hashlib
from typing import Any


def conversation_id(text: str) -> str:
    """Stable 12-character id of a conversation opener (whitespace-normalised)."""
    normalised = " ".join(text.split())
    return hashlib.sha1(normalised.encode("utf-8")).hexdigest()[:12]


def conversation_key(body: Any) -> tuple[str | None, int | None]:
    """Return ``(conv_id, turn)`` from a chat request body, or ``(None, None)``."""
    if not isinstance(body, dict):
        return None, None
    messages = body.get("messages")
    if not isinstance(messages, list):
        return None, None
    users = [item for item in messages
             if isinstance(item, dict) and item.get("role") == "user"]
    if not users:
        return None, None
    opener = users[0].get("content")
    conv_id = conversation_id(opener) if isinstance(opener, str) and opener.strip() else None
    return conv_id, len(users)
