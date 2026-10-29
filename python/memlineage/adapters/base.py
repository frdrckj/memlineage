"""Shared record shape for the store adapters."""

import json
import uuid
from typing import Any

from memlineage._context import ActiveWrite


def stable_id(store: str, namespace: str, key: str) -> str:
    """One id for the same store, namespace, and key."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"memlineage:{store}:{namespace}:{key}"))


def text_of(messages: str | list[Any] | dict[str, Any]) -> str:
    """Flatten a Mem0 message into the text the policy sees."""
    if isinstance(messages, str):
        return messages
    if isinstance(messages, dict):
        content = messages.get("content", "")
        return content if isinstance(content, str) else json.dumps(content, sort_keys=True)
    parts: list[str] = []
    for message in messages:
        if isinstance(message, str):
            parts.append(message)
        elif isinstance(message, dict):
            content = message.get("content", "")
            parts.append(content if isinstance(content, str) else str(content))
        else:
            parts.append(str(message))
    return "\n".join(parts)


def provenance_fields(active: ActiveWrite, principal: str, session: str) -> dict[str, Any]:
    """Provenance dict for a record that should not pick up a later source block."""
    return {
        "source_kind": active.source_kind,
        "source_ref": active.source_ref,
        "trust": "untrusted" if active.taint else "trusted",
        "principal": principal,
        "session_id": session,
        "parent_ids": [],
        "taint": sorted(active.taint),
    }


def decision_dict(action: str, rule_id: str, weight: float | None) -> dict[str, Any]:
    return {"action": action, "rule_id": rule_id, "retrieval_weight": weight}
