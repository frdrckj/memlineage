"""Shared record shape for the store adapters."""

import hashlib
import json
import uuid
from typing import Any

from memlineage import MemlineageError
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


def stored_provenance(record: dict[str, Any]) -> dict[str, Any]:
    """Provenance taken from a released audit record, not the current source block."""
    parents = record.get("parent_ids") or []
    taint = record.get("taint") or []
    return {
        "source_kind": record["source_kind"],
        "source_ref": record["source_ref"],
        "trust": record["trust"],
        "principal": record["principal"],
        "session_id": record["session_id"],
        "parent_ids": list(parents),
        "taint": list(taint),
    }


def require_hash(record: dict[str, Any]) -> None:
    """Refuse a released record whose text no longer matches its provenance."""
    digest = hashlib.sha256(str(record["content"]).encode()).hexdigest()
    if digest != record["content_sha256"]:
        raise MemlineageError("content hash does not match provenance")


def decision_dict(action: str, rule_id: str, weight: float | None) -> dict[str, Any]:
    return {"action": action, "rule_id": rule_id, "retrieval_weight": weight}
