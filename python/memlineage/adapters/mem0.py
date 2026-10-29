"""Wrap a Mem0 OSS `Memory` so writes are checked and reads are filtered.

Mem0 2.2 keeps `add` synchronous. Pass `infer=False` when the caller already
has the text to store. The wrapper does not call an LLM itself.
"""

from typing import Any

from memlineage import Firewall
from memlineage._context import current
from memlineage.adapters.base import decision_dict, provenance_fields, stable_id, text_of


class GuardedMemory:
    """Same calls as `Memory.add`, `update`, `delete`, `search`, and `get_all`."""

    def __init__(self, inner: Any, firewall: Firewall) -> None:
        self._inner = inner
        self._firewall = firewall

    def add(self, messages: str | list[Any] | dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        """Check, then `add` only when the decision is allow."""
        text = text_of(messages)
        user_id = kwargs.get("user_id")
        principal = current().principal or (user_id if isinstance(user_id, str) else "")
        session = current().session or (
            kwargs.get("run_id") if isinstance(kwargs.get("run_id"), str) else ""
        )
        record_id = stable_id("mem0", principal, text)
        decision = self._firewall.check(
            {
                "id": record_id,
                "content": text,
                "store": "mem0",
                "namespace": ["memories"],
                "key": principal,
            }
        )
        noted = decision_dict(decision.action, decision.rule_id, decision.retrieval_weight)
        if decision.action != "allow":
            return {"results": [], "memlineage": noted}
        metadata = dict(kwargs.get("metadata") or {})
        metadata["memlineage"] = provenance_fields(current(), principal, session or "")
        kwargs["metadata"] = metadata
        result = self._inner.add(messages, **kwargs)
        if isinstance(result, dict):
            merged = dict(result)
            merged["memlineage"] = noted
            return merged
        return {"results": result, "memlineage": noted}

    def update(self, memory_id: str, text: str | None = None, **kwargs: Any) -> Any:
        """Check the new text, then update only when the decision is allow."""
        body = text if text is not None else str(kwargs.get("data", ""))
        decision = self._firewall.check(
            {
                "id": memory_id,
                "content": body,
                "store": "mem0",
                "namespace": ["memories"],
            }
        )
        if decision.action != "allow":
            return {
                "memlineage": decision_dict(
                    decision.action, decision.rule_id, decision.retrieval_weight
                )
            }
        return self._inner.update(memory_id, text=text, **kwargs)

    def delete(self, memory_id: str) -> Any:
        """Log the delete and pass it through when the decision is allow."""
        decision = self._firewall.check(
            {
                "id": memory_id,
                "content": f"delete {memory_id}",
                "store": "mem0",
                "namespace": ["memories"],
            }
        )
        if decision.action != "allow":
            return {
                "memlineage": decision_dict(
                    decision.action, decision.rule_id, decision.retrieval_weight
                )
            }
        return self._inner.delete(memory_id)

    def search(self, query: str, **kwargs: Any) -> dict[str, Any]:
        """Search, then drop results the policy would hide."""
        kwargs = _with_user_filter(kwargs)
        result = self._inner.search(query, **kwargs)
        return self._filter_result(result)

    def get_all(self, **kwargs: Any) -> dict[str, Any]:
        """List, then drop results the policy would hide."""
        kwargs = _with_user_filter(kwargs)
        result = self._inner.get_all(**kwargs)
        return self._filter_result(result)

    def _filter_result(self, result: Any) -> dict[str, Any]:
        if not isinstance(result, dict):
            return {"results": []}
        rows = result.get("results", [])
        if not isinstance(rows, list):
            return dict(result)
        prepared = [_row_record(row) for row in rows if isinstance(row, dict)]
        kept_ids = {item["id"] for item in self._firewall.filter_reads(prepared)}
        filtered = dict(result)
        filtered["results"] = [
            row for row in rows if isinstance(row, dict) and row.get("id") in kept_ids
        ]
        return filtered


def guard_mem0(memory: Any, firewall: Firewall) -> GuardedMemory:
    """Return a wrapper with the same write and read calls as `memory`."""
    return GuardedMemory(memory, firewall)


def _with_user_filter(kwargs: dict[str, Any]) -> dict[str, Any]:
    user_id = kwargs.pop("user_id", None)
    filters = dict(kwargs.get("filters") or {})
    if isinstance(user_id, str) and "user_id" not in filters:
        filters["user_id"] = user_id
    if filters:
        kwargs["filters"] = filters
    return kwargs


def _row_record(row: dict[str, Any]) -> dict[str, Any]:
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    stored = metadata.get("memlineage") if isinstance(metadata, dict) else None
    record: dict[str, Any] = {
        "id": str(row.get("id", "")),
        "content": str(row.get("memory", "")),
        "store": "mem0",
        "namespace": ["memories"],
    }
    if isinstance(stored, dict):
        record["provenance"] = stored
    return record
