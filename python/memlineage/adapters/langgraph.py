"""Wrap any LangGraph store. The first namespace segment is the policy prefix."""

import json
from typing import Any

from langgraph.store.base import BaseStore, Item, SearchItem

from memlineage import Firewall
from memlineage._context import current
from memlineage.adapters.base import provenance_fields, stable_id

_META = "_memlineage"


class GuardedStore(BaseStore):
    """`put`, `get`, `search`, and `delete` go through the firewall."""

    def __init__(self, inner: BaseStore, firewall: Firewall) -> None:
        self._inner = inner
        self._firewall = firewall

    def batch(self, ops: Any) -> list[Any]:
        """Run each op through the checked methods."""
        results: list[Any] = []
        for op in ops:
            name = type(op).__name__
            if name == "PutOp":
                if op.value is None:
                    self.delete(op.namespace, op.key)
                else:
                    self.put(op.namespace, op.key, dict(op.value))
                results.append(None)
            elif name == "GetOp":
                results.append(self.get(op.namespace, op.key))
            elif name == "SearchOp":
                results.append(
                    self.search(
                        op.namespace_prefix,
                        query=op.query,
                        filter=op.filter,
                        limit=op.limit,
                        offset=op.offset,
                    )
                )
            else:
                results.append(None)
        return results

    async def abatch(self, ops: Any) -> list[Any]:
        """Async batch. The check itself is synchronous."""
        return self.batch(ops)

    def put(
        self,
        namespace: tuple[str, ...],
        key: str,
        value: dict[str, Any],
        index: Any = None,
        **kwargs: Any,
    ) -> None:
        """Check the value. Store it only when the decision is allow."""
        content = json.dumps(value, sort_keys=True, default=str)
        decision = self._firewall.check(_record(namespace, key, content))
        if decision.action != "allow":
            return
        stored = dict(value)
        stored[_META] = provenance_fields(current(), current().principal, current().session)
        self._inner.put(namespace, key, stored, index=index, **kwargs)

    def get(self, namespace: tuple[str, ...], key: str, **kwargs: Any) -> Any:
        """Return the item when the policy still allows it."""
        item = self._inner.get(namespace, key, **kwargs)
        if item is None:
            return None
        kept = self._firewall.filter_reads([_item_record(item)])
        if not kept:
            return None
        return _strip(item)

    def search(self, namespace_prefix: tuple[str, ...], /, **kwargs: Any) -> list[Any]:
        """Search, then drop items the policy hides."""
        items = self._inner.search(namespace_prefix, **kwargs)
        records = [_item_record(item) for item in items]
        allowed = {record["id"] for record in self._firewall.filter_reads(records)}
        return [
            _strip(item)
            for item, record in zip(items, records, strict=True)
            if record["id"] in allowed
        ]

    def delete(self, namespace: tuple[str, ...], key: str) -> None:
        """Log the delete and pass it through when the decision is allow."""
        existing = self._inner.get(namespace, key)
        content = "delete"
        if existing is not None:
            content = json.dumps(_public_value(existing.value), sort_keys=True, default=str)
        decision = self._firewall.check(_record(namespace, key, content))
        if decision.action != "allow":
            return
        self._inner.delete(namespace, key)


def _record(namespace: tuple[str, ...], key: str, content: str) -> dict[str, Any]:
    return {
        "id": stable_id("langgraph", "/".join(namespace), key),
        "content": content,
        "store": "langgraph",
        "namespace": list(namespace),
        "key": key,
    }


def _item_record(item: Any) -> dict[str, Any]:
    value = item.value if isinstance(item.value, dict) else {}
    stored = value.get(_META) if isinstance(value, dict) else None
    record = _record(
        tuple(item.namespace),
        item.key,
        json.dumps(_public_value(value), sort_keys=True, default=str),
    )
    if isinstance(stored, dict):
        record["provenance"] = stored
    return record


def _public_value(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != _META}


def _strip(item: Any) -> Any:
    value = item.value if isinstance(item.value, dict) else {}
    if _META not in value:
        return item
    cleaned = _public_value(value)
    if isinstance(item, SearchItem):
        return SearchItem(
            namespace=tuple(item.namespace),
            key=item.key,
            value=cleaned,
            created_at=item.created_at,
            updated_at=item.updated_at,
            score=item.score,
        )
    return Item(
        value=cleaned,
        key=item.key,
        namespace=tuple(item.namespace),
        created_at=item.created_at,
        updated_at=item.updated_at,
    )
