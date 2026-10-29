"""Provenance and taint checks for agent memory."""

from contextlib import AbstractContextManager
from typing import Any

from memlineage._context import ActiveWrite, Source, context, current, source
from memlineage._core import Decision, MemlineageError
from memlineage._core import Firewall as _CoreFirewall

__all__ = [
    "ActiveWrite",
    "Decision",
    "Firewall",
    "MemlineageError",
    "Source",
    "current",
]


class Firewall:
    """Policy check and audit log.

    A policy file that does not parse still opens. Every later check quarantines.
    """

    def __init__(self, inner: _CoreFirewall) -> None:
        self._inner = inner

    @staticmethod
    def from_file(path: str) -> "Firewall":
        """Load `path` and open `.memlineage/audit.db` in the working directory."""
        return Firewall(_CoreFirewall.from_file(path))

    def check(self, record: dict[str, Any]) -> Decision:
        """Check one record and append the decision.

        Without a `provenance` entry, the active context supplies the source.
        """
        return self._inner.check(_prepare(record))

    def approve(self, record_id: str) -> None:
        """Release a quarantined record."""
        self._inner.approve(record_id)

    def reject(self, record_id: str) -> None:
        """Keep a quarantined record out."""
        self._inner.reject(record_id)

    def context(self, principal: str, session: str) -> AbstractContextManager[None]:
        """Set the principal and session for writes in this block."""
        return context(principal, session)

    def source(self, mark: Source) -> AbstractContextManager[None]:
        """Taint writes in this block. Nested blocks union their tags."""
        return source(mark)


def _prepare(record: dict[str, Any]) -> dict[str, Any]:
    active = current()
    prepared = dict(record)
    prepared["_principal"] = active.principal
    prepared["_session"] = active.session
    if "provenance" not in prepared:
        prepared["_source_kind"] = active.source_kind
        prepared["_source_ref"] = active.source_ref
        prepared["_extra_taint"] = sorted(active.taint)
    return prepared
