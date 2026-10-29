from contextlib import AbstractContextManager
from typing import Any

from memlineage._context import ActiveWrite as ActiveWrite
from memlineage._context import Source as Source
from memlineage._context import current as current
from memlineage._core import Decision as Decision
from memlineage._core import MemlineageError as MemlineageError

__all__ = [
    "ActiveWrite",
    "Decision",
    "Firewall",
    "MemlineageError",
    "Source",
    "current",
]

class Firewall:
    def __init__(self, inner: Any) -> None: ...
    @staticmethod
    def from_file(path: str) -> Firewall: ...
    def check(self, record: dict[str, Any]) -> Decision: ...
    def approve(self, record_id: str) -> None: ...
    def reject(self, record_id: str) -> None: ...
    def context(self, principal: str, session: str) -> AbstractContextManager[None]: ...
    def source(self, mark: Source) -> AbstractContextManager[None]: ...
