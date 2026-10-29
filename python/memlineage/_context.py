"""Context for the current writer. Safe to use from separate asyncio tasks."""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Source:
    """Where the bytes inside a source block came from."""

    kind: str
    ref: str

    @staticmethod
    def web(url: str) -> "Source":
        """A page."""
        return Source("web", url)

    @staticmethod
    def tool(name: str) -> "Source":
        """Output of one tool. The taint tag is `tool:<name>`."""
        return Source("tool", name)

    @staticmethod
    def document(path: str) -> "Source":
        """A file."""
        return Source("document", path)

    @staticmethod
    def user() -> "Source":
        """The principal's own message."""
        return Source("user", "")

    @staticmethod
    def system() -> "Source":
        """Operator or system config."""
        return Source("system", "")

    def tag(self) -> str | None:
        """Taint tag for this mark, if it has one."""
        if self.kind == "web":
            return "web"
        if self.kind == "document":
            return "document"
        if self.kind == "tool":
            return f"tool:{self.ref}"
        return None


@dataclass(frozen=True, slots=True)
class ActiveWrite:
    """The writer and source stack visible to the current task."""

    principal: str
    session: str
    source_kind: str
    source_ref: str
    taint: frozenset[str]


@dataclass(frozen=True, slots=True)
class _Frame:
    principal: str
    session: str
    sources: tuple[Source, ...]


_frame: ContextVar[_Frame | None] = ContextVar("memlineage_frame", default=None)


def current() -> ActiveWrite:
    """Read the active writer. Empty when no context block is open."""
    frame = _frame.get()
    if frame is None:
        return ActiveWrite("", "", "unknown", "", frozenset())
    tags: set[str] = set()
    for mark in frame.sources:
        tag = mark.tag()
        if tag is not None:
            tags.add(tag)
    if not frame.sources:
        return ActiveWrite(frame.principal, frame.session, "unknown", "", frozenset())
    inner = frame.sources[-1]
    return ActiveWrite(
        frame.principal,
        frame.session,
        inner.kind,
        inner.ref,
        frozenset(tags),
    )


@contextmanager
def context(principal: str, session: str) -> Iterator[None]:
    """Set the principal and session. An inner block replaces both."""
    outer = _frame.get()
    sources = outer.sources if outer is not None else ()
    token = _frame.set(_Frame(principal, session, sources))
    try:
        yield
    finally:
        _frame.reset(token)


@contextmanager
def source(mark: Source) -> Iterator[None]:
    """Push a source mark. Tags from the outer marks stay."""
    outer = _frame.get()
    if outer is None:
        raise RuntimeError("source() needs an active context()")
    token = _frame.set(_Frame(outer.principal, outer.session, outer.sources + (mark,)))
    try:
        yield
    finally:
        _frame.reset(token)
