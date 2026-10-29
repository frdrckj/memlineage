import asyncio

import pytest

from memlineage import Firewall, Source, current
from memlineage._context import context, source


def test_nested_sources_union_taint() -> None:
    with context("user-42", "s-981"):
        with source(Source.web("https://example.test/a")):
            with source(Source.tool("browser")):
                active = current()
    assert active.principal == "user-42"
    assert active.session == "s-981"
    assert active.source_kind == "tool"
    assert active.source_ref == "browser"
    assert active.taint == frozenset({"web", "tool:browser"})


def test_source_outside_context_fails() -> None:
    with pytest.raises(RuntimeError, match="active context"):
        with source(Source.user()):
            pass


def test_inner_context_replaces_principal_and_keeps_sources() -> None:
    with context("user-a", "s-a"):
        with source(Source.web("https://example.test")):
            with context("user-b", "s-b"):
                active = current()
    assert active.principal == "user-b"
    assert active.session == "s-b"
    assert active.taint == frozenset({"web"})


def test_asyncio_tasks_keep_separate_contexts() -> None:
    async def work(principal: str) -> str:
        with context(principal, "session"):
            await asyncio.sleep(0)
            return current().principal

    async def main() -> tuple[str, str]:
        first, second = await asyncio.gather(work("user-a"), work("user-b"))
        return first, second

    assert asyncio.run(main()) == ("user-a", "user-b")


def test_firewall_methods_use_the_same_context() -> None:
    fw = Firewall.__new__(Firewall)
    with fw.context("user-42", "s-1"):
        with fw.source(Source.document("/notes.pdf")):
            active = current()
    assert active.source_kind == "document"
    assert active.source_ref == "/notes.pdf"
