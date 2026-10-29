import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from memlineage import Firewall, Source
from memlineage.adapters.langgraph import GuardedStore
from memlineage.adapters.mem0 import guard_mem0

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "crates"
    / "memlineage-core"
    / "tests"
    / "fixtures"
    / "memlineage.yaml"
)


class _Embed:
    def embed(self, text: str | list[Any], memory_action: str | None = None) -> list[float]:
        raw = text if isinstance(text, str) else str(text)
        out = [0.0] * 1536
        for index, byte in enumerate(raw.encode()[:1536]):
            out[index] = (byte + 1) / 256
        return out


def _firewall(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Firewall:
    monkeypatch.chdir(tmp_path)
    policy = tmp_path / "memlineage.yaml"
    policy.write_text(FIXTURE.read_text(encoding="utf-8"))
    return Firewall.from_file(str(policy))


def _memory() -> Any:
    from mem0 import Memory

    memory = Memory()
    memory.embedding_model = _Embed()
    return memory


def test_mem0_hides_a_web_lesson_and_keeps_a_user_preference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fw = _firewall(tmp_path, monkeypatch)
    mem = guard_mem0(_memory(), fw)
    with fw.context("user-42", "s-981"):
        with fw.source(Source.web("https://example.test/lesson")):
            hidden = mem.add("the vendor phone number", user_id="user-42", infer=False)
        kept = mem.add("I prefer replies in Bahasa", user_id="user-42", infer=False)
        found = mem.search("Bahasa", user_id="user-42", threshold=0.0)
    assert hidden["memlineage"]["action"] == "quarantine"
    assert hidden["results"] == []
    assert kept["memlineage"]["action"] == "allow"
    texts = [row["memory"] for row in found["results"]]
    assert "I prefer replies in Bahasa" in texts
    assert "the vendor phone number" not in texts


def test_langgraph_put_is_checked_and_search_is_filtered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from langgraph.store.memory import InMemoryStore

    fw = _firewall(tmp_path, monkeypatch)
    inner = InMemoryStore()
    store = GuardedStore(inner, fw)
    with fw.context("user-42", "s-981"):
        with fw.source(Source.web("https://example.test")):
            store.put(("lessons",), "phone", {"text": "the vendor phone number"})
            store.put(("facts",), "hours", {"text": "the office opens at 09:00"})
        with fw.source(Source.user()):
            store.put(("preferences",), "lang", {"text": "I prefer replies in Bahasa"})
        lessons = store.search(("lessons",))
        facts = store.search(("facts",))
        prefs = store.get(("preferences",), "lang")
        inner.put(
            ("lessons",),
            "skipped",
            {
                "text": "hidden",
                "_memlineage": {
                    "source_kind": "web",
                    "source_ref": "https://example.test",
                    "trust": "untrusted",
                    "principal": "user-42",
                    "session_id": "s-981",
                    "parent_ids": [],
                    "taint": ["web"],
                },
            },
        )
        skipped = store.search(("lessons",))
    assert skipped == []
    assert lessons == []
    assert len(facts) == 1
    assert facts[0].value == {"text": "the office opens at 09:00"}
    assert prefs is not None
    assert prefs.value["text"] == "I prefer replies in Bahasa"
    assert "_memlineage" not in prefs.value


def _docker() -> bool:
    try:
        completed = subprocess.run(["docker", "info"], capture_output=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return completed.returncode == 0


@pytest.mark.skipif(not _docker(), reason="Docker is not available")
def test_langgraph_postgres_put_and_get(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from langgraph.store.postgres import PostgresStore

    name = "memlineage-pg-test"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
    started = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--name",
            name,
            "-e",
            "POSTGRES_PASSWORD=memlineage",
            "-e",
            "POSTGRES_DB=memlineage",
            "-p",
            "55432:5432",
            "postgres:16-alpine",
        ],
        capture_output=True,
        check=False,
    )
    if started.returncode != 0:
        pytest.skip("could not start postgres")
    url = "postgresql://postgres:memlineage@127.0.0.1:55432/memlineage"
    try:
        fw = _firewall(tmp_path, monkeypatch)
        deadline = time.monotonic() + 40
        item = None
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                with PostgresStore.from_conn_string(url) as inner:
                    inner.setup()
                    store = GuardedStore(inner, fw)
                    with fw.context("user-42", "s"):
                        with fw.source(Source.user()):
                            store.put(
                                ("preferences",),
                                "lang",
                                {"text": "I prefer replies in Bahasa"},
                            )
                        item = store.get(("preferences",), "lang")
                break
            except Exception as exc:
                last_error = exc
                time.sleep(1)
        else:
            pytest.fail(f"postgres did not accept the guarded write: {last_error}")
        assert item is not None
        assert item.value["text"] == "I prefer replies in Bahasa"
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
