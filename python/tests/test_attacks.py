import shutil
import subprocess
from pathlib import Path

import pytest

from memlineage import Source
from memlineage.adapters.langgraph import GuardedStore
from memlineage.adapters.mem0 import guard_mem0
from memlineage.attack import decision_for, langgraph_kept, load_suite, mem0_action
from tests.test_adapters import _firewall, _memory

SCENARIOS = Path(__file__).resolve().parents[2] / "attacks" / "scenarios"


def test_core_decisions_match_the_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    firewall = _firewall(tmp_path, monkeypatch)
    for scenario in load_suite(SCENARIOS):
        if scenario["kind"] == "tamper":
            continue
        actual = decision_for(firewall, scenario, "langgraph")
        assert actual == scenario["expected"], scenario["id"]


def test_langgraph_and_mem0_follow_write_scenarios(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from langgraph.store.memory import InMemoryStore

    firewall = _firewall(tmp_path, monkeypatch)
    store = GuardedStore(InMemoryStore(), firewall)
    memory = guard_mem0(_memory(), firewall)
    for scenario in load_suite(SCENARIOS):
        if scenario["kind"] != "write":
            continue
        expected = str(scenario["expected"])
        kept = langgraph_kept(firewall, store, scenario)
        assert kept is (expected == "allow"), scenario["id"]
        assert mem0_action(firewall, memory, scenario) == expected, scenario["id"]


def test_cross_principal_read_is_hidden(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from langgraph.store.memory import InMemoryStore

    firewall = _firewall(tmp_path, monkeypatch)
    store = GuardedStore(InMemoryStore(), firewall)
    with firewall.context("user-a", "s-1"):
        with firewall.source(Source.user()):
            store.put(("preferences",), "lang", {"text": "I prefer replies in Bahasa"})
    with firewall.context("user-b", "s-1"):
        assert store.get(("preferences",), "lang") is None
    scenario = next(item for item in load_suite(SCENARIOS) if item["id"] == "ML-007")
    assert decision_for(firewall, scenario, "langgraph") == "block"


def _cli() -> Path:
    found = shutil.which("memlineage")
    if found is not None:
        return Path(found)
    root = Path(__file__).resolve().parents[2]
    for name in ("debug", "release"):
        path = root / "target" / name / "memlineage"
        if path.is_file():
            return path
    pytest.fail("memlineage binary is not built")


def test_cli_suite_passes_on_all_stores() -> None:
    binary = str(_cli())
    for store in ("mem0", "langgraph", "mcp-memory"):
        completed = subprocess.run(
            [
                binary,
                "attack",
                "run",
                "--suite",
                "core",
                "--store",
                store,
                "--scenarios",
                str(SCENARIOS),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        assert "10 passed" in completed.stdout
