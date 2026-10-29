"""Run the shared attack scenarios through the Python adapters."""

from pathlib import Path
from typing import Any

import yaml

from memlineage import Firewall, Source
from memlineage.adapters.langgraph import GuardedStore

_SOURCES = {
    "user": Source.user,
    "system": Source.system,
    "web": Source.web,
    "document": Source.document,
    "tool": Source.tool,
}


def load_suite(directory: Path, suite: str = "core") -> list[dict[str, Any]]:
    """Load scenario files for one suite, sorted by id."""
    scenarios: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.yaml")):
        loaded: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict) and loaded.get("suite") == suite:
            scenarios.append(loaded)
    return scenarios


def source_for(spec: dict[str, Any]) -> Source:
    """Build the source mark named in a scenario."""
    kind = str(spec.get("kind", "unknown"))
    ref = str(spec.get("ref", ""))
    builder = _SOURCES.get(kind)
    if builder is None:
        return Source.user()
    if kind in {"web", "document", "tool"}:
        return builder(ref)
    return builder()


def decision_for(firewall: Firewall, scenario: dict[str, Any], store: str) -> str:
    """Ask the core for the decision, using the scenario's reader when set."""
    principal = str(scenario.get("principal", "user-42"))
    reader = str(scenario.get("reader") or principal)
    session = str(scenario.get("session", "s-1"))
    namespace = scenario.get("namespace") or ["memories"]
    record: dict[str, Any] = {
        "content": str(scenario.get("input", "")),
        "store": store,
        "namespace": list(namespace),
        "principal": principal,
    }
    kind = str(scenario.get("kind", "write"))
    if kind == "derive":
        record["provenance"] = {
            "source_kind": "agent",
            "source_ref": "",
            "trust": "untrusted",
            "principal": principal,
            "session_id": session,
            "parent_ids": [],
            "taint": ["web"],
        }
        with firewall.context(reader, session):
            return firewall.check(record).action
    source = source_for(dict(scenario.get("source") or {}))
    with firewall.context(reader, session):
        with firewall.source(source):
            if kind == "read":
                record["provenance"] = {
                    "source_kind": "user",
                    "source_ref": "",
                    "trust": "trusted",
                    "principal": principal,
                    "session_id": session,
                    "parent_ids": [],
                    "taint": [],
                }
            return firewall.check(record).action


def adapter_hides(action: str) -> bool:
    """Quarantine and block stay out of later reads."""
    return action in {"quarantine", "block"}


def langgraph_kept(firewall: Firewall, store: GuardedStore, scenario: dict[str, Any]) -> bool:
    """True when a guarded put left the value readable."""
    namespace = tuple(str(part) for part in (scenario.get("namespace") or ["memories"]))
    key = str(scenario["id"])
    value = {"text": str(scenario.get("input", ""))}
    principal = str(scenario.get("principal", "user-42"))
    session = str(scenario.get("session", "s-1"))
    source = source_for(dict(scenario.get("source") or {}))
    with firewall.context(principal, session):
        with firewall.source(source):
            store.put(namespace, key, value)
            return store.get(namespace, key) is not None


def mem0_action(firewall: Firewall, memory: Any, scenario: dict[str, Any]) -> str:
    """Decision recorded by the Mem0 wrapper."""
    principal = str(scenario.get("principal", "user-42"))
    session = str(scenario.get("session", "s-1"))
    source = source_for(dict(scenario.get("source") or {}))
    with firewall.context(principal, session):
        with firewall.source(source):
            result = memory.add(str(scenario.get("input", "")), user_id=principal, infer=False)
    noted = result.get("memlineage", {})
    return str(noted.get("action", ""))


def markdown_table(reports: list[tuple[str, str, str, str]]) -> str:
    """Markdown table of id, title, expected, and actual."""
    lines = [
        "| ID | Scenario | Expected | Actual |",
        "| --- | --- | --- | --- |",
    ]
    for scenario_id, title, expected, actual in reports:
        lines.append(f"| {scenario_id} | {title} | {expected} | {actual} |")
    return "\n".join(lines) + "\n"
