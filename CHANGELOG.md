# Changelog

## Unreleased

- `review approve` and `review reject` record the reviewer and an optional reason.
- A release stays out of the store until the Mem0 or LangGraph adapter applies it.
- `verify` fails when the quarantine table does not match the audit log.
- `approve` and `reject` now take a reviewer. That is a break in the Rust and Python API.
- Attack scenarios ML-011 and ML-012.

## 0.1.0

- Core policy engine. First match wins. No match quarantines the write.
- Provenance and taint on every write. A derived write keeps the parent taint.
- Hash-chained audit log in SQLite. `verify` reports the first broken link.
- Command line for the audit log.
- MCP memory proxy for write tools and filtered reads.
- Python package with a Mem0 wrapper and a LangGraph store.
