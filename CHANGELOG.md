# Changelog

## 0.1.0

- Core policy engine. First match wins. No match quarantines the write.
- Provenance and taint on every write. A derived write keeps the parent taint.
- Hash-chained audit log in SQLite. `verify` reports the first broken link.
- Command line for the audit log.
- MCP memory proxy for write tools and filtered reads.
- Python package with a Mem0 wrapper and a LangGraph store.
