# memlineage

memlineage checks a memory write before it lands, and a memory read before it comes back. Every record carries its origin. The policy allows, quarantines, or blocks.

Install and the scenario table are in the repository README.

## Commands

`memlineage` reads `.memlineage/audit.db`. Pass `--db` to use another file.

- `ls` lists the latest decision for each record.
- `show ID` prints the content, the provenance, and the rule.
- `review` lists quarantined records. The line includes the source URL or path.
- `review approve ID` releases one record. `review reject ID` keeps it out.
- `rollback --to TIME --taint TAG` appends a block event for allowed records after that time whose taint contains the tag. It does not delete store rows.
- `diff --since TIME` groups changes by source.
- `trace ID` lists records derived from that one.
- `verify` prints `ok`, or `broken` and exits 1.
- `attack run --suite core --store langgraph` runs the shared scenario files.

## Docs build

```
pip install mkdocs-material
mkdocs serve
```
