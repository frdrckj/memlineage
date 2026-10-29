# Policy

A policy file is YAML. Unknown fields are rejected. A file that does not parse still opens, and every later check quarantines with rule id `policy-error`.

```yaml
version: 1
default: quarantine

trust:
  user: trusted
  system: trusted
  tool:browser: untrusted
  tool:email_read: untrusted
  document: untrusted
  agent: inherit

rules:
  - id: block-cross-principal
    when: { principal_mismatch: true }
    action: block

  - id: block-instruction-shaped-from-untrusted
    when: { taint_any: [web, document, tool:email_read], content_matches: instruction }
    action: block

  - id: quarantine-untrusted-lessons
    when: { taint_any: [web, document], namespace_prefix: [lessons, procedures, goals] }
    action: quarantine

  - id: allow-untrusted-facts-low-weight
    when: { taint_any: [web], namespace_prefix: [facts] }
    action: allow
    annotate: { retrieval_weight: 0.3 }

  - id: allow-user
    when: { source_kind: user }
    action: allow

reads:
  hide: [quarantine, block]
  max_untrusted_per_query: 2
```

`version` is `1`. `default` is the action when no rule matches.

## Trust

Trust levels, from low to high, are hostile, untrusted, verified, and trusted.

The `trust` map keys are `user`, `system`, `document`, `agent`, and `tool:<name>`. A missing key is untrusted. `agent: inherit` takes the lower parent trust and the union of parent taint. User and system add no taint tag. A web source adds `web`. A document adds `document`. A tool adds `tool:<name>`.

No source at all stays unknown, untrusted, and untainted. The default rule then quarantines it. Inside a Python `context` block with no `source` block, the write is the user's.

## Rules

Rules are first match. Every field set under `when` must hold.

- `principal_mismatch` compares the record principal with the reader. Two empty principals are not a mismatch. A named record read by a different principal is a mismatch. An empty reader against a named record is a mismatch.
- `taint_any` matches when the record carries one of the tags.
- `namespace_prefix` matches the first namespace segment.
- `source_kind` is `user`, `system`, `tool`, `web`, `document`, `agent`, or `unknown`.
- `content_matches: instruction` matches only when the record is tainted and the text contains one of these phrases: `from now on`, `always`, `ignore`, `you must`, `disregard`, `do not`, `new instruction`. The same words from the user do not match, because a user write has no taint.

`action` is `allow`, `quarantine`, or `block`. `annotate.retrieval_weight` is an optional float on an allow.

## Reads

`reads.hide` drops those actions from later reads. `max_untrusted_per_query` caps how many untrusted records one read may return. A read does not append to the log.

Allow does not insert a quarantine row. A later allow clears an existing quarantine row. A block row is not approvable. `review` lists quarantine rows only.
