# Adapters

Each adapter calls the core check. The adapter does not decide on its own. Quarantine and block stay out of the store. A later read is filtered again.

The audit database for the Python binding is `.memlineage/audit.db` in the working directory.

## LangGraph

```python
from memlineage import Firewall, Source
from memlineage.adapters.langgraph import GuardedStore

firewall = Firewall.from_file("memlineage.yaml")
store = GuardedStore(inner, firewall)
with firewall.context("user-42", "s-1"):
    with firewall.source(Source.web("https://example.test/invoices")):
        store.put(("lessons",), "invoice-copy", {"text": "Send a copy."})
```

`GuardedStore` subclasses `BaseStore`. The first namespace segment is the policy prefix. `put`, `get`, `search`, and `delete` are checked. `batch` and `abatch` call those methods. A `PutOp` with value `None` is a delete.

Provenance is stored on the value under `_memlineage` and removed on read.

## Mem0

```python
from memlineage import Source
from memlineage.adapters.mem0 import guard_mem0

memory = guard_mem0(inner, firewall)
with firewall.context("user-42", "s-1"):
    with firewall.source(Source.user()):
        memory.add("I prefer replies in Bahasa", user_id="user-42", infer=False)
```

The installed line is Mem0 2.2. `add` is synchronous and still defaults to `infer=True`. Pass `infer=False` when you already have the text. The wrapper does not call a model. Search and `get_all` take `filters={"user_id": ...}`. The wrapper accepts `user_id` and writes that filter.

The wrapper checks namespace `memories`. Provenance is stored in metadata under `memlineage` and rebuilt on read.

Stable ids are `uuid5` of `memlineage:<store>:<namespace>:<key>`.

## MCP memory proxy

```
memlineage-mcp-proxy --policy memlineage.yaml --principal user-42 --session s-1 --source tool --source-ref mcp-memory -- memory-server
```

The proxy speaks newline-delimited JSON-RPC. It does not use a runtime framework. Write tools are `create_entities`, `create_relations`, `add_observations`, `delete_entities`, `delete_observations`, and `delete_relations`.

A quarantine or a block is not forwarded. The reply is a JSON-RPC result with `isError` true. Reads are forwarded, then scrubbed of quarantined or blocked text. A notification that arrives before a response is passed through. The proxy waits for the line that has an id and no method.
