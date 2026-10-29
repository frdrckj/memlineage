# Contributing

The license is Apache-2.0.

Run the checks from the repository root before you open a change.

```
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo deny check
```

Python checks run in `python/` after `maturin develop`.

```
ruff check .
ruff format --check .
mypy --strict memlineage tests pack_cli.py
pytest
```

Build the command before the attack tests.

```
cargo build -p memlineage-py --bin memlineage
```

The attack files live in `attacks/scenarios/`. Rust and Python read the same files.

```
memlineage attack run --suite core --store langgraph
```

Docs use mkdocs-material.

```
pip install mkdocs-material
mkdocs build
```

Security reports go to the address in `SECURITY.md`. Do not open a public issue for those.

The release workflow publishes on a `v*` tag. It does not run on a branch push. Before the first tag, add a trusted publisher on PyPI for the `pypi` environment and on crates.io for the `crates-io` environment. The workflow file is `.github/workflows/release.yml`.
