# Poisoned lesson

No model and no API key. The script is a fake agent.

```
cargo build -p memlineage-py --bin memlineage
python examples/poisoned_lesson_demo/demo.py
```

The first run stores the lesson. A later session would send it.
The second run quarantines the lesson. `memlineage review` prints the page URL.
