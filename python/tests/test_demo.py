import subprocess
import sys
from pathlib import Path


def test_demo_quarantines_and_review_shows_the_url() -> None:
    root = Path(__file__).resolve().parents[2]
    demo = root / "examples" / "poisoned_lesson_demo" / "demo.py"
    completed = subprocess.run(
        [sys.executable, str(demo)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "https://example.test/invoices" in completed.stdout
    assert "quarantined" in completed.stdout
