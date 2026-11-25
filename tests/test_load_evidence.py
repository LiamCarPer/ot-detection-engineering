"""Guard the committed sustained-load evidence."""

from __future__ import annotations

import json
from pathlib import Path

EVIDENCE = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "evidence"
    / "load"
    / "summary.json"
)


def _runs() -> list[dict]:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))["runs"]


def test_sustained_target_has_no_drops() -> None:
    run = next(r for r in _runs() if r["target_eps"] == 4000)
    assert run["dropped"] == 0
    assert run["achieved_eps"] >= 3_900
    assert run["p99_us"] is not None


def test_saturated_target_shows_bounded_drops() -> None:
    run = next(r for r in _runs() if r["target_eps"] == 20000)
    assert run["dropped"] > 0
    assert run["drop_rate"] > 0
    assert run["max_queue"] == run["queue_size"]
