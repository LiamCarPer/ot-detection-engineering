"""Guard the committed YARA evidence.

YARA validation is offline, so it runs in CI directly; the committed evidence is
a record that can be reviewed without installing the engine.
"""

from __future__ import annotations

import json
from pathlib import Path

EVIDENCE = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "evidence"
    / "yara"
    / "summary.json"
)


def _evidence() -> dict:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_a_rule_was_validated() -> None:
    assert _evidence()["rules"]


def test_every_fixture_case_passed() -> None:
    for row in _evidence()["rules"]:
        assert row["cases"], row["rule"]
        for case in row["cases"]:
            assert case["passed"], f"{row['rule']}: {case['name']}"


def test_the_payload_scan_and_selftest_passed() -> None:
    evidence = _evidence()
    assert evidence["payload_scan"]["passed"]
    assert evidence["selftest"]["eicar"] is True
