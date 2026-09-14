"""Functional evidence: the native rules fired on the committed captures.

CI cannot run Suricata, so the run is captured once (tools/suricata_check.py)
and committed, and these tests assert the committed evidence against the
expectations in tools/otde/evidence.py. Regenerate with `make suricata-check`.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.otde.evidence import EXPECTED_SIDS, read_alert_sids

EVIDENCE_DIR = Path(__file__).resolve().parents[1] / "deploy" / "evidence"


def test_attack_captures_fire_the_expected_detections() -> None:
    failures = []
    for name, expected in EXPECTED_SIDS.items():
        observed = read_alert_sids(EVIDENCE_DIR / name / "eve.json")
        if observed != expected:
            failures.append(f"{name}: expected {sorted(expected)}, observed {sorted(observed)}")
    assert not failures, "\n".join(failures)


def test_benign_captures_are_silent() -> None:
    for name in EXPECTED_SIDS:
        if name.endswith("_benign"):
            assert read_alert_sids(EVIDENCE_DIR / name / "eve.json") == set(), name


def test_summary_matches_the_evidence() -> None:
    summary = json.loads((EVIDENCE_DIR / "summary.json").read_text(encoding="utf-8"))
    assert set(summary) == set(EXPECTED_SIDS)
    for name, sids in summary.items():
        assert set(sids) == read_alert_sids(EVIDENCE_DIR / name / "eve.json"), name


def test_evidence_contains_only_alerts() -> None:
    for eve_path in sorted(EVIDENCE_DIR.glob("*/eve.json")):
        for line in eve_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                assert json.loads(line)["event_type"] == "alert", eve_path
