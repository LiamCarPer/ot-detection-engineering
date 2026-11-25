"""Guard the committed lab benign-capture evidence."""

from __future__ import annotations

import json
from pathlib import Path

EVIDENCE = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "evidence"
    / "benign-lab"
    / "summary.json"
)


def _summary() -> dict:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_capture_metadata_is_recorded() -> None:
    summary = _summary()
    capture = summary["capture"]
    assert capture["path"]
    assert len(capture["sha256"]) == 64
    assert capture["bytes"] > 0
    assert summary["events"] > 0


def test_every_network_family_is_measured() -> None:
    families = _summary()["families"]
    for name in (
        "sigma_single_event",
        "sigma_correlation",
        "baseline",
        "conduit",
        "stateful",
        "native",
    ):
        assert name in families


def test_the_pilot_has_no_network_false_positives() -> None:
    families = _summary()["families"]
    assert families["sigma_single_event"]["false_positive_events"] == 0
    assert families["baseline"]["false_positive_events"] == 0
    assert families["conduit"]["false_positive_events"] == 0
    assert families["sigma_correlation"]["fired"] == []
    assert families["stateful"]["fired"] == []
    assert families["native"]["false_positive_alerts"] == 0


def test_not_observed_families_are_labelled() -> None:
    not_observed = _summary()["families"]["not_observed"]
    assert "host/sysmon" in not_observed["families"]
    assert "not present" in not_observed["reason"]


def test_capture_span_and_rate_are_recorded() -> None:
    summary = _summary()
    assert summary["span_seconds"] > 0
    assert summary["events_per_hour"] > 0
