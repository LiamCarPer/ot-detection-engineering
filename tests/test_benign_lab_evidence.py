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
    assert summary["decoders"]["modbus"] == "tshark"
    capture = summary["capture"]
    assert capture["path"]
    assert len(capture["sha256"]) == 64
    assert capture["bytes"] > 0
    assert summary["events"] > 0


def test_capture_spans_more_than_a_day() -> None:
    window = _summary()["window"]
    assert window["span_seconds"] > 24 * 3600
    assert window["first_event_at"]
    assert window["last_event_at"]
    assert _summary()["events_per_hour"] > 0


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


def test_the_corpus_is_not_flow_only() -> None:
    coverage = _summary()["coverage"]
    assert coverage["by_service"].get("ot_ndr/modbus", 0) > 1_000
    assert coverage["sigma_single_event"]["with_input"] >= 9
    # A zero from a rule with no input is not a measurement; the report must
    # carry the list rather than hide it.
    assert coverage["sigma_single_event"]["without_input"]


def test_sigma_and_native_are_clean_on_the_committed_capture() -> None:
    families = _summary()["families"]
    assert families["sigma_single_event"]["false_positive_events"] == 0
    assert families["conduit"]["false_positive_events"] == 0
    assert families["sigma_correlation"]["fired"] == []
    assert families["stateful"]["fired"] == []
    assert families["native"]["false_positive_alerts"] == 0


def test_the_lab_trained_baseline_is_clean() -> None:
    baseline = _summary()["lab_baseline"]
    assert baseline["exercised"] is True
    assert baseline["test_events"] > 100_000
    assert baseline["events"] == 0
    assert all(count == 0 for count in baseline["per_rule"].values())


def test_the_committed_baseline_domain_shift_is_disclosed() -> None:
    # The committed baseline was learned from the generated seed. On the lab
    # every asset and pair is new; the report must say so rather than present
    # the resulting events as a false-positive rate.
    assert _summary()["families"]["baseline"]["false_positive_events"] > 0


def test_not_observed_families_are_labelled() -> None:
    not_observed = _summary()["families"]["not_observed"]
    assert "host/sysmon" in not_observed["families"]
    assert "not present" in not_observed["reason"]
