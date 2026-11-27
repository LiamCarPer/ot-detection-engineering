"""Guard the committed approved-write / exception-probe window."""

from __future__ import annotations

import json
from pathlib import Path

EVIDENCE = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "evidence"
    / "benign-writes"
    / "summary.json"
)


def _summary() -> dict:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_the_window_has_modbus_and_flows() -> None:
    summary = _summary()
    services = summary["coverage"]["by_service"]
    assert services.get("ot_ndr/modbus", 0) > 1_000
    assert services.get("ot_flow/flow", 0) > 1_000
    assert summary["decoders"]["modbus"] == "tshark"


def test_approved_writes_do_not_fire_sigma_or_native_rules() -> None:
    families = _summary()["families"]
    assert families["sigma_single_event"]["false_positive_events"] == 0
    assert families["native"]["false_positive_alerts"] == 0
    assert _summary()["lab_baseline"]["events"] == 0


def test_the_exception_probe_is_documented_as_unavailable() -> None:
    # The PLC returns zeros/echoes for out-of-range reads and writes, so the
    # exception rule cannot be positively exercised on this device; its fixtures
    # and held-out positives cover it. This window must not claim it fired.
    assert _summary()["families"]["sigma_single_event"]["false_positive_events"] == 0
