"""Functional evidence: the generated ruler rules run inside OT-Security-Lab.

CI has no lab, so the integration run is captured once (tools/lab_loki_check.py)
and committed; these tests assert the committed evidence. Regenerate with the lab
up via `LAB_REVISION=<rev> python tools/lab_loki_check.py`.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.otde.evidence import EXPECTED_LAB_RULES, LAB_NDR_SERVICES

EVIDENCE_DIR = (
    Path(__file__).resolve().parents[1] / "deploy" / "evidence" / "lab-loki"
)


def _summary() -> dict:
    return json.loads((EVIDENCE_DIR / "summary.json").read_text(encoding="utf-8"))


def _events() -> dict[str, list[dict]]:
    return json.loads((EVIDENCE_DIR / "events.json").read_text(encoding="utf-8"))


def test_every_expected_generated_rule_is_firing_in_the_lab() -> None:
    summary = _summary()
    assert summary["expected"] == EXPECTED_LAB_RULES
    captured = {rule["name"]: rule for rule in summary["rules"]}
    assert set(captured) == set(EXPECTED_LAB_RULES)
    for name, group in EXPECTED_LAB_RULES.items():
        assert captured[name]["group"] == group
        assert captured[name]["state"] == "firing", name
        assert captured[name]["health"] == "ok", name


def test_lab_ships_the_normalized_protocol_telemetry() -> None:
    events = _events()
    summary = _summary()
    assert summary["events_total"] == sum(len(samples) for samples in events.values()) > 0
    for service in LAB_NDR_SERVICES:
        key = f"ot_ndr/{service}"
        samples = events[key]
        assert samples, f"no {key} events captured"
        assert summary["streams"][key] == len(samples)
        for sample in samples:
            assert sample["stream"]["job"] == "ot_ndr"
            assert sample["stream"]["service"] == service


def test_dnp3_events_carry_link_and_function_semantics() -> None:
    for sample in _events()["ot_ndr/dnp3"]:
        assert "direction=" in sample["line"]
        assert "function_code=" in sample["line"]
        assert "link_source=" in sample["line"]


def test_opcua_events_carry_the_service_and_direction() -> None:
    # opcua_service is optional: only plaintext (None/Sign) service bodies expose
    # it, so message/close frames carry the header without a service.
    lines = [sample["line"] for sample in _events()["ot_ndr/opcua"]]
    assert all("message_type=" in line for line in lines)
    assert any("opcua_service=" in line and "direction=" in line for line in lines)


def test_s7comm_events_carry_the_function_code() -> None:
    for sample in _events()["ot_ndr/s7comm"]:
        assert "direction=" in sample["line"]
        assert "function_code=" in sample["line"]


def test_firewall_and_process_events_carry_their_contract() -> None:
    events = _events()
    for sample in events["ot_firewall"]:
        assert sample["stream"]["job"] == "ot_firewall"
        assert "action=DROP" in sample["line"]
        assert "dst_zone=control" in sample["line"]
    for sample in events["ot_process"]:
        assert sample["stream"]["job"] == "ot_process"
        assert "event_type=process_safety_violation" in sample["line"]
