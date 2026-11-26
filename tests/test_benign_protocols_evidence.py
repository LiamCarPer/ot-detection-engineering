"""Guard the committed benign protocol-window evidence."""

from __future__ import annotations

import json
from pathlib import Path

EVIDENCE = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "evidence"
    / "benign-protocols"
    / "summary.json"
)


def _summary() -> dict:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_the_modbus_decoder_is_recorded() -> None:
    assert _summary()["decoders"]["modbus"] == "tshark"


def test_the_window_is_recorded_and_short() -> None:
    window = _summary()["window"]
    assert 0.3 * 3600 < window["span_seconds"] < 0.7 * 3600
    assert _summary()["events"] > 10_000


def test_the_protocol_services_have_input() -> None:
    services = _summary()["coverage"]["by_service"]
    for service in (
        "ot_ndr/dnp3",
        "ot_ndr/opcua",
        "ot_ndr/s7comm",
        "ot_ndr/modbus",
        "ot_snmp/snmp",
    ):
        assert services.get(service, 0) > 0, service


def test_sigma_coverage_moved_past_the_flow_window() -> None:
    coverage = _summary()["coverage"]["sigma_single_event"]
    assert coverage["with_input"] >= 22
    assert coverage["total"] == 30
    # These need sources a network capture does not carry, or an attack.
    assert set(coverage["without_input"]) == {
        "rules/sigma/ot/ot_detection_service_down.yml",
        "rules/sigma/ot/ot_firewall_control_zone_egress.yml",
        "rules/sigma/ot/ot_firewall_cross_zone_violation.yml",
        "rules/sigma/ot/ot_firewall_enterprise_control_service.yml",
        "rules/sigma/ot/ot_hmi_login_failure.yml",
        "rules/sigma/ot/ot_host_suspicious_modbus_client.yml",
        "rules/sigma/ot/ot_plc_logic_tampered.yml",
        "rules/sigma/ot/ot_process_safety_violation.yml",
    }


def test_the_window_has_no_false_positives() -> None:
    families = _summary()["families"]
    assert families["sigma_single_event"]["false_positive_events"] == 0
    assert families["native"]["false_positive_alerts"] == 0
    assert _summary()["lab_baseline"]["events"] == 0
