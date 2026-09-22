"""Unit tests for the collector's contract normalization and source adapters."""

from __future__ import annotations

from pathlib import Path

from collector import contract, sinks
from collector.sources import netflow, snmp, suricata, zeek

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = REPO_ROOT / "collector" / "samples"


def test_normalize_timestamp_from_epoch() -> None:
    assert contract.normalize_timestamp(1700000000.0) == "2023-11-14T22:13:20Z"


def test_normalize_timestamp_from_offset_string() -> None:
    assert (
        contract.normalize_timestamp("2023-11-14T22:13:20.026000+0000")
        == "2023-11-14T22:13:20.026000Z"
    )


def test_suricata_modbus_maps_to_the_contract() -> None:
    events = list(suricata.events([SAMPLES / "suricata" / "modbus_attack.eve.json"]))
    requests = [
        event
        for event in events
        if event["service"] == "modbus" and event["direction"] == "request"
    ]
    assert {event["function_code"] for event in requests} == {6, 16}
    assert all(event["product"] == "ot_ndr" for event in requests)
    assert all(event["src_ip"] == "172.24.0.10" and event["unit_id"] == 1 for event in requests)
    # The two single-register writes target 1024 and 50000.
    single = [event for event in requests if event["function_code"] == 6]
    assert {event["register"] for event in single} == {1024, 50000}


def test_suricata_dnp3_keeps_link_identity() -> None:
    events = list(suricata.events([SAMPLES / "suricata" / "dnp3_attack.eve.json"]))
    direct_operate = next(event for event in events if event["function_code"] == 5)
    assert direct_operate["direction"] == "request"
    assert direct_operate["link_source"] == 7
    assert direct_operate["link_destination"] == 1
    assert direct_operate["link_function"] == 4


def test_zeek_modbus_maps_functions_and_omits_the_register() -> None:
    events = list(zeek.events([SAMPLES / "zeek" / "modbus_attack.modbus.log"]))
    assert events
    assert {event["function_code"] for event in events} >= {6, 16}
    # Zeek's modbus.log has no register address, so the field must be absent.
    assert all("register" not in event for event in events)


def test_zeek_dnp3_omits_the_link_address() -> None:
    events = list(zeek.events([SAMPLES / "zeek" / "dnp3_attack.dnp3.log"]))
    assert events
    assert all("link_source" not in event for event in events)


def test_zeek_conn_maps_to_the_flow_contract() -> None:
    events = list(zeek.events([SAMPLES / "zeek" / "modbus_attack.conn.log"]))
    assert events
    flow = events[0]
    assert flow["product"] == "ot_flow"
    assert flow["service"] == "flow"
    assert flow["dst_port"] == 502
    assert flow["app_protocol"] == "modbus"
    assert isinstance(flow["duration"], float)
    assert isinstance(flow["bytes"], int)


def test_netflow_export_maps_to_the_flow_contract() -> None:
    events = list(netflow.events([SAMPLES / "netflow" / "flows.json"]))
    assert events
    assert all(event["product"] == "ot_flow" and event["service"] == "flow" for event in events)
    assert {event["dst_port"] for event in events} == {502, 20000}


def test_snmp_export_maps_to_the_snmp_contract() -> None:
    events = list(snmp.events([SAMPLES / "snmp" / "attack.json"]))
    assert {event["event_type"] for event in events} == {
        "device_restart",
        "interface_down",
        "config_change",
    }
    assert all(event["product"] == "ot_snmp" and event["service"] == "snmp" for event in events)


def test_every_sample_event_validates_against_the_schema() -> None:
    for path in sorted((SAMPLES / "suricata").glob("*.json")):
        for event in suricata.events([path]):
            assert contract.schema_errors(event) == [], event
    for path in sorted((SAMPLES / "zeek").glob("*.log")):
        for event in zeek.events([path]):
            assert contract.schema_errors(event) == [], event
    for path in sorted((SAMPLES / "netflow").glob("*.json")):
        for event in netflow.events([path]):
            assert contract.schema_errors(event) == [], event
    for path in sorted((SAMPLES / "snmp").glob("*.json")):
        for event in snmp.events([path]):
            assert contract.schema_errors(event) == [], event


def test_loki_sink_groups_by_service_with_the_routing_label() -> None:
    events = list(suricata.events([SAMPLES / "suricata" / "dnp3_attack.eve.json"]))
    streams = sinks.to_loki_streams(events)
    assert len(streams) == 1
    assert streams[0]["stream"] == {"job": "ot_ndr", "service": "dnp3"}
    timestamp, line = streams[0]["values"][0]
    assert timestamp.isdigit()
    assert "function_code=" in line
