"""Governance tests for the threat model and the security control register.

A control that is documented but not backed by a test, or a threat with no
control, is security theatre. These tests make the register fail loudly instead.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "coverage"))

from security_coverage import build_report, load  # noqa: E402

MODEL, REGISTER = load()
THREATS = {threat["id"]: threat for threat in MODEL["threats"]}
CONTROLS = {control["id"]: control for control in REGISTER["controls"]}
ASSETS = {asset["id"] for asset in MODEL["assets"]}
STATUSES = {"implemented", "planned"}


def test_ids_are_unique() -> None:
    assert len(THREATS) == len(MODEL["threats"])
    assert len(CONTROLS) == len(REGISTER["controls"])


def test_every_threat_has_a_control() -> None:
    for threat in THREATS.values():
        assert threat["controls"], f"{threat['id']} has no control"
        for control_id in threat["controls"]:
            assert control_id in CONTROLS, f"{threat['id']} references {control_id}"


def test_every_control_mitigates_a_threat() -> None:
    for control in CONTROLS.values():
        assert control["threats"], f"{control['id']} mitigates no threat"
        for threat_id in control["threats"]:
            assert threat_id in THREATS, f"{control['id']} references {threat_id}"


def test_the_mapping_is_bidirectional() -> None:
    for threat in THREATS.values():
        for control_id in threat["controls"]:
            assert threat["id"] in CONTROLS[control_id]["threats"], (
                f"{control_id} does not list {threat['id']}"
            )
    for control in CONTROLS.values():
        for threat_id in control["threats"]:
            assert control["id"] in THREATS[threat_id]["controls"], (
                f"{threat_id} does not list {control['id']}"
            )


def test_threats_reference_a_declared_asset() -> None:
    for threat in THREATS.values():
        assert threat["asset"] in ASSETS, f"{threat['id']} uses unknown asset"


def test_statuses_are_known() -> None:
    for control in CONTROLS.values():
        assert control["status"] in STATUSES, control["id"]


def test_implemented_controls_have_existing_evidence() -> None:
    for control in CONTROLS.values():
        if control["status"] != "implemented":
            continue
        assert control.get("verify"), f"{control['id']} has no verification command"
        evidence = control.get("evidence")
        assert evidence, f"{control['id']} has no evidence"
        assert (REPO_ROOT / evidence).exists(), f"{control['id']} evidence missing: {evidence}"


def test_coverage_report_is_consistent() -> None:
    report = build_report()
    summary = report["summary"]
    assert summary["threats_total"] == len(THREATS)
    assert summary["controls_total"] == len(CONTROLS)
    covered = sum(1 for threat in report["threats"] if threat["covered"])
    assert summary["threats_covered"] == covered
    implemented = sum(1 for control in CONTROLS.values() if control["status"] == "implemented")
    assert summary["controls_implemented"] == implemented
