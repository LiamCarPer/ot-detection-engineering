"""Guard the detection catalogue and its health report."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools.detection_health import (  # noqa: E402
    CATALOG_PATH,
    OUT_DIR,
    build_health,
    discover_rules,
    main,
)

VOLUME_PATH = REPO_ROOT / "analysis" / "out" / "rule_health.json"


def _catalog() -> dict:
    return yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))


def _write_catalog(path: Path, catalog: dict) -> Path:
    path.write_text(yaml.safe_dump(catalog, sort_keys=False), encoding="utf-8")
    return path


def test_catalogue_has_no_schema_or_identity_gaps() -> None:
    health = build_health()
    assert health["schema_errors"] == []
    assert health["gaps"] == [], health["gaps"]
    assert health["totals"]["rules"] == health["totals"]["discovered_rules"]


def test_every_rule_has_exactly_one_entry() -> None:
    catalog = _catalog()
    entries = catalog["rules"]
    ids = [entry["id"] for entry in entries]
    assert len(ids) == len(set(ids))
    assert set(ids) == set(discover_rules())


def test_techniques_match_the_rules() -> None:
    discovered = discover_rules()
    for entry in _catalog()["rules"]:
        rule = discovered[entry["id"]]
        assert sorted(set(entry["techniques"])) == rule.techniques, entry["id"]


def test_every_stable_rule_has_a_runbook_volume_and_validation_date() -> None:
    stable = [entry for entry in _catalog()["rules"] if entry["status"] == "stable"]
    assert len(stable) == 6
    for entry in stable:
        assert entry["owner"]
        assert entry["data_source"]
        assert entry["expected_volume"] is not None
        assert entry["last_validated"]
        assert entry["runbook"]
        assert (REPO_ROOT / entry["runbook"]).exists(), entry["runbook"]


def test_catalogued_volume_matches_the_lab_analysis() -> None:
    health = build_health()
    by_id = {row["id"]: row for row in health["per_rule"]}
    volume = json.loads(VOLUME_PATH.read_text(encoding="utf-8"))["rules"]
    by_type = {row["alert_type"]: row for row in volume}
    for entry in _catalog()["rules"]:
        types = entry.get("lab_alert_types", [])
        if not types:
            continue
        expected_raw = sum(by_type[t]["raw_alerts"] for t in types)
        expected_episodes = sum(by_type[t]["episodes"] for t in types)
        assert by_id[entry["id"]]["raw_alerts"] == expected_raw
        assert by_id[entry["id"]]["episodes"] == expected_episodes


def test_health_summary_and_report_are_current() -> None:
    assert main(["--check"]) == 0
    report = (OUT_DIR / "report.md").read_text(encoding="utf-8")
    health = build_health()
    assert str(health["totals"]["rules"]) in report
    assert str(health["totals"]["stable"]) in report
    assert str(health["totals"]["with_observed_volume"]) in report


def test_a_missing_catalogue_entry_is_a_gap(tmp_path: Path) -> None:
    catalog = _catalog()
    catalog["rules"] = catalog["rules"][1:]
    path = _write_catalog(tmp_path / "catalog.yaml", catalog)
    health = build_health(path)
    assert any("no catalogue entry" in gap["issue"] for gap in health["gaps"])


def test_a_stable_rule_without_a_runbook_is_a_gap(tmp_path: Path) -> None:
    catalog = copy.deepcopy(_catalog())
    stable = next(entry for entry in catalog["rules"] if entry["status"] == "stable")
    stable["runbook"] = None
    path = _write_catalog(tmp_path / "catalog.yaml", catalog)
    health = build_health(path)
    assert any("no runbook" in gap["issue"] for gap in health["gaps"])


def test_a_stale_volume_is_a_gap(tmp_path: Path) -> None:
    catalog = copy.deepcopy(_catalog())
    entry = next(entry for entry in catalog["rules"] if entry["expected_volume"])
    entry["expected_volume"]["raw_alerts"] += 1
    path = _write_catalog(tmp_path / "catalog.yaml", catalog)
    health = build_health(path)
    assert any("expected_volume is stale" in gap["issue"] for gap in health["gaps"])


def test_schema_rejects_an_unknown_status(tmp_path: Path) -> None:
    catalog = copy.deepcopy(_catalog())
    catalog["rules"][0]["status"] = "bogus"
    path = _write_catalog(tmp_path / "catalog.yaml", catalog)
    health = build_health(path)
    assert health["schema_errors"]


def test_no_runbook_is_missing() -> None:
    for entry in _catalog()["rules"]:
        if entry["runbook"]:
            assert (REPO_ROOT / entry["runbook"]).exists()
