"""Guard the lab alert-flood case study.

The case study is a claim about real data, so the numbers must be derived from
the pinned snapshot and the narrative must not drift from the generated summary.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from analysis.lab_case_study import (  # noqa: E402
    build,
    main,
    verify_snapshot,
)

SNAPSHOT = REPO_ROOT / "analysis" / "data" / "lab-2026-11-24"
OUT = REPO_ROOT / "analysis" / "out"
CASE_STUDY = REPO_ROOT / "docs" / "CASE_STUDY_ALERT_FLOOD.md"


def test_snapshot_hashes_match_the_manifest() -> None:
    manifest = verify_snapshot(SNAPSHOT)
    assert manifest["source_commit"] == "df9fae4799b56a7aad7338967421ee4b0430cdda"
    assert manifest["snapshot"] == "lab-2026-11-24"


def test_snapshot_has_the_expected_shape() -> None:
    summary, _, _ = build(SNAPSHOT)
    assert summary["alerts"]["raw"] == 151
    assert summary["alerts"]["types"] == 17
    assert summary["alerts"]["sources"] == 4
    assert summary["alerts"]["duration_seconds"] == 160.292


def test_every_alert_is_assigned_to_a_campaign() -> None:
    summary, _, _ = build(SNAPSHOT)
    assigned = sum(campaign["raw_alerts"] for campaign in summary["campaigns"]["items"])
    assert assigned == summary["alerts"]["raw"]


def test_campaigns_are_the_four_adversary_sources_plus_health() -> None:
    summary, _, _ = build(SNAPSHOT)
    campaigns = summary["campaigns"]["items"]
    assert summary["campaigns"]["total"] == 5
    assert len(campaigns) == 5
    assert {campaign["source_ip"] for campaign in campaigns} == {
        "172.24.0.10",
        "172.23.0.20",
        "172.22.0.30",
        "172.24.0.30",
        None,
    }
    assert [campaign["id"] for campaign in campaigns] == ["C1", "C2", "C3", "C4", "C5"]


def test_the_queue_reduces_without_erasing_the_raw_count() -> None:
    summary, _, _ = build(SNAPSHOT)
    assert summary["episodes"]["total"] == 24
    assert summary["episodes"]["duplicate_ratio"] == 0.8411
    assert summary["episodes"]["total"] < summary["alerts"]["raw"]
    assert summary["campaigns"]["total"] < summary["episodes"]["total"]


def test_rule_health_covers_every_alert_type() -> None:
    summary, _, health = build(SNAPSHOT)
    assert len(health["rules"]) == summary["alerts"]["types"]
    assert {rule["alert_type"] for rule in health["rules"]} == {
        row["alert_type"] for row in summary["episodes"]["by_type"]
    }
    cross_zone = next(
        rule for rule in health["rules"] if rule["alert_type"] == "CROSS_ZONE_VIOLATION"
    )
    assert cross_zone["raw_alerts"] == 74
    assert cross_zone["episodes"] == 6
    assert cross_zone["duplicate_ratio"] == 0.9189


def test_secondary_datasets_are_labelled_separately() -> None:
    summary, _, _ = build(SNAPSHOT)
    assert summary["siem_lifecycle"]["rows"] == 364
    assert summary["siem_lifecycle"]["status"] == {"firing": 305, "resolved": 59}
    assert summary["runtime_totals"]["alerts"] == 581
    assert summary["runtime_totals"]["captured_at"] == "2026-10-25T01:01:45Z"


def test_committed_outputs_are_current() -> None:
    assert main(["--input", str(SNAPSHOT), "--out", str(OUT), "--check"]) == 0


def test_generated_report_contains_the_summary_numbers() -> None:
    summary, report, _ = build(SNAPSHOT)
    assert str(summary["alerts"]["raw"]) in report
    assert str(summary["episodes"]["total"]) in report
    assert str(summary["campaigns"]["total"]) in report
    assert str(summary["episodes"]["duplicate_ratio"]) in report
    assert "C1" in report and "C3" in report


def test_case_study_uses_the_computed_numbers() -> None:
    text = CASE_STUDY.read_text(encoding="utf-8")
    summary, _, _ = build(SNAPSHOT)
    assert f"{summary['alerts']['raw']} alerts" in text
    assert f"{summary['episodes']['total']} timed episodes" in text
    assert "84.1%" in text
    assert "96.7%" in text
    assert "581" in text
    assert "364" in text


def test_case_study_does_not_claim_production_or_time_saved() -> None:
    text = CASE_STUDY.read_text(encoding="utf-8").lower()
    assert "does not prove" in text
    assert "no analyst action timestamps" in text
    assert "time saved" in text
    assert "plant traffic" in text
