"""Keep the claims register and reviewer guide honest.

The claims register is only useful if it stays in step with the rules. These
tests check the few figures that are cheap to derive offline; the expensive ones
(held-out metrics, emulation) are checked by their own suites and by the
commands the register names.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "coverage"))

from generate_coverage import build_report  # noqa: E402

from tools.otde.rules import (  # noqa: E402
    correlation_rule_paths,
    native_rule_paths,
    single_event_rule_paths,
    stateful_rule_paths,
    yara_rule_paths,
)
from tools.otde.suricata import read_rules  # noqa: E402

CLAIMS = REPO_ROOT / "docs" / "CLAIMS.md"
REVIEWER_GUIDE = REPO_ROOT / "docs" / "REVIEWER_GUIDE.md"
RESULTS = REPO_ROOT / "docs" / "RESULTS.md"
README = REPO_ROOT / "README.md"


def test_claims_coverage_matches_the_coverage_map() -> None:
    summary = build_report()["summary"]
    expected = (
        f"{summary['techniques_covered']} / {summary['techniques_total']} "
        f"techniques ({summary['coverage_pct']}%)"
    )
    assert expected in CLAIMS.read_text(encoding="utf-8")


def test_claims_rule_counts_match_the_repository() -> None:
    native = sum(
        len([rule for rule in read_rules(path) if rule.sid is not None])
        for path in native_rule_paths()
    )
    expected = (
        f"{len(single_event_rule_paths())} Sigma + "
        f"{len(correlation_rule_paths())} correlation + "
        f"{len(yara_rule_paths())} YARA + {native} native + "
        f"{len(stateful_rule_paths())} stateful"
    )
    assert expected in CLAIMS.read_text(encoding="utf-8")


def test_readme_per_tactic_table_matches_the_coverage_map() -> None:
    text = README.read_text(encoding="utf-8")
    start = text.index("## Coverage: prioritized, not padded")
    end = text.index("## Results at a glance", start)
    rows = re.findall(r"^\| ([^|]+?) \| (\d+) / (\d+) \|", text[start:end], re.MULTILINE)
    observed = {
        name.strip().lower(): (int(covered), int(total))
        for name, covered, total in rows
    }
    expected = {
        tactic["name"].lower(): (
            tactic["techniques_covered"],
            tactic["techniques_total"],
        )
        for tactic in build_report()["tactics"]
    }
    assert observed == expected


def test_readme_and_results_use_the_same_coverage_framing() -> None:
    summary = build_report()["summary"]
    raw = (
        f"{summary['techniques_covered']} / {summary['techniques_total']} "
        f"techniques ({summary['coverage_pct']}%)"
    )
    assert raw in README.read_text(encoding="utf-8")
    assert raw in RESULTS.read_text(encoding="utf-8")


def test_claims_register_marks_only_the_canonical_numbers_current() -> None:
    text = CLAIMS.read_text(encoding="utf-8")
    assert "Older draft figures" in text
    assert "not current" in text


def test_reviewer_guide_links_to_the_claims_register() -> None:
    text = REVIEWER_GUIDE.read_text(encoding="utf-8")
    assert "docs/CLAIMS.md" in text
    assert "Where to be skeptical" in text


def test_claims_and_reviewer_guide_are_linked_from_the_readme() -> None:
    text = README.read_text(encoding="utf-8")
    assert "docs/CLAIMS.md" in text
    assert "docs/REVIEWER_GUIDE.md" in text


def test_readme_performance_numbers_match_the_evidence() -> None:
    perf = json.loads(
        (REPO_ROOT / "deploy" / "evidence" / "perf" / "summary.json").read_text(
            encoding="utf-8"
        )
    )
    rates = [row["frames_per_second"] / 1_000_000 for row in perf["protocols"].values()]
    low = min(rates)
    high = max(rates)
    replay = perf["pipeline"]["events_per_second"]
    text = README.read_text(encoding="utf-8")
    assert f"{low:.1f}–{high:.1f}M decoder frames/s" in text
    assert f"~{round(replay, -2):,.0f} replay events/s" in text


def test_all_family_fpr_is_clean_and_reported() -> None:
    report = json.loads(
        (REPO_ROOT / "deploy" / "evidence" / "fpr" / "summary.json").read_text(
            encoding="utf-8"
        )
    )
    families = report["families"]
    assert families["sigma_single_event"]["false_positive_events"] == 0
    assert families["baseline"]["false_positive_events"] == 0
    assert families["conduit"]["false_positive_events"] == 0
    assert families["sigma_correlation"]["fired"] == []
    assert families["stateful"]["fired"] == []
    assert families["native"]["false_positive_alerts"] == 0
    assert families["yara"]["false_positive_files"] == 0
    assert "deploy/evidence/fpr/report.md" in README.read_text(encoding="utf-8")


def test_readme_catalogue_numbers_match_the_health_report() -> None:
    health = json.loads(
        (REPO_ROOT / "deploy" / "evidence" / "health" / "summary.json").read_text(
            encoding="utf-8"
        )
    )["totals"]
    text = README.read_text(encoding="utf-8")
    assert f"{health['rules']} rules" in text
    assert f"{health['stable']} stable" in text
    assert f"{health['rules'] - health['stable']} experimental" in text


def test_stale_57_is_gone() -> None:
    assert "other 57" not in REVIEWER_GUIDE.read_text(encoding="utf-8")


def test_evidence_map_is_linked_and_documents_the_lab_snapshot() -> None:
    evidence_map = (REPO_ROOT / "docs" / "EVIDENCE_MAP.md").read_text(encoding="utf-8")
    assert "2026-09-15" in evidence_map
    assert "predates the p1 rule changes" in evidence_map.lower()
    assert "docs/EVIDENCE_MAP.md" in README.read_text(encoding="utf-8")
    assert "EVIDENCE_MAP.md" in CLAIMS.read_text(encoding="utf-8")
