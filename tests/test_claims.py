"""Keep the claims register and reviewer guide honest.

The claims register is only useful if it stays in step with the rules. These
tests check the few figures that are cheap to derive offline; the expensive ones
(held-out metrics, emulation) are checked by their own suites and by the
commands the register names.
"""

from __future__ import annotations

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


def test_claims_register_marks_stale_numbers_as_stale() -> None:
    text = CLAIMS.read_text(encoding="utf-8")
    assert "17.5%" in text and "stale" in text.lower()
    assert "52 benign events" in text


def test_reviewer_guide_links_to_the_claims_register() -> None:
    text = REVIEWER_GUIDE.read_text(encoding="utf-8")
    assert "docs/CLAIMS.md" in text
    assert "Where to be skeptical" in text


def test_claims_and_reviewer_guide_are_linked_from_the_readme() -> None:
    text = README.read_text(encoding="utf-8")
    assert "docs/CLAIMS.md" in text
    assert "docs/REVIEWER_GUIDE.md" in text
