"""Keep the README results table honest.

The repository claims the numbers are derived from the rules, so the headline
figures in the README must match what the coverage map and the committed
emulation run actually produce. These tests fail when a rule change moves a
number without the README being updated.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "coverage"))
sys.path.insert(0, str(REPO_ROOT / "purple" / "runner"))

from generate_coverage import build_report  # noqa: E402
from run_emulation import evaluate, load_plan  # noqa: E402

README_PATH = REPO_ROOT / "README.md"
OLD_PLAN = REPO_ROOT / "purple" / "emulation" / "emulation-plan-2026-09-13.yaml"
OLD_OBSERVATIONS = REPO_ROOT / "purple" / "emulation" / "lab-observations-2026-09-13.json"
PURPLE_RESULTS = REPO_ROOT / "deploy" / "evidence" / "purple" / "emulation_results.json"


def test_readme_coverage_matches_the_coverage_map() -> None:
    readme = README_PATH.read_text(encoding="utf-8")
    summary = build_report()["summary"]
    expected = (
        f"{summary['techniques_covered']} / {summary['techniques_total']} techniques "
        f"({summary['coverage_pct']}%)"
    )
    assert expected in readme, f"README coverage is stale; expected {expected!r}"


def test_readme_mttd_matches_the_recorded_run() -> None:
    readme = README_PATH.read_text(encoding="utf-8")
    observations = json.loads(OLD_OBSERVATIONS.read_text(encoding="utf-8"))
    summary = evaluate(load_plan(OLD_PLAN), observations)["summary"]
    assert f"{summary['mean_mttd_seconds']} s" in readme, "README MTTD is stale"
    assert (
        f"{summary['expectations_detected']} / {summary['expectations_total']} expectations"
        in readme
    ), "README detection rate is stale"


def test_readme_purple_coverage_matches_the_replay() -> None:
    readme = README_PATH.read_text(encoding="utf-8")
    summary = json.loads(PURPLE_RESULTS.read_text(encoding="utf-8"))["summary"]
    expected = (
        f"{summary['expectations_detected']} / {summary['expectations_total']} expectations"
    )
    assert expected in readme, "README purple coverage is stale"
    assert "8 steps" in readme
    assert f"{summary['unexpected_alerts']} unexpected" in readme
