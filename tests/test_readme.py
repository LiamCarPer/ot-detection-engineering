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
OBSERVATIONS_PATH = REPO_ROOT / "purple" / "emulation" / "lab-observations.json"


def test_readme_coverage_matches_the_coverage_map() -> None:
    readme = README_PATH.read_text(encoding="utf-8")
    summary = build_report()["summary"]
    expected = (
        f"{summary['techniques_covered']} / {summary['techniques_total']} techniques "
        f"({summary['coverage_pct']}%)"
    )
    assert expected in readme, f"README coverage is stale; expected {expected!r}"


def test_readme_emulation_matches_the_committed_run() -> None:
    readme = README_PATH.read_text(encoding="utf-8")
    observations = json.loads(OBSERVATIONS_PATH.read_text(encoding="utf-8"))
    summary = evaluate(load_plan(), observations)["summary"]
    assert f"{summary['mean_mttd_seconds']} s" in readme, "README MTTD is stale"
    assert (
        f"{summary['expectations_detected']} / {summary['expectations_total']} expectations"
        in readme
    ), "README detection rate is stale"
