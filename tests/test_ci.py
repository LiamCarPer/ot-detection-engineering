"""Keep the CI evidence gates in step with the Makefile.

The repository's central claim is that committed evidence cannot drift. That is
only true if CI actually runs each check. This test parses the workflow and fails
when an evidence tool is missing, or when it is run in write mode instead of
check mode.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = REPO_ROOT / "Makefile"

# Evidence tools whose committed output must be checked, not rewritten, in CI.
EVIDENCE_TOOLS = (
    "tools/yara_check.py",
    "tools/decoder_check.py",
    "tools/collector_check.py",
    "tools/baseline_check.py",
    "tools/conduit_check.py",
    "tools/stateful_check.py",
    "tools/perf_check.py",
    "metrics/fpr.py",
    "tools/detection_health.py",
    "analysis/lab_case_study.py",
    "purple/runner/run_emulation.py",
    "tools/allowlists.py",
    "tools/process_model_check.py",
    "coverage/security_coverage.py",
    "tools/check_action_pins.py",
)

# Tools that only have a check mode; no --check flag exists.
CHECK_ONLY = {"tools/check_action_pins.py"}


def _steps() -> list[str]:
    data = yaml.safe_load(CI.read_text(encoding="utf-8"))
    return [
        step.get("run", "")
        for job in data["jobs"].values()
        for step in job.get("steps", [])
        if step.get("run")
    ]


def test_every_evidence_tool_runs_in_ci() -> None:
    text = "\n".join(_steps())
    missing = [tool for tool in EVIDENCE_TOOLS if tool not in text]
    assert not missing, f"no CI step runs: {missing}"


def test_every_evidence_tool_runs_in_check_mode() -> None:
    steps = _steps()
    failures = []
    for tool in EVIDENCE_TOOLS:
        if tool in CHECK_ONLY:
            continue
        matching = [step for step in steps if tool in step]
        if not any("--check" in step for step in matching):
            failures.append(tool)
    assert not failures, f"CI runs these without --check: {failures}"


def test_make_check_includes_the_all_family_fpr_gate() -> None:
    text = MAKEFILE.read_text(encoding="utf-8")
    check = next(line for line in text.splitlines() if line.startswith("check:"))
    assert "fpr-check" in check
    assert "health-check" in check
    assert "case-study-check" in check
    assert "purple-check" in check
