"""Check the independent mass-balance monitor against the process rule.

Three scenarios are simulated: a normal fill/drain cycle, an external open
command at a high level, and the same command while the reported level is pinned
by a spoof. Each event stream is run through the repository's
``Process Safety Violation`` rule.

The comparison that matters is the spoof: a monitor that trusts the PLC's level
register sees 41% and stays quiet, while the mass balance sees 94% and trips.
The evidence records both so the independence claim is measurable, not asserted.

This is a model, not plant data. The live lab run is separate evidence.

Usage:
    python tools/process_model_check.py
    python tools/process_model_check.py --check
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sigma.rule import SigmaRule  # noqa: E402

from services.process.mass_balance import HIGH_LEVEL, simulate  # noqa: E402
from tools.otde.matcher import match  # noqa: E402

RULE = REPO_ROOT / "rules" / "sigma" / "ot" / "ot_process_safety_violation.yml"
OUT_DIR = REPO_ROOT / "deploy" / "evidence" / "process-model"
SCENARIOS = ("normal", "unsafe", "spoof")


def _detections(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rule = SigmaRule.from_yaml(RULE.read_text(encoding="utf-8"))
    return [event for event in events if match(rule, event)]


def _summary(scenario: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    detections = _detections(events)
    first = detections[0] if detections else None
    violation = next(
        (event for event in events if event["event_type"] == "process_safety_violation"),
        None,
    )
    return {
        "scenario": scenario,
        "events": len(events),
        "detections": len(detections),
        "max_estimated_level_pct": max(event["tank_level_pct"] for event in events),
        "max_divergence_pct": max(event["divergence_pct"] for event in events),
        "first_detection": (
            {
                "estimated_level_pct": first["tank_level_pct"],
                "reported_level_pct": first["reported_level_pct"],
                "timestamp": first["timestamp"],
            }
            if first
            else None
        ),
        # A shadow monitor trusts the reported level. It can only trip when the
        # reported value is inside the envelope, which is exactly what a spoof
        # prevents.
        "shadow_would_detect": bool(
            violation and violation["reported_level_pct"] >= HIGH_LEVEL
        ),
    }


def build() -> dict[str, Any]:
    results = []
    for scenario in SCENARIOS:
        events = simulate(scenario)
        results.append(_summary(scenario, events))
    by_name = {row["scenario"]: row for row in results}
    failures: list[str] = []
    if by_name["normal"]["detections"] != 0:
        failures.append("the normal cycle produced a detection")
    if by_name["unsafe"]["detections"] != 1:
        failures.append("the unsafe command was not detected")
    if by_name["spoof"]["detections"] != 1:
        failures.append("the spoof did not produce a mass-balance detection")
    if by_name["spoof"]["shadow_would_detect"]:
        failures.append("the shadow monitor was expected to be blinded by the spoof")
    if by_name["spoof"]["max_divergence_pct"] < 40:
        failures.append("the spoof divergence is smaller than the test requires")
    return {
        "schema_version": 1,
        "model": (
            "tank with measured inlet/outlet flow; the estimator never reads the "
            "reported level"
        ),
        "rule": RULE.relative_to(REPO_ROOT).as_posix(),
        "high_level_pct": HIGH_LEVEL,
        "scenarios": results,
        "failures": failures,
    }


def render(report: dict[str, Any]) -> str:
    lines = [
        "# Process mass-balance model",
        "",
        "Model, not plant data. The estimator integrates measured inlet and outlet",
        "flow and never reads the PLC's reported level.",
        "",
        "| Scenario | Events | Rule detections | Shadow would detect | "
        "Max estimated | Max divergence |",
        "| :-- | --: | --: | :--: | --: | --: |",
    ]
    for row in report["scenarios"]:
        lines.append(
            f"| {row['scenario']} | {row['events']} | {row['detections']} | "
            f"{'yes' if row['shadow_would_detect'] else 'no'} | "
            f"{row['max_estimated_level_pct']:.1f}% | {row['max_divergence_pct']:.1f}% |"
        )
    lines += [
        "",
        "The spoof row is the point: the reported level is pinned near 40%, so a",
        "monitor that trusts the register stays quiet, while the mass balance",
        "reaches the 90% envelope and the rule fires.",
        "",
        "## Limits",
        "",
        "- A two-flow tank model, not a plant. Flow transmitters, density and",
        "  geometry are simplified.",
        "- The estimator's constants must be calibrated per tank; a wrong capacity",
        "  shows up as drift, not as a spoof.",
        "- Offline model evidence; the live lab run is separate.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    report = build()
    if report["failures"]:
        print("process model check failed:")
        for failure in report["failures"]:
            print(f"  - {failure}")
        return 1
    out = OUT_DIR
    summary = out / "summary.json"
    markdown = out / "report.md"
    if args.check:
        if (
            not summary.exists()
            or not markdown.exists()
            or json.loads(summary.read_text(encoding="utf-8")) != report
            or markdown.read_text(encoding="utf-8") != render(report)
        ):
            print("process model evidence is stale: run `make process-model`")
            return 1
        print("process model evidence is current")
        return 0
    out.mkdir(parents=True, exist_ok=True)
    summary.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    markdown.write_text(render(report), encoding="utf-8")
    for row in report["scenarios"]:
        print(
            f"{row['scenario']}: {row['detections']} detections, "
            f"max divergence {row['max_divergence_pct']}%"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
