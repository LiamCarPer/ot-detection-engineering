"""Compute detection-quality metrics from repository artifacts.

Four measurements are produced from content that already lives in the
repository, so the numbers cannot drift from the detections:

- **Rule validation.** Each rule is evaluated against its labeled positive and
  negative fixtures to produce precision, recall and false-positive rate.
- **Baseline false positives.** Every Sigma rule is evaluated against a corpus
  of benign operational events. A benign event that matches any rule is a false
  positive.
- **ATT&CK for ICS coverage.** The share of ICS techniques with at least one
  detection, from the generated coverage map.
- **Emulation results.** Detection rate and mean MTTD from the last purple-team
  run, if one is present.

Usage:
    python metrics/compute.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "coverage") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "coverage"))

from generate_coverage import build_report  # noqa: E402
from sigma.rule import SigmaRule  # noqa: E402

from tools.otde.matcher import match  # noqa: E402
from tools.otde.rules import load_cases, sigma_rule_paths  # noqa: E402

DEFAULT_BASELINE = REPO_ROOT / "metrics" / "baseline" / "benign-events.jsonl"
DEFAULT_EMULATION = REPO_ROOT / "purple" / "results" / "emulation_results.json"
DEFAULT_OUT = REPO_ROOT / "metrics" / "out"


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def load_baseline(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def fixture_metrics() -> tuple[list[dict], dict]:
    per_rule = []
    totals = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    for rule_path in sigma_rule_paths():
        rule = SigmaRule.from_yaml(rule_path.read_text(encoding="utf-8"))
        counts = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
        for case in load_cases(rule_path):
            observed = match(rule, case.event)
            if case.expect_match and observed:
                counts["tp"] += 1
            elif case.expect_match and not observed:
                counts["fn"] += 1
            elif not case.expect_match and observed:
                counts["fp"] += 1
            else:
                counts["tn"] += 1
        for key in totals:
            totals[key] += counts[key]
        per_rule.append(
            {
                "rule": rule_path.relative_to(REPO_ROOT).as_posix(),
                "title": rule.title,
                **counts,
                "precision": _ratio(counts["tp"], counts["tp"] + counts["fp"]),
                "recall": _ratio(counts["tp"], counts["tp"] + counts["fn"]),
            }
        )
    aggregate = {
        **totals,
        "precision": _ratio(totals["tp"], totals["tp"] + totals["fp"]),
        "recall": _ratio(totals["tp"], totals["tp"] + totals["fn"]),
        "false_positive_rate": _ratio(totals["fp"], totals["fp"] + totals["tn"]),
    }
    return per_rule, aggregate


def baseline_metrics(events: list[dict]) -> dict:
    rules = [
        (
            path.relative_to(REPO_ROOT).as_posix(),
            SigmaRule.from_yaml(path.read_text(encoding="utf-8")),
        )
        for path in sigma_rule_paths()
    ]
    false_positives = []
    for index, event in enumerate(events):
        matches = [name for name, rule in rules if match(rule, event)]
        if matches:
            false_positives.append({"event_index": index, "rules": matches})
    return {
        "events_total": len(events),
        "false_positive_events": len(false_positives),
        "false_positive_rate": _ratio(len(false_positives), len(events)),
        "details": false_positives,
    }


def load_emulation(path: Path) -> dict | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def build_metrics(baseline_path: Path, emulation_path: Path) -> dict:
    per_rule, fixture = fixture_metrics()
    coverage = build_report()["summary"]
    emulation = load_emulation(emulation_path)
    return {
        "coverage": coverage,
        "rule_validation": {"per_rule": per_rule, "aggregate": fixture},
        "baseline": baseline_metrics(load_baseline(baseline_path)),
        "emulation": emulation["summary"] if emulation else None,
    }


def render_markdown(metrics: dict) -> str:
    coverage = metrics["coverage"]
    fixture = metrics["rule_validation"]["aggregate"]
    baseline = metrics["baseline"]
    emulation = metrics["emulation"]

    lines = [
        "# Detection Metrics",
        "",
        "| Metric | Value |",
        "| :--- | ---: |",
        f"| ATT&CK for ICS coverage | {coverage['techniques_covered']}/"
        f"{coverage['techniques_total']} ({coverage['coverage_pct']}%) |",
        f"| Rule precision | {fixture['precision']} |",
        f"| Rule recall | {fixture['recall']} |",
        f"| Fixture false-positive rate | {fixture['false_positive_rate']} |",
        f"| Baseline false-positive rate | {baseline['false_positive_rate']} |",
    ]
    if emulation:
        lines += [
            f"| Emulation detection rate | {emulation['detection_rate_pct']}% |",
            f"| Mean MTTD | {emulation['mean_mttd_seconds']} s |",
        ]
    else:
        lines.append("| Emulation detection rate | not run |")

    lines += [
        "",
        "## Rule validation",
        "",
        "| Rule | TP | FN | FP | TN | Precision | Recall |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for rule in metrics["rule_validation"]["per_rule"]:
        lines.append(
            f"| {rule['title']} | {rule['tp']} | {rule['fn']} | {rule['fp']} | "
            f"{rule['tn']} | {rule['precision']} | {rule['recall']} |"
        )

    lines += [
        "",
        "## Baseline",
        "",
        f"{baseline['false_positive_events']} of {baseline['events_total']} benign "
        "events matched a rule.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    parser.add_argument("--emulation", default=str(DEFAULT_EMULATION))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)

    metrics = build_metrics(Path(args.baseline), Path(args.emulation))
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "report.md").write_text(render_markdown(metrics), encoding="utf-8")

    coverage = metrics["coverage"]
    print(
        f"coverage {coverage['coverage_pct']}% | "
        f"precision {metrics['rule_validation']['aggregate']['precision']} | "
        f"recall {metrics['rule_validation']['aggregate']['recall']} | "
        f"baseline FPR {metrics['baseline']['false_positive_rate']} -> {out_dir}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
