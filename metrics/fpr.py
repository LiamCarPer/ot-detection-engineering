"""Measure false positives for every detection family, not only Sigma.

The historical headline ``0 / 1,000`` evaluated the single-event Sigma rules and
called it the baseline false-positive rate. That left the behaviour-baseline,
conduit, correlation and stateful families unmeasured, and they were not silent.
This module measures each family against the same committed benign corpus and
reports the result separately, so no family hides behind another family's clean
number.

Families:

- ``sigma_single_event``: each single-event Sigma rule against each event.
- ``sigma_correlation``: each correlation rule against the whole benign
  sequence; a correlation is either fired or not on the corpus.
- ``baseline``: each behaviour-baseline rule against each event, using the
  committed baseline learned from the held-out seed.
- ``conduit``: each conduit rule against each event, using the committed policy.
- ``stateful``: each stateful rule against the whole benign sequence.
- ``native``: alert counts in the committed benign Suricata captures.
- ``yara``: committed benign and near-miss fixtures that a rule must not match.

``event_shapes`` reports how many distinct behavioural shapes the corpus
contains. The corpus repeats a small number of templates, so a binomial
interval over 1,000 rows overstates the effective sample size; the shape count
is reported next to the interval rather than hidden.

Usage:
    python metrics/fpr.py
    python metrics/fpr.py --check
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "metrics") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "metrics"))

from sigma.collection import SigmaCollection  # noqa: E402
from sigma.correlations import SigmaCorrelationRule  # noqa: E402
from sigma.rule import SigmaRule  # noqa: E402
from stats import rounded_interval  # noqa: E402

from tools.otde.baseline import load_baseline, load_baseline_rule, match_baseline  # noqa: E402
from tools.otde.conduit import load_conduit_rule, load_policy, match_conduit  # noqa: E402
from tools.otde.correlation import match_correlation  # noqa: E402
from tools.otde.matcher import match  # noqa: E402
from tools.otde.rules import (  # noqa: E402
    SIGMA_RULES_DIR,
    baseline_rule_paths,
    conduit_rule_paths,
    single_event_rule_paths,
    stateful_rule_paths,
)
from tools.otde.stateful import load_stateful_rule, match_stateful  # noqa: E402

CORPUS = REPO_ROOT / "metrics" / "baseline" / "benign-events.jsonl"
OUT_DIR = REPO_ROOT / "deploy" / "evidence" / "fpr"
OUT_JSON = OUT_DIR / "summary.json"
OUT_MARKDOWN = OUT_DIR / "report.md"
EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence"
BENIGN_CAPTURES = ("modbus_benign", "dnp3_benign", "opcua_benign", "s7comm_benign")


def _load_events() -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in CORPUS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _ratio(numerator: int, denominator: int) -> float | None:
    if denominator == 0:
        return None
    return round(numerator / denominator, 4)


def _shape(event: dict[str, Any]) -> tuple:
    """A coarse behavioural shape, ignoring timestamps and ephemeral values."""
    keys = (
        "product",
        "service",
        "direction",
        "function_code",
        "event_type",
        "action",
        "proto",
        "message_type",
        "opcua_service",
        "flow_state",
        "src_zone",
        "dst_zone",
    )
    return tuple(event.get(key) for key in keys)


def sigma_single_event(events: list[dict]) -> dict[str, Any]:
    rules = [
        (
            path.relative_to(REPO_ROOT).as_posix(),
            SigmaRule.from_yaml(path.read_text(encoding="utf-8")),
        )
        for path in single_event_rule_paths()
    ]
    per_rule = {name: 0 for name, _ in rules}
    false_positive_events: list[int] = []
    for index, event in enumerate(events):
        matched = False
        for name, rule in rules:
            if match(rule, event):
                per_rule[name] += 1
                matched = True
        if matched:
            false_positive_events.append(index)
    rate = _ratio(len(false_positive_events), len(events))
    low, high = rounded_interval(len(false_positive_events), len(events))
    return {
        "rules": len(rules),
        "false_positive_events": len(false_positive_events),
        "false_positive_rate": rate,
        "false_positive_rate_ci95": [low, high],
        "per_rule": per_rule,
        "event_indexes": false_positive_events,
    }


def sigma_correlation(events: list[dict]) -> dict[str, Any]:
    collection = SigmaCollection.load_ruleset([SIGMA_RULES_DIR])
    rules = [rule for rule in collection.rules if isinstance(rule, SigmaCorrelationRule)]
    per_rule = {}
    per_rule_input = {}
    for rule in rules:
        per_rule[rule.title] = match_correlation(rule, events)
        references = [
            reference.rule
            for reference in rule.referenced_rules
            if reference.rule is not None and isinstance(reference.rule, SigmaRule)
        ]
        per_rule_input[rule.title] = sum(
            1
            for event in events
            if any(match(reference, event) for reference in references)
        )
    return {
        "rules": len(rules),
        "fired": [title for title, fired in per_rule.items() if fired],
        "per_rule": per_rule,
        "per_rule_input": per_rule_input,
        "not_exercised": [
            title for title, count in per_rule_input.items() if count == 0
        ],
    }


def baseline_family(events: list[dict]) -> dict[str, Any]:
    baseline = load_baseline()
    rules = [
        load_baseline_rule(path)
        for path in baseline_rule_paths()
    ]
    per_rule = {rule["title"]: 0 for rule in rules}
    false_positive_events: list[int] = []
    for index, event in enumerate(events):
        matched = False
        for rule in rules:
            if match_baseline(rule, event, baseline):
                per_rule[rule["title"]] += 1
                matched = True
        if matched:
            false_positive_events.append(index)
    return {
        "rules": len(rules),
        "false_positive_events": len(false_positive_events),
        "false_positive_rate": _ratio(len(false_positive_events), len(events)),
        "per_rule": per_rule,
        "event_indexes": false_positive_events,
    }


def conduit_family(events: list[dict]) -> dict[str, Any]:
    policy = load_policy()
    rules = [load_conduit_rule(path) for path in conduit_rule_paths()]
    per_rule = {rule["title"]: 0 for rule in rules}
    false_positive_events: list[int] = []
    for index, event in enumerate(events):
        matched = False
        for rule in rules:
            if match_conduit(rule, event, policy):
                per_rule[rule["title"]] += 1
                matched = True
        if matched:
            false_positive_events.append(index)
    return {
        "rules": len(rules),
        "false_positive_events": len(false_positive_events),
        "false_positive_rate": _ratio(len(false_positive_events), len(events)),
        "per_rule": per_rule,
        "event_indexes": false_positive_events,
    }


def stateful_family(events: list[dict]) -> dict[str, Any]:
    per_rule = {}
    for path in stateful_rule_paths():
        rule = load_stateful_rule(path)
        per_rule[rule["title"]] = match_stateful(rule, events)
    return {
        "rules": len(per_rule),
        "fired": [title for title, fired in per_rule.items() if fired],
        "per_rule": per_rule,
    }


def native_family() -> dict[str, Any]:
    captures = {}
    for name in BENIGN_CAPTURES:
        eve = EVIDENCE_DIR / name / "eve.json"
        alerts = 0
        if eve.exists():
            alerts = sum(
                1
                for line in eve.read_text(encoding="utf-8").splitlines()
                if line.strip() and json.loads(line).get("event_type") == "alert"
            )
        captures[name] = alerts
    return {
        "measured_from": "committed benign Suricata captures",
        "false_positive_alerts": sum(captures.values()),
        "per_capture": captures,
    }


def yara_family() -> dict[str, Any]:
    summary = EVIDENCE_DIR / "yara" / "summary.json"
    if not summary.exists():
        return {"measured_from": "committed YARA fixtures", "status": "missing"}
    evidence = json.loads(summary.read_text(encoding="utf-8"))
    negatives = 0
    false_positives = 0
    for row in evidence.get("rules", []):
        for case in row.get("cases", []):
            if case.get("expected") == "no_match":
                negatives += 1
                if case.get("observed"):
                    false_positives += 1
    return {
        "measured_from": "committed YARA benign and near-miss fixtures",
        "false_positive_files": false_positives,
        "negative_files": negatives,
    }


def build() -> dict[str, Any]:
    events = _load_events()
    shapes = Counter(_shape(event) for event in events)
    families = {
        "sigma_single_event": sigma_single_event(events),
        "sigma_correlation": sigma_correlation(events),
        "baseline": baseline_family(events),
        "conduit": conduit_family(events),
        "stateful": stateful_family(events),
        "native": native_family(),
        "yara": yara_family(),
    }
    return {
        "schema_version": 1,
        "corpus": {
            "path": CORPUS.relative_to(REPO_ROOT).as_posix(),
            "events": len(events),
            "distinct_event_shapes": len(shapes),
            "note": (
                "The corpus cycles a fixed template set. A binomial interval over "
                "1,000 rows overstates the effective sample size; the shape count "
                "is the honest diversity measure."
            ),
        },
        "families": families,
    }


def _rate(value: float | None) -> str:
    return "—" if value is None else f"{value:.4f}"


def render_markdown(report: dict[str, Any]) -> str:
    families = report["families"]
    corpus = report["corpus"]
    lines = [
        "# False-positive measurement by family",
        "",
        f"Corpus: `{corpus['path']}` — **{corpus['events']}** events, "
        f"**{corpus['distinct_event_shapes']}** distinct behavioural shapes.",
        "",
        "The corpus cycles a fixed template set, so the binomial interval over "
        "1,000 rows overstates the effective sample size. The shape count is "
        "the honest diversity measure.",
        "",
        "| Family | Rules | Benign matches | Rate |",
        "| :--- | ---: | ---: | ---: |",
    ]
    single = families["sigma_single_event"]
    lines.append(
        f"| Sigma single-event | {single['rules']} | "
        f"{single['false_positive_events']} / {corpus['events']} events | "
        f"{_rate(single['false_positive_rate'])} |"
    )
    correlation = families["sigma_correlation"]
    lines.append(
        f"| Sigma correlation | {correlation['rules']} | "
        f"{len(correlation['fired'])} fired; "
        f"{correlation['rules'] - len(correlation['not_exercised'])}/"
        f"{correlation['rules']} had referenced-rule input | "
        f"{'—' if not correlation['fired'] else 'see detail'} |"
    )
    baseline = families["baseline"]
    lines.append(
        f"| Behaviour baseline | {baseline['rules']} | "
        f"{baseline['false_positive_events']} / {corpus['events']} events | "
        f"{_rate(baseline['false_positive_rate'])} |"
    )
    conduit = families["conduit"]
    lines.append(
        f"| Conduit | {conduit['rules']} | "
        f"{conduit['false_positive_events']} / {corpus['events']} events | "
        f"{_rate(conduit['false_positive_rate'])} |"
    )
    stateful = families["stateful"]
    lines.append(
        f"| Stateful | {stateful['rules']} | "
        f"{len(stateful['fired'])} fired on the corpus | "
        f"{'—' if not stateful['fired'] else 'see detail'} |"
    )
    native = families["native"]
    lines.append(
        f"| Native Suricata | {len(native['per_capture'])} benign captures | "
        f"{native['false_positive_alerts']} alerts | — |"
    )
    yara = families["yara"]
    lines.append(
        f"| YARA | {yara.get('negative_files', 0)} negative files | "
        f"{yara.get('false_positive_files', 0)} matched | — |"
    )

    lines += ["", "## Detail", ""]
    if correlation["fired"]:
        lines.append(
            "- Correlation rules fired on benign input: "
            + ", ".join(sorted(correlation["fired"]))
        )
    if stateful["fired"]:
        lines.append(
            "- Stateful rules fired on benign input: "
            + ", ".join(sorted(stateful["fired"]))
        )
    noisy_baseline = {
        title: count for title, count in baseline["per_rule"].items() if count
    }
    if noisy_baseline:
        lines.append(
            "- Behaviour-baseline rules with benign matches: "
            + ", ".join(f"{title} ({count})" for title, count in sorted(noisy_baseline.items()))
        )
    noisy_conduit = {
        title: count for title, count in conduit["per_rule"].items() if count
    }
    if noisy_conduit:
        lines.append(
            "- Conduit rules with benign matches: "
            + ", ".join(f"{title} ({count})" for title, count in sorted(noisy_conduit.items()))
        )
    if correlation.get("not_exercised"):
        lines.append(
            "- Correlation rules with no referenced-rule input on this corpus are "
            "not a measured zero: "
            + ", ".join(sorted(correlation["not_exercised"]))
        )
    if not stateful["fired"]:
        lines.append(
            "- Stateful: 0 fired. The engineering-change rule needs an "
            "engineering-source write, which this corpus does not contain; its "
            "held-out windows cover it."
        )
    if not (correlation["fired"] or stateful["fired"] or noisy_baseline or noisy_conduit):
        lines.append("- No correlation, baseline, conduit or stateful rule fired on benign input.")
    lines += [
        "",
        "This report is generated by `python metrics/fpr.py`. Use `--check` in CI "
        "to fail on drift.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Fail if the report has drifted")
    args = parser.parse_args(argv)

    report = build()
    payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
    markdown = render_markdown(report)

    if args.check:
        problems = []
        if not OUT_JSON.exists() or OUT_JSON.read_text(encoding="utf-8") != payload:
            problems.append(str(OUT_JSON.relative_to(REPO_ROOT)))
        if not OUT_MARKDOWN.exists() or OUT_MARKDOWN.read_text(encoding="utf-8") != markdown:
            problems.append(str(OUT_MARKDOWN.relative_to(REPO_ROOT)))
        if problems:
            print("false-positive report is stale; run make fpr:")
            for problem in problems:
                print(f"  - {problem}")
            return 1
        print("false-positive report is current")
        return 0

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(payload, encoding="utf-8")
    OUT_MARKDOWN.write_text(markdown, encoding="utf-8")
    single = report["families"]["sigma_single_event"]
    baseline = report["families"]["baseline"]
    conduit = report["families"]["conduit"]
    correlation = report["families"]["sigma_correlation"]
    stateful = report["families"]["stateful"]
    print(
        "all-family false positives: "
        f"Sigma {single['false_positive_events']}/{report['corpus']['events']}, "
        f"baseline {baseline['false_positive_events']}, "
        f"conduit {conduit['false_positive_events']}, "
        f"correlation {len(correlation['fired'])} fired, "
        f"stateful {len(stateful['fired'])} fired "
        f"-> {OUT_MARKDOWN}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
