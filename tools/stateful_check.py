"""Prove the stateful detections and their baselines.

The stateful rules in ``rules/stateful`` need context: a learned process-value
baseline, an approved change calendar, or a per-asset protocol profile. This
runner verifies that each committed baseline is reproducible, that the calendar
is schema-valid, and that every labeled window produces the expected result.

It needs no SIEM, container or lab, so CI performs it directly. The committed
evidence is guarded by ``tests/test_stateful.py``.

Usage:
    python tools/stateful_check.py
    python tools/stateful_check.py --check
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402
from jsonschema import Draft202012Validator  # noqa: E402

from baseline.build import collect  # noqa: E402
from baseline.build_asset_behaviour import BENIGN_INPUTS  # noqa: E402
from baseline.build_asset_behaviour import build as build_asset  # noqa: E402
from baseline.build_process_values import DEFAULT_INPUT as PROCESS_INPUT  # noqa: E402
from baseline.build_process_values import build as build_process  # noqa: E402
from tools.otde.rules import stateful_rule_paths  # noqa: E402
from tools.otde.stateful import (  # noqa: E402
    load_stateful_rule,
    match_stateful,
)

EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence" / "stateful"
EVIDENCE_PATH = EVIDENCE_DIR / "summary.json"
PROCESS_BASELINE = REPO_ROOT / "baseline" / "process-values.json"
ASSET_BASELINE = REPO_ROOT / "baseline" / "asset-behaviour.json"
CALENDAR = REPO_ROOT / "metadata" / "change-calendar.yaml"
CALENDAR_SCHEMA = REPO_ROOT / "metadata" / "change-calendar.schema.json"
TESTCASE_SCHEMA = REPO_ROOT / "metadata" / "stateful-testcase.schema.json"


def _sidecar(rule_path: Path) -> dict:
    return yaml.safe_load(rule_path.with_suffix(".test.yaml").read_text(encoding="utf-8"))


def _process_baseline_current() -> bool:
    events = [
        json.loads(line)
        for line in PROCESS_INPUT.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    return build_process(events) == json.loads(PROCESS_BASELINE.read_text(encoding="utf-8"))


def _asset_baseline_current() -> bool:
    events, _ = collect("suricata", BENIGN_INPUTS)
    committed = json.loads(ASSET_BASELINE.read_text(encoding="utf-8"))
    return build_asset(events) == committed


def _calendar_valid() -> tuple[bool, int]:
    calendar = yaml.safe_load(CALENDAR.read_text(encoding="utf-8"))
    schema = json.loads(CALENDAR_SCHEMA.read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema).iter_errors(calendar))
    return not errors, len(calendar.get("windows", []))


def evaluate() -> dict:
    testcase_schema = json.loads(TESTCASE_SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(testcase_schema)
    rules = []
    windows_total = windows_passed = 0

    for rule_path in stateful_rule_paths():
        rule = load_stateful_rule(rule_path)
        sidecar = _sidecar(rule_path)
        errors = [error.message for error in validator.iter_errors(sidecar)]
        cases = []
        for window in sidecar.get("windows", []):
            windows_total += 1
            observed = match_stateful(rule, window["events"])
            expected = window["expect"] == "match"
            passed = observed == expected
            windows_passed += int(passed)
            cases.append(
                {
                    "name": window["name"],
                    "expected": window["expect"],
                    "observed": "match" if observed else "no_match",
                    "passed": passed,
                }
            )
        rules.append(
            {
                "rule": rule_path.relative_to(REPO_ROOT).as_posix(),
                "title": rule["title"],
                "schema_errors": errors,
                "windows": cases,
            }
        )

    calendar_ok, calendar_windows = _calendar_valid()
    return {
        "rules": rules,
        "baselines": {
            "process_current": _process_baseline_current(),
            "asset_current": _asset_baseline_current(),
            "calendar_valid": calendar_ok,
            "calendar_windows": calendar_windows,
        },
        "summary": {
            "rules": len(rules),
            "windows": windows_total,
            "windows_passed": windows_passed,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    evidence = evaluate()
    if args.check:
        expected = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
        if not EVIDENCE_PATH.exists() or EVIDENCE_PATH.read_text(encoding="utf-8") != expected:
            print("stateful evidence is stale; run make stateful")
            return 1
        print("stateful evidence is current")
        return 0

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    failures = []
    if not evidence["baselines"]["process_current"]:
        failures.append("process baseline is stale; run baseline/build_process_values.py")
    if not evidence["baselines"]["asset_current"]:
        failures.append("asset baseline is stale; run baseline/build_asset_behaviour.py")
    if not evidence["baselines"]["calendar_valid"]:
        failures.append("change calendar does not match its schema")
    for rule in evidence["rules"]:
        if rule["schema_errors"]:
            failures.append(f"{rule['rule']}: {rule['schema_errors']}")
        for case in rule["windows"]:
            if not case["passed"]:
                failures.append(
                    f"{rule['rule']}: {case['name']} expected {case['expected']}, "
                    f"observed {case['observed']}"
                )

    if failures:
        print("stateful validation failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        f"stateful validation passed: {evidence['summary']['rules']} rules, "
        f"{evidence['summary']['windows']} windows, "
        f"{evidence['baselines']['calendar_windows']} change windows"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
