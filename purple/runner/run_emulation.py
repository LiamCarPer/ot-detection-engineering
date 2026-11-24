"""Execute an adversary emulation plan and measure whether detections fire.

The runner has two modes:

- ``--execute`` runs each step's command (for example ``docker exec`` into the
  lab), records when the action started, waits for the telemetry to settle, and
  reads the ground-truth alerts the lab emitted.
- ``--observations FILE`` replays a recorded observation file instead of
  touching a live lab. This keeps the evaluation logic testable and lets a run
  be reproduced from an artifact.

Both modes feed the same pure ``evaluate`` function, which matches each expected
signal to the first alert inside the step's time window and computes MTTD. The
evaluated observations are written alongside the results so any run can be
reproduced from a committed artifact.

Usage:
    python purple/runner/run_emulation.py --validate
    python purple/runner/run_emulation.py --execute --alerts /path/to/alerts.json
    python purple/runner/run_emulation.py --observations observations.json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402
from jsonschema import Draft202012Validator  # noqa: E402

from tools.otde.rules import technique_ids, techniques_for  # noqa: E402

DEFAULT_PLAN = REPO_ROOT / "purple" / "emulation" / "emulation-plan.yaml"
DEFAULT_SCHEMA = REPO_ROOT / "purple" / "emulation" / "plan.schema.json"
DEFAULT_OUT = REPO_ROOT / "purple" / "results"


class EmulationDataError(RuntimeError):
    """Raised when recorded lab data contradicts the plan or its labels."""


def load_plan(path: Path = DEFAULT_PLAN) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def validate_plan(plan: dict, schema_path: Path = DEFAULT_SCHEMA) -> list[str]:
    """Return a list of problems; empty means the plan is valid."""
    problems: list[str] = []
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    for error in Draft202012Validator(schema).iter_errors(plan):
        location = "/".join(str(part) for part in error.absolute_path)
        problems.append(f"schema: {location}: {error.message}")
    if problems:
        return problems

    known = technique_ids()
    seen_ids: set[str] = set()
    for step in plan["steps"]:
        if step["id"] in seen_ids:
            problems.append(f"duplicate step id: {step['id']}")
        seen_ids.add(step["id"])

        if "technique" in step and step["technique"] not in known:
            problems.append(f"{step['id']}: unknown technique {step['technique']}")

        for expectation in step["expectations"]:
            technique = expectation["technique"]
            if technique not in known:
                problems.append(f"{step['id']}: unknown technique {technique}")
            lab_technique = expectation.get("lab_technique")
            if lab_technique not in known:
                problems.append(f"{step['id']}: unknown lab technique {lab_technique}")
            rule_path = REPO_ROOT / expectation["rule"]
            if not rule_path.exists():
                problems.append(f"{step['id']}: rule not found: {expectation['rule']}")
                continue
            if technique not in techniques_for(rule_path):
                problems.append(f"{step['id']}: {expectation['rule']} does not detect {technique}")
    return problems


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        # The lab detectors run in UTC containers and emit naive timestamps
        # from datetime.now(), so interpret naive values as UTC.
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def load_alerts(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _alerts_in_window(
    alerts: list[dict], signal: str | None, started: datetime, finished: datetime | None
) -> list[tuple[datetime, dict]]:
    """Return the matching alerts inside the window, oldest first.

    ``signal=None`` returns every alert in the window, which is what the
    unexpected-alert and benign-window checks need.
    """
    matches = []
    for alert in alerts:
        if signal is not None and alert.get("alert_type") != signal:
            continue
        timestamp = alert.get("timestamp")
        if not timestamp:
            continue
        moment = parse_timestamp(timestamp)
        if moment < started:
            continue
        if finished is not None and moment > finished:
            continue
        matches.append((moment, alert))
    return sorted(matches, key=lambda item: item[0])


def _check_lab_technique(
    step: dict, expectation: dict, candidates: list[tuple[datetime, dict]]
) -> None:
    """Fail if a matched alert carries a technique other than the plan's label.

    The plan's ``technique`` is the repository rule's mapping; ``lab_technique``
    is the label the lab's ground truth carries. They can legitimately differ
    (a rule detects the command, the lab alert describes the impact), but the
    difference must be declared and the recorded data must match it. Without
    this check a mismatch passes silently because the runner only compares
    ``alert_type``.
    """
    expected = expectation.get("lab_technique")
    if not expected:
        return
    observed = {
        str(alert.get("mitre_id")) for _, alert in candidates if alert.get("mitre_id") is not None
    }
    mismatched = [alert for _, alert in candidates if str(alert.get("mitre_id")) != expected]
    if mismatched:
        raise EmulationDataError(
            f"{step['id']}/{expectation['signal']}: expected lab technique "
            f"{expected}, observed {sorted(observed) or ['<missing>']}"
        )


def evaluate(plan: dict, observations: dict) -> dict:
    steps = []
    expectations_total = 0
    expectations_detected = 0
    mttds: list[float] = []
    plan_expected_types = {
        expectation["signal"]
        for step in plan["steps"]
        for expectation in step["expectations"]
    }

    # The multi-step replay format stores the alert list once and a window per
    # step. The single-step format stores alerts inside each step. Support both.
    global_alerts = observations.get("alerts") if "steps" in observations else None

    for step in plan["steps"]:
        if global_alerts is not None:
            observation = observations["steps"].get(step["id"], {})
            alerts = global_alerts
        else:
            observation = observations.get(step["id"], {})
            alerts = observation.get("alerts", [])

        started_raw = observation.get("started_at")
        started = parse_timestamp(started_raw) if started_raw else None
        window_start_raw = observation.get("window_started_at") or started_raw
        window_start = parse_timestamp(window_start_raw) if window_start_raw else None
        window_end_raw = observation.get("window_finished_at") or observation.get("finished_at")
        window_end = parse_timestamp(window_end_raw) if window_end_raw else None

        expectation_results = []
        for expectation in step["expectations"]:
            expectations_total += 1
            candidates = (
                _alerts_in_window(alerts, expectation["signal"], window_start, window_end)
                if window_start is not None
                else []
            )
            _check_lab_technique(step, expectation, candidates)
            alert = candidates[0][1] if candidates else None
            detected = alert is not None
            mttd = None
            if detected:
                expectations_detected += 1
                if started is not None:
                    mttd = round((parse_timestamp(alert["timestamp"]) - started).total_seconds(), 3)
                    mttds.append(mttd)
            expectation_results.append(
                {
                    "signal": expectation["signal"],
                    "technique": expectation["technique"],
                    "lab_technique": expectation.get("lab_technique"),
                    "rule": expectation["rule"],
                    "detected": detected,
                    "alert_mitre_id": alert.get("mitre_id") if alert else None,
                    "mttd_seconds": mttd,
                }
            )

        unexpected = []
        if window_start is not None:
            unexpected = [
                {
                    "timestamp": alert.get("timestamp"),
                    "alert_type": alert.get("alert_type"),
                    "source_ip": alert.get("source_ip"),
                    "mitre_id": alert.get("mitre_id"),
                }
                for _, alert in _alerts_in_window(alerts, None, window_start, window_end)
                if alert.get("alert_type") not in plan_expected_types
            ]

        steps.append(
            {
                "id": step["id"],
                "name": step["name"],
                "technique": step.get("technique"),
                "detected": all(item["detected"] for item in expectation_results),
                "unexpected_alerts": unexpected,
                "expectations": expectation_results,
            }
        )

    benign = None
    benign_observation = observations.get("benign")
    if benign_observation:
        benign_start_raw = benign_observation.get("started_at") or benign_observation.get(
            "window_started_at"
        )
        benign_end_raw = benign_observation.get("finished_at") or benign_observation.get(
            "window_finished_at"
        )
        benign_alerts = (
            global_alerts
            if global_alerts is not None
            else benign_observation.get("alerts", [])
        )
        found = []
        if benign_start_raw and benign_end_raw:
            found = [
                {
                    "timestamp": alert.get("timestamp"),
                    "alert_type": alert.get("alert_type"),
                    "source_ip": alert.get("source_ip"),
                }
                for _, alert in _alerts_in_window(
                    benign_alerts,
                    None,
                    parse_timestamp(benign_start_raw),
                    parse_timestamp(benign_end_raw),
                )
            ]
        benign = {
            "window_started_at": benign_start_raw,
            "window_finished_at": benign_end_raw,
            "alerts": found,
            "passed": not found,
        }

    return {
        "plan": plan["name"],
        "steps": steps,
        "benign": benign,
        "summary": {
            "expectations_total": expectations_total,
            "expectations_detected": expectations_detected,
            "detection_rate_pct": round(100 * expectations_detected / expectations_total, 1)
            if expectations_total
            else 0.0,
            "mean_mttd_seconds": round(sum(mttds) / len(mttds), 3) if mttds else None,
            "max_mttd_seconds": round(max(mttds), 3) if mttds else None,
            "unexpected_alerts": sum(len(step["unexpected_alerts"]) for step in steps),
            "benign_alerts": len(benign["alerts"]) if benign else None,
            "benign_passed": benign["passed"] if benign else None,
        },
    }


def _default_runner(command: str) -> None:
    subprocess.run(command, shell=True, check=True)


def run_plan(
    plan: dict,
    alerts_path: Path,
    settle_seconds: float,
    runner: Callable[[str], None] = _default_runner,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    sleeper: Callable[[float], None] = time.sleep,
) -> dict:
    observations: dict[str, dict] = {}
    for step in plan["steps"]:
        execute = step.get("execute")
        if not execute:
            continue
        started = clock()
        runner(execute["command"])
        sleeper(settle_seconds)
        finished = clock()
        observations[step["id"]] = {
            "started_at": started.isoformat(),
            "finished_at": finished.isoformat(),
            "alerts": load_alerts(alerts_path),
        }
    return observations


def render_markdown(results: dict) -> str:
    summary = results["summary"]
    mean_mttd = summary["mean_mttd_seconds"]
    lines = [
        "# Adversary Emulation Results",
        "",
        f"Plan: {results['plan']}",
        "",
        f"- Expectations: {summary['expectations_detected']} / "
        f"{summary['expectations_total']} detected "
        f"({summary['detection_rate_pct']}%)",
        f"- Mean MTTD: {mean_mttd if mean_mttd is not None else 'n/a'} s",
        f"- Unexpected alerts in step windows: {summary['unexpected_alerts']}",
    ]
    if results.get("benign") is not None:
        benign = results["benign"]
        lines.append(
            f"- Benign window: {'passed' if benign['passed'] else 'failed'} "
            f"({len(benign['alerts'])} alert(s))"
        )
    lines += [
        "",
        "| Step | Technique | Signal | Detected | MTTD (s) |",
        "| :--- | :--- | :--- | :--- | ---: |",
    ]
    for step in results["steps"]:
        for expectation in step["expectations"]:
            mttd = expectation["mttd_seconds"]
            lines.append(
                f"| {step['name']} | {expectation['technique']} | "
                f"{expectation['signal']} | "
                f"{'yes' if expectation['detected'] else 'no'} | "
                f"{mttd if mttd is not None else ''} |"
            )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", default=str(DEFAULT_PLAN))
    parser.add_argument("--observations", help="Replay a recorded observation file")
    parser.add_argument("--execute", action="store_true", help="Run the plan against a live lab")
    parser.add_argument("--alerts", help="Path to the lab alerts JSONL file (with --execute)")
    parser.add_argument("--settle-seconds", type=float, default=3.0)
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--validate", action="store_true", help="Validate the plan and exit")
    parser.add_argument("--check", action="store_true", help="Fail if committed evidence drifts")
    args = parser.parse_args(argv)

    plan = load_plan(Path(args.plan))
    problems = validate_plan(plan)
    if problems:
        print("plan validation failed:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print(f"plan valid: {plan['name']} ({len(plan['steps'])} steps)")

    if args.validate or (not args.observations and not args.execute):
        return 0

    if args.observations:
        observations = json.loads(Path(args.observations).read_text(encoding="utf-8"))
    else:
        if not args.alerts:
            print("--execute requires --alerts", file=sys.stderr)
            return 2
        observations = run_plan(plan, Path(args.alerts), args.settle_seconds)

    results = evaluate(plan, observations)
    report = render_markdown(results)
    out_dir = Path(args.out)

    if args.check:
        expected = {
            "emulation_results.json": json.dumps(results, indent=2) + "\n",
            "emulation_report.md": report,
        }
        stale = [
            name
            for name, content in expected.items()
            if not (out_dir / name).exists()
            or (out_dir / name).read_text(encoding="utf-8") != content
        ]
        if stale:
            print(f"emulation evidence is stale: {', '.join(stale)}")
            return 1
        print("emulation evidence is current")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "observations.json").write_text(
        json.dumps(observations, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "emulation_results.json").write_text(
        json.dumps(results, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "emulation_report.md").write_text(report, encoding="utf-8")

    summary = results["summary"]
    print(
        f"detection rate: {summary['expectations_detected']}/{summary['expectations_total']} "
        f"({summary['detection_rate_pct']}%), "
        f"unexpected {summary['unexpected_alerts']}, "
        f"benign {'n/a' if summary['benign_passed'] is None else summary['benign_passed']} "
        f"-> {out_dir}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
