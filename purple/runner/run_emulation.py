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

from tools.otde.rules import REPO_ROOT as _REPO_ROOT  # noqa: E402
from tools.otde.rules import technique_ids, techniques_for  # noqa: E402

DEFAULT_PLAN = _REPO_ROOT / "purple" / "emulation" / "emulation-plan.yaml"
DEFAULT_SCHEMA = _REPO_ROOT / "purple" / "emulation" / "plan.schema.json"
DEFAULT_OUT = _REPO_ROOT / "purple" / "results"


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
            rule_path = _REPO_ROOT / expectation["rule"]
            if not rule_path.exists():
                problems.append(f"{step['id']}: rule not found: {expectation['rule']}")
                continue
            if technique not in techniques_for(rule_path):
                problems.append(
                    f"{step['id']}: {expectation['rule']} does not detect {technique}"
                )
    return problems


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        # The lab emits naive local timestamps (datetime.now().isoformat()).
        # Interpret them as local time so MTTD is correct on any host timezone.
        parsed = parsed.astimezone()
    return parsed


def load_alerts(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text.startswith("["):
        return json.loads(text)
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def _first_matching_alert(
    alerts: list[dict], signal: str, started: datetime, finished: datetime | None
) -> dict | None:
    matches = []
    for alert in alerts:
        if alert.get("alert_type") != signal:
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
    if not matches:
        return None
    return min(matches, key=lambda item: item[0])[1]


def evaluate(plan: dict, observations: dict) -> dict:
    steps = []
    expectations_total = 0
    expectations_detected = 0
    mttds: list[float] = []

    for step in plan["steps"]:
        observation = observations.get(step["id"], {})
        started_raw = observation.get("started_at")
        started = parse_timestamp(started_raw) if started_raw else None
        finished_raw = observation.get("finished_at")
        finished = parse_timestamp(finished_raw) if finished_raw else None
        alerts = observation.get("alerts", [])

        expectation_results = []
        for expectation in step["expectations"]:
            expectations_total += 1
            alert = (
                _first_matching_alert(alerts, expectation["signal"], started, finished)
                if started is not None
                else None
            )
            detected = alert is not None
            mttd = None
            if detected:
                expectations_detected += 1
                if started is not None:
                    mttd = round(
                        (parse_timestamp(alert["timestamp"]) - started).total_seconds(), 3
                    )
                    mttds.append(mttd)
            expectation_results.append(
                {
                    "signal": expectation["signal"],
                    "technique": expectation["technique"],
                    "rule": expectation["rule"],
                    "detected": detected,
                    "mttd_seconds": mttd,
                }
            )

        steps.append(
            {
                "id": step["id"],
                "name": step["name"],
                "technique": step.get("technique"),
                "detected": all(item["detected"] for item in expectation_results),
                "expectations": expectation_results,
            }
        )

    return {
        "plan": plan["name"],
        "steps": steps,
        "summary": {
            "expectations_total": expectations_total,
            "expectations_detected": expectations_detected,
            "detection_rate_pct": round(100 * expectations_detected / expectations_total, 1)
            if expectations_total
            else 0.0,
            "mean_mttd_seconds": round(sum(mttds) / len(mttds), 3) if mttds else None,
            "max_mttd_seconds": round(max(mttds), 3) if mttds else None,
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
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "observations.json").write_text(
        json.dumps(observations, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "emulation_results.json").write_text(
        json.dumps(results, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "emulation_report.md").write_text(render_markdown(results), encoding="utf-8")

    summary = results["summary"]
    print(
        f"detection rate: {summary['expectations_detected']}/{summary['expectations_total']} "
        f"({summary['detection_rate_pct']}%) -> {out_dir}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
