"""Run the adversary emulation plan against the repository's live Loki rules.

The replay runner in ``run_emulation.py`` matches the lab's ``alert_type``
snapshot. This runner is the other half: it starts each step, records the action
start/stop times, polls the lab's Loki ruler, and evaluates the **generated
repository rules** that fire. It is deliberately strict:

- each step has its own allowed rule set; an expected rule firing in another
  step is not silently accepted;
- the window starts at action start, not at the first expected alert;
- a benign window runs before the first step and after the last;
- every run records misses and unexpected rules, so a run can fail.

Usage:
    python purple/runner/live_lab.py --loki-url http://localhost:3100 --runs 3
    python purple/runner/live_lab.py --check-rules-only
"""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404 - fixed plan commands, no user input
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402

from tools.otde.http import open_http  # noqa: E402

DEFAULT_PLAN = REPO_ROOT / "purple" / "emulation" / "emulation-plan.yaml"
DEFAULT_OUT = REPO_ROOT / "deploy" / "evidence" / "purple-live"
DEFAULT_LOKI = "http://localhost:3100"
DEFAULT_LAB_ALERTS = Path(
    "/media/liamcarvajal/Storage/code/ot-security-lab/detection/logs/alerts.json"
)


def _get_json(url: str) -> dict:
    with open_http(url, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def ruler_rules(base_url: str) -> dict[str, dict[str, Any]]:
    payload = _get_json(f"{base_url.rstrip('/')}/prometheus/api/v1/rules")
    rules: dict[str, dict[str, Any]] = {}
    for group in payload["data"]["groups"]:
        for rule in group["rules"]:
            rules[rule["name"]] = {
                "name": rule["name"],
                "group": group["name"],
                "state": rule.get("state"),
                "health": rule.get("health"),
                "last_evaluation": rule.get("lastEvaluation"),
            }
    return rules


def expected_groups(
    plan: dict,
) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, list[str]]]:
    """Split each step into required Sigma, allowed Sigma and native rules.

    Only Sigma rules are in the generated Loki bundle. A native Suricata rule is
    proven by the capture evidence, not by the ruler; the live run records it as
    not evaluated here rather than silently expecting a group that cannot exist.
    Secondary rules are legitimate consequences of the action and are allowed
    without being required.
    """
    required: dict[str, set[str]] = {}
    allowed: dict[str, set[str]] = {}
    native: dict[str, list[str]] = {}
    for step in plan["steps"]:
        required[step["id"]] = set()
        allowed[step["id"]] = set()
        native[step["id"]] = []
        for expectation in step["expectations"]:
            rule = expectation["rule"]
            if rule.startswith("rules/sigma/"):
                required[step["id"]].add(Path(rule).stem)
            else:
                native[step["id"]].append(rule)
        for secondary in step.get("secondary", []):
            rule = secondary["rule"]
            if rule.startswith("rules/sigma/"):
                allowed[step["id"]].add(Path(rule).stem)
            else:
                native[step["id"]].append(rule)
        allowed[step["id"]] |= required[step["id"]]
    return required, allowed, native


def groups_by_name(rules: dict[str, dict[str, Any]]) -> dict[str, str]:
    return {rule["group"]: rule["name"] for rule in rules.values()}


def wait_for_rules(
    base_url: str, expected: set[str], timeout: float
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    deadline = time.monotonic() + timeout
    while True:
        rules = ruler_rules(base_url)
        groups = groups_by_name(rules)
        missing = sorted(expected - set(groups))
        if not missing or time.monotonic() >= deadline:
            return rules, missing
        time.sleep(1.0)


def restart_rule_state(
    container: str,
    base_url: str,
    expected: set[str],
    clear_data: bool,
    timeout: float = 60,
) -> list[str]:
    """Clear the lab's rule lookback state and restart Loki.

    A restart alone is not enough: the ruler's ``count_over_time`` looks back
    into the stored chunks, so an attack from the previous step still fires for
    up to five minutes. Clearing ``/tmp/loki`` gives the benign window a clean
    starting point.
    """
    if clear_data:
        subprocess.run(  # nosec B603 - fixed container and path
            ["docker", "exec", container, "sh", "-c", "rm -rf /tmp/loki/*"],
            check=False,
            capture_output=True,
            text=True,
        )
    subprocess.run(  # nosec B603 - fixed container name
        ["docker", "restart", container], check=True, capture_output=True, text=True
    )
    time.sleep(2)
    _rules, missing = wait_for_rules(base_url, expected, timeout=timeout)
    return missing


def _read_lab_alerts(path: Path) -> list[dict]:
    if not path.exists():
        return []
    alerts = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            alerts.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return alerts


def _new_lab_alerts(path: Path, before: set[int]) -> list[dict]:
    alerts = _read_lab_alerts(path)
    return [alert for index, alert in enumerate(alerts) if index not in before]


def _alert_identity(alerts: list[dict]) -> set[int]:
    return set(range(len(alerts)))


def poll_window(
    base_url: str,
    required: set[str],
    allowed: set[str],
    duration: float,
    poll_seconds: float,
    quiet_after: float,
) -> dict[str, Any]:
    """Poll the ruler for a window and return required hits and unexpected rules."""
    first_fire: dict[str, str] = {}
    observed: set[str] = set()
    fired: set[str] = set()
    deadline = time.monotonic() + duration + quiet_after
    while time.monotonic() < deadline:
        rules = ruler_rules(base_url)
        groups = groups_by_name(rules)
        for group, name in groups.items():
            if group not in allowed:
                continue
            rule = rules[name]
            if rule.get("state") == "firing":
                fired.add(group)
                if group in required and group not in first_fire:
                    first_fire[group] = datetime.now(UTC).isoformat()
                    observed.add(group)
        time.sleep(poll_seconds)
    return {
        "expected": sorted(required),
        "observed": sorted(observed),
        "first_fire": first_fire,
        "unexpected": sorted(fired - allowed),
    }


def run_once(
    plan: dict,
    base_url: str,
    settle_seconds: float,
    poll_seconds: float,
    quiet_seconds: float,
    lab_alerts: Path,
    restart_container: str | None,
    clear_loki_data: bool,
) -> dict[str, Any]:
    required, allowed, native = expected_groups(plan)
    all_expected = set().union(*allowed.values())
    rules, missing = wait_for_rules(base_url, all_expected, timeout=60)
    if missing:
        raise RuntimeError(f"generated rules missing from the lab ruler: {missing}")

    if restart_container:
        missing = restart_rule_state(
            restart_container, base_url, all_expected, clear_loki_data
        )
        if missing:
            raise RuntimeError(f"generated rules missing after restart: {missing}")

    steps = []
    lab_before = _alert_identity(_read_lab_alerts(lab_alerts))
    # Benign window before any action.
    benign_rules = poll_window(
        base_url, all_expected, all_expected, quiet_seconds, poll_seconds, 0.0
    )
    benign_lab = _new_lab_alerts(lab_alerts, lab_before)
    if benign_rules["observed"] or benign_lab:
        steps.append(
            {
                "id": "benign-before",
                "started_at": datetime.now(UTC).isoformat(),
                "expected": [],
                "observed": benign_rules["observed"],
                "unexpected": benign_rules["observed"],
                "lab_alerts": [a.get("alert_type") for a in benign_lab],
            }
        )

    for step in plan["steps"]:
        lab_before = _alert_identity(_read_lab_alerts(lab_alerts))
        started = datetime.now(UTC)
        command = step["execute"]["command"]
        print(f"[live] {step['id']}: {command}", flush=True)
        # A long stimulus can fire and resolve while the command is still
        # running; polling only after it exits misses the alert. Watch the
        # required rules for the whole command and merge the earliest firing
        # into the normal post-command window.
        stop = threading.Event()
        during: dict[str, Any] = {"first_fire": {}, "fired": set()}

        def watch(
            stop: threading.Event = stop,
            step: dict[str, Any] = step,
            during: dict[str, Any] = during,
        ) -> None:
            while not stop.is_set():
                try:
                    rules = ruler_rules(base_url)
                except Exception:  # noqa: BLE001 - transient ruler read
                    time.sleep(poll_seconds)
                    continue
                groups = groups_by_name(rules)
                for group, name in groups.items():
                    if group not in required[step["id"]]:
                        continue
                    if rules[name].get("state") == "firing":
                        during["fired"].add(group)
                        during["first_fire"].setdefault(
                            group, datetime.now(UTC).isoformat()
                        )
                time.sleep(poll_seconds)

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        result = subprocess.run(  # nosec B603 - fixed plan command
            command, shell=True, capture_output=True, text=True
        )
        stop.set()
        watcher.join(timeout=5)
        settle = max(settle_seconds, 2.0)
        poll = poll_window(
            base_url,
            required[step["id"]],
            allowed[step["id"]],
            settle,
            poll_seconds,
            quiet_seconds,
        )
        for group, timestamp in during["first_fire"].items():
            poll["first_fire"].setdefault(group, timestamp)
        poll["observed"] = sorted(set(poll["observed"]) | during["fired"])
        finished = datetime.now(UTC)
        lab_new = _new_lab_alerts(lab_alerts, lab_before)
        steps.append(
            {
                "id": step["id"],
                "started_at": started.isoformat(),
                "finished_at": finished.isoformat(),
                "returncode": result.returncode,
                "expected": poll["expected"],
                "observed": poll["observed"],
                "unexpected": poll["unexpected"],
                "first_fire": poll["first_fire"],
                "native_not_evaluated": native[step["id"]],
                "lab_alerts": sorted({a.get("alert_type") for a in lab_new if a.get("alert_type")}),
            }
        )

    if restart_container:
        restart_rule_state(
            restart_container, base_url, all_expected, clear_loki_data
        )
    lab_before = _alert_identity(_read_lab_alerts(lab_alerts))
    after = poll_window(
        base_url, all_expected, all_expected, quiet_seconds, poll_seconds, 0.0
    )
    lab_after = _new_lab_alerts(lab_alerts, lab_before)
    steps.append(
        {
            "id": "benign-after",
            "started_at": datetime.now(UTC).isoformat(),
            "expected": [],
            "observed": after["observed"],
            "unexpected": after["observed"],
            "lab_alerts": [a.get("alert_type") for a in lab_after],
        }
    )
    return {"steps": steps}


def summarize(runs: list[dict[str, Any]]) -> dict[str, Any]:
    steps: dict[str, dict[str, Any]] = {}
    for run_index, run in enumerate(runs, start=1):
        for step in run["steps"]:
            if step["id"].startswith("benign"):
                continue
            entry = steps.setdefault(
                step["id"],
                {"expected": [], "detected": 0, "runs": 0, "misses": [], "unexpected": set()},
            )
            entry["runs"] += 1
            entry["expected"] = step["expected"]
            missing = sorted(set(step["expected"]) - set(step["observed"]))
            if missing:
                entry["misses"].append({"run": run_index, "rules": missing})
            else:
                entry["detected"] += 1
            entry["unexpected"].update(step["unexpected"])
    for entry in steps.values():
        entry["unexpected"] = sorted(entry["unexpected"])
        entry["detection_rate"] = (
            round(entry["detected"] / entry["runs"], 4) if entry["runs"] else None
        )
    mttds = []
    for run in runs:
        for step in run["steps"]:
            started = step.get("started_at")
            if not started or not step.get("first_fire"):
                continue
            start = datetime.fromisoformat(started.replace("Z", "+00:00"))
            for timestamp in step["first_fire"].values():
                finish = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                mttds.append((finish - start).total_seconds())
    return {
        "runs": len(runs),
        "steps": steps,
        "mttd_seconds": {
            "samples": len(mttds),
            "mean": round(sum(mttds) / len(mttds), 3) if mttds else None,
            "max": round(max(mttds), 3) if mttds else None,
        },
        "benign_before": [
            run["steps"][0]
            for run in runs
            if run["steps"] and run["steps"][0]["id"] == "benign-before"
        ],
        "benign_after": [
            run["steps"][-1]
            for run in runs
            if run["steps"] and run["steps"][-1]["id"] == "benign-after"
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", default=str(DEFAULT_PLAN))
    parser.add_argument("--loki-url", default=DEFAULT_LOKI)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--settle-seconds", type=float, default=5.0)
    parser.add_argument("--poll-seconds", type=float, default=0.5)
    parser.add_argument("--quiet-seconds", type=float, default=30.0)
    parser.add_argument("--lab-alerts", default=str(DEFAULT_LAB_ALERTS))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument(
        "--restart-loki",
        action="store_true",
        default=True,
        help="Restart the lab Loki before each run and before the benign-after window (default)",
    )
    parser.add_argument("--no-restart-loki", dest="restart_loki", action="store_false")
    parser.add_argument("--loki-container", default="ot_loki")
    parser.add_argument(
        "--keep-loki-data",
        dest="clear_loki_data",
        action="store_false",
        help=(
            "Do not clear /tmp/loki before a restart; the lookback state will "
            "leak into the benign window"
        ),
    )
    parser.add_argument(
        "--check-rules-only",
        action="store_true",
        help="Check that every expected generated rule is loaded, then exit",
    )
    args = parser.parse_args(argv)

    plan = yaml.safe_load(Path(args.plan).read_text(encoding="utf-8"))
    required, allowed, _native = expected_groups(plan)
    expected = set().union(*allowed.values())
    rules, missing = wait_for_rules(args.loki_url, expected, timeout=30)
    if missing:
        print(f"missing generated rules in the lab ruler: {missing}", file=sys.stderr)
        return 1
    print(f"{len(expected)} generated rule groups loaded")
    if args.check_rules_only:
        return 0

    runs = []
    for index in range(args.runs):
        print(f"=== live run {index + 1}/{args.runs} ===", flush=True)
        runs.append(
            run_once(
                plan,
                args.loki_url,
                args.settle_seconds,
                args.poll_seconds,
                args.quiet_seconds,
                Path(args.lab_alerts),
                args.loki_container if args.restart_loki else None,
                args.clear_loki_data,
            )
        )

    summary = summarize(runs)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    for index, run in enumerate(runs, start=1):
        (out_dir / f"run-{index}.json").write_text(
            json.dumps(run, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
