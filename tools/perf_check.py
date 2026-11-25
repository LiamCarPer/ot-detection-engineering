"""Measure decoder throughput and offline replay throughput.

Two measurements are recorded:

- the Rust decoder microbenchmark, one iteration per set of committed example
  frames, reporting per-frame p50/p99 and frames/sec;
- an offline replay of the benign corpus through every single-event Sigma rule,
  reporting events/sec, p50/p99 and the number of matches. The replay runs
  1,000 distinct events ten times; "events" is evaluation passes, not distinct
  inputs.

The second is a validation-pipeline benchmark, not a production sensor
benchmark. The committed summary records the hardware and method so the numbers
cannot be read as machine-independent.

Usage:
    python tools/perf_check.py
    python tools/perf_check.py --check
    python tools/perf_check.py --smoke
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sigma.rule import SigmaRule  # noqa: E402

from tools.otde.matcher import match  # noqa: E402
from tools.otde.rules import single_event_rule_paths  # noqa: E402

EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence" / "perf"
EVIDENCE_PATH = EVIDENCE_DIR / "summary.json"
TOOLS_DIR = REPO_ROOT / "tools"
BENIGN = REPO_ROOT / "metrics" / "baseline" / "benign-events.jsonl"
PROTOCOLS = ("dnp3", "s7comm", "opcua")


def run_benchmark(iterations: int) -> dict[str, dict]:
    result = subprocess.run(
        [
            "cargo",
            "run",
            "--release",
            "-p",
            "ot-perf",
            "--",
            "--iterations",
            str(iterations),
        ],
        cwd=TOOLS_DIR,
        check=True,
        capture_output=True,
        text=True,
    )
    protocols = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        row = json.loads(line)
        protocols[row["protocol"]] = row
    missing = set(PROTOCOLS) - set(protocols)
    if missing:
        raise RuntimeError(f"benchmark did not report: {sorted(missing)}")
    return protocols


def _cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _memory_total_kb() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


def _tool_version(command: list[str]) -> str:
    try:
        return subprocess.run(
            command, check=True, capture_output=True, text=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _load_rules() -> list[SigmaRule]:
    return [
        SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
        for path in single_event_rule_paths()
    ]


def run_replay(repetitions: int) -> dict:
    events = [
        json.loads(line)
        for line in BENIGN.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rules = _load_rules()
    latencies: list[float] = []
    matches = 0
    started = time.perf_counter()
    for _ in range(repetitions):
        for event in events:
            moment = time.perf_counter()
            for rule in rules:
                if match(rule, event):
                    matches += 1
            latencies.append(time.perf_counter() - moment)
    elapsed = time.perf_counter() - started
    total_events = len(events) * repetitions
    latencies.sort()
    return {
        "events": total_events,
        "rules": len(rules),
        "repetitions": repetitions,
        "elapsed_seconds": round(elapsed, 6),
        "events_per_second": round(total_events / elapsed, 2) if elapsed else 0.0,
        "p50_us": round(latencies[len(latencies) // 2] * 1_000_000, 3),
        "p99_us": round(latencies[(len(latencies) * 99) // 100] * 1_000_000, 3),
        "matches": matches,
    }


def summarize(
    protocols: dict[str, dict], pipeline: dict, iterations: int
) -> dict:
    return {
        "schema_version": 1,
        "hardware": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor() or "unknown",
            "cpu_model": _cpu_model(),
            "cpu_count": os.cpu_count(),
            "memory_total_kb": _memory_total_kb(),
        },
        "toolchain": {
            "python": platform.python_version(),
            "cargo": _tool_version(["cargo", "--version"]),
        },
        "method": {
            "decoder_iterations": iterations,
            "decoder_warmup": 100,
            "decoder_unit": "one iteration decodes every committed example frame",
            "decoder_latency_unit": "one latency sample per decoded frame",
            "replay_repetitions": pipeline["repetitions"],
            "replay_unit": "one event through every single-event Sigma rule",
            "replay_events_total": pipeline["events"],
            "replay_distinct_events": pipeline["events"] // max(pipeline["repetitions"], 1),
        },
        "protocols": protocols,
        "pipeline": pipeline,
        "slo": {
            "decoder_p99_ns_per_frame_max": 10_000,
            "pipeline_events_per_second_min": 1_000,
            "pipeline_matches_allowed": 0,
            "decoder_p99_within_slo": all(
                row["p99_ns_per_frame"] <= 10_000 for row in protocols.values()
            ),
            "pipeline_within_slo": pipeline["events_per_second"] >= 1_000,
            "pipeline_matches_within_slo": pipeline["matches"] == 0,
        },
    }


def validate(summary: dict) -> list[str]:
    problems = []
    if summary.get("schema_version") != 1:
        problems.append("schema_version must be 1")
    for protocol in PROTOCOLS:
        row = summary.get("protocols", {}).get(protocol)
        if not row:
            problems.append(f"missing protocol {protocol}")
            continue
        for key in ("frames_per_second", "p50_ns_per_frame", "p99_ns_per_frame", "total_frames"):
            if key not in row:
                problems.append(f"{protocol}: missing {key}")
        if row.get("total_frames", 0) <= 0:
            problems.append(f"{protocol}: total_frames must be positive")
    pipeline = summary.get("pipeline", {})
    for key in ("events", "rules", "events_per_second", "p50_us", "p99_us", "matches"):
        if key not in pipeline:
            problems.append(f"pipeline: missing {key}")
    if pipeline.get("events", 0) <= 0:
        problems.append("pipeline: events must be positive")

    # The SLO flags are derived from the recorded numbers, never trusted as
    # stored booleans. A stale or edited summary must not pass by saying "true".
    slo = summary.get("slo", {})
    max_p99 = slo.get("decoder_p99_ns_per_frame_max")
    min_eps = slo.get("pipeline_events_per_second_min")
    allowed_matches = slo.get("pipeline_matches_allowed")
    if not isinstance(max_p99, int) or max_p99 <= 0:
        problems.append("slo: decoder_p99_ns_per_frame_max must be a positive integer")
    if not isinstance(min_eps, int) or min_eps <= 0:
        problems.append("slo: pipeline_events_per_second_min must be a positive integer")
    if not isinstance(allowed_matches, int) or allowed_matches < 0:
        problems.append("slo: pipeline_matches_allowed must be a non-negative integer")

    if isinstance(max_p99, int) and max_p99 > 0:
        try:
            decoder_ok = all(
                summary["protocols"][protocol]["p99_ns_per_frame"] <= max_p99
                for protocol in PROTOCOLS
            )
        except (KeyError, TypeError):
            decoder_ok = False
        if slo.get("decoder_p99_within_slo") is not decoder_ok:
            problems.append(
                "slo: decoder_p99_within_slo does not match the recorded p99 values"
            )
        if not decoder_ok:
            problems.append(
                f"slo: a decoder p99 exceeds {max_p99} ns/frame"
            )

    if isinstance(min_eps, int) and min_eps > 0:
        pipeline_ok = pipeline.get("events_per_second", 0) >= min_eps
        if slo.get("pipeline_within_slo") is not pipeline_ok:
            problems.append(
                "slo: pipeline_within_slo does not match the recorded throughput"
            )
        if not pipeline_ok:
            problems.append(
                f"slo: replay throughput is below {min_eps} events/s"
            )

    if isinstance(allowed_matches, int) and allowed_matches >= 0:
        matches_ok = pipeline.get("matches", 0) <= allowed_matches
        if slo.get("pipeline_matches_within_slo") is not matches_ok:
            problems.append(
                "slo: pipeline_matches_within_slo does not match the recorded matches"
            )
        if not matches_ok:
            problems.append(
                f"slo: replay produced {pipeline.get('matches')} matches, allowed {allowed_matches}"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=10_000)
    parser.add_argument("--repetitions", type=int, default=10)
    parser.add_argument("--smoke", action="store_true", help="Small run; do not write evidence")
    parser.add_argument("--check", action="store_true", help="Validate committed evidence")
    args = parser.parse_args(argv)

    if args.check:
        if not EVIDENCE_PATH.exists():
            print("performance evidence is missing; run make perf")
            return 1
        summary = json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))
        problems = validate(summary)
        if problems:
            print("performance evidence is invalid:")
            for problem in problems:
                print(f"  - {problem}")
            return 1
        print("performance evidence is current")
        return 0

    iterations = 100 if args.smoke else args.iterations
    repetitions = 2 if args.smoke else args.repetitions
    protocols = run_benchmark(iterations)
    pipeline = run_replay(repetitions)
    summary = summarize(protocols, pipeline, iterations)

    if args.smoke:
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        "performance: "
        + ", ".join(
            f"{name} {row['frames_per_second'] / 1_000_000:.1f}M frames/s"
            for name, row in protocols.items()
        )
        + f", replay {pipeline['events_per_second']:.0f} events/s -> {EVIDENCE_PATH}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
