"""Sustained matcher load and a bounded-queue drop test.

The decoder microbenchmark measures tiny frames; this measures the validation
path that actually runs on every event. It replays a real lab-derived event file
at a target events-per-second, through every single-event Sigma rule, with a
bounded queue. If service time exceeds the arrival interval the queue fills and
the run records drops instead of pretending the pipeline kept up.

This is a single-process model, not a production sensor. It is the honest
ceiling for this Python matcher and a regression guard for rule cost.

Usage:
    python tools/load_check.py --events /path/to/events.jsonl --target-eps 1000 --duration 10
"""

from __future__ import annotations

import argparse
import json
import platform
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sigma.rule import SigmaRule  # noqa: E402

from tools.otde.matcher import match  # noqa: E402
from tools.otde.rules import single_event_rule_paths  # noqa: E402

OUT_DIR = REPO_ROOT / "deploy" / "evidence" / "load"
OUT_JSON = OUT_DIR / "summary.json"
OUT_MD = OUT_DIR / "report.md"


def _load_events(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _rules() -> list[SigmaRule]:
    return [
        SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
        for path in single_event_rule_paths()
    ]


def run(events: list[dict], target_eps: int, duration: float, queue_size: int) -> dict[str, Any]:
    rules = _rules()
    if not events:
        raise ValueError("the event file is empty")
    total = max(1, int(target_eps * duration))
    work: queue.Queue = queue.Queue(maxsize=queue_size)
    stop = object()
    processed = 0
    matches = 0
    dropped = 0
    latencies: list[float] = []
    max_queue = 0
    lock = threading.Lock()

    def consumer() -> None:
        nonlocal processed, matches, max_queue
        while True:
            item = work.get()
            if item is stop:
                work.task_done()
                return
            enqueued, event = item
            for rule in rules:
                if match(rule, event):
                    matches += 1
            latencies.append(time.perf_counter() - enqueued)
            processed += 1
            with lock:
                max_queue = max(max_queue, work.qsize())
            work.task_done()

    worker = threading.Thread(target=consumer, daemon=True)
    worker.start()
    started = time.perf_counter()
    for index in range(total):
        target = started + index / target_eps
        now = time.perf_counter()
        if now < target:
            time.sleep(target - now)
        try:
            work.put_nowait((time.perf_counter(), events[index % len(events)]))
        except queue.Full:
            dropped += 1
    work.put(stop)
    worker.join()
    elapsed = time.perf_counter() - started
    latencies.sort()
    return {
        "target_eps": target_eps,
        "duration_seconds": duration,
        "queue_size": queue_size,
        "attempts": total,
        "processed": processed,
        "dropped": dropped,
        "drop_rate": round(dropped / total, 6) if total else 0.0,
        "achieved_eps": round(processed / elapsed, 2) if elapsed else 0.0,
        "max_queue": max_queue,
        "p50_us": round(latencies[(len(latencies) * 50) // 100] * 1_000_000, 3)
        if latencies
        else None,
        "p99_us": round(latencies[(len(latencies) * 99) // 100] * 1_000_000, 3)
        if latencies
        else None,
        "rules": len(rules),
        "matches": matches,
        "hardware": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor() or "unknown",
            "python": platform.python_version(),
        },
    }


def build(events_path: Path, target_eps: int, duration: float, queue_size: int) -> dict[str, Any]:
    events = _load_events(events_path)
    return {
        "schema_version": 1,
        "source": str(events_path),
        "events": len(events),
        "runs": [
            run(events, target_eps, duration, queue_size),
            run(events, target_eps * 5, duration, queue_size),
        ],
    }


def render(report: dict[str, Any]) -> str:
    lines = [
        "# Sustained matcher load",
        "",
        f"Source: `{report['source']}` ({report['events']} distinct events)",
        "",
        "| Target EPS | Processed | Dropped | Achieved EPS | p99 | Max queue |",
        "| ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in report["runs"]:
        lines.append(
            f"| {row['target_eps']} | {row['processed']} | {row['dropped']} "
            f"({row['drop_rate'] * 100:.3f}%) | {row['achieved_eps']} | "
            f"{row['p99_us']} µs | {row['max_queue']} |"
        )
    lines += [
        "",
        "The queue is bounded; a target the matcher cannot sustain shows drops,",
        "not an unbounded queue. This is a single-process Python matcher, not a",
        "production sensor or a pcap replay.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", required=True)
    parser.add_argument("--target-eps", type=int, default=1_000)
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--queue-size", type=int, default=10_000)
    parser.add_argument("--out", default=str(OUT_DIR))
    args = parser.parse_args(argv)
    report = build(Path(args.events), args.target_eps, args.duration, args.queue_size)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "report.md").write_text(render(report), encoding="utf-8")
    for row in report["runs"]:
        print(
            f"{row['target_eps']} EPS -> {row['achieved_eps']} achieved, "
            f"{row['dropped']} drops, p99 {row['p99_us']} us"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
