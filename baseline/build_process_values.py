"""Build the process-value baseline used by the setpoint-drift detection.

The baseline is the mean and population standard deviation of a process value
per asset, computed from the benign corpus. It is deterministic and committed,
so a drift check catches an accidental change and the detection's threshold is
reviewable.

Usage:
    python baseline/build_process_values.py
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = REPO_ROOT / "metrics" / "baseline" / "benign-events.jsonl"
DEFAULT_OUT = REPO_ROOT / "baseline" / "process-values.json"
FIELD = "tank_level_pct"


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def build(events: list[dict]) -> dict:
    values: dict[str, list[float]] = defaultdict(list)
    for event in events:
        if event.get("product") != "ot_process":
            continue
        if event.get("event_type") != "process_update":
            continue
        asset = event.get("asset")
        value = event.get(FIELD)
        if asset and value is not None:
            values[str(asset)].append(float(value))

    assets = {}
    for asset, samples in sorted(values.items()):
        if not samples:
            continue
        assets[asset] = {
            "mean": round(statistics.mean(samples), 3),
            "std": round(statistics.pstdev(samples), 3),
            "samples": len(samples),
        }
    return {
        "schema_version": 1,
        "generated_from": [_relative(DEFAULT_INPUT)],
        "field": FIELD,
        "assets": assets,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)

    events = [
        json.loads(line)
        for line in Path(args.input).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    baseline = build(events)
    Path(args.out).write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    print(f"process baseline: {len(baseline['assets'])} assets -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
