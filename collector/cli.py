"""Collect standard OT sensor output into the normalized telemetry contract.

Usage:
    python -m collector.cli --source suricata --input eve.json
    python -m collector.cli --source zeek --input modbus.log --input dnp3.log
    python -m collector.cli --source suricata --input eve.json --sink loki \
        --loki-url http://localhost:3100/loki/api/v1/push

Every emitted event is validated against ``metadata/telemetry.schema.json``;
schema violations are reported and make the command exit non-zero.
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from pathlib import Path

from collector import contract
from collector.sinks import push_loki, to_jsonl, to_loki_streams
from collector.sources import suricata, zeek

SOURCES = {"suricata": suricata, "zeek": zeek}
DEFAULT_LOKI_URL = "http://localhost:3100/loki/api/v1/push"


def _expand(patterns: list[str]) -> list[Path]:
    files: list[Path] = []
    for pattern in patterns:
        matches = sorted(glob.glob(pattern))
        if not matches:
            raise FileNotFoundError(pattern)
        files.extend(Path(match) for match in matches)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=sorted(SOURCES), required=True)
    parser.add_argument("--input", action="append", required=True, help="File or glob (repeatable)")
    parser.add_argument("--sink", choices=["jsonl", "loki"], default="jsonl")
    parser.add_argument("--loki-url", default=DEFAULT_LOKI_URL)
    parser.add_argument(
        "--dry-run", action="store_true", help="Print the Loki payload instead of pushing"
    )
    args = parser.parse_args(argv)

    files = _expand(args.input)
    events = list(SOURCES[args.source].events(files))

    errors = [message for event in events for message in contract.schema_errors(event)]
    for message in errors:
        print(f"schema: {message}", file=sys.stderr)

    if args.sink == "jsonl":
        sys.stdout.write(to_jsonl(events))
    else:
        streams = to_loki_streams(events)
        if args.dry_run:
            print(json.dumps(streams, indent=2))
        else:
            push_loki(streams, args.loki_url)

    services = ", ".join(sorted({event["service"] for event in events}))
    print(
        f"collected {len(events)} event(s) from {len(files)} file(s): {services}",
        file=sys.stderr,
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
