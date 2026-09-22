"""Build the OT behaviour baseline from normalized contract events.

The baseline is deterministic: the same events produce the same artifact, so it
is committed and a drift check catches an accidental change. It is built from
benign telemetry only — the collector's benign samples — because a baseline that
has seen the attack would not flag it.

Usage:
    python baseline/build.py --source suricata \
        --input 'collector/samples/suricata/*_benign.eve.json'
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
from collections import defaultdict
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from collector.contract import schema_errors  # noqa: E402
from collector.sources import suricata, zeek  # noqa: E402

BASELINE_PATH = REPO_ROOT / "baseline" / "ot-behaviour.json"
SOURCES = {"suricata": suricata, "zeek": zeek}
OT_NDR = "ot_ndr"


def build(events: Iterable[dict[str, Any]], generated_from: Sequence[str]) -> dict[str, Any]:
    """Reduce normalized OT telemetry to the behaviour baseline."""
    assets: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    functions: dict[str, set[int]] = defaultdict(set)
    services: set[str] = set()

    for event in events:
        if event.get("product") != OT_NDR:
            continue
        src = event.get("src_ip")
        dst = event.get("dst_ip")
        if src:
            assets.add(src)
        if dst:
            assets.add(dst)
        if src and dst:
            pairs.add((src, dst))
        service = event.get("service")
        if service:
            services.add(service)
        code = event.get("function_code")
        if service and code is not None:
            functions[service].add(int(code))

    return {
        "schema_version": 1,
        "generated_from": sorted(generated_from),
        "assets": sorted(assets),
        "pairs": [list(pair) for pair in sorted(pairs)],
        "functions": {service: sorted(codes) for service, codes in sorted(functions.items())},
        "services": sorted(services),
    }


def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def collect(sensor: str, patterns: Sequence[str]) -> tuple[list[dict], list[str]]:
    files: list[Path] = []
    for pattern in patterns:
        matches = sorted(glob.glob(pattern))
        if not matches:
            raise FileNotFoundError(pattern)
        files.extend(Path(match) for match in matches)
    events = list(SOURCES[sensor].events(files))
    return events, [_relative(path) for path in files]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=sorted(SOURCES), required=True)
    parser.add_argument("--input", action="append", required=True, help="File or glob (repeatable)")
    parser.add_argument("--out", default=str(BASELINE_PATH))
    args = parser.parse_args(argv)

    events, inputs = collect(args.source, args.input)
    errors = [error for event in events for error in schema_errors(event)]
    for message in errors:
        print(f"schema: {message}", file=sys.stderr)
    if errors:
        return 1

    baseline = build(events, inputs)
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    print(
        f"baseline: {len(baseline['assets'])} assets, {len(baseline['pairs'])} pairs, "
        f"{len(baseline['functions'])} services -> {out_path}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
