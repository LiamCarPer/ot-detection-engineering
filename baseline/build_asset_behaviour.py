"""Build the per-asset protocol baseline used by the asset-behaviour detection.

The baseline records, for each destination asset, the services and function
codes observed in benign Suricata samples. It is deliberately per asset: a
function code that is normal on one PLC can still be new on another.

Usage:
    python baseline/build_asset_behaviour.py
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from baseline.build import collect  # noqa: E402

DEFAULT_OUT = REPO_ROOT / "baseline" / "asset-behaviour.json"
BENIGN_INPUTS = [
    "collector/samples/suricata/modbus_benign.eve.json",
    "collector/samples/suricata/dnp3_benign.eve.json",
]


def build(events: list[dict]) -> dict:
    services: dict[str, set[str]] = defaultdict(set)
    functions: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))

    for event in events:
        if event.get("product") != "ot_ndr":
            continue
        asset = event.get("dst_ip")
        service = event.get("service")
        if not asset or not service:
            continue
        services[str(asset)].add(str(service))
        code = event.get("function_code")
        if code is not None:
            try:
                functions[str(asset)][str(service)].add(int(code))
            except (TypeError, ValueError):
                continue

    assets = {}
    for asset in sorted(services):
        assets[asset] = {
            "services": sorted(services[asset]),
            "functions": {
                service: sorted(codes)
                for service, codes in sorted(functions[asset].items())
            },
        }
    return {
        "schema_version": 1,
        "generated_from": list(BENIGN_INPUTS),
        "assets": assets,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)

    events, _ = collect("suricata", BENIGN_INPUTS)
    baseline = build(events)
    Path(args.out).write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
    print(f"asset baseline: {len(baseline['assets'])} assets -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
