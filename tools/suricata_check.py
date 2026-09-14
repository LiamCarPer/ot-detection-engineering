"""Run Suricata over the generated captures and record alert evidence.

Suricata is executed in a container so validation needs no host install. The
raw eve log is filtered to alert records only, which keeps the committed
evidence small and focused, and the run is checked against
``tools/otde/evidence.py`` so a rule that stops firing fails the run.

Usage:
    python tools/suricata_check.py
    python tools/suricata_check.py --no-docker   # only verify committed evidence
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.otde.evidence import EXPECTED_SIDS, read_alert_sids  # noqa: E402

DEFAULT_IMAGE = "jasonish/suricata:latest"
CAPTURES_DIR = REPO_ROOT / "tests" / "captures"
RULES_FILE = REPO_ROOT / "deploy" / "suricata" / "ot-detection.rules"
EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence"

# DNP3 and Modbus application-layer detection is disabled in the stock config.
SURICATA_SETS = [
    "app-layer.protocols.modbus.enabled=yes",
    "app-layer.protocols.dnp3.enabled=yes",
]


def run_suricata(name: str, image: str) -> Path:
    out_dir = EVIDENCE_DIR / name
    # Suricata appends to an existing eve.json, so start from a clean directory;
    # otherwise a rerun merges fresh alerts with the committed evidence.
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    command = [
        "docker", "run", "--rm",
        "-v", f"{RULES_FILE.parent}:/rules:ro",
        "-v", f"{CAPTURES_DIR}:/pcap:ro",
        "-v", f"{EVIDENCE_DIR}:/out",
        image,
        "-r", f"/pcap/{name}.pcap",
        "-S", "/rules/ot-detection.rules",
        *[arg for value in SURICATA_SETS for arg in ("--set", value)],
        "-l", f"/out/{name}",
    ]
    subprocess.run(command, check=True)

    # The container writes as root; read the log, then replace the directory with
    # a user-owned copy that contains only the alert records.
    eve_path = out_dir / "eve.json"
    alerts = [
        line
        for line in eve_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and json.loads(line).get("event_type") == "alert"
    ]
    shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    eve_path.write_text("\n".join(alerts) + ("\n" if alerts else ""), encoding="utf-8")
    return eve_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--no-docker", action="store_true", help="Only verify committed evidence")
    args = parser.parse_args(argv)

    if not args.no_docker:
        for name in EXPECTED_SIDS:
            run_suricata(name, args.image)
            print(f"ran {name}")

    failures = []
    summary = {}
    for name, expected in EXPECTED_SIDS.items():
        observed = read_alert_sids(EVIDENCE_DIR / name / "eve.json")
        summary[name] = sorted(observed)
        if observed != expected:
            failures.append(f"{name}: expected {sorted(expected)}, observed {sorted(observed)}")

    (EVIDENCE_DIR / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if failures:
        print("suricata validation failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"suricata validation passed for {len(EXPECTED_SIDS)} captures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
