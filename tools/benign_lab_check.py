"""Measure every network-detection family against a real lab capture.

The generated corpus is a model. This runner takes a PCAP captured at the lab
gateway, runs Suricata (with the repository rules) and Zeek over it, normalizes
the output through the collector, and applies the same all-family FPR functions
the generated-corpus harness uses.

Host, auth, PLC-diagnostic and sensor-health events are not in a network capture;
the report labels them as not observed rather than claiming a clean result.

Usage:
    python tools/benign_lab_check.py --pcap /path/to/benign-24h.pcap
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess  # nosec B404 - fixed Docker commands
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "metrics") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "metrics"))

from fpr import (  # noqa: E402
    baseline_family,
    conduit_family,
    sigma_correlation,
    sigma_single_event,
    stateful_family,
)

from collector.sources import suricata, zeek  # noqa: E402

OUT_DIR = REPO_ROOT / "deploy" / "evidence" / "benign-lab"
SUMMARY = OUT_DIR / "summary.json"
REPORT = OUT_DIR / "report.md"
RULES = REPO_ROOT / "deploy" / "suricata" / "ot-detection.rules"
SURICATA_IMAGE = "jasonish/suricata:latest"
ZEEK_IMAGE = "zeek/zeek:latest"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_suricata(pcap: Path, out: Path) -> list[dict[str, Any]]:
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    command = [
        "docker", "run", "--rm",
        "-v", f"{pcap.parent}:/pcap:ro",
        "-v", f"{RULES.parent}:/rules:ro",
        "-v", f"{out.parent}:/out",
        SURICATA_IMAGE,
        "-r", f"/pcap/{pcap.name}",
        "-S", "/rules/ot-detection.rules",
        "--set", "app-layer.protocols.modbus.enabled=yes",
        "--set", "app-layer.protocols.dnp3.enabled=yes",
        "-l", f"/out/{out.name}",
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)  # nosec B603
    eve = out / "eve.json"
    records = []
    for line in eve.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def _run_zeek(pcap: Path, out: Path) -> None:
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    command = [
        "docker", "run", "--rm",
        "-v", f"{pcap.parent}:/pcap:ro",
        "-v", f"{out}:/out",
        "-w", "/out",
        ZEEK_IMAGE,
        "zeek", "-r", f"/pcap/{pcap.name}",
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)  # nosec B603


def _normalized_events(suricata_dir: Path, zeek_dir: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    eve = suricata_dir / "eve.json"
    if eve.exists():
        events.extend(suricata.events([eve]))
    conn = zeek_dir / "conn.log"
    if conn.exists():
        events.extend(zeek.events([conn]))
    return events


def build(pcap: Path, events_out: Path | None = None) -> dict[str, Any]:
    work = Path(tempfile.mkdtemp(prefix="otde-benign-lab-"))
    local = work / "capture.pcap"
    shutil.copyfile(pcap, local)

    suricata_records = _run_suricata(local, work / "suricata")
    _run_zeek(local, work / "zeek")
    alerts = [
        record for record in suricata_records if record.get("event_type") == "alert"
    ]
    events = _normalized_events(work / "suricata", work / "zeek")

    families = {
        "sigma_single_event": sigma_single_event(events),
        "sigma_correlation": sigma_correlation(events),
        "baseline": baseline_family(events),
        "conduit": conduit_family(events),
        "stateful": stateful_family(events),
        "native": {
            "measured_from": "Suricata over the lab capture",
            "false_positive_alerts": len(alerts),
            "signatures": sorted(
                {record["alert"]["signature"] for record in alerts}
            ),
        },
        "not_observed": {
            "reason": "not present in a network capture",
            "families": ["host/sysmon", "auth/hmi", "plc/diagnostics", "detection_health"],
        },
    }
    if events_out:
        events_out.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )
    return {
        "schema_version": 1,
        "capture": {
            "path": str(pcap),
            "sha256": _sha256(pcap),
            "bytes": pcap.stat().st_size,
            "captured_at": datetime.now(UTC).isoformat(),
        },
        "events": len(events),
        "suricata_alerts": len(alerts),
        "families": families,
    }


def render(report: dict[str, Any]) -> str:
    f = report["families"]
    lines = [
        "# Lab benign capture",
        "",
        f"Capture: `{report['capture']['path']}`  ",
        f"SHA-256: `{report['capture']['sha256']}`  ",
        f"Size: {report['capture']['bytes']:,} bytes  ",
        f"Normalized events: {report['events']}",
        "",
        "| Family | Result |",
        "| :-- | :-- |",
        f"| Sigma single-event | "
        f"{f['sigma_single_event']['false_positive_events']} / {report['events']} events |",
        f"| Sigma correlation | {len(f['sigma_correlation']['fired'])} fired |",
        f"| Behaviour baseline | {f['baseline']['false_positive_events']} events |",
        f"| Conduit | {f['conduit']['false_positive_events']} events |",
        f"| Stateful | {len(f['stateful']['fired'])} fired |",
        f"| Native Suricata | {f['native']['false_positive_alerts']} alerts |",
        "| Host/auth/PLC/health | not observed in a network capture |",
        "",
        "## Native alerts",
        "",
    ]
    signatures = f["native"]["signatures"]
    lines.extend(f"- {signature}" for signature in signatures) if signatures else lines.append(
        "- none"
    )
    lines += [
        "",
        "This is real lab background traffic, not a plant. Host, auth, PLC and",
        "health families are measured on their own committed samples, not here.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--out", default=str(OUT_DIR))
    parser.add_argument(
        "--events-out",
        default=None,
        help="Optional JSONL path for the normalized events, for a load replay",
    )
    args = parser.parse_args(argv)
    report = build(
        Path(args.pcap), Path(args.events_out) if args.events_out else None
    )
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "report.md").write_text(render(report), encoding="utf-8")
    print(
        f"lab benign: {report['events']} events, "
        f"Sigma {report['families']['sigma_single_event']['false_positive_events']} FP, "
        f"native {report['suricata_alerts']} alerts -> {out}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
