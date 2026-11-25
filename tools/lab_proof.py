"""Run the lab-dependent proofs and write one summary.

The committed evidence each tool writes is the detail; this is the operator's
one-command view: what ran, what passed, what was skipped and why.

The benign capture is protected. If the capture process is running, or the PCAP
was written in the last five minutes, the attack steps are skipped rather than
contaminating a 24-hour baseline. The saved capture is still analysed, because
that is a read of a file, not traffic.

Usage:
    python tools/lab_proof.py --dry-run
    python tools/lab_proof.py
    python tools/lab_proof.py --no-attacks
"""

from __future__ import annotations

import argparse
import json
import subprocess  # nosec B404 - fixed commands, no user input
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = REPO_ROOT / "deploy" / "evidence" / "lab-proof"
LAB_DIR = Path("/media/liamcarvajal/Storage/code/ot-security-lab")
CAPTURE = LAB_DIR / "detection" / "logs" / "benign-24h.pcap"
CAPTURE_IDLE_SECONDS = 300


@dataclass
class Step:
    name: str
    description: str
    command: list[str]
    evidence: Path
    attack: bool = False
    timeout: int = 3600
    status: str = "pending"
    seconds: float = 0.0
    detail: str = ""
    tags: list[str] = field(default_factory=list)


def _capture_active() -> tuple[bool, str]:
    try:
        running = subprocess.run(  # nosec B603
            ["pgrep", "-f", "benign_capture.py"],
            capture_output=True,
            text=True,
            check=False,
        )
        if running.returncode == 0:
            return True, "the capture process is running"
    except FileNotFoundError:
        pass
    if CAPTURE.exists():
        age = time.time() - CAPTURE.stat().st_mtime
        if age < CAPTURE_IDLE_SECONDS:
            return True, f"the capture was written {age:.0f}s ago"
    return False, ""


def _steps(include_attacks: bool) -> list[Step]:
    py = sys.executable
    steps = [
        Step(
            "sensor-health",
            "The Detection Service Stopped rule fires in the live ruler",
            [py, "tools/lab_health_check.py"],
            REPO_ROOT / "deploy" / "evidence" / "lab-health",
            tags=["sensor health"],
        ),
        Step(
            "live-rules",
            "Every rule the lab exercises fires on live traffic",
            [py, "tools/lab_loki_check.py"],
            REPO_ROOT / "deploy" / "evidence" / "lab-loki",
            tags=["live rules"],
        ),
        Step(
            "live-purple",
            "The repository rules fire for the live emulation steps",
            [
                py,
                "purple/runner/live_lab.py",
                "--runs",
                "1",
                "--out",
                str(REPO_ROOT / "deploy" / "evidence" / "purple-live"),
            ],
            REPO_ROOT / "deploy" / "evidence" / "purple-live",
            attack=True,
            timeout=1800,
            tags=["purple"],
        ),
        Step(
            "engine-parity",
            "Converted SPL, PPL and KQL select the matcher's events",
            [py, "tools/engine_parity.py", "--unblock-open-search"],
            REPO_ROOT / "deploy" / "evidence" / "engine-parity",
            tags=["parity"],
        ),
        Step(
            "benign-capture",
            "All network families over the saved lab capture",
            [py, "tools/benign_lab_check.py", "--pcap", str(CAPTURE)],
            REPO_ROOT / "deploy" / "evidence" / "benign-lab",
            timeout=7200,
            tags=["benign"],
        ),
    ]
    if not include_attacks:
        for step in steps:
            if step.attack:
                step.status = "skipped"
                step.detail = "attacks disabled (--no-attacks)"
    return steps


def run(include_attacks: bool, dry_run: bool) -> dict[str, Any]:
    steps = _steps(include_attacks)
    active, reason = _capture_active()
    started = datetime.now(UTC)
    for step in steps:
        if step.status == "skipped":
            continue
        if step.attack and active:
            step.status = "skipped"
            step.detail = f"benign capture in progress: {reason}"
            continue
        if dry_run:
            step.status = "planned"
            step.detail = " ".join(step.command)
            continue
        begun = time.perf_counter()
        try:
            result = subprocess.run(  # nosec B603
                step.command,
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                timeout=step.timeout,
                check=False,
            )
            step.seconds = round(time.perf_counter() - begun, 2)
            step.status = "pass" if result.returncode == 0 else "fail"
            tail = (result.stderr or result.stdout).strip().splitlines()[-3:]
            step.detail = " | ".join(tail)
        except subprocess.TimeoutExpired:
            step.seconds = round(time.perf_counter() - begun, 2)
            step.status = "fail"
            step.detail = f"timed out after {step.timeout}s"
    return {
        "schema_version": 1,
        "started_at": started.isoformat(),
        "finished_at": datetime.now(UTC).isoformat(),
        "capture_active": active,
        "capture_reason": reason,
        "steps": [
            {
                "name": step.name,
                "description": step.description,
                "status": step.status,
                "seconds": step.seconds,
                "detail": step.detail,
                "evidence": step.evidence.relative_to(REPO_ROOT).as_posix(),
                "tags": step.tags,
                "attack": step.attack,
            }
            for step in steps
        ],
    }


def render(summary: dict[str, Any]) -> str:
    lines = [
        "# Lab proof",
        "",
        f"Run: {summary['started_at']} to {summary['finished_at']}",
        "",
        "| Step | Status | Seconds | Evidence |",
        "| :-- | :-- | --: | :-- |",
    ]
    for step in summary["steps"]:
        lines.append(
            f"| {step['name']} | {step['status']} | {step['seconds']} | "
            f"`{step['evidence']}` |"
        )
    if summary["capture_active"]:
        lines += [
            "",
            f"Attack steps were skipped: {summary['capture_reason']}. The benign",
            "capture must not be contaminated by emulation traffic.",
        ]
    lines += ["", "## Details", ""]
    for step in summary["steps"]:
        lines.append(f"- **{step['name']}**: {step['detail'] or step['status']}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-attacks", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--out", default=str(OUT_DIR))
    args = parser.parse_args(argv)
    summary = run(not args.no_attacks, args.dry_run)
    if not args.dry_run:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        (out / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (out / "report.md").write_text(render(summary), encoding="utf-8")
    for step in summary["steps"]:
        print(f"{step['name']}: {step['status']} ({step['seconds']}s) {step['detail']}")
    if args.dry_run:
        return 0
    return 0 if all(step["status"] in {"pass", "skipped"} for step in summary["steps"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
