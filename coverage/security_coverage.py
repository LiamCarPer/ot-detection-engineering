"""Generate the security-control coverage report.

Coverage is derived, never hand-maintained: the threat model
(``metadata/threat-model.yaml``) says which threats exist and which controls
mitigate them, and the control register (``metadata/security-controls.yaml``)
says which controls are actually implemented and what proves it. The report
shows which threats currently have at least one implemented control, and which
are only planned — the security equivalent of an ATT&CK coverage map.

Usage:
    python coverage/security_coverage.py
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
THREAT_MODEL = REPO_ROOT / "metadata" / "threat-model.yaml"
CONTROLS = REPO_ROOT / "metadata" / "security-controls.yaml"
DEFAULT_OUT = REPO_ROOT / "coverage" / "out"


def load() -> tuple[dict, dict]:
    return (
        yaml.safe_load(THREAT_MODEL.read_text(encoding="utf-8")),
        yaml.safe_load(CONTROLS.read_text(encoding="utf-8")),
    )


def build_report() -> dict:
    model, register = load()
    controls = {control["id"]: control for control in register["controls"]}
    implemented = {cid for cid, control in controls.items() if control["status"] == "implemented"}

    threat_rows = []
    for threat in model["threats"]:
        covered = [cid for cid in threat["controls"] if cid in implemented]
        threat_rows.append(
            {
                "id": threat["id"],
                "title": threat["title"],
                "framework": threat["framework"],
                "category": threat["category"],
                "asset": threat["asset"],
                "controls": threat["controls"],
                "covered": bool(covered),
                "implemented_controls": covered,
            }
        )

    covered = [threat for threat in threat_rows if threat["covered"]]
    return {
        "summary": {
            "threats_total": len(threat_rows),
            "threats_covered": len(covered),
            "coverage_pct": round(100 * len(covered) / len(threat_rows), 1) if threat_rows else 0.0,
            "controls_total": len(controls),
            "controls_implemented": len(implemented),
        },
        "assets": model["assets"],
        "threats": threat_rows,
        "controls": [
            {
                "id": control["id"],
                "title": control["title"],
                "status": control["status"],
                "verify": control.get("verify"),
                "evidence": control.get("evidence"),
            }
            for control in register["controls"]
        ],
    }


def render_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Security Control Coverage",
        "",
        f"**{summary['threats_covered']} / {summary['threats_total']}** threats have an "
        f"implemented control ({summary['coverage_pct']}%); "
        f"**{summary['controls_implemented']} / {summary['controls_total']}** controls are "
        "implemented.",
        "",
        "Generated from `metadata/threat-model.yaml` and "
        "`metadata/security-controls.yaml` by `coverage/security_coverage.py`.",
        "",
        "## Threats",
        "",
        "| Threat | Asset | Framework | Implemented controls | Covered |",
        "| :--- | :--- | :--- | :--- | :--- |",
    ]
    for threat in report["threats"]:
        controls = ", ".join(threat["implemented_controls"]) or "none"
        lines.append(
            f"| {threat['id']} {threat['title']} | {threat['asset']} | "
            f"{threat['framework']} | {controls} | "
            f"{'yes' if threat['covered'] else 'no'} |"
        )

    lines += [
        "",
        "## Controls",
        "",
        "| Control | Status | Verify | Evidence |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for control in report["controls"]:
        lines.append(
            f"| {control['id']} {control['title']} | {control['status']} | "
            f"`{control['verify']}` | `{control['evidence']}` |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args(argv)

    report = build_report()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "security_coverage.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "security_coverage.md").write_text(render_markdown(report), encoding="utf-8")

    summary = report["summary"]
    print(
        f"security coverage: {summary['threats_covered']}/{summary['threats_total']} threats "
        f"({summary['coverage_pct']}%), {summary['controls_implemented']}/"
        f"{summary['controls_total']} controls implemented -> {out_dir}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
