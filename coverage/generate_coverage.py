"""Generate the MITRE ATT&CK for ICS coverage map from detection content.

Coverage is derived, never hand-maintained. The generator reads the pinned ICS
catalog and every rule's technique tags (Sigma tags and native Suricata
metadata) and reports, per tactic, which techniques are detected and by which
rules. Output is deterministic: JSON for tooling, Markdown for review, and a
self-contained HTML heatmap for presentation.

Usage:
    python coverage/generate_coverage.py
    python coverage/generate_coverage.py --out coverage/out
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.otde.rules import detected_techniques, load_catalog  # noqa: E402

# Left-to-right order of the ATT&CK for ICS matrix.
TACTIC_ORDER = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "evasion",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "inhibit-response-function",
    "impair-process-control",
    "impact",
]


def build_report() -> dict:
    catalog = load_catalog()
    detected = detected_techniques()
    known_ids = {technique["id"] for technique in catalog["techniques"]}

    tactics = sorted(
        catalog["tactics"],
        key=lambda tactic: TACTIC_ORDER.index(tactic["shortname"])
        if tactic["shortname"] in TACTIC_ORDER
        else len(TACTIC_ORDER),
    )

    technique_rows = []
    for technique in catalog["techniques"]:
        sources = detected.get(technique["id"], [])
        technique_rows.append(
            {
                "id": technique["id"],
                "name": technique["name"],
                "tactics": technique["tactics"],
                "covered": technique["id"] in detected,
                "rule_count": len(sources),
                "sources": sources,
            }
        )

    tactic_rows = []
    for tactic in tactics:
        members = [t for t in technique_rows if tactic["id"] in t["tactics"]]
        covered = [t for t in members if t["covered"]]
        tactic_rows.append(
            {
                "id": tactic["id"],
                "name": tactic["name"],
                "shortname": tactic["shortname"],
                "techniques_total": len(members),
                "techniques_covered": len(covered),
                "coverage_pct": round(100 * len(covered) / len(members), 1) if members else 0.0,
                "techniques": [t["id"] for t in members],
            }
        )

    covered_ids = sorted(t for t in detected if t in known_ids)
    return {
        "attack_version": catalog["attack_version"],
        "summary": {
            "techniques_total": len(technique_rows),
            "techniques_covered": len(covered_ids),
            "coverage_pct": round(100 * len(covered_ids) / len(technique_rows), 1),
            "rules_total": sum(len(v) for v in detected.values()),
        },
        "tactics": tactic_rows,
        "techniques": technique_rows,
    }


def render_markdown(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# MITRE ATT&CK for ICS Coverage",
        "",
        f"ATT&CK for ICS v{report['attack_version']} — "
        f"**{summary['techniques_covered']} / {summary['techniques_total']}** techniques "
        f"covered ({summary['coverage_pct']}%).",
        "",
        "Generated from rule technique tags by `coverage/generate_coverage.py`.",
        "",
        "## Coverage by tactic",
        "",
        "| Tactic | Covered | Techniques | Coverage |",
        "| :--- | ---: | ---: | ---: |",
    ]
    for tactic in report["tactics"]:
        lines.append(
            f"| {tactic['name']} | {tactic['techniques_covered']} | "
            f"{tactic['techniques_total']} | {tactic['coverage_pct']}% |"
        )

    detected = [t for t in report["techniques"] if t["covered"]]
    lines += ["", "## Detected techniques", ""]
    if not detected:
        lines.append("_No techniques are currently covered._")
    else:
        lines += [
            "| Technique | Name | Rules |",
            "| :--- | :--- | ---: |",
        ]
        for technique in detected:
            lines.append(
                f"| [{technique['id']}]"
                f"(https://attack.mitre.org/techniques/{technique['id'].replace('.', '/')}/) "
                f"| {technique['name']} | {technique['rule_count']} |"
            )
    return "\n".join(lines) + "\n"


def render_html(report: dict) -> str:
    summary = report["summary"]
    covered_ids = {t["id"] for t in report["techniques"] if t["covered"]}
    by_id = {t["id"]: t for t in report["techniques"]}
    columns = []
    for tactic in report["tactics"]:
        cells = []
        for technique_id in tactic["techniques"]:
            technique = by_id[technique_id]
            state = "covered" if technique_id in covered_ids else "open"
            title = f"{technique_id} {technique['name']} — {technique['rule_count']} rule(s)"
            cells.append(
                f'<div class="technique {state}" title="{html.escape(title)}">'
                f'<span class="id">{technique_id}</span>'
                f'<span class="name">{html.escape(technique["name"])}</span></div>'
            )
        columns.append(
            '<div class="tactic">'
            f'<h3>{html.escape(tactic["name"])}</h3>'
            f'<div class="count">{tactic["techniques_covered"]}/{tactic["techniques_total"]}</div>'
            + "".join(cells)
            + "</div>"
        )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MITRE ATT&CK for ICS Coverage</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
  h1 {{ margin-bottom: 0.25rem; }}
  .subtitle {{ color: #555; margin-top: 0; }}
  .matrix {{ display: flex; gap: 0.75rem; overflow-x: auto; margin-top: 1.5rem; }}
  .tactic {{ min-width: 190px; }}
  .tactic h3 {{ font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }}
  .count {{ font-size: 0.75rem; color: #666; margin-bottom: 0.4rem; }}
  .technique {{
    border-radius: 4px; padding: 0.35rem 0.5rem;
    margin-bottom: 0.3rem; font-size: 0.75rem;
  }}
  .technique .id {{ font-weight: 600; display: block; }}
  .technique .name {{ display: block; }}
  .covered {{ background: #c6efce; border-left: 4px solid #2e7d32; }}
  .open {{ background: #f2f2f2; border-left: 4px solid #ccc; color: #777; }}
</style>
</head>
<body>
<h1>MITRE ATT&CK for ICS Coverage</h1>
<p class="subtitle">ATT&amp;CK for ICS v{report['attack_version']} —
{summary['techniques_covered']} / {summary['techniques_total']} techniques
({summary['coverage_pct']}%)</p>
<div class="matrix">
{''.join(columns)}
</div>
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(REPO_ROOT / "coverage" / "out"))
    args = parser.parse_args(argv)

    report = build_report()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "attack_ics_coverage.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (out_dir / "attack_ics_coverage.md").write_text(render_markdown(report), encoding="utf-8")
    (out_dir / "attack_ics_coverage.html").write_text(render_html(report), encoding="utf-8")

    summary = report["summary"]
    print(
        f"coverage: {summary['techniques_covered']}/{summary['techniques_total']} "
        f"techniques ({summary['coverage_pct']}%) -> {out_dir}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
