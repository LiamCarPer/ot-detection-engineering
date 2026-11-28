"""Validate and report the operational health of the detection catalogue.

The catalogue is the operating context around each rule: owner, severity, data
source, expected volume, runbook, validation age and lifecycle status. This tool
refuses a rule without an entry, an entry without a rule, a technique mismatch,
or a `stable` rule that lacks a runbook, observed volume or recent validation.

It also joins the catalogue to the Phase 1 lab analysis (`rule_health.json`) so a
catalogued volume cannot silently drift from the data it came from.

Usage:
    python tools/detection_health.py
    python tools/detection_health.py --check
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402
from jsonschema import Draft202012Validator  # noqa: E402

from tools.otde.rules import (  # noqa: E402
    baseline_rule_paths,
    baseline_techniques,
    conduit_rule_paths,
    conduit_techniques,
    correlation_rule_paths,
    load_sigma_rule,
    native_rule_paths,
    sigma_techniques,
    single_event_rule_paths,
    stateful_rule_paths,
    stateful_techniques,
    yara_rule_paths,
    yara_techniques,
)
from tools.otde.suricata import read_rules  # noqa: E402

CATALOG_PATH = REPO_ROOT / "metadata" / "detection-catalog.yaml"
SCHEMA_PATH = REPO_ROOT / "metadata" / "detection-catalog.schema.json"
VOLUME_PATH = REPO_ROOT / "analysis" / "out" / "rule_health.json"
OUT_DIR = REPO_ROOT / "deploy" / "evidence" / "health"
OUT_SUMMARY = OUT_DIR / "summary.json"
OUT_REPORT = OUT_DIR / "report.md"

# The catalogue is audited against a fixed date so the report and --check are
# deterministic. Bump this when the catalogue is re-reviewed.
AS_OF = date(2026, 11, 24)
MAX_AGE_DAYS = 180
YARA_ID_RE = re.compile(r"^\s*rule\s+(\w+)", re.MULTILINE)


@dataclass(frozen=True)
class Rule:
    id: str
    path: str
    title: str
    kind: str
    techniques: list[str]


def _relative(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def discover_rules() -> dict[str, Rule]:
    """Return every rule the repository ships, keyed by its catalog id."""
    rules: dict[str, Rule] = {}

    for paths, kind, technique_fn in (
        (single_event_rule_paths(), "sigma", sigma_techniques),
        (correlation_rule_paths(), "correlation", sigma_techniques),
        (yara_rule_paths(), "yara", yara_techniques),
        (baseline_rule_paths(), "baseline", baseline_techniques),
        (conduit_rule_paths(), "conduit", conduit_techniques),
        (stateful_rule_paths(), "stateful", stateful_techniques),
    ):
        for path in paths:
            if kind == "yara":
                text = path.read_text(encoding="utf-8")
                match = YARA_ID_RE.search(text)
                if not match:
                    raise ValueError(f"{path} has no YARA rule identifier")
                rule_id = match.group(1)
                title = rule_id
            elif kind in ("baseline", "conduit", "stateful"):
                data = yaml.safe_load(path.read_text(encoding="utf-8"))
                rule_id = str(data["id"])
                title = str(data["title"])
            else:
                rule = load_sigma_rule(path)
                rule_id = str(rule.id)
                title = rule.title
            if rule_id in rules:
                raise ValueError(f"duplicate rule id {rule_id}: {rules[rule_id].path} and {path}")
            rules[rule_id] = Rule(
                id=rule_id,
                path=_relative(path),
                title=title,
                kind=kind,
                techniques=sorted(set(technique_fn(path))),
            )

    for path in native_rule_paths():
        for rule in read_rules(path):
            if rule.sid is None:
                continue
            rule_id = f"sid:{rule.sid}"
            if rule_id in rules:
                raise ValueError(f"duplicate native SID {rule.sid}")
            rules[rule_id] = Rule(
                id=rule_id,
                path=_relative(path),
                title=rule.msg or f"Suricata SID {rule.sid}",
                kind="native",
                techniques=sorted(set(rule.attack_ics)),
            )
    return rules


def load_catalog(path: Path = CATALOG_PATH) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _volume_summary(volume: dict | None) -> str | None:
    if not volume:
        return None
    kind = volume.get("volume_kind", "unknown")
    return f"{volume['raw_alerts']} raw / {volume['episodes']} episodes ({kind})"


def _parse_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def build_health(
    catalog_path: Path = CATALOG_PATH,
    as_of: date = AS_OF,
    max_age_days: int = MAX_AGE_DAYS,
) -> dict:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    catalog = load_catalog(catalog_path)
    validator = Draft202012Validator(schema)
    schema_errors = [
        f"{'/'.join(str(part) for part in error.absolute_path)}: {error.message}"
        for error in validator.iter_errors(catalog)
    ]

    discovered = discover_rules()
    entries = catalog.get("rules", [])
    by_id: dict[str, dict] = {}
    gaps: list[dict] = []
    warnings: list[dict] = []

    for entry in entries:
        entry_id = str(entry.get("id"))
        if entry_id in by_id:
            gaps.append(
                {
                    "id": entry_id,
                    "title": entry.get("title"),
                    "issue": "duplicate catalog id",
                }
            )
        by_id[entry_id] = entry

    for rule_id in sorted(set(discovered) - set(by_id)):
        gaps.append(
            {
                "id": rule_id,
                "title": discovered[rule_id].title,
                "issue": "rule has no catalogue entry",
            }
        )
    for rule_id in sorted(set(by_id) - set(discovered)):
        gaps.append(
            {
                "id": rule_id,
                "title": by_id[rule_id].get("title"),
                "issue": "catalogue entry has no rule",
            }
        )

    volume_by_type: dict[str, dict] = {}
    if VOLUME_PATH.exists():
        raw = json.loads(VOLUME_PATH.read_text(encoding="utf-8"))
        volume_by_type = {row["alert_type"]: row for row in raw.get("rules", [])}

    stable_total = stable_with_runbook = stable_with_volume = stale_total = 0
    observed_volume_total = 0

    for entry in entries:
        entry_id = str(entry["id"])
        rule = discovered.get(entry_id)
        if rule is None:
            continue
        issues: list[str] = []
        path = REPO_ROOT / entry["rule"]
        if not path.exists():
            issues.append(f"rule path does not exist: {entry['rule']}")
        if rule.path != entry["rule"]:
            issues.append(f"rule path mismatch: catalogue {entry['rule']}, discovered {rule.path}")
        if sorted(set(entry.get("techniques", []))) != rule.techniques:
            issues.append(
                f"technique mismatch: catalogue {entry.get('techniques')}, "
                f"rule {rule.techniques}"
            )
        if entry["kind"] != rule.kind:
            issues.append(f"kind mismatch: catalogue {entry['kind']}, discovered {rule.kind}")
        if rule.kind == "native" and str(entry.get("id")) != f"sid:{entry.get('sid')}":
            issues.append("native entry id and sid disagree")

        volume = entry.get("expected_volume")
        if volume:
            observed_volume_total += 1
        lab_types = entry.get("lab_alert_types", [])
        if lab_types and volume_by_type:
            observed_raw = sum(volume_by_type.get(t, {}).get("raw_alerts", 0) for t in lab_types)
            observed_eps = sum(volume_by_type.get(t, {}).get("episodes", 0) for t in lab_types)
            if not volume:
                issues.append("lab_alert_types present but expected_volume is null")
            elif (volume["raw_alerts"], volume["episodes"]) != (observed_raw, observed_eps):
                issues.append(
                    "expected_volume is stale: catalogue "
                    f"{volume['raw_alerts']}/{volume['episodes']}, "
                    f"lab {observed_raw}/{observed_eps}"
                )

        last_validated = _parse_date(entry.get("last_validated"))
        age_days = (as_of - last_validated).days if last_validated else None

        if entry["status"] == "stable":
            stable_total += 1
            if entry.get("runbook"):
                if (REPO_ROOT / entry["runbook"]).exists():
                    stable_with_runbook += 1
                else:
                    issues.append(f"runbook not found: {entry['runbook']}")
            else:
                issues.append("stable rule has no runbook")
            if volume:
                stable_with_volume += 1
            else:
                issues.append("stable rule has no expected_volume")
            if last_validated is None:
                issues.append("stable rule has no last_validated")
            elif age_days is not None and age_days > max_age_days:
                stale_total += 1
                issues.append(f"stable rule validation is {age_days} days old")

        if issues:
            gaps.append({"id": entry_id, "title": entry["title"], "issue": "; ".join(issues)})
        elif entry["status"] != "stable":
            missing = []
            if not entry.get("runbook"):
                missing.append("no runbook")
            if not volume:
                missing.append("no observed volume")
            if not last_validated:
                missing.append("no last_validated")
            if missing:
                warnings.append(
                    {"id": entry_id, "title": entry["title"], "issue": "; ".join(missing)}
                )

    per_rule = []
    gap_ids = {gap["id"] for gap in gaps}
    warn_ids = {warning["id"] for warning in warnings}
    for entry in entries:
        entry_id = str(entry["id"])
        last_validated = _parse_date(entry.get("last_validated"))
        per_rule.append(
            {
                "id": entry_id,
                "title": entry["title"],
                "kind": entry["kind"],
                "severity": entry["severity"],
                "status": entry["status"],
                "owner": entry["owner"],
                "runbook": entry.get("runbook"),
                "has_runbook": bool(entry.get("runbook")),
                "expected_volume": _volume_summary(entry.get("expected_volume")),
                "raw_alerts": entry["expected_volume"]["raw_alerts"]
                if entry.get("expected_volume")
                else None,
                "episodes": entry["expected_volume"]["episodes"]
                if entry.get("expected_volume")
                else None,
                "last_validated": entry.get("last_validated"),
                "age_days": (as_of - last_validated).days if last_validated else None,
                "health": (
                    "gap" if entry_id in gap_ids else "warn" if entry_id in warn_ids else "ok"
                ),
            }
        )

    summary = {
        "as_of": as_of.isoformat(),
        "catalog_version": catalog.get("version"),
        "totals": {
            "rules": len(entries),
            "discovered_rules": len(discovered),
            "stable": stable_total,
            "stable_with_runbook": stable_with_runbook,
            "stable_with_observed_volume": stable_with_volume,
            "stable_stale": stale_total,
            "with_observed_volume": observed_volume_total,
            "gaps": len(gaps),
            "warnings": len(warnings),
        },
        "by_kind": dict(sorted(Counter(entry["kind"] for entry in entries).items())),
        "by_status": dict(sorted(Counter(entry["status"] for entry in entries).items())),
        "by_severity": dict(sorted(Counter(entry["severity"] for entry in entries).items())),
        "schema_errors": schema_errors,
        "gaps": gaps,
        "warnings": warnings,
        "per_rule": per_rule,
    }
    return summary


def render_markdown(summary: dict) -> str:
    totals = summary["totals"]
    lines = [
        "# Detection health",
        "",
        f"Audited as of **{summary['as_of']}**. Generated by "
        "`tools/detection_health.py`; do not edit by hand.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| :--- | ---: |",
        f"| Rules in the catalogue | {totals['rules']} |",
        f"| Rules discovered in the repository | {totals['discovered_rules']} |",
        f"| Stable | {totals['stable']} |",
        f"| Stable with a runbook | {totals['stable_with_runbook']} |",
        f"| Stable with observed lab volume | {totals['stable_with_observed_volume']} |",
        f"| Rules with observed lab volume | {totals['with_observed_volume']} |",
        f"| Stable rules with stale validation | {totals['stable_stale']} |",
        f"| Blocking gaps that must be fixed | {totals['gaps']} |",
        f"| Warnings on experimental rules | {totals['warnings']} |",
        "",
        "By kind: " + ", ".join(f"`{k}` {v}" for k, v in summary["by_kind"].items()),
        "",
        "By severity: " + ", ".join(f"`{k}` {v}" for k, v in summary["by_severity"].items()),
        "",
        "## Stable rules",
        "",
        "| Rule | Severity | Runbook | Volume | Last validated | Age (days) |",
        "| :-- | :-- | :-- | :-- | :-- | --: |",
    ]
    for row in summary["per_rule"]:
        if row["status"] != "stable":
            continue
        lines.append(
            f"| {row['title']} | {row['severity']} | "
            f"{'[runbook](../../../' + row['runbook'] + ')' if row['runbook'] else '—'} | "
            f"{row['expected_volume'] or '—'} | {row['last_validated'] or '—'} | "
            f"{row['age_days'] if row['age_days'] is not None else '—'} |"
        )

    lines += ["", "## Rules with observed lab volume", "",
              "| Rule | Raw | Episodes | Status | Health |",
              "| :-- | --: | --: | :-- | :-- |"]
    for row in summary["per_rule"]:
        if not row["expected_volume"]:
            continue
        lines.append(
            f"| {row['title']} | {row['raw_alerts']} | {row['episodes']} | "
            f"{row['status']} | {row['health']} |"
        )

    lines += ["", "## Gaps", ""]
    if summary["gaps"]:
        lines += ["| Rule | Issue |", "| :-- | :-- |"]
        for gap in summary["gaps"]:
            lines.append(f"| {gap['title']} | {gap['issue']} |")
    else:
        lines.append("None.")

    lines += ["", "## Warnings", ""]
    if summary["warnings"]:
        lines.append(
            f"{len(summary['warnings'])} experimental rules have at least one operating "
            "gap (usually no runbook or no observed volume). Runbooks and volume are "
            "promotion criteria, not requirements for an experimental rule."
        )
    else:
        lines.append("None.")
    if summary["schema_errors"]:
        lines += ["", "## Schema errors", ""] + [
            f"- {error}" for error in summary["schema_errors"]
        ]

    lines += [
        "",
        "## How to promote a rule",
        "",
        "1. Give it an owner and a data source.",
        "2. Write a runbook under `docs/runbooks/`.",
        "3. Record observed volume from a lab run or a production baseline.",
        "4. Set `last_validated` and `status: stable`.",
        "5. Run `make health` and commit the refreshed evidence.",
        "",
        "## Reproduce",
        "",
        "```bash",
        "make health",
        "make health-check",
        "```",
        "",
    ]
    return "\n".join(lines)


def write_outputs(summary: dict, report: str) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_SUMMARY.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    OUT_REPORT.write_text(report, encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", default=str(CATALOG_PATH))
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--today",
        action="store_true",
        help="Age stable rules against the real date instead of the frozen audit date",
    )
    args = parser.parse_args(argv)

    if args.today:
        # The committed report is frozen for determinism. This operational check
        # is not: a rule that was current when committed must still be re-reviewed
        # after MAX_AGE_DAYS.
        summary = build_health(Path(args.catalog), as_of=date.today())
        stale = [
            row
            for row in summary["per_rule"]
            if row["status"] == "stable" and (row["age_days"] or 0) > MAX_AGE_DAYS
        ]
        if stale:
            print(f"{len(stale)} stable rule(s) are older than {MAX_AGE_DAYS} days:")
            for row in stale:
                print(f"  - {row['title']}: {row['age_days']} days")
            return 1
        print(f"stable rules are within the {MAX_AGE_DAYS}-day age gate as of {date.today()}")
        return 0

    summary = build_health(Path(args.catalog))
    report = render_markdown(summary)

    if summary["schema_errors"]:
        print("detection catalogue schema errors:")
        for error in summary["schema_errors"]:
            print(f"  - {error}")
        return 1
    if summary["gaps"]:
        print(f"detection catalogue has {len(summary['gaps'])} gap(s):")
        for gap in summary["gaps"]:
            print(f"  - {gap['id']} ({gap['title']}): {gap['issue']}")
        return 1

    if args.check:
        expected_summary = json.dumps(summary, indent=2, sort_keys=True) + "\n"
        if not OUT_SUMMARY.exists() or OUT_SUMMARY.read_text(encoding="utf-8") != expected_summary:
            print("detection health summary is stale; run make health")
            return 1
        if not OUT_REPORT.exists() or OUT_REPORT.read_text(encoding="utf-8") != report:
            print("detection health report is stale; run make health")
            return 1
        print("detection health is current")
        return 0

    write_outputs(summary, report)
    print(
        f"detection health: {summary['totals']['rules']} rules, "
        f"{summary['totals']['stable']} stable, "
        f"{summary['totals']['gaps']} gaps -> {OUT_DIR}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
