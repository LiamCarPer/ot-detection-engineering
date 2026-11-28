"""Measure what the Alertmanager grouping policy does to the lab queue.

This script applies the Alertmanager policy's declared ``group_by`` key to the
committed lab snapshot. Alertmanager is not replayed: it groups, but does not
execute group_wait, repeat intervals or inhibit rules. The lab snapshot has
``alert_type`` and IPs but no ``severity`` label or ``dst_zone``; those are
resolved from the detection catalogue and the asset inventory, and an unknown
severity stays ``unknown`` rather than being guessed.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ALERTS = REPO_ROOT / "analysis" / "data" / "lab-2026-11-24" / "alerts.jsonl"
OUT_DIR = REPO_ROOT / "analysis" / "out"
OUT_JSON = OUT_DIR / "suppression.json"
OUT_MARKDOWN = OUT_DIR / "suppression.md"

POLICY = REPO_ROOT / "deploy" / "alertmanager" / "ot-inhibit.yml"
CATALOGUE = REPO_ROOT / "metadata" / "detection-catalog.yaml"
ASSETS = REPO_ROOT / "metadata" / "assets.yaml"


def _alerts() -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in ALERTS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _policy_group_by() -> list[str]:
    policy = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    return list(policy["route"]["group_by"])


def _severity_map() -> dict[str, str]:
    catalogue = yaml.safe_load(CATALOGUE.read_text(encoding="utf-8"))
    mapping: dict[str, str] = {}
    for rule in catalogue["rules"]:
        for alert_type in rule.get("lab_alert_types") or []:
            mapping[alert_type] = rule["severity"]
    return mapping


def _zone_map() -> dict[str, str]:
    inventory = yaml.safe_load(ASSETS.read_text(encoding="utf-8"))
    return {str(asset["ip"]): asset["zone"] for asset in inventory["assets"]}


def _key(alert: dict[str, Any], group_by: list[str], severity: dict, zone: dict) -> tuple:
    values = []
    for field in group_by:
        if field == "alertname":
            value = alert.get("alert_type")
        elif field == "severity":
            value = severity.get(str(alert.get("alert_type")), "unknown")
        elif field == "src_ip":
            value = alert.get("source_ip")
        elif field == "dst_ip":
            value = alert.get("dest_ip")
        elif field == "dst_zone":
            value = zone.get(str(alert.get("dest_ip")))
        else:
            value = alert.get(field)
        values.append(str(value) if value is not None else None)
    return tuple(values)


def build() -> dict[str, Any]:
    alerts = _alerts()
    group_by = _policy_group_by()
    severity = _severity_map()
    zone = _zone_map()
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for alert in alerts:
        groups[_key(alert, group_by, severity, zone)].append(alert)

    preserved = {}
    for label, predicate in {
        "C2_hmi_login": lambda alert: alert.get("alert_type") == "HMI_LOGIN_FAILURE",
        "C3_protocol_chain": lambda alert: alert.get("source_ip") == "172.23.0.20",
        "C4_operator_write": lambda alert: (
            alert.get("alert_type") == "UNAUTHORIZED_MODBUS_WRITE"
            and alert.get("source_ip") == "172.22.0.30"
        ),
        "C5_sensor_health": lambda alert: alert.get("alert_type") == "DETECTION_SERVICE_DOWN",
    }.items():
        preserved[label] = sum(1 for alert in alerts if predicate(alert))

    by_type = Counter(str(alert.get("alert_type")) for alert in alerts)
    return {
        "schema_version": 1,
        "source": ALERTS.relative_to(REPO_ROOT).as_posix(),
        "policy": POLICY.relative_to(REPO_ROOT).as_posix(),
        "group_by": group_by,
        "severity_source": "metadata/detection-catalog.yaml; unknown stays unknown",
        "zone_source": "metadata/assets.yaml",
        "raw_alerts": len(alerts),
        "notifications": len(groups),
        "reduction_pct": round(100 * (1 - len(groups) / len(alerts)), 2) if alerts else 0.0,
        "groups": [
            {
                "key": list(key),
                "alerts": len(rows),
            }
            for key, rows in sorted(
                groups.items(),
                key=lambda item: tuple(value or "" for value in item[0]),
            )
        ],
        "by_alert_type": dict(sorted(by_type.items())),
        "preserved": preserved,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Suppression result",
        "",
        f"Source: `{report['source']}`  ",
        f"Policy: `{report['policy']}`",
        "",
        "| View | Count |",
        "| :-- | --: |",
        f"| Raw alerts | {report['raw_alerts']} |",
        f"| Notifications under the group key | {report['notifications']} |",
        f"| Reduction | {report['reduction_pct']}% |",
        "",
        "## Preserved signals",
        "",
        "| Signal | Alerts |",
        "| :-- | --: |",
    ]
    for label, count in report["preserved"].items():
        lines.append(f"| {label} | {count} |")
    lines += [
        "",
        "The grouping key is the policy's `group_by` list: "
        + ", ".join(f"`{field}`" for field in report["group_by"])
        + ".",
        "",
        "The snapshot has no `severity` label or `dst_zone`; severity is resolved",
        "from the detection catalogue (unknown stays unknown) and zone from the",
        "asset inventory. This is a grouping model, not an Alertmanager replay:",
        "`group_wait`, repeat intervals and inhibit rules are not simulated.",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    report = build()
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    OUT_MARKDOWN.write_text(render_markdown(report), encoding="utf-8")
    print(
        f"suppression: {report['raw_alerts']} alerts -> "
        f"{report['notifications']} notifications "
        f"({report['reduction_pct']}%) -> {OUT_JSON}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
