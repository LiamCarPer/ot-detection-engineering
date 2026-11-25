"""Measure what the Alertmanager grouping policy does to the lab queue.

The policy groups alerts by ``(alert_type, source, destination)``, matching the
case study's episode definition. This script does not claim to replay
Alertmanager; it applies the declared group key to the committed snapshot and
reports how many notifications the analyst receives, and which distinct signals
survive.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
ALERTS = REPO_ROOT / "analysis" / "data" / "lab-2026-11-24" / "alerts.jsonl"
OUT_DIR = REPO_ROOT / "analysis" / "out"
OUT_JSON = OUT_DIR / "suppression.json"
OUT_MARKDOWN = OUT_DIR / "suppression.md"

POLICY = REPO_ROOT / "deploy" / "alertmanager" / "ot-inhibit.yml"


def _alerts() -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in ALERTS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def build() -> dict[str, Any]:
    alerts = _alerts()
    groups: dict[tuple[str, str | None, str | None], list[dict]] = defaultdict(list)
    for alert in alerts:
        groups[
            (
                str(alert.get("alert_type")),
                alert.get("source_ip"),
                alert.get("dest_ip"),
            )
        ].append(alert)

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
        "raw_alerts": len(alerts),
        "notifications": len(groups),
        "reduction_pct": round(100 * (1 - len(groups) / len(alerts)), 2) if alerts else 0.0,
        "groups": [
            {
                "alert_type": key[0],
                "source_ip": key[1],
                "dest_ip": key[2],
                "alerts": len(rows),
            }
            for key, rows in sorted(groups.items(), key=lambda item: (item[0][0], item[0][1] or ""))
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
        "The grouping key is `(alert_type, source, destination)`, the same key as",
        "the case study's 60-second episode. A new source or destination is a new",
        "group; the sensor-health and process-safety events are not in an inhibit",
        "rule.",
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
