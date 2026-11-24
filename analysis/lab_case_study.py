"""Reproducible analysis of the lab's alert flood.

The input is a pinned snapshot of the alert logs from OT-Security-Lab. The tool
normalizes the two NDJSON formats, collapses repeated signals into timed
episodes, groups episodes into campaigns by source and time gap, and produces a
deterministic summary, a rule-health seed, and a Markdown report.

It does not call a SIEM, a database or the lab. `--check` fails when the
committed outputs differ from a fresh run, so the case study cannot drift.

Usage:
    python analysis/lab_case_study.py
    python analysis/lab_case_study.py --check
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = REPO_ROOT / "analysis" / "data" / "lab-2026-11-24"
DEFAULT_OUT = REPO_ROOT / "analysis" / "out"

# The lab runs each scenario from a distinct source. These labels are the
# analyst-facing names for the four adversary campaigns and the sensor-health
# event; an unknown source falls back to its address rather than guessing.
SCENARIO_LABELS = {
    "172.24.0.10": "Enterprise pivot and unauthorized Modbus write",
    "172.23.0.20": "Compromised EWS across DNP3, S7comm and OPC UA",
    "172.22.0.30": "Operator-workstation PowerShell write",
    "172.24.0.30": "HMI credential attack",
    "sensor-health": "Detection producer health",
}

EPISODE_WINDOW_SECONDS = 60
CAMPAIGN_GAP_SECONDS = 600


@dataclass(frozen=True)
class Alert:
    timestamp: datetime
    alert_type: str
    source_ip: str | None
    dest_ip: str | None
    technique: str | None
    status: str | None
    severity: str | None
    raw: dict = field(compare=False, repr=False)


@dataclass
class Episode:
    alert_type: str
    source_ip: str | None
    dest_ip: str | None
    first: datetime
    last: datetime
    count: int
    techniques: set[str] = field(default_factory=set)


@dataclass
class Campaign:
    key: str
    label: str
    source_ip: str | None
    episodes: list[Episode] = field(default_factory=list)

    @property
    def first(self) -> datetime:
        return min(episode.first for episode in self.episodes)

    @property
    def last(self) -> datetime:
        return max(episode.last for episode in self.episodes)

    @property
    def raw_alerts(self) -> int:
        return sum(episode.count for episode in self.episodes)

    @property
    def techniques(self) -> set[str]:
        return {technique for episode in self.episodes for technique in episode.techniques}

    @property
    def alert_types(self) -> set[str]:
        return {episode.alert_type for episode in self.episodes}


def parse_timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def load_ndjson(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def normalize_row(row: dict) -> Alert:
    timestamp = row.get("timestamp") or row.get("received_at")
    alert_type = row.get("alert_type") or row.get("alertname")
    if not timestamp or not alert_type:
        raise ValueError(f"alert has no timestamp or type: {row!r}")
    return Alert(
        timestamp=parse_timestamp(timestamp),
        alert_type=str(alert_type),
        source_ip=row.get("source_ip") or row.get("src_ip"),
        dest_ip=row.get("dest_ip") or row.get("dst_ip"),
        technique=row.get("mitre_id"),
        status=row.get("status"),
        severity=row.get("severity"),
        raw=row,
    )


def load_alerts(path: Path) -> list[Alert]:
    return sorted((normalize_row(row) for row in load_ndjson(path)), key=lambda a: a.timestamp)


def verify_snapshot(input_dir: Path) -> dict:
    manifest = json.loads((input_dir / "manifest.json").read_text(encoding="utf-8"))
    for name, meta in manifest["files"].items():
        data = (input_dir / name).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != meta["sha256"]:
            raise ValueError(f"snapshot hash mismatch for {name}: {actual} != {meta['sha256']}")
    return manifest


def source_key(alert: Alert) -> str:
    if alert.source_ip:
        return alert.source_ip
    if alert.alert_type == "DETECTION_SERVICE_DOWN":
        return "sensor-health"
    return "unknown-source"


def build_episodes(
    alerts: list[Alert], window_seconds: int = EPISODE_WINDOW_SECONDS
) -> list[Episode]:
    """Collapse identical signals within a window into one episode.

    The key is (alert_type, source, destination). A repeat after the window is a
    new episode: a sustained campaign over hours must not become one event.
    """
    grouped: dict[tuple[str, str | None, str | None], list[Alert]] = defaultdict(list)
    for alert in alerts:
        grouped[(alert.alert_type, alert.source_ip, alert.dest_ip)].append(alert)

    episodes: list[Episode] = []
    for (alert_type, source_ip, dest_ip), rows in grouped.items():
        rows.sort(key=lambda a: a.timestamp)
        current: Episode | None = None
        for row in rows:
            if current is None or (row.timestamp - current.last).total_seconds() > window_seconds:
                current = Episode(
                    alert_type=alert_type,
                    source_ip=source_ip,
                    dest_ip=dest_ip,
                    first=row.timestamp,
                    last=row.timestamp,
                    count=1,
                )
                episodes.append(current)
            else:
                current.last = row.timestamp
                current.count += 1
            if row.technique:
                current.techniques.add(row.technique)
    return sorted(episodes, key=lambda e: (e.first, e.alert_type))


def build_campaigns(
    episodes: list[Episode], gap_seconds: int = CAMPAIGN_GAP_SECONDS
) -> list[Campaign]:
    by_source: dict[str, list[Episode]] = defaultdict(list)
    for episode in episodes:
        key = episode.source_ip or "sensor-health"
        by_source[key].append(episode)

    campaigns: list[Campaign] = []
    for key, items in by_source.items():
        items.sort(key=lambda e: e.first)
        current: Campaign | None = None
        for episode in items:
            if current is None or (episode.first - current.last).total_seconds() > gap_seconds:
                current = Campaign(
                    key=key,
                    label=SCENARIO_LABELS.get(key, f"Traffic from {key}"),
                    source_ip=episode.source_ip,
                )
                campaigns.append(current)
            current.episodes.append(episode)
    return sorted(campaigns, key=lambda c: c.first)


def _iso(moment: datetime) -> str:
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def summarize(
    alerts: list[Alert],
    episodes: list[Episode],
    campaigns: list[Campaign],
    manifest: dict,
    siem_rows: list[Alert],
    runtime: dict,
) -> dict:
    first = min(a.timestamp for a in alerts)
    last = max(a.timestamp for a in alerts)
    type_counts = Counter(a.alert_type for a in alerts)
    source_counts = Counter(source_key(a) for a in alerts)

    episode_by_type = Counter(episode.alert_type for episode in episodes)
    type_rows = []
    for alert_type, raw in type_counts.most_common():
        eps = episode_by_type.get(alert_type, 0)
        type_rows.append(
            {
                "alert_type": alert_type,
                "raw_alerts": raw,
                "episodes": eps,
                "unique_sources": len(
                    {source_key(a) for a in alerts if a.alert_type == alert_type}
                ),
                "duplicate_ratio": round(1 - _ratio(eps, raw), 4),
                "first_seen": _iso(min(a.timestamp for a in alerts if a.alert_type == alert_type)),
                "last_seen": _iso(max(a.timestamp for a in alerts if a.alert_type == alert_type)),
            }
        )

    campaign_rows = [
        {
            "id": f"C{index}",
            "label": campaign.label,
            "source_ip": campaign.source_ip,
            "first_seen": _iso(campaign.first),
            "last_seen": _iso(campaign.last),
            "duration_seconds": round((campaign.last - campaign.first).total_seconds(), 3),
            "raw_alerts": campaign.raw_alerts,
            "episodes": len(campaign.episodes),
            "alert_types": sorted(campaign.alert_types),
            "techniques": sorted(campaign.techniques),
        }
        for index, campaign in enumerate(campaigns, start=1)
    ]

    siem_status = Counter(row.status or "unknown" for row in siem_rows)
    siem_names = Counter(row.alert_type for row in siem_rows)
    runtime_counts = runtime.get("alerts", {}).get("alert_counts", {})

    return {
        "snapshot": manifest["snapshot"],
        "provenance": {
            "source_repository": manifest["source_repository"],
            "source_commit": manifest["source_commit"],
            "captured_at": manifest["captured_at"],
            "captured_until": manifest["captured_until"],
            "timezone": manifest["timezone"],
        },
        "alerts": {
            "raw": len(alerts),
            "types": len(type_counts),
            "sources": len({a.source_ip for a in alerts if a.source_ip}),
            "first_seen": _iso(first),
            "last_seen": _iso(last),
            "duration_seconds": round((last - first).total_seconds(), 3),
        },
        "episodes": {
            "total": len(episodes),
            "window_seconds": EPISODE_WINDOW_SECONDS,
            "duplicate_ratio": round(1 - _ratio(len(episodes), len(alerts)), 4),
            "by_type": type_rows,
        },
        "campaigns": {
            "total": len(campaigns),
            "alert_to_campaign_ratio": _ratio(len(alerts), len(campaigns)),
            "items": campaign_rows,
        },
        "sources": [
            {
                "source": source,
                "raw_alerts": count,
                "campaigns": sum(1 for c in campaigns if c.key == source),
                "alert_types": sorted({a.alert_type for a in alerts if source_key(a) == source}),
            }
            for source, count in source_counts.most_common()
        ],
        "siem_lifecycle": {
            "rows": len(siem_rows),
            "first_seen": _iso(min(a.timestamp for a in siem_rows)) if siem_rows else None,
            "last_seen": _iso(max(a.timestamp for a in siem_rows)) if siem_rows else None,
            "status": dict(sorted(siem_status.items())),
            "top_alerts": [
                {"alertname": name, "rows": count} for name, count in siem_names.most_common(10)
            ],
        },
        "runtime_totals": {
            "captured_at": runtime.get("captured_at"),
            "alerts": sum(runtime_counts.values()),
            "types": len(runtime_counts),
            "sources": len(runtime.get("alerts", {}).get("distinct_sources", [])),
            "by_type": dict(sorted(runtime_counts.items())),
        },
        "rule_health": type_rows,
    }


def _mermaid_timeline(campaigns: list[dict]) -> str:
    lines = [
        "```mermaid",
        "gantt",
        "    title Lab alert campaigns, 2026-11-24 (UTC)",
        "    dateFormat YYYY-MM-DDTHH:mm:ss",
        "    axisFormat %H:%M:%S",
    ]
    for campaign in campaigns:
        # Mermaid's gantt dateFormat does not accept fractional seconds.
        start = campaign["first_seen"].split(".")[0].rstrip("Z")
        duration = max(1, int(campaign["duration_seconds"]))
        label = campaign["label"].replace(",", " ")
        lines.append(f"    section {campaign['id']}")
        lines.append(f"    {label} :{campaign['id'].lower()}, {start}, {duration}s")
    lines.append("```")
    return "\n".join(lines)


def render_markdown(summary: dict) -> str:
    alerts = summary["alerts"]
    episodes = summary["episodes"]
    campaigns = summary["campaigns"]
    lines = [
        "# Lab alert-flood analysis",
        "",
        "Generated by `analysis/lab_case_study.py` from a pinned lab snapshot. "
        "Do not edit by hand; run `make case-study`.",
        "",
        "## Provenance",
        "",
        "| Field | Value |",
        "| :--- | :--- |",
        f"| Snapshot | `{summary['snapshot']}` |",
        f"| Lab repository | {summary['provenance']['source_repository']} |",
        f"| Lab commit | `{summary['provenance']['source_commit']}` |",
        f"| Captured | {summary['provenance']['captured_at']} → "
        f"{summary['provenance']['captured_until']} |",
        f"| Timezone | {summary['provenance']['timezone']} |",
        "",
        "## At a glance",
        "",
        "| Metric | Value |",
        "| :--- | ---: |",
        f"| Raw alerts | {alerts['raw']} |",
        f"| Alert types | {alerts['types']} |",
        f"| Sources | {alerts['sources']} |",
        f"| Window | {alerts['first_seen']} → {alerts['last_seen']} "
        f"({alerts['duration_seconds']} s) |",
        f"| Episodes ({episodes['window_seconds']} s window) | {episodes['total']} |",
        f"| Duplicate ratio | {episodes['duplicate_ratio']} |",
        f"| Campaigns | {campaigns['total']} |",
        f"| Alerts per campaign | {campaigns['alert_to_campaign_ratio']} |",
        "",
        "## Campaigns",
        "",
        "| ID | Source | Campaign | Raw | Episodes | Techniques | Window (s) |",
        "| :-- | :-- | :-- | --: | --: | :-- | --: |",
    ]
    for campaign in campaigns["items"]:
        lines.append(
            f"| {campaign['id']} | {campaign['source_ip'] or '—'} | {campaign['label']} | "
            f"{campaign['raw_alerts']} | {campaign['episodes']} | "
            f"{', '.join(campaign['techniques']) or '—'} | {campaign['duration_seconds']} |"
        )

    lines += [
        "",
        "## Alert types",
        "",
        "| Alert type | Raw | Episodes | Sources | Duplicate ratio |",
        "| :-- | --: | --: | --: | --: |",
    ]
    for row in episodes["by_type"]:
        lines.append(
            f"| {row['alert_type']} | {row['raw_alerts']} | {row['episodes']} | "
            f"{row['unique_sources']} | {row['duplicate_ratio']} |"
        )

    lines += ["", "## Timeline", "", _mermaid_timeline(campaigns["items"]), ""]

    siem = summary["siem_lifecycle"]
    lines += [
        "## SIEM lifecycle (secondary)",
        "",
        "This is the firing/resolved log, not the 160-second burst. It spans a "
        "different period and is included for alert-lifecycle realism, not for "
        "the campaign count.",
        "",
        "| Metric | Value |",
        "| :--- | ---: |",
        f"| Rows | {siem['rows']} |",
        f"| Window | {siem['first_seen']} → {siem['last_seen']} |",
        f"| Firing / resolved | {siem['status'].get('firing', 0)} / "
        f"{siem['status'].get('resolved', 0)} |",
        "",
        "Top alert names: " + ", ".join(
            f"`{row['alertname']}` ({row['rows']})" for row in siem["top_alerts"]
        ),
        "",
        "## Recorded runtime totals (different run)",
        "",
        "The lab's runtime evidence file is an aggregate from an earlier run, not "
        "the 160-second snapshot. It is cited only as corroboration of scale.",
        "",
        "| Metric | Value |",
        "| :--- | ---: |",
        f"| Captured | {summary['runtime_totals']['captured_at']} |",
        f"| Alerts | {summary['runtime_totals']['alerts']} |",
        f"| Types | {summary['runtime_totals']['types']} |",
        f"| Sources | {summary['runtime_totals']['sources']} |",
        "",
        "## Reproduce",
        "",
        "```bash",
        "make case-study",
        "```",
        "",
        "`--check` fails when this report, the summary or the rule-health seed "
        "differs from a fresh run.",
        "",
    ]
    return "\n".join(lines)


def build(input_dir: Path = DEFAULT_INPUT) -> tuple[dict, str, dict]:
    manifest = verify_snapshot(input_dir)
    alerts = load_alerts(input_dir / "alerts.jsonl")
    siem_rows = load_alerts(input_dir / "siem_alerts.jsonl")
    runtime = json.loads((input_dir / "runtime_evidence.json").read_text(encoding="utf-8"))
    episodes = build_episodes(alerts)
    campaigns = build_campaigns(episodes)
    summary = summarize(alerts, episodes, campaigns, manifest, siem_rows, runtime)
    return summary, render_markdown(summary), {"rules": summary["rule_health"]}


def write_outputs(out_dir: Path, summary: dict, report: str, health: dict) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out_dir / "report.md").write_text(report, encoding="utf-8")
    (out_dir / "rule_health.json").write_text(
        json.dumps(health, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--check", action="store_true", help="Fail if committed outputs drift")
    args = parser.parse_args(argv)

    input_dir = Path(args.input)
    out_dir = Path(args.out)
    summary, report, health = build(input_dir)

    if args.check:
        expected = {
            "summary.json": json.dumps(summary, indent=2, sort_keys=True) + "\n",
            "report.md": report,
            "rule_health.json": json.dumps(health, indent=2, sort_keys=True) + "\n",
        }
        failures = []
        for name, content in expected.items():
            path = out_dir / name
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                failures.append(name)
        if failures:
            print(f"case-study outputs are stale: {', '.join(failures)}")
            return 1
        print("case-study outputs are current")
        return 0

    write_outputs(out_dir, summary, report, health)
    print(
        f"{summary['alerts']['raw']} alerts -> {summary['episodes']['total']} episodes -> "
        f"{summary['campaigns']['total']} campaigns -> {out_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
