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
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaRule

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

from baseline.build import build as build_baseline  # noqa: E402
from collector.contract import event as contract_event  # noqa: E402
from collector.sources import suricata, zeek  # noqa: E402
from tools.otde.baseline import load_baseline_rule, match_baseline  # noqa: E402
from tools.otde.rules import (  # noqa: E402
    SIGMA_RULES_DIR,
    baseline_rule_paths,  # noqa: E402
    single_event_rule_paths,
    stateful_rule_paths,
)

OUT_DIR = REPO_ROOT / "deploy" / "evidence" / "benign-lab"
SUMMARY = OUT_DIR / "summary.json"
REPORT = OUT_DIR / "report.md"
RULES = REPO_ROOT / "deploy" / "suricata" / "ot-detection.rules"
SURICATA_IMAGE = (
    "jasonish/suricata@sha256:3656d09b39e85b3a438b13fe32883ae04743ef86b72e594f45b52c6154edf5c9"
)
ZEEK_IMAGE = (
    "zeek/zeek@sha256:70733f4e540ba1608e37e00c6a93d009f79734262c9ec2ba09d90aa9abc16de5"
)


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
        # The gateway capture has checksum offload; without this Suricata can
        # discard packets that Zeek would otherwise reassemble.
        "--set", "stream.checksum-validation=no",
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
    # The capture comes from a virtual gateway with checksum offload. Without
    # -C Zeek discards those packets and splits connections; on the pilot this
    # inflated the flow count from 5,881 to 13,949. Loading the OT analyzers
    # gives us modbus.log/dnp3.log, not just conn.log.
    script = out / "local.zeek"
    script.write_text(
        "@load base/protocols/modbus\n@load base/protocols/dnp3\n", encoding="utf-8"
    )
    command = [
        "docker", "run", "--rm",
        "-v", f"{pcap.parent}:/pcap:ro",
        "-v", f"{out}:/out",
        "-w", "/out",
        ZEEK_IMAGE,
        "zeek", "-C", "-r", f"/pcap/{pcap.name}", "/out/local.zeek",
    ]
    subprocess.run(command, check=True, capture_output=True, text=True)  # nosec B603


TSHARK_FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "mbtcp.trans_id",
    "mbtcp.unit_id",
    "modbus.func_code",
    "modbus.reference_num",
    "modbus.word_cnt",
    "modbus.regval_uint16",
    "modbus.exception_code",
)


def _tshark_modbus(pcap: Path) -> list[dict[str, Any]]:
    """Decode Modbus/TCP with the Wireshark dissector.

    Zeek's ``modbus.log`` has direction and function but no register or
    quantity, so the block-read and enumeration rules cannot be evaluated from
    it. ``tshark`` exposes the reference number, word count, values and
    exception code, which is what the Sigma rules need.
    """
    if not shutil.which("tshark"):
        return []
    command = [
        "tshark", "-n", "-r", str(pcap), "-Y", "modbus", "-T", "fields",
        "-E", "separator=\t",
    ]
    for field in TSHARK_FIELDS:
        command.extend(["-e", field])
    result = subprocess.run(  # nosec B603 - fixed command, local file
        command, capture_output=True, text=True, check=True
    )
    events: list[dict[str, Any]] = []
    for line in result.stdout.splitlines():
        columns = line.split("\t")
        if len(columns) != len(TSHARK_FIELDS) or not columns[0] or not columns[2]:
            continue
        row = dict(zip(TSHARK_FIELDS, columns, strict=True))
        function = _int(row.get("modbus.func_code"))
        if function is None:
            continue
        exception = _int(row.get("modbus.exception_code"))
        # tshark can report the exception function code (0x80|FC). The contract
        # keeps the base function and the exception code separate.
        if function >= 0x80:
            function -= 0x80
        direction = "response" if _int(row.get("tcp.srcport")) == 502 else "request"
        values = [
            int(value)
            for value in (row.get("modbus.regval_uint16") or "").split(",")
            if value.strip().isdigit()
        ]
        events.append(
            contract_event(
                "ot_ndr",
                "modbus",
                float(row["frame.time_epoch"]),
                direction=direction,
                src_ip=row.get("ip.src"),
                dst_ip=row.get("ip.dst"),
                src_port=_int(row.get("tcp.srcport")),
                dst_port=_int(row.get("tcp.dstport")),
                transaction_id=_int(row.get("mbtcp.trans_id")),
                unit_id=_int(row.get("mbtcp.unit_id")),
                function_code=function,
                register=_int(row.get("modbus.reference_num")),
                quantity=_int(row.get("modbus.word_cnt")),
                values=values or None,
                exception_code=exception,
            )
        )
    return events


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _normalized_events(
    suricata_dir: Path, zeek_dir: Path, pcap: Path
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    eve = suricata_dir / "eve.json"
    if eve.exists():
        events.extend(suricata.events([eve]))
    # conn.log is the flow baseline; dnp3.log carries the DNP3 function. Modbus
    # comes from tshark when it is available because Zeek omits register and
    # quantity; the Zeek log is the fallback.
    logs = [zeek_dir / "conn.log", zeek_dir / "dnp3.log"]
    modbus = _tshark_modbus(pcap)
    if modbus:
        events.extend(modbus)
    else:
        logs.append(zeek_dir / "modbus.log")
    existing = [path for path in logs if path.exists()]
    events.extend(zeek.events(existing))
    return events


def _rule_inputs(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Per-rule logsource input, so a vacuous zero is labelled as such."""
    counts = Counter((event.get("product"), event.get("service")) for event in events)
    rules: dict[str, Any] = {}
    for path in single_event_rule_paths():
        rule = SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
        product = rule.logsource.product
        service = rule.logsource.service
        available = counts.get((product, service), 0)
        rules[path.relative_to(REPO_ROOT).as_posix()] = {
            "product": product,
            "service": service,
            "events": available,
            "exercised": available > 0,
        }
    missing = [name for name, entry in rules.items() if not entry["exercised"]]
    return {
        "rules": rules,
        "total": len(rules),
        "with_input": len(rules) - len(missing),
        "without_input": missing,
    }


def _correlation_inputs(
    counts: Counter, collection: SigmaCollection
) -> dict[str, Any]:
    rules: dict[str, Any] = {}
    for rule in collection.rules:
        if not isinstance(rule, SigmaCorrelationRule):
            continue
        services = {
            (reference.rule.logsource.product, reference.rule.logsource.service)
            for reference in rule.referenced_rules
            if reference.rule is not None
        }
        available = sum(counts.get(key, 0) for key in services)
        rules[Path(rule.source.path).stem] = {
            "services": sorted(f"{product}/{service}" for product, service in services),
            "events": available,
            "exercised": available > 0,
        }
    return {
        "rules": rules,
        "total": len(rules),
        "with_input": sum(1 for entry in rules.values() if entry["exercised"]),
    }


def _stateful_inputs(events: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter((event.get("product"), event.get("service")) for event in events)
    rules: dict[str, Any] = {}
    for path in stateful_rule_paths():
        document = yaml.safe_load(path.read_text(encoding="utf-8"))["stateful"]
        products = document.get("products") or [document.get("product")]
        services = document.get("services")
        if services:
            available = sum(
                counts.get((product, service), 0)
                for product in products
                for service in services
            )
        else:
            available = sum(
                count
                for (product, _service), count in counts.items()
                if product in products
            )
        rules[path.stem] = {
            "products": [product for product in products if product],
            "services": services or [],
            "events": available,
            "exercised": available > 0,
        }
    return {"rules": rules, "total": len(rules)}


def _lab_baseline(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Learn the baseline from the first slice and test on the rest.

    The committed baseline was learned from the generated seed. Run against a
    different environment it flags every asset and pair as new — a domain shift,
    not a false positive. The meaningful measure is a baseline learned on an
    early benign window and tested on the remainder.
    """
    moments = []
    for event in events:
        value = event.get("timestamp")
        if not isinstance(value, str):
            continue
        try:
            moments.append(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            continue
    if len(moments) < 2:
        return {"events": 0, "per_rule": {}, "exercised": False}
    first, last = min(moments), max(moments)
    span = (last - first).total_seconds()
    train_seconds = min(7200.0, span * 0.2)
    split = first + timedelta(seconds=train_seconds)
    train = []
    test = []
    for event in events:
        value = event.get("timestamp")
        if not isinstance(value, str):
            continue
        try:
            moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            continue
        (train if moment <= split else test).append(event)
    learned = build_baseline(train, ["lab-capture:training-window"])
    rules = [load_baseline_rule(path) for path in baseline_rule_paths()]
    per_rule = {rule["title"]: 0 for rule in rules}
    matched = 0
    for event in test:
        hit = False
        for rule in rules:
            if match_baseline(rule, event, learned):
                per_rule[rule["title"]] += 1
                hit = True
        if hit:
            matched += 1
    return {
        "training_seconds": round(train_seconds, 1),
        "training_events": len(train),
        "test_events": len(test),
        "events": matched,
        "per_rule": per_rule,
        "exercised": len(test) > 0,
    }


def _coverage(events: list[dict[str, Any]]) -> dict[str, Any]:
    counts = Counter((event.get("product"), event.get("service")) for event in events)
    collection = SigmaCollection.load_ruleset([SIGMA_RULES_DIR])
    ndr = sum(
        count
        for (product, _service), count in counts.items()
        if product == "ot_ndr"
    )
    firewall = sum(
        count
        for (product, _service), count in counts.items()
        if product == "ot_firewall"
    )
    return {
        "by_service": {
            f"{product}/{service}": count
            for (product, service), count in sorted(counts.items(), key=lambda item: -item[1])
        },
        "sigma_single_event": _rule_inputs(events),
        "sigma_correlation": _correlation_inputs(counts, collection),
        "stateful": _stateful_inputs(events),
        "baseline": {
            "product": "ot_ndr",
            "events": ndr,
            "exercised": ndr > 0,
        },
        "conduit": {
            "product": "ot_firewall",
            "events": firewall,
            "exercised": firewall > 0,
        },
    }


def _observed_span(
    events: list[dict[str, Any]],
) -> tuple[float, float | None, str | None, str | None]:
    moments = []
    for event in events:
        value = event.get("timestamp")
        if not isinstance(value, str):
            continue
        try:
            moments.append(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            continue
    if len(moments) < 2:
        return 0.0, None, None, None
    first, last = min(moments), max(moments)
    span = (last - first).total_seconds()
    return (
        span,
        round(len(events) / (span / 3600), 2) if span else None,
        first.isoformat(),
        last.isoformat(),
    )


def build(pcap: Path, events_out: Path | None = None) -> dict[str, Any]:
    work = Path(tempfile.mkdtemp(prefix="otde-benign-lab-"))
    local = work / "capture.pcap"
    shutil.copyfile(pcap, local)

    suricata_records = _run_suricata(local, work / "suricata")
    _run_zeek(local, work / "zeek")
    alerts = [
        record for record in suricata_records if record.get("event_type") == "alert"
    ]
    events = _normalized_events(work / "suricata", work / "zeek", local)
    coverage = _coverage(events)
    lab_baseline = _lab_baseline(events)

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
    span, per_hour, first_event, last_event = _observed_span(events)
    if events_out:
        events_out.write_text(
            "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
            encoding="utf-8",
        )
    # The 24-hour run copies a ~1 GB capture; leaving it behind fills /tmp.
    shutil.rmtree(work, ignore_errors=True)
    return {
        "schema_version": 1,
        "capture": {
            "path": str(pcap),
            "sha256": _sha256(pcap),
            "bytes": pcap.stat().st_size,
            "analyzed_at": datetime.now(UTC).isoformat(),
        },
        "window": {
            "first_event_at": first_event,
            "last_event_at": last_event,
            "span_seconds": round(span, 3),
        },
        "events": len(events),
        "events_per_hour": per_hour,
        "suricata_alerts": len(alerts),
        "coverage": coverage,
        "lab_baseline": lab_baseline,
        "families": families,
    }


def render(report: dict[str, Any]) -> str:
    f = report["families"]
    c = report["coverage"]
    lines = [
        "# Lab benign capture",
        "",
        f"Capture: `{report['capture']['path']}`  ",
        f"SHA-256: `{report['capture']['sha256']}`  ",
        f"Size: {report['capture']['bytes']:,} bytes  ",
        f"Window: {report['window']['first_event_at']} to "
        f"{report['window']['last_event_at']} "
        f"({report['window']['span_seconds'] / 3600:.2f} h)  ",
        f"Normalized events: {report['events']:,} "
        f"({report['events_per_hour']} / h)",
        "",
        "| Family | Result | Input |",
        "| :-- | :-- | :-- |",
        f"| Sigma single-event | "
        f"{f['sigma_single_event']['false_positive_events']} / {report['events']} events | "
        f"{c['sigma_single_event']['with_input']} / {c['sigma_single_event']['total']} rules |",
        f"| Sigma correlation | {len(f['sigma_correlation']['fired'])} fired | "
        f"{c['sigma_correlation']['with_input']} / {c['sigma_correlation']['total']} rules |",
        f"| Committed baseline (domain shift) | "
        f"{f['baseline']['false_positive_events']} events | "
        f"{'yes' if c['baseline']['exercised'] else 'no NDR events'} |",
        f"| Lab-trained baseline | {report['lab_baseline']['events']} / "
        f"{report['lab_baseline']['test_events']} test events | "
        f"train {report['lab_baseline']['training_events']} |",
        f"| Conduit | {f['conduit']['false_positive_events']} events | "
        f"{'yes' if c['conduit']['exercised'] else 'no firewall events'} |",
        f"| Stateful | {len(f['stateful']['fired'])} fired | "
        f"{sum(1 for r in c['stateful']['rules'].values() if r['exercised'])} / "
        f"{c['stateful']['total']} rules |",
        f"| Native Suricata | {f['native']['false_positive_alerts']} alerts | "
        "protocols present |",
        "| Host/auth/PLC/health | not observed in a network capture | n/a |",
        "",
        "## Input coverage",
        "",
        "| Service | Events |",
        "| :-- | --: |",
    ]
    for service, count in c["by_service"].items():
        lines.append(f"| {service} | {count:,} |")
    missing = c["sigma_single_event"]["without_input"]
    lines += [
        "",
        f"Sigma single-event: **{c['sigma_single_event']['with_input']} / "
        f"{c['sigma_single_event']['total']}** rules had events from their own "
        "logsource.",
    ]
    if missing:
        lines.append("")
        lines.append(
            "Not exercised (zero events from their logsource, so a zero is not a "
            "measurement):"
        )
        for name in missing:
            lines.append(f"- `{name}`")
    unexercised_correlation = [
        name
        for name, entry in c["sigma_correlation"]["rules"].items()
        if not entry["exercised"]
    ]
    if unexercised_correlation:
        lines += ["", "Correlation rules without referenced-service input: " + ", ".join(
            f"`{name}`" for name in unexercised_correlation
        )]
    lines += [
        "",
        "## Baseline",
        "",
        f"The committed baseline flags {f['baseline']['false_positive_events']:,} events: "
        "it was learned from the generated seed and the lab's assets and pairs are "
        "new to it. That is a domain shift, not a false-positive rate.",
        "",
        f"A baseline learned on the first "
        f"{report['lab_baseline']['training_seconds'] / 60:.0f} minutes "
        f"({report['lab_baseline']['training_events']:,} events) and tested on the "
        f"remaining {report['lab_baseline']['test_events']:,} flags "
        f"**{report['lab_baseline']['events']}** events.",
    ]
    if not c["conduit"]["exercised"]:
        lines += [
            "",
            "Conduit and firewall families are **not exercised**: the capture has "
            "packets, not the gateway's iptables log records.",
        ]
    lines += [
        "",
        "## Native alerts",
        "",
    ]
    signatures = f["native"]["signatures"]
    lines.extend(f"- {signature}" for signature in signatures) if signatures else lines.append(
        "- none"
    )
    fired = [
        (rule, count)
        for family in ("sigma_single_event", "baseline", "conduit")
        for rule, count in f[family]["per_rule"].items()
        if count
    ]
    lines += ["", "## Rules with any match", ""]
    if fired:
        lines.extend(f"- `{rule}`: {count}" for rule, count in fired)
    else:
        lines.append("- none")
    lines += [
        "",
        "This is real lab background traffic, not a plant. Host, auth, PLC, health",
        "and firewall families are measured on their own committed samples, not here.",
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
