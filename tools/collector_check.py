"""Prove that real collector output fires the Sigma rules.

The rules run on the telemetry contract (docs/TELEMETRY.md), but until now
nothing in the repository produced that contract from a real sensor: the only
events were hand-written fixtures or the decoders' raw JSON. This runner closes
the loop. It normalizes committed sensor samples -- Suricata ``eve.json`` and
Zeek ``modbus.log``/``dnp3.log``, captured from the repository's own PCAPs --
validates every event against ``metadata/telemetry.schema.json``, routes the
events through the same pySigma matcher the rule tests use, and asserts that the
rules fired match ``tools/otde/evidence.py``.

It needs no SIEM and no container, so CI performs it directly; the committed
evidence is guarded by ``tests/test_collector_evidence.py``.

Usage:
    python tools/collector_check.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import yaml  # noqa: E402
from sigma.rule import SigmaRule  # noqa: E402

from collector import contract  # noqa: E402
from collector.sources import suricata, zeek  # noqa: E402
from tools.otde.evidence import EXPECTED_COLLECTOR_RULES  # noqa: E402
from tools.otde.matcher import match  # noqa: E402
from tools.otde.rules import sigma_rule_paths  # noqa: E402

SAMPLES_DIR = REPO_ROOT / "collector" / "samples"
EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence" / "collector"
EVIDENCE_PATH = EVIDENCE_DIR / "summary.json"

ADAPTERS = {"suricata": suricata, "zeek": zeek}

# Sample key -> (sensor, input files relative to collector/samples).
SAMPLES: dict[str, tuple[str, list[str]]] = {
    "suricata/modbus_attack": ("suricata", ["suricata/modbus_attack.eve.json"]),
    "suricata/modbus_benign": ("suricata", ["suricata/modbus_benign.eve.json"]),
    "suricata/dnp3_attack": ("suricata", ["suricata/dnp3_attack.eve.json"]),
    "suricata/dnp3_benign": ("suricata", ["suricata/dnp3_benign.eve.json"]),
    "zeek/modbus_attack": ("zeek", ["zeek/modbus_attack.modbus.log"]),
    "zeek/modbus_benign": ("zeek", ["zeek/modbus_benign.modbus.log"]),
    "zeek/dnp3_attack": ("zeek", ["zeek/dnp3_attack.dnp3.log"]),
    "zeek/dnp3_benign": ("zeek", ["zeek/dnp3_benign.dnp3.log"]),
}


def _single_event_rules() -> dict[str, list[SigmaRule]]:
    """Rules keyed by logsource service, excluding correlation rules.

    Correlation rules are evaluated over event sequences, not by this per-event
    proof, so they are skipped here without depending on the correlation tooling.
    """
    by_service: dict[str, list[SigmaRule]] = {}
    for path in sigma_rule_paths():
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "correlation" in data:
            continue
        rule = SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
        by_service.setdefault(rule.logsource.service, []).append(rule)
    return by_service


def evaluate() -> dict[str, dict]:
    rules = _single_event_rules()
    summary: dict[str, dict] = {}
    for key, (sensor, files) in SAMPLES.items():
        paths = [SAMPLES_DIR / name for name in files]
        events = list(ADAPTERS[sensor].events(paths))
        schema_errors = [error for event in events for error in contract.schema_errors(event)]
        observed = {
            rule.title
            for event in events
            for rule in rules.get(event["service"], [])
            if match(rule, event)
        }
        summary[key] = {
            "sensor": sensor,
            "inputs": files,
            "events": len(events),
            "expected": sorted(EXPECTED_COLLECTOR_RULES[key]),
            "observed": sorted(observed),
            "schema_errors": schema_errors,
        }
    return summary


def main() -> int:
    summary = evaluate()
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    failures: list[str] = []
    for key, entry in summary.items():
        if entry["schema_errors"]:
            failures.append(f"{key}: {len(entry['schema_errors'])} schema error(s)")
        if entry["observed"] != entry["expected"]:
            failures.append(
                f"{key}: expected {entry['expected']}, observed {entry['observed']}"
            )

    if failures:
        print("collector validation failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    events = sum(entry["events"] for entry in summary.values())
    validated = sum(len(entry["expected"]) for entry in summary.values())
    print(
        f"collector validation passed: {events} events across {len(summary)} samples, "
        f"{validated} rule firings"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
