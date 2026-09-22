"""Prove the behaviour-baseline rules against committed telemetry.

The behaviour rules in ``rules/baseline`` flag deviations from the learned OT
behaviour baseline. This runner closes the loop the same way ``collector_check``
does: it rebuilds the baseline from the benign samples (proving the committed
artefact is current), then evaluates every baseline rule against every committed
sample and asserts the rules that fired match ``tools/otde/evidence.py``.

It needs no SIEM and no container, so CI performs it directly; the committed
evidence is guarded by ``tests/test_baseline_evidence.py``.

Usage:
    python tools/baseline_check.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from baseline.build import BASELINE_PATH, build, collect  # noqa: E402
from tools.collector_check import ADAPTERS, SAMPLES  # noqa: E402
from tools.otde.baseline import load_baseline, load_baseline_rule, match_baseline  # noqa: E402
from tools.otde.evidence import EXPECTED_BASELINE_RULES  # noqa: E402

SAMPLES_DIR = REPO_ROOT / "collector" / "samples"
BASELINE_RULES_DIR = REPO_ROOT / "rules" / "baseline"
EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence" / "baseline"
EVIDENCE_PATH = EVIDENCE_DIR / "summary.json"

# The baseline is learned from the benign Suricata samples only: a baseline that
# has seen an attack would not flag it.
BENIGN_INPUTS = [
    "collector/samples/suricata/modbus_benign.eve.json",
    "collector/samples/suricata/dnp3_benign.eve.json",
]


def _rules() -> list[dict]:
    return [
        load_baseline_rule(path)
        for path in sorted(BASELINE_RULES_DIR.glob("*.yml"))
        if ".test." not in path.name
    ]


def evaluate() -> dict:
    benign_events, inputs = collect("suricata", BENIGN_INPUTS)
    learned = build(benign_events, inputs)
    committed = load_baseline()
    rules = _rules()

    samples: dict[str, dict] = {}
    for key, (sensor, files) in SAMPLES.items():
        events = list(ADAPTERS[sensor].events([SAMPLES_DIR / name for name in files]))
        observed = {
            rule["title"]
            for event in events
            for rule in rules
            if match_baseline(rule, event, committed)
        }
        samples[key] = {
            "events": len(events),
            "expected": sorted(EXPECTED_BASELINE_RULES[key]),
            "observed": sorted(observed),
        }

    return {
        "baseline_current": learned == committed,
        "baseline": {
            "assets": len(committed["assets"]),
            "pairs": len(committed["pairs"]),
            "services": committed["services"],
        },
        "rules": sorted(rule["title"] for rule in rules),
        "samples": samples,
    }


def main() -> int:
    evidence = evaluate()
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    failures: list[str] = []
    if not evidence["baseline_current"]:
        failures.append(f"committed baseline is stale: regenerate with {BASELINE_PATH.name}")
    for key, entry in evidence["samples"].items():
        if entry["observed"] != entry["expected"]:
            failures.append(f"{key}: expected {entry['expected']}, observed {entry['observed']}")

    if failures:
        print("baseline validation failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    events = sum(entry["events"] for entry in evidence["samples"].values())
    print(
        f"baseline validation passed: {len(evidence['rules'])} rules over {events} events, "
        f"{evidence['baseline']['assets']} baseline assets"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
