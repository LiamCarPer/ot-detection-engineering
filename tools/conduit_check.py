"""Prove the conduit rules against committed telemetry.

The rules in ``rules/conduit`` flag traffic that violates the intended
segmentation in ``metadata/ot-conduit-policy.yaml``. This runner evaluates every
conduit rule against every committed sample, asserts the firings against
``tools/otde/evidence.py``, and records which declared conduits were observed
and which were not — the drift signal that a documented path is unused.

It needs no SIEM and no container, so CI performs it directly; the committed
evidence is guarded by ``tests/test_conduit_evidence.py``.

Usage:
    python tools/conduit_check.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.collector_check import ADAPTERS, SAMPLES, SAMPLES_DIR  # noqa: E402
from tools.otde.conduit import (  # noqa: E402
    load_conduit_rule,
    load_policy,
    match_conduit,
    observed_conduits,
    unused_conduits,
)
from tools.otde.evidence import EXPECTED_CONDUIT_RULES  # noqa: E402

CONDUIT_RULES_DIR = REPO_ROOT / "rules" / "conduit"
EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence" / "conduit"
EVIDENCE_PATH = EVIDENCE_DIR / "summary.json"


def _rules() -> list[dict]:
    return [
        load_conduit_rule(path)
        for path in sorted(CONDUIT_RULES_DIR.glob("*.yml"))
        if ".test." not in path.name
    ]


def evaluate() -> dict:
    policy = load_policy()
    rules = _rules()

    samples: dict[str, dict] = {}
    all_events: list[dict] = []
    for key, (sensor, files) in SAMPLES.items():
        events = list(ADAPTERS[sensor].events([SAMPLES_DIR / name for name in files]))
        all_events.extend(events)
        observed = {
            rule["title"]
            for event in events
            for rule in rules
            if match_conduit(rule, event, policy)
        }
        samples[key] = {
            "events": len(events),
            "expected": sorted(EXPECTED_CONDUIT_RULES[key]),
            "observed": sorted(observed),
        }

    return {
        "zones": [zone["name"] for zone in policy["zones"]],
        "declared_conduits": [[c["from"], c["to"]] for c in policy["conduits"]],
        "observed_conduits": sorted([list(pair) for pair in observed_conduits(policy, all_events)]),
        "unused_conduits": unused_conduits(policy, all_events),
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
    if not evidence["observed_conduits"]:
        failures.append("no declared conduit was observed; the policy or samples are wrong")
    for key, entry in evidence["samples"].items():
        if entry["observed"] != entry["expected"]:
            failures.append(f"{key}: expected {entry['expected']}, observed {entry['observed']}")

    if failures:
        print("conduit validation failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(
        f"conduit validation passed: {len(evidence['rules'])} rules, "
        f"{len(evidence['observed_conduits'])} observed conduits, "
        f"{len(evidence['unused_conduits'])} declared but unused"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
