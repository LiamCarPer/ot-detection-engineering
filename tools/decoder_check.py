"""Prove that real decoder output drives the repository's Sigma rules.

The Rust decoders and the Sigma rules are tested separately; nothing else
asserts that the events the decoders actually emit satisfy the rules. This
runner decodes every committed example frame with the built decoder, routes each
normalized event through the same pySigma matcher the rule tests use, and
records which rules fired. It fails if the set of rules that fired differs from
``tools/otde/evidence.py``, so a decoder or rule change that breaks the link
fails the run.

CI builds and tests Rust in a separate step, so the run is captured once and the
committed evidence is guarded by ``tests/test_decoder_evidence.py``.

Usage:
    python tools/decoder_check.py
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sigma.rule import SigmaRule  # noqa: E402

from tools.otde.evidence import EXPECTED_DECODER_RULES  # noqa: E402
from tools.otde.matcher import match  # noqa: E402
from tools.otde.rules import sigma_rule_paths  # noqa: E402

TOOLS_DIR = REPO_ROOT / "tools"
EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence" / "decoders"
EVIDENCE_PATH = EVIDENCE_DIR / "summary.json"

# Detection event service -> decoder crate. The service is also the Sigma
# logsource service, which is how the matcher routes an event to its rules.
DECODERS: dict[str, str] = {
    "dnp3": "dnp3-dpi",
    "s7comm": "s7comm-dpi",
    "opcua": "opcua-dpi",
}


def build(cargo: str) -> None:
    subprocess.run(
        [cargo, "build", "--workspace"],
        cwd=TOOLS_DIR,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def rules_for_service(service: str) -> list[SigmaRule]:
    rules = []
    for path in sigma_rule_paths():
        rule = SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
        if rule.logsource.service == service:
            rules.append(rule)
    return rules


def decode(crate: str, service: str) -> list[dict]:
    binary = TOOLS_DIR / "target" / "debug" / crate
    examples = TOOLS_DIR / crate / "examples" / "frames.hex"
    result = subprocess.run(
        [str(binary), str(examples)],
        check=True,
        capture_output=True,
        text=True,
    )
    events = []
    for line in result.stdout.splitlines():
        if line.strip():
            event = json.loads(line)
            # The collector that ships decoder output attaches the logsource
            # routing fields; reproduce that here so the matcher can route.
            events.append({"product": "ot_ndr", "service": service, **event})
    return events


def evaluate(service: str, expected: set[str]) -> dict:
    rules = rules_for_service(service)
    events = decode(DECODERS[service], service)
    observed: set[str] = set()
    unmatched = 0
    for event in events:
        fired = {rule.title for rule in rules if match(rule, event)}
        if fired:
            observed |= fired
        else:
            unmatched += 1
    return {
        "examples": f"tools/{DECODERS[service]}/examples/frames.hex",
        "events": len(events),
        "unmatched_events": unmatched,
        "expected": sorted(expected),
        "observed": sorted(observed),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--no-build", action="store_true", help="Use the existing binaries")
    args = parser.parse_args(argv)

    if not args.no_build:
        build(args.cargo)

    summary = {
        service: evaluate(service, expected)
        for service, expected in EXPECTED_DECODER_RULES.items()
    }
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    failures = []
    for service, entry in summary.items():
        if set(entry["observed"]) != set(entry["expected"]):
            failures.append(
                f"{service}: expected {entry['expected']}, observed {entry['observed']}"
            )
    if failures:
        print("decoder validation failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    total = sum(entry["events"] for entry in summary.values())
    print(f"decoder validation passed: {total} events across {len(summary)} protocols")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
