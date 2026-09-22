"""Offline, narrated end-to-end demo of the detection pipeline.

For each protocol decoder this walks one real committed example frame through
the whole chain: decode it with the dependency-free Rust decoder, show the
normalized event, match it against the Sigma rules with the same pySigma matcher
the tests use, then print the queries generated for each target platform. It
needs no SIEM, no Docker and no network, so it is the fastest way to see the
repository work on a clean checkout.

Usage:
    make demo
    python tools/demo.py
    python tools/demo.py --no-build   # reuse the existing binaries
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
for extra in (REPO_ROOT, REPO_ROOT / "pipelines"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

from convert import BACKENDS  # noqa: E402
from sigma.collection import SigmaCollection  # noqa: E402
from sigma.rule import SigmaRule  # noqa: E402

from tools import decoder_check  # noqa: E402
from tools.otde.matcher import match  # noqa: E402
from tools.otde.rules import single_event_rule_paths  # noqa: E402

RULE_ORDER = ("loki", "splunk", "sentinel", "opensearch")


def rule_paths_by_title() -> dict[str, Path]:
    paths = {}
    # Single-event rules only; the demo walks one event through one rule, and the
    # correlation rule needs a sequence.
    for path in single_event_rule_paths():
        rule = SigmaRule.from_yaml(path.read_text(encoding="utf-8"))
        paths[rule.title] = path
    return paths


def _rule_techniques(rule: SigmaRule) -> str:
    tags = sorted(str(tag).upper() for tag in rule.tags if str(tag).startswith("attack."))
    return ", ".join(tag.removeprefix("ATTACK.") for tag in tags)


def _show_conversions(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    for backend in RULE_ORDER:
        backend_cls, extension = BACKENDS[backend]
        query = backend_cls().convert(SigmaCollection.from_yaml(text))[0]
        print(f"\n  [{backend} .{extension}]")
        for line in query.splitlines():
            print(f"    {line}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--no-build", action="store_true", help="Use the existing binaries")
    args = parser.parse_args(argv)

    if not args.no_build:
        print("building the Rust decoders ...")
        decoder_check.build(args.cargo)

    titles = rule_paths_by_title()
    total_events = 0
    fired: set[str] = set()

    print("\nOT Detection Engineering — decoder -> Sigma rule -> SIEM query")
    print("=" * 68)

    for service, crate in decoder_check.DECODERS.items():
        rules = decoder_check.rules_for_service(service)
        events = decoder_check.decode(crate, service)
        total_events += len(events)
        fired_here = {rule.title for event in events for rule in rules if match(rule, event)}
        fired |= fired_here

        source = f"tools/{crate}/examples/frames.hex"
        print(f"\n## {service}  ({len(events)} decoded events from {source})")
        sample = next(
            (event for event in events if any(match(rule, event) for rule in rules)),
            events[0] if events else None,
        )
        if sample is not None:
            routing = {"product", "service"}
            printable = {key: value for key, value in sample.items() if key not in routing}
            print("  normalized event:")
            for key, value in printable.items():
                print(f"    {key}: {json.dumps(value)}")
        print(f"  rules fired: {', '.join(sorted(fired_here)) or 'none'}")

    print("\n## Generated queries")
    print("=" * 68)
    representative = next(iter(sorted(fired)))
    rule = SigmaRule.from_yaml(titles[representative].read_text(encoding="utf-8"))
    techniques = _rule_techniques(rule)
    print(f"\n{representative}" + (f"  [{techniques}]" if techniques else ""))
    _show_conversions(titles[representative])

    print("\n## Summary")
    print("=" * 68)
    print(f"  protocols decoded : {len(decoder_check.DECODERS)}")
    print(f"  events evaluated  : {total_events}")
    print(f"  distinct rules fired: {len(fired)}")
    for title in sorted(fired):
        print(f"    - {title}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
