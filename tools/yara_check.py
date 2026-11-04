"""Compile and prove the YARA rules against committed artifacts.

YARA is the file/blob layer: PLC project files, firmware images and scripts on an
engineering workstation, which the network detections never see. This runner
compiles every rule in ``rules/yara``, scans each fixture and asserts the
expected match, scans a synthetic protocol payload blob with the same ruleset,
and runs the engine against the EICAR test string assembled in memory.

No real malware is committed; the fixtures are inert marker artifacts (see
``tests/yara/samples/README.md``).

Usage:
    python tools/yara_check.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import yara_x  # noqa: E402

from tools.otde.rules import load_yara_cases, yara_rule_paths  # noqa: E402

EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence" / "yara"
EVIDENCE_PATH = EVIDENCE_DIR / "summary.json"
PAYLOAD = REPO_ROOT / "tests" / "yara" / "samples" / "payloads" / "s7_block_with_pe.bin"
PAYLOAD_EXPECTED = ["OT_S7_Firmware_With_Embedded_PE"]
IDENTIFIER_RE = re.compile(r"^\s*rule\s+(\w+)", re.MULTILINE)


def _identifier(path: Path) -> str:
    match = IDENTIFIER_RE.search(path.read_text(encoding="utf-8"))
    if not match:
        raise ValueError(f"{path} has no rule identifier")
    return match.group(1)


def _compile(sources: list[str]) -> yara_x.Rules:
    return yara_x.compile("\n".join(sources))


def _matches(rules: yara_x.Rules, data: bytes) -> set[str]:
    results = yara_x.Scanner(rules).scan(data)
    return {rule.identifier for rule in results.matching_rules}


def _eicar_selftest() -> bool:
    """Prove the engine detects a recognised malicious signature without malware.

    The EICAR test string is assembled in memory and never written to disk.
    """
    eicar = (
        "X5O!P%@AP[4"
        + "\\"
        + "PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    )
    escaped = eicar.replace("\\", "\\\\")
    source = f'rule EICAR_Test {{ strings: $e = "{escaped}" ascii condition: $e }}'
    return "EICAR_Test" in _matches(_compile([source]), eicar.encode("utf-8"))


def evaluate() -> dict:
    paths = yara_rule_paths()
    rules = _compile([path.read_text(encoding="utf-8") for path in paths])

    rule_rows = []
    for path in paths:
        identifier = _identifier(path)
        cases = []
        for case in load_yara_cases(path):
            expected = case.expect_match
            observed = identifier in _matches(rules, (REPO_ROOT / case.file).read_bytes())
            cases.append(
                {
                    "name": case.name,
                    "file": case.file,
                    "expected": "match" if expected else "no_match",
                    "observed": observed,
                    "passed": observed == expected,
                }
            )
        rule_rows.append(
            {
                "rule": identifier,
                "file": path.relative_to(REPO_ROOT).as_posix(),
                "cases": cases,
            }
        )

    payload_matches = sorted(_matches(rules, PAYLOAD.read_bytes()))
    return {
        "rules": rule_rows,
        "payload_scan": {
            "file": PAYLOAD.relative_to(REPO_ROOT).as_posix(),
            "expected": PAYLOAD_EXPECTED,
            "matches": payload_matches,
            "passed": payload_matches == PAYLOAD_EXPECTED,
        },
        "selftest": {"eicar": _eicar_selftest()},
    }


def main() -> int:
    evidence = evaluate()
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    failures: list[str] = []
    for row in evidence["rules"]:
        for case in row["cases"]:
            if not case["passed"]:
                failures.append(
                    f"{row['rule']}: {case['name']} expected {case['expected']} "
                    f"on {case['file']}"
                )
    if not evidence["payload_scan"]["passed"]:
        failures.append(f"payload scan: {evidence['payload_scan']}")
    if not evidence["selftest"]["eicar"]:
        failures.append("EICAR self-test did not match")

    if failures:
        print("YARA validation failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    cases = sum(len(row["cases"]) for row in evidence["rules"])
    print(
        f"YARA validation passed: {len(evidence['rules'])} rules, {cases} fixtures, "
        "payload scan and EICAR self-test"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
