"""Structural governance tests for native Suricata rules."""

from __future__ import annotations

from pathlib import Path

import pytest
from support.loader import REPO_ROOT, native_rule_paths, technique_ids
from support.suricata import read_rules

RULE_PATHS = native_rule_paths()
TECHNIQUE_IDS = technique_ids()
SID_MIN = 1000000
SID_MAX = 1000999


def _path_id(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def _all_rules():
    for path in RULE_PATHS:
        yield from read_rules(path)


def test_native_rules_are_discovered() -> None:
    assert RULE_PATHS, "no native rules found under rules/native"


@pytest.mark.parametrize("rule_path", RULE_PATHS, ids=_path_id)
def test_file_contains_rules(rule_path: Path) -> None:
    assert read_rules(rule_path), f"{rule_path} contains no rules"


def test_every_rule_has_required_fields() -> None:
    failures = []
    for rule in _all_rules():
        location = f"{rule.source.name}:{rule.line_number}"
        if rule.action != "alert":
            failures.append(f"{location}: expected an alert rule")
        if rule.sid is None:
            failures.append(f"{location}: missing sid")
        if rule.rev is None:
            failures.append(f"{location}: missing rev")
        if not rule.msg:
            failures.append(f"{location}: missing msg")
        if not rule.classtype:
            failures.append(f"{location}: missing classtype")
        if not rule.attack_ics:
            failures.append(f"{location}: missing attack_ics metadata")
    assert not failures, "\n".join(failures)


def test_attack_ics_metadata_is_known() -> None:
    failures = []
    for rule in _all_rules():
        for technique_id in rule.attack_ics:
            if technique_id not in TECHNIQUE_IDS:
                failures.append(f"{rule.source.name}:{rule.line_number}: {technique_id}")
    assert not failures, "unknown ATT&CK for ICS techniques:\n" + "\n".join(failures)


def test_sids_are_unique_and_in_reserved_range() -> None:
    seen: dict[int, str] = {}
    failures = []
    for rule in _all_rules():
        location = f"{rule.source.name}:{rule.line_number}"
        if rule.sid is None:
            continue
        if not SID_MIN <= rule.sid <= SID_MAX:
            failures.append(f"{location}: sid {rule.sid} outside {SID_MIN}-{SID_MAX}")
        if rule.sid in seen:
            failures.append(f"{location}: sid {rule.sid} already used by {seen[rule.sid]}")
        seen[rule.sid] = location
    assert not failures, "\n".join(failures)
