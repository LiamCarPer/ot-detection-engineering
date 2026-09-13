"""Unit tests for the pySigma-based event matcher.

These tests pin the semantics of the test harness itself. If the matcher is
wrong, the rule tests are meaningless, so its behaviour is specified explicitly
here with small synthetic rules.
"""

from __future__ import annotations

import pytest
from sigma.rule import SigmaRule
from support.sigma_matcher import UnsupportedFeatureError, match

_RULE_TEMPLATE = """
title: {title}
id: {uuid}
status: test
description: matcher unit test
logsource:
  product: test
detection:
{detection}
level: low
author: test
date: 2026-09-13
"""

_UUIDS = {
    "equality": "00000000-0000-0000-0000-000000000001",
    "contains": "00000000-0000-0000-0000-000000000002",
    "regex": "00000000-0000-0000-0000-000000000003",
    "cased": "00000000-0000-0000-0000-000000000004",
    "cidr": "00000000-0000-0000-0000-000000000005",
    "numeric": "00000000-0000-0000-0000-000000000006",
    "exists": "00000000-0000-0000-0000-000000000007",
    "keyword": "00000000-0000-0000-0000-000000000008",
    "fieldref": "00000000-0000-0000-0000-000000000009",
}


def _rule(name: str, detection: str) -> SigmaRule:
    return SigmaRule.from_yaml(
        _RULE_TEMPLATE.format(title=name, uuid=_UUIDS[name], detection=detection)
    )


def test_equality_and_list_is_or() -> None:
    detection = "  selection:\n    code:\n      - 6\n      - 16\n  condition: selection"
    rule = _rule("equality", detection)
    assert match(rule, {"code": 6})
    assert match(rule, {"code": 16})
    assert not match(rule, {"code": 3})
    assert not match(rule, {})


def test_string_equality_is_case_insensitive_by_default() -> None:
    rule = _rule("equality", "  selection:\n    zone: IT\n  condition: selection")
    assert match(rule, {"zone": "it"})
    assert match(rule, {"zone": "It"})


def test_contains_startswith_endswith() -> None:
    rule = _rule(
        "contains",
        "  selection:\n"
        "    msg|contains: verify\n"
        "    src_ip|startswith: 172.24.\n"
        "    path|endswith: .exe\n"
        "  condition: selection",
    )
    assert match(rule, {"msg": "please verify now", "src_ip": "172.24.0.10", "path": "x.exe"})
    assert not match(rule, {"msg": "nope", "src_ip": "172.24.0.10", "path": "x.exe"})
    assert not match(rule, {"msg": "verify", "src_ip": "10.0.0.1", "path": "x.exe"})


def test_regex_is_unanchored_search() -> None:
    rule = _rule("regex", "  selection:\n    detail|re: 'exception.*code'\n  condition: selection")
    assert match(rule, {"detail": "modbus exception 0x02 code"})
    assert not match(rule, {"detail": "no match here"})


def test_cased_is_case_sensitive() -> None:
    rule = _rule("cased", "  selection:\n    user|cased: Admin\n  condition: selection")
    assert match(rule, {"user": "Admin"})
    assert not match(rule, {"user": "admin"})


def test_cidr_membership() -> None:
    rule = _rule("cidr", "  selection:\n    src_ip|cidr: 172.24.0.0/24\n  condition: selection")
    assert match(rule, {"src_ip": "172.24.0.10"})
    assert not match(rule, {"src_ip": "172.21.0.10"})
    assert not match(rule, {"src_ip": "not-an-ip"})


def test_numeric_comparison() -> None:
    rule = _rule("numeric", "  selection:\n    level|gte: 90\n  condition: selection")
    assert match(rule, {"level": 98})
    assert match(rule, {"level": 90})
    assert not match(rule, {"level": 42})
    assert not match(rule, {"level": "not-a-number"})


def test_exists_and_missing_field() -> None:
    rule = _rule("exists", "  selection:\n    value|exists: true\n  condition: selection")
    assert match(rule, {"value": 0})
    assert not match(rule, {})


def test_keyword_detection_searches_all_values() -> None:
    rule = _rule("keyword", "  keywords:\n    - malicious\n  condition: keywords")
    assert match(rule, {"message": "this is malicious traffic", "src_ip": "10.0.0.1"})
    assert match(rule, {"nested": {"detail": "MALICIOUS"}})
    assert not match(rule, {"message": "benign"})


def test_unsupported_feature_raises() -> None:
    rule = _rule("fieldref", "  selection:\n    dst|fieldref: src\n  condition: selection")
    with pytest.raises(UnsupportedFeatureError):
        match(rule, {"src": "10.0.0.1", "dst": "10.0.0.1"})
