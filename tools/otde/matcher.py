"""Evaluate a parsed Sigma rule against a normalized event.

This is a validation tool, not a detection engine. It exists so that every rule
in ``rules/sigma`` can be proven to fire on a labeled positive event and stay
quiet on a labeled negative event without deploying a SIEM. The test suite uses
it for rule regression and the metrics layer uses it to estimate false-positive
behaviour on benign telemetry.

The matcher deliberately builds on pySigma's own parser and post-processor
(``SigmaRule`` / ``SigmaCondition``) rather than re-reading YAML. pySigma is
responsible for condition parsing, detection linking and modifier application;
this module only interprets the resulting tree. Interpretation covers the
feature subset used in this repository and raises ``UnsupportedFeatureError`` on
anything else, so a rule using an unimplemented feature fails loudly instead of
passing a test it never really exercised.

Supported: field equality, lists (OR within a field), ``contains``,
``startswith``, ``endswith``, ``re``, ``cased``, ``all``, ``cidr``, ``gt``,
``gte``, ``lt``, ``lte``, ``neq``, ``exists``, ``null``, boolean, numeric,
keyword (value-only) detections, and ``and`` / ``or`` / ``not`` conditions.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
    SigmaCondition,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
)


class UnsupportedFeatureError(RuntimeError):
    """Raised when a rule uses a Sigma feature this test harness cannot evaluate."""


def match(rule: SigmaRule, event: Mapping[str, Any]) -> bool:
    """Return True if ``event`` satisfies ``rule``."""
    conditions = rule.detection.condition
    if not conditions:
        raise UnsupportedFeatureError(f"rule '{rule.title}' has no condition")
    return any(
        _eval_condition(SigmaCondition(condition, rule.detection).parsed, event)
        for condition in conditions
    )


def _eval_condition(node: Any, event: Mapping[str, Any]) -> bool:
    if node is None:
        return False
    if isinstance(node, ConditionAND):
        return all(_eval_condition(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_eval_condition(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _eval_condition(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _eval_field(event, node.field, node.value)
    if isinstance(node, ConditionValueExpression):
        return _eval_keyword(event, node.value)
    raise UnsupportedFeatureError(f"unsupported condition node: {type(node).__name__}")


def _eval_field(event: Mapping[str, Any], field: str, value: Any) -> bool:
    actual = _lookup(event, field)
    return _value_matches(value, actual)


def _lookup(event: Mapping[str, Any], field: str) -> Any:
    if field in event:
        return event[field]
    if "." in field:
        node: Any = event
        for part in field.split("."):
            if not isinstance(node, Mapping) or part not in node:
                return None
            node = node[part]
        return node
    return None


def _eval_keyword(event: Mapping[str, Any], value: Any) -> bool:
    """A value-only detection matches if any scalar in the event contains it."""
    for candidate in _scalars(event):
        if candidate is None:
            continue
        if isinstance(value, SigmaString):
            if _contains_string(value, candidate):
                return True
        elif _value_matches(value, candidate):
            return True
    return False


def _contains_string(value: SigmaString, candidate: Any) -> bool:
    """Keyword semantics: the value has to appear anywhere in the candidate."""
    pattern = str(value)
    haystack = str(candidate)
    case_sensitive = isinstance(value, SigmaCasedString)
    flags = 0 if case_sensitive else re.IGNORECASE
    if value.contains_special():
        return re.search(_wildcard_to_regex(pattern), haystack, flags=flags) is not None
    if case_sensitive:
        return pattern in haystack
    return pattern.lower() in haystack.lower()


def _scalars(node: Any) -> list[Any]:
    if isinstance(node, Mapping):
        out: list[Any] = []
        for value in node.values():
            out.extend(_scalars(value))
        return out
    if isinstance(node, (list, tuple)):
        out = []
        for value in node:
            out.extend(_scalars(value))
        return out
    return [node]


def _value_matches(value: Any, actual: Any) -> bool:
    if isinstance(value, SigmaNull):
        return actual is None
    if isinstance(value, SigmaExists):
        return (actual is not None) == value.exists
    if isinstance(value, SigmaBool):
        return _coerce_bool(actual) == value.boolean
    if isinstance(value, SigmaNumber):
        return _coerce_number(actual) == value.number
    if isinstance(value, SigmaCompareExpression):
        return _compare(value, actual)
    if isinstance(value, SigmaCIDRExpression):
        return _match_cidr(value, actual)
    if isinstance(value, SigmaRegularExpression):
        return _match_regex(value, actual)
    if isinstance(value, SigmaFieldReference):
        raise UnsupportedFeatureError("field-reference comparisons are not supported")
    if isinstance(value, SigmaString):
        return _match_string(value, actual)
    raise UnsupportedFeatureError(f"unsupported value type: {type(value).__name__}")


def _coerce_bool(actual: Any) -> bool | None:
    if isinstance(actual, bool):
        return actual
    if isinstance(actual, str):
        lowered = actual.strip().lower()
        if lowered in {"true", "yes"}:
            return True
        if lowered in {"false", "no"}:
            return False
    return None


def _coerce_number(actual: Any) -> float | None:
    if isinstance(actual, bool) or actual is None:
        return None
    if isinstance(actual, (int, float)):
        return float(actual)
    if isinstance(actual, str):
        try:
            return float(actual.strip())
        except ValueError:
            return None
    return None


def _compare(value: SigmaCompareExpression, actual: Any) -> bool:
    left = _coerce_number(actual)
    right = _coerce_number(getattr(value.number, "number", value.number))
    if left is None or right is None:
        return False
    op = value.op.name
    return {
        "LT": left < right,
        "LTE": left <= right,
        "GT": left > right,
        "GTE": left >= right,
        "NEQ": left != right,
    }[op]


def _match_cidr(value: SigmaCIDRExpression, actual: Any) -> bool:
    if not isinstance(actual, str):
        return False
    try:
        return ipaddress.ip_address(actual.strip()) in value.network
    except ValueError:
        return False


def _match_regex(value: SigmaRegularExpression, actual: Any) -> bool:
    if actual is None:
        return False
    pattern = str(value.regexp)
    flags = re.IGNORECASE if _regex_case_insensitive(value) else 0
    return re.search(pattern, str(actual), flags=flags) is not None


def _regex_case_insensitive(value: SigmaRegularExpression) -> bool:
    return any(flag.name == "I" for flag in getattr(value, "flags", set()))


def _match_string(value: SigmaString, actual: Any) -> bool:
    if actual is None:
        return False
    pattern = str(value)
    case_sensitive = isinstance(value, SigmaCasedString)
    flags = 0 if case_sensitive else re.IGNORECASE
    if value.contains_special():
        regex = _wildcard_to_regex(pattern)
        return re.fullmatch(regex, str(actual), flags=flags) is not None
    left = str(actual)
    return left == pattern if case_sensitive else left.lower() == pattern.lower()


def _wildcard_to_regex(pattern: str) -> str:
    """Translate a Sigma wildcard string into an anchored regular expression."""
    out = []
    for char in pattern:
        if char == "*":
            out.append(".*")
        elif char == "?":
            out.append(".")
        else:
            out.append(re.escape(char))
    return "".join(out)
