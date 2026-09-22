"""Evaluate a Sigma correlation rule against a sequence of events.

The single-event matcher in ``tools/otde/matcher.py`` cannot evaluate a
correlation rule: it has no detection block, and its meaning depends on a
window. This module adds the missing half so a correlation rule can be proven
offline, against labeled positive and negative event sequences, in the same way
every single-event rule is proven against its fixture.

Only ``value_count`` correlations are implemented, because that is the only type
the repository uses. Anything else raises ``UnsupportedCorrelationError`` rather
than returning a result the test never really exercised — the same rule the
single-event matcher applies to unimplemented Sigma features.

Semantics implemented: of the events the referenced rules match, group by the
correlation's ``group-by`` fields, count the distinct values of the condition's
field inside a sliding ``timespan`` window, and compare that count with the
condition operator. An event's position in the window comes from its
``timestamp``; an event without one is an error, not a silent zero.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from typing import Any

from sigma.correlations import (
    SigmaCorrelationCondition,
    SigmaCorrelationConditionOperator,
    SigmaCorrelationRule,
    SigmaCorrelationType,
)

from tools.otde.matcher import lookup_field, match


class UnsupportedCorrelationError(RuntimeError):
    """Raised when a correlation rule uses a feature this harness cannot evaluate."""


CONDITION_OPERATORS = {
    SigmaCorrelationConditionOperator.LT: lambda count, threshold: count < threshold,
    SigmaCorrelationConditionOperator.LTE: lambda count, threshold: count <= threshold,
    SigmaCorrelationConditionOperator.GT: lambda count, threshold: count > threshold,
    SigmaCorrelationConditionOperator.GTE: lambda count, threshold: count >= threshold,
    SigmaCorrelationConditionOperator.EQ: lambda count, threshold: count == threshold,
    SigmaCorrelationConditionOperator.NEQ: lambda count, threshold: count != threshold,
}


def match_correlation(rule: SigmaCorrelationRule, events: Sequence[Mapping[str, Any]]) -> bool:
    """Return True if ``events`` satisfy the correlation rule."""
    if rule.type != SigmaCorrelationType.VALUE_COUNT:
        raise UnsupportedCorrelationError(
            f"correlation type '{rule.type.name.lower()}' is not implemented; "
            "only value_count is supported"
        )
    if not rule.referenced_rules or any(
        reference.rule is None for reference in rule.referenced_rules
    ):
        raise UnsupportedCorrelationError(
            f"correlation rule '{rule.title}' has unresolved rule references"
        )
    condition = rule.condition
    if not isinstance(condition, SigmaCorrelationCondition):
        raise UnsupportedCorrelationError(
            f"correlation rule '{rule.title}' has no supported condition"
        )
    if condition.op not in CONDITION_OPERATORS:
        raise UnsupportedCorrelationError(f"unsupported condition operator: {condition.op}")
    if not condition.fieldref:
        raise UnsupportedCorrelationError(
            f"value_count correlation '{rule.title}' has no field reference to count"
        )
    if rule.timespan is None:
        raise UnsupportedCorrelationError(
            f"correlation rule '{rule.title}' has no timespan; a count without a window "
            "is not a correlation this harness can evaluate"
        )

    threshold = condition.count
    field = str(condition.fieldref)
    group_by = [str(group) for group in (rule.group_by or [])]
    window = rule.timespan.seconds

    matched: list[tuple[datetime, Mapping[str, Any]]] = []
    for event in events:
        if any(match(reference.rule, event) for reference in rule.referenced_rules):
            matched.append((_event_time(event, rule), event))
    if not matched:
        return False

    compare = CONDITION_OPERATORS[condition.op]
    span = timedelta(seconds=window)
    # A sliding window: the count has to reach the threshold inside some window
    # of the declared length, not merely somewhere in the sequence.
    for start in sorted({moment for moment, _ in matched}):
        distinct: dict[tuple, set] = defaultdict(set)
        for moment, event in matched:
            if not start <= moment < start + span:
                continue
            key = tuple(lookup_field(event, group) for group in group_by)
            distinct[key].add(lookup_field(event, field))
        if any(compare(len(values), threshold) for values in distinct.values()):
            return True
    return False


def _event_time(event: Mapping[str, Any], rule: SigmaCorrelationRule) -> datetime:
    timestamp = event.get("timestamp")
    if not timestamp:
        raise UnsupportedCorrelationError(
            f"correlation rule '{rule.title}' is evaluated over a window, so every event "
            "needs a timestamp"
        )
    try:
        return datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError as error:
        raise UnsupportedCorrelationError(f"unparsable event timestamp: {timestamp}") from error
