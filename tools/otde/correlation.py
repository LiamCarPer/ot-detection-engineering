"""Evaluate a Sigma correlation rule against a sequence of events.

The single-event matcher in ``tools/otde/matcher.py`` cannot evaluate a
correlation rule: it has no detection block, and its meaning depends on a
window. This module adds the missing half so a correlation rule can be proven
offline, against labeled positive and negative event sequences, in the same way
every single-event rule is proven against its fixture.

``value_count`` and ``event_count`` are implemented. Anything else raises
``UnsupportedCorrelationError`` rather than returning a result the test never
really exercised — the same rule the single-event matcher applies to
unimplemented Sigma features.

Semantics implemented, over the events the referenced rules match and grouped by
the correlation's ``group-by`` fields inside a sliding ``timespan`` window:

- ``value_count`` counts the distinct values of the condition's ``field``.
- ``event_count`` counts the events themselves.

Only the threshold operators ``gt`` and ``gte`` are supported. The "any window
satisfies" semantics used for a threshold is not meaningful for ``lt``, ``lte``
or ``neq``: a single-event window would satisfy ``lt: 10`` and the rule would
fire on almost any input. Those operators raise instead of returning a result
that looks like a detection. ``eq`` is also rejected for the same reason: a
window can always be chosen to contain exactly the requested number of events.

Duplicate events are counted once: the same observation delivered twice is one
observation, not two. An event without a timestamp, or a matched event missing
the counted or grouped field, is an error rather than a silent zero.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
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


# Threshold operators only. See the module docstring for why the negative and
# exact operators are rejected instead of being approximated.
CONDITION_OPERATORS = {
    SigmaCorrelationConditionOperator.GT: lambda count, threshold: count > threshold,
    SigmaCorrelationConditionOperator.GTE: lambda count, threshold: count >= threshold,
}

REJECTED_OPERATORS = {
    SigmaCorrelationConditionOperator.LT: "a one-event window would satisfy it",
    SigmaCorrelationConditionOperator.LTE: "a one-event window would satisfy it",
    SigmaCorrelationConditionOperator.EQ: "a window can always be chosen to match exactly",
    SigmaCorrelationConditionOperator.NEQ: "a one-event window would satisfy it",
}


def match_correlation(rule: SigmaCorrelationRule, events: Sequence[Mapping[str, Any]]) -> bool:
    """Return True if ``events`` satisfy the correlation rule."""
    if rule.type not in (SigmaCorrelationType.VALUE_COUNT, SigmaCorrelationType.EVENT_COUNT):
        raise UnsupportedCorrelationError(
            f"correlation type '{rule.type.name.lower()}' is not implemented; "
            "only value_count and event_count are supported"
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
    if condition.op in REJECTED_OPERATORS:
        raise UnsupportedCorrelationError(
            f"correlation rule '{rule.title}' uses operator '{condition.op.name.lower()}': "
            f"{REJECTED_OPERATORS[condition.op]}, so 'any window satisfies' is not a "
            "meaningful semantic; implement fixed-window semantics before enabling it"
        )
    if condition.op not in CONDITION_OPERATORS:
        raise UnsupportedCorrelationError(f"unsupported condition operator: {condition.op}")
    if rule.type == SigmaCorrelationType.VALUE_COUNT and not condition.fieldref:
        raise UnsupportedCorrelationError(
            f"value_count correlation '{rule.title}' has no field reference to count"
        )
    if rule.timespan is None:
        raise UnsupportedCorrelationError(
            f"correlation rule '{rule.title}' has no timespan; a count without a window "
            "is not a correlation this harness can evaluate"
        )

    threshold = condition.count
    field = str(condition.fieldref) if condition.fieldref else None
    group_by = [str(group) for group in (rule.group_by or [])]
    window = rule.timespan.seconds

    matched: list[tuple[datetime, Mapping[str, Any]]] = []
    seen: set[str] = set()
    for event in events:
        if any(match(reference.rule, event) for reference in rule.referenced_rules):
            identity = _identity(event)
            if identity in seen:
                continue
            seen.add(identity)
            matched.append((_event_time(event, rule), event))
    if not matched:
        return False

    compare = CONDITION_OPERATORS[condition.op]
    span = timedelta(seconds=window)
    # A sliding window: the count has to reach the threshold inside some window
    # of the declared length, not merely somewhere in the sequence.
    for start in sorted({moment for moment, _ in matched}):
        if rule.type == SigmaCorrelationType.VALUE_COUNT:
            distinct: dict[tuple, set] = defaultdict(set)
            for moment, event in matched:
                if not start <= moment < start + span:
                    continue
                key = _group_key(event, group_by, rule)
                value = lookup_field(event, field)
                if value is None:
                    raise UnsupportedCorrelationError(
                        f"correlation rule '{rule.title}' counts '{field}', but a matched "
                        "event does not carry it; a missing value is not a distinct value"
                    )
                distinct[key].add(_hashable(value))
            if any(compare(len(values), threshold) for values in distinct.values()):
                return True
        else:
            counts: dict[tuple, int] = defaultdict(int)
            for moment, event in matched:
                if not start <= moment < start + span:
                    continue
                key = _group_key(event, group_by, rule)
                counts[key] += 1
            if any(compare(count, threshold) for count in counts.values()):
                return True
    return False


def _identity(event: Mapping[str, Any]) -> str:
    try:
        return json.dumps(event, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return repr(sorted(event.items()))


def _group_key(
    event: Mapping[str, Any], group_by: list[str], rule: SigmaCorrelationRule
) -> tuple:
    key = []
    for group in group_by:
        value = lookup_field(event, group)
        if value is None:
            raise UnsupportedCorrelationError(
                f"correlation rule '{rule.title}' groups by '{group}', but a matched "
                "event does not carry it; collapsing missing groups into one bucket "
                "would count unrelated events together"
            )
        key.append(_hashable(value))
    return tuple(key)


def _hashable(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return json.dumps(value, sort_keys=True, default=str)


def _event_time(event: Mapping[str, Any], rule: SigmaCorrelationRule) -> datetime:
    timestamp = event.get("timestamp")
    if not timestamp:
        raise UnsupportedCorrelationError(
            f"correlation rule '{rule.title}' is evaluated over a window, so every event "
            "needs a timestamp"
        )
    try:
        parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError as error:
        raise UnsupportedCorrelationError(f"unparsable event timestamp: {timestamp}") from error
    # Normalize naive input to UTC. Mixing naive and aware datetimes otherwise
    # raises a bare TypeError from the comparison instead of a clear error.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
