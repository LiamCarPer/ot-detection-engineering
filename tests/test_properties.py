"""Property-based security tests for the matcher, the contract and the evaluators.

These are not examples: they assert invariants over generated input, which is the
security-relevant question — does the library ever raise, emit an invalid event,
or lose information when the input is arbitrary? Example-based tests prove the
cases we thought of; these look for the ones we did not.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st
from sigma.rule import SigmaRule

from collector import contract
from tools.otde.baseline import load_baseline, load_baseline_rule, match_baseline
from tools.otde.conduit import load_conduit_rule, load_policy, match_conduit
from tools.otde.matcher import match
from tools.otde.rules import baseline_rule_paths, conduit_rule_paths

REPO_ROOT = Path(__file__).resolve().parents[1]
MODBUS_RULE = SigmaRule.from_yaml(
    (REPO_ROOT / "rules" / "sigma" / "ot" / "ot_modbus_unauthorized_write.yml").read_text(
        encoding="utf-8"
    )
)
BASELINE_RULES = [load_baseline_rule(path) for path in baseline_rule_paths()]
CONDUIT_RULES = [load_conduit_rule(path) for path in conduit_rule_paths()]
BASELINE = load_baseline()
POLICY = load_policy()

FIELDS = [
    "product",
    "service",
    "direction",
    "function_code",
    "src_ip",
    "dst_ip",
    "dst_port",
    "event_type",
    "opcua_service",
]
SCALARS = (
    st.none()
    | st.booleans()
    | st.integers()
    | st.floats(allow_nan=False, allow_infinity=False)
    | st.text(max_size=20)
)


@st.composite
def arbitrary_events(draw):
    keys = draw(st.sets(st.sampled_from(FIELDS), max_size=len(FIELDS)))
    return {key: draw(SCALARS) for key in keys}


@settings(max_examples=50, deadline=None)
@given(arbitrary_events())
def test_the_matcher_never_raises_on_arbitrary_events(event: dict) -> None:
    match(MODBUS_RULE, event)


@settings(max_examples=50, deadline=None)
@given(arbitrary_events())
def test_the_baseline_evaluator_never_raises(event: dict) -> None:
    for rule in BASELINE_RULES:
        match_baseline(rule, event, BASELINE)


@settings(max_examples=50, deadline=None)
@given(arbitrary_events())
def test_the_conduit_evaluator_never_raises(event: dict) -> None:
    for rule in CONDUIT_RULES:
        match_conduit(rule, event, POLICY)


@settings(max_examples=50, deadline=None)
@given(
    st.integers(min_value=0, max_value=4_102_444_800),
    st.integers(min_value=0, max_value=100),
)
def test_built_events_always_validate(epoch: int, function_code: int) -> None:
    built = contract.event(
        "ot_ndr",
        "modbus",
        epoch,
        direction="request",
        function_code=function_code,
        src_ip="172.24.0.10",
        dst_ip="172.21.0.10",
    )
    assert contract.schema_errors(built) == []


@settings(max_examples=50, deadline=None)
@given(
    st.datetimes(
        min_value=datetime(1970, 1, 1),
        max_value=datetime(2100, 1, 1),
        timezones=st.just(UTC),
    )
)
def test_timestamp_normalization_is_idempotent(moment: datetime) -> None:
    once = contract.normalize_timestamp(moment.isoformat())
    assert contract.normalize_timestamp(once) == once
