"""Evaluate stateful OT detections against a sequence of events.

Some detections are not single-event signatures and not simple counts:

- a process value that drifts away from a learned baseline for several samples;
- a write that falls outside an approved engineering-change window;
- a known asset that starts using a service or function code it never used.

Sigma single-event and correlation rules cannot express those conditions
cleanly, so they live in ``rules/stateful`` with a small, explicit evaluator.
The evaluator raises on a rule type it does not implement rather than returning
a result the test never exercised.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
STATEFUL_KEY = "stateful"


class UnsupportedStatefulError(RuntimeError):
    """Raised when a stateful rule uses a feature this harness cannot evaluate."""


def is_stateful_rule(rule_path: Path) -> bool:
    data = yaml.safe_load(Path(rule_path).read_text(encoding="utf-8"))
    return isinstance(data, dict) and STATEFUL_KEY in data


def load_stateful_rule(rule_path: Path) -> dict[str, Any]:
    return yaml.safe_load(Path(rule_path).read_text(encoding="utf-8"))


def _parse_timestamp(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as error:
        raise UnsupportedStatefulError(f"unparsable timestamp: {value}") from error
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed


def _load_json(path: Path) -> dict:
    if not path.exists():
        raise UnsupportedStatefulError(f"baseline not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _load_calendar(path: Path) -> dict:
    if not path.exists():
        raise UnsupportedStatefulError(f"change calendar not found: {path}")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _value_drift(config: Mapping[str, Any], events: Sequence[Mapping[str, Any]]) -> bool:
    baseline = _load_json(REPO_ROOT / str(config["baseline"]))
    field = str(config.get("field", baseline.get("field", "value")))
    product = config.get("product", "ot_process")
    event_type = config.get("event_type", "process_update")
    threshold = float(config.get("z_threshold", 3.0))
    required = int(config.get("consecutive", 3))
    direction = str(config.get("direction", "both"))

    consecutive: dict[str, int] = defaultdict(int)
    for event in events:
        if event.get("product") != product or event.get("event_type") != event_type:
            continue
        asset = event.get("asset")
        value = event.get(field)
        if not asset or value is None:
            consecutive[str(asset)] = 0
            continue
        stats = baseline.get("assets", {}).get(str(asset))
        if not stats or field != baseline.get("field"):
            consecutive[str(asset)] = 0
            continue
        std = float(stats.get("std", 0))
        if std <= 0:
            consecutive[str(asset)] = 0
            continue
        z = (float(value) - float(stats["mean"])) / std
        above = direction in ("both", "above") and z >= threshold
        below = direction in ("both", "below") and z <= -threshold
        if above or below:
            consecutive[str(asset)] += 1
        else:
            consecutive[str(asset)] = 0
        if consecutive[str(asset)] >= required:
            return True
    return False


def _window_matches(
    window: Mapping[str, Any], event: Mapping[str, Any], moment: datetime
) -> bool:
    start = _parse_timestamp(window["starts"])
    end = _parse_timestamp(window["ends"])
    if not start <= moment <= end:
        return False
    for field in ("src_ip", "dst_ip", "service"):
        if field in window and window[field] != event.get(field):
            return False

    # Time and endpoints are necessary but not sufficient: the change must also
    # cover what is being written. A register outside the approved range, or a
    # function code outside the approved set, is outside the change.
    scope = window.get("scope") or {}
    if "function_codes" in scope:
        try:
            code = int(event.get("function_code"))
        except (TypeError, ValueError):
            return False
        if code not in {int(value) for value in scope["function_codes"]}:
            return False
    register = event.get("register")
    register_end = event.get("register_end", register)
    if scope.get("register_min") is not None:
        try:
            if register is None or int(register) < int(scope["register_min"]):
                return False
        except (TypeError, ValueError):
            return False
    if scope.get("register_max") is not None:
        try:
            if register_end is None or int(register_end) > int(scope["register_max"]):
                return False
        except (TypeError, ValueError):
            return False

    ticket = window.get("ticket")
    change_id = event.get("change_id")
    if ticket and change_id is not None and change_id != ticket:
        return False
    if window.get("require_change_id") and change_id is None:
        return False
    return True


def _change_window(config: Mapping[str, Any], events: Sequence[Mapping[str, Any]]) -> bool:
    calendar = _load_calendar(REPO_ROOT / str(config["calendar"]))
    windows = calendar.get("windows", [])
    write_codes = {int(code) for code in config.get("write_function_codes", [6, 16, 26, 27, 28])}
    products = set(config.get("products", ["ot_ndr"]))
    services = set(config["services"]) if config.get("services") else None
    engineering_sources = (
        set(str(source) for source in config["engineering_sources"])
        if config.get("engineering_sources")
        else None
    )
    for event in events:
        if event.get("product") not in products:
            continue
        if services is not None and event.get("service") not in services:
            continue
        # An operator setpoint change is not an engineering change. The rule is
        # scoped to the engineering workstations that are allowed to change
        # logic or configuration; writes from other hosts are covered by the
        # unauthorized-writer rules.
        if engineering_sources is not None and event.get("src_ip") not in engineering_sources:
            continue
        if event.get("direction") != "request":
            continue
        try:
            code = int(event.get("function_code"))
        except (TypeError, ValueError):
            continue
        if code not in write_codes:
            continue
        timestamp = event.get("timestamp")
        if not timestamp:
            raise UnsupportedStatefulError(
                "a change-window write needs a timestamp to join the calendar"
            )
        moment = _parse_timestamp(timestamp)
        if not any(_window_matches(window, event, moment) for window in windows):
            return True
    return False


def _process_envelope(
    config: Mapping[str, Any], events: Sequence[Mapping[str, Any]]
) -> bool:
    """Flag a process value that stays outside an absolute safety envelope.

    This is the repo's own envelope check over process telemetry. It does not
    depend on the external monitor's ``process_safety_violation`` label: it
    reads the level itself and requires several consecutive samples outside the
    bound, so a single sensor spike does not fire.
    """
    field = str(config.get("field", "tank_level_pct"))
    low = float(config.get("min", 5))
    high = float(config.get("max", 95))
    required = int(config.get("consecutive", 3))
    products = set(config.get("products", ["ot_process"]))
    event_type = config.get("event_type", "process_update")
    consecutive: dict[str, int] = defaultdict(int)
    for event in events:
        if event.get("product") not in products or event.get("event_type") != event_type:
            continue
        asset = event.get("asset")
        value = event.get(field)
        if not asset or value is None:
            consecutive[str(asset)] = 0
            continue
        outside = float(value) < low or float(value) > high
        consecutive[str(asset)] = consecutive[str(asset)] + 1 if outside else 0
        if consecutive[str(asset)] >= required:
            return True
    return False


def _dnp3_select_operate(
    config: Mapping[str, Any], events: Sequence[Mapping[str, Any]]
) -> bool:
    """Flag an Operate that has no matching Select inside the pairing window.

    Normal DNP3 control is select-before-operate: the master selects a point,
    the outstation reserves it, and the master operates it. An Operate without a
    preceding Select for the same link source, object index and control code is
    either a broken master or an attempt to skip the reservation step. Direct
    Operate (FC5/6) is a different command and is covered by the unauthorized-
    master rule, not this pairing check.
    """
    window = float(config.get("pair_window_seconds", 10))
    products = set(config.get("products", ["ot_ndr"]))
    services = set(config.get("services", ["dnp3"]))
    pending: list[tuple[datetime, tuple[Any, Any, Any]]] = []
    ordered = sorted(events, key=lambda event: str(event.get("timestamp", "")))
    for event in ordered:
        if event.get("product") not in products or event.get("service") not in services:
            continue
        if event.get("direction") != "request":
            continue
        try:
            code = int(event.get("function_code"))
        except (TypeError, ValueError):
            continue
        if code not in (3, 4):
            continue
        timestamp = event.get("timestamp")
        if not timestamp:
            raise UnsupportedStatefulError(
                "a DNP3 select/operate pairing needs a timestamp on every control event"
            )
        moment = _parse_timestamp(timestamp)
        key = (
            event.get("link_source"),
            event.get("object_index"),
            event.get("control_code"),
        )
        if any(part is None for part in key):
            # Without the point and control code the pair cannot be attributed.
            # The decoder emits both for a CROB; do not guess.
            continue
        if code == 3:
            pending.append((moment, key))
            continue
        matched = next(
            (
                entry
                for entry in pending
                if entry[1] == key and 0 <= (moment - entry[0]).total_seconds() <= window
            ),
            None,
        )
        if matched is None:
            return True
        pending.remove(matched)
    return False


def _asset_protocol_baseline(
    config: Mapping[str, Any], events: Sequence[Mapping[str, Any]]
) -> bool:
    baseline = _load_json(REPO_ROOT / str(config["baseline"]))
    products = set(config.get("products", ["ot_ndr"]))
    for event in events:
        # The per-asset profile is learned from protocol telemetry. A flow or
        # firewall event has a service name but no protocol profile, so it must
        # not be judged against a protocol baseline.
        if event.get("product") not in products:
            continue
        if event.get("direction", "request") != "request":
            continue
        asset = event.get("dst_ip")
        service = event.get("service")
        if not asset or not service:
            continue
        profile = baseline.get("assets", {}).get(str(asset))
        if not profile:
            # An unknown asset is the new-asset rule's job, not this one.
            continue
        if service not in profile.get("services", []):
            return True
        code = event.get("function_code")
        if code is not None:
            try:
                code = int(code)
            except (TypeError, ValueError):
                continue
            if code not in profile.get("functions", {}).get(service, []):
                return True
    return False


def match_stateful(
    rule: Mapping[str, Any], events: Sequence[Mapping[str, Any]]
) -> bool:
    """Return True if ``events`` satisfy the rule's stateful condition."""
    config = rule.get(STATEFUL_KEY)
    if not isinstance(config, Mapping):
        raise UnsupportedStatefulError(f"rule '{rule.get('title')}' has no stateful block")
    kind = config.get("type")
    if kind == "value_drift":
        return _value_drift(config, events)
    if kind == "change_window":
        return _change_window(config, events)
    if kind == "asset_protocol_baseline":
        return _asset_protocol_baseline(config, events)
    if kind == "dnp3_select_operate":
        return _dnp3_select_operate(config, events)
    if kind == "process_envelope":
        return _process_envelope(config, events)
    raise UnsupportedStatefulError(f"unsupported stateful type: {kind!r}")
