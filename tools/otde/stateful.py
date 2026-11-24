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
    return True


def _change_window(config: Mapping[str, Any], events: Sequence[Mapping[str, Any]]) -> bool:
    calendar = _load_calendar(REPO_ROOT / str(config["calendar"]))
    windows = calendar.get("windows", [])
    write_codes = {int(code) for code in config.get("write_function_codes", [6, 16, 26, 27, 28])}
    products = set(config.get("products", ["ot_ndr"]))
    for event in events:
        if event.get("product") not in products:
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


def _asset_protocol_baseline(
    config: Mapping[str, Any], events: Sequence[Mapping[str, Any]]
) -> bool:
    baseline = _load_json(REPO_ROOT / str(config["baseline"]))
    for event in events:
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
    raise UnsupportedStatefulError(f"unsupported stateful type: {kind!r}")
