"""Evaluate a behaviour-baseline rule against an event and the OT baseline.

The single-event matcher in ``tools/otde/matcher.py`` evaluates a Sigma rule on
its own; a behaviour rule's meaning depends on the committed OT behaviour
baseline (``baseline/ot-behaviour.json``). This module adds that context so a
deviation rule can be proven offline against labeled events, the same way every
Sigma rule is proven against its fixture.

Only the deviation types the repository uses are implemented. Anything else
raises ``UnsupportedBaselineError`` rather than returning a result that was never
really exercised — the principle the matcher and the correlation evaluator
already follow.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_PATH = REPO_ROOT / "baseline" / "ot-behaviour.json"
BASELINE_KEY = "baseline"


class UnsupportedBaselineError(RuntimeError):
    """Raised when a behaviour rule uses a feature this harness cannot evaluate."""


def load_baseline(path: Path = BASELINE_PATH) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def is_baseline_rule(rule_path: Path) -> bool:
    """True when the file is a behaviour-baseline rule rather than a Sigma rule."""
    data = yaml.safe_load(Path(rule_path).read_text(encoding="utf-8"))
    return isinstance(data, dict) and BASELINE_KEY in data


def load_baseline_rule(rule_path: Path) -> dict[str, Any]:
    return yaml.safe_load(Path(rule_path).read_text(encoding="utf-8"))


def match_baseline(
    rule: Mapping[str, Any], event: Mapping[str, Any], baseline: Mapping[str, Any]
) -> bool:
    """Return True if ``event`` deviates from ``baseline`` in the way ``rule`` names."""
    config = rule.get(BASELINE_KEY)
    if not isinstance(config, Mapping):
        raise UnsupportedBaselineError(f"rule '{rule.get('title')}' has no baseline block")
    service = config.get("service")
    if service is not None and event.get("service") != service:
        return False

    kind = config.get("type")
    if kind == "new_asset":
        field = config.get("field", "src_ip")
        value = event.get(field)
        return value is not None and value not in baseline.get("assets", [])
    if kind == "new_pair":
        src = event.get("src_ip")
        dst = event.get("dst_ip")
        if not src or not dst:
            return False
        return [src, dst] not in baseline.get("pairs", [])
    if kind == "new_function_code":
        code = event.get("function_code")
        event_service = event.get("service")
        if code is None or event_service is None:
            return False
        known = baseline.get("functions", {}).get(event_service, [])
        return int(code) not in known
    raise UnsupportedBaselineError(f"unsupported baseline type: {kind!r}")
