"""Guard the suppression policy and its measured result."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "analysis"))

from suppression import build  # noqa: E402

POLICY = REPO_ROOT / "deploy" / "alertmanager" / "ot-inhibit.yml"
RESULT = REPO_ROOT / "analysis" / "out" / "suppression.json"


def _policy() -> dict:
    return yaml.safe_load(POLICY.read_text(encoding="utf-8"))


def test_policy_groups_by_the_entity_that_matters() -> None:
    policy = _policy()
    group_by = policy["route"]["group_by"]
    assert "src_ip" in group_by
    assert "dst_ip" in group_by
    assert policy["route"]["repeat_interval"] == "4h"
    assert policy["receivers"][0]["name"] == "ot-webhook"


def test_policy_never_inhibits_safety_or_sensor_health() -> None:
    text = POLICY.read_text(encoding="utf-8")
    assert "Detection_Service_Stopped" not in text
    assert "Process_Safety" not in text


def test_committed_result_is_reproducible_and_preserves_the_signals() -> None:
    committed = json.loads(RESULT.read_text(encoding="utf-8"))
    assert committed == build()
    assert committed["raw_alerts"] == 151
    assert committed["group_by"] == _policy()["route"]["group_by"]
    assert committed["notifications"] <= 24
    assert committed["preserved"]["C2_hmi_login"] > 0
    assert committed["preserved"]["C3_protocol_chain"] > 0
    assert committed["preserved"]["C4_operator_write"] > 0
    assert committed["preserved"]["C5_sensor_health"] > 0
