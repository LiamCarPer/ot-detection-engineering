"""Guard the committed performance evidence."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools.perf_check import EVIDENCE_PATH, main, validate  # noqa: E402


def _summary() -> dict:
    return json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))


def test_evidence_has_all_protocols_and_pipeline() -> None:
    summary = _summary()
    assert set(summary["protocols"]) == {"dnp3", "s7comm", "opcua"}
    assert summary["pipeline"]["events"] > 0
    assert summary["pipeline"]["rules"] > 0
    assert summary["hardware"]["cpu_model"]
    assert summary["toolchain"]["python"]


def test_committed_evidence_is_valid() -> None:
    assert validate(_summary()) == []
    assert main(["--check"]) == 0


def test_missing_protocol_is_rejected() -> None:
    summary = copy.deepcopy(_summary())
    del summary["protocols"]["dnp3"]
    assert any("missing protocol dnp3" in problem for problem in validate(summary))


def test_zero_events_is_rejected() -> None:
    summary = copy.deepcopy(_summary())
    summary["pipeline"]["events"] = 0
    assert any("events must be positive" in problem for problem in validate(summary))


def test_slo_flags_are_recorded() -> None:
    slo = _summary()["slo"]
    assert slo["decoder_p99_within_slo"] is True
    assert slo["pipeline_within_slo"] is True
    assert slo["pipeline_matches_within_slo"] is True
