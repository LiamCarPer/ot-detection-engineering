"""Functional evidence: the decoders' events fired the expected Sigma rules.

CI builds and tests the Rust decoders in a separate step, so the decoder-to-rule
run is captured once (tools/decoder_check.py) and committed; these tests assert
the committed evidence against the expectations in tools/otde/evidence.py.
Regenerate with `make decoder-check`.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.otde.evidence import EXPECTED_DECODER_RULES

EVIDENCE_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "evidence"
    / "decoders"
    / "summary.json"
)


def _summary() -> dict:
    return json.loads(EVIDENCE_PATH.read_text(encoding="utf-8"))


def test_every_protocol_was_evaluated() -> None:
    assert set(_summary()) == set(EXPECTED_DECODER_RULES)


def test_every_expected_rule_fired_once() -> None:
    summary = _summary()
    for service, expected in EXPECTED_DECODER_RULES.items():
        assert set(summary[service]["expected"]) == expected
        assert set(summary[service]["observed"]) == expected


def test_every_protocol_decoded_events() -> None:
    summary = _summary()
    for service, entry in summary.items():
        assert entry["events"] > 0, service
