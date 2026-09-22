"""Guard the committed conduit evidence.

The conduit proof needs the committed telemetry samples, so it is run once
(tools/conduit_check.py) and committed; these tests assert the evidence. They
fail if a rule stops firing on a sample or the policy stops matching the samples.
"""

from __future__ import annotations

import json
from pathlib import Path

from tools.otde.evidence import EXPECTED_CONDUIT_RULES

EVIDENCE = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "evidence"
    / "conduit"
    / "summary.json"
)


def _evidence() -> dict:
    return json.loads(EVIDENCE.read_text(encoding="utf-8"))


def test_every_sample_is_covered_and_matches_expected() -> None:
    samples = _evidence()["samples"]
    assert set(samples) == set(EXPECTED_CONDUIT_RULES)
    for key, entry in samples.items():
        assert entry["observed"] == sorted(EXPECTED_CONDUIT_RULES[key]), key


def test_a_declared_conduit_was_observed() -> None:
    evidence = _evidence()
    declared = {tuple(conduit) for conduit in evidence["declared_conduits"]}
    observed = {tuple(pair) for pair in evidence["observed_conduits"]}
    # Observed traffic may include undeclared pairs (the violations the rules
    # flag); at least one declared conduit must actually be exercised, or the
    # policy and the samples would be disjoint.
    assert observed
    assert observed & declared


def test_benign_samples_are_silent() -> None:
    for key, entry in _evidence()["samples"].items():
        if "benign" in key:
            assert entry["observed"] == [], key
