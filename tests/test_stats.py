"""Tests for the Wilson score interval used in detection reporting."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "metrics"))

from stats import wilson_interval  # noqa: E402


def test_zero_events_still_has_a_nonzero_upper_bound() -> None:
    low, high = wilson_interval(0, 1000)
    assert low == 0.0
    assert 0.003 < high < 0.004


def test_the_interval_contains_the_point_estimate() -> None:
    for successes, trials in ((0, 10), (3, 10), (9, 10), (100, 100), (0, 1)):
        low, high = wilson_interval(successes, trials)
        assert low <= successes / trials <= high


def test_the_interval_is_symmetric_around_one_half() -> None:
    low, high = wilson_interval(50, 100)
    assert (low + high) / 2 == pytest.approx(0.5, abs=1e-9)


def test_a_larger_sample_tightens_the_interval() -> None:
    _, small = wilson_interval(0, 10)
    _, large = wilson_interval(0, 1000)
    assert large < small


def test_invalid_inputs_are_rejected() -> None:
    with pytest.raises(ValueError):
        wilson_interval(0, 0)
    with pytest.raises(ValueError):
        wilson_interval(5, 4)
