"""Small statistical helpers for detection-quality reporting.

A rate measured over a finite sample is an estimate. Reporting ``0.0`` for zero
observed events over N trials is misleading: it claims certainty the sample
cannot support. These helpers produce a two-sided Wilson score interval, which
stays sane at 0 and 1 where the normal approximation breaks down.
"""

from __future__ import annotations

import math

# 95% two-sided normal quantile.
Z_95 = 1.959963984540054


def wilson_interval(successes: int, trials: int, z: float = Z_95) -> tuple[float, float]:
    """Return the Wilson score interval ``(low, high)`` for a binomial rate."""
    if trials <= 0:
        raise ValueError("trials must be positive")
    if not 0 <= successes <= trials:
        raise ValueError("successes must be between 0 and trials")
    p = successes / trials
    denominator = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denominator
    margin = (z * math.sqrt(p * (1 - p) / trials + z * z / (4 * trials * trials))) / denominator
    low = max(0.0, centre - margin)
    high = min(1.0, centre + margin)
    if low < 1e-12:
        low = 0.0
    if high > 1 - 1e-12:
        high = 1.0
    return low, high


def rounded_interval(successes: int, trials: int, digits: int = 4) -> tuple[float, float]:
    """Wilson interval rounded for JSON and Markdown output."""
    low, high = wilson_interval(successes, trials)
    return round(low, digits), round(high, digits)
