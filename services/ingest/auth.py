"""API-key authentication and a bounded in-memory rate limiter."""

from __future__ import annotations

import hmac
import threading
import time
from collections import defaultdict, deque
from collections.abc import Callable


def key_matches(presented: str | None, expected: str) -> bool:
    """Compare an API key in constant time.

    ``hmac.compare_digest`` avoids a timing oracle that a plain ``==`` would
    introduce. An empty or missing key never matches.
    """
    if not presented:
        return False
    return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


class RateLimiter:
    """A sliding-window limiter keyed by client identity.

    In-memory and per-process: it bounds abuse of one instance, and a deployment
    behind several replicas should also enforce a limit at the edge. The point is
    that the service never relies on the client to be polite.
    """

    def __init__(
        self,
        limit: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._clock = clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            hits = self._hits[key]
            while hits and now - hits[0] >= self.window_seconds:
                hits.popleft()
            if len(hits) >= self.limit:
                return False
            hits.append(now)
            return True
