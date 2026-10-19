"""HTTP helpers that refuse non-HTTP(S) schemes.

``urllib.request.urlopen`` also accepts ``file:``, ``ftp:`` and custom schemes, so
a URL taken from configuration or an environment variable could read a local file
or reach a handler the caller did not intend. Every outbound request in this
repository goes through this helper, which validates the scheme first.
"""

from __future__ import annotations

import urllib.request
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}


class UnsafeUrlError(ValueError):
    """Raised when a URL does not use an allowed scheme."""


def open_http(
    url: str,
    *,
    data: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    method: str | None = None,
    timeout: float = 10.0,
) -> Any:
    """Open an HTTP(S) request, rejecting any other URL scheme."""
    scheme = urlparse(url).scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeUrlError(f"refusing non-HTTP(S) URL scheme: {scheme or '<none>'}")
    request = urllib.request.Request(
        url, data=data, headers=dict(headers or {}), method=method
    )
    # The scheme is validated above; bandit cannot infer that.
    return urllib.request.urlopen(request, timeout=timeout)  # nosec B310
