"""Evaluate a conduit rule against an event and the declared zone/conduit policy.

Sigma cannot reference an external segmentation policy, so drift from the
intended segmentation is its own small rule family (``rules/conduit``),
evaluated against ``metadata/ot-conduit-policy.yaml``. The policy is the
intended Purdue zones and the conduits between them; a rule names the kind of
deviation, and this module decides it per event.

Only the deviation types the repository uses are implemented; anything else
raises ``UnsupportedConduitError`` — the fail-loud principle the matcher, the
correlation evaluator and the behaviour evaluator already follow.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "metadata" / "ot-conduit-policy.yaml"
CONDUIT_KEY = "conduit"


class UnsupportedConduitError(RuntimeError):
    """Raised when a conduit rule uses a feature this harness cannot evaluate."""


def load_policy(path: Path = POLICY_PATH) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def is_conduit_rule(rule_path: Path) -> bool:
    data = yaml.safe_load(Path(rule_path).read_text(encoding="utf-8"))
    return isinstance(data, dict) and CONDUIT_KEY in data


def load_conduit_rule(rule_path: Path) -> dict[str, Any]:
    return yaml.safe_load(Path(rule_path).read_text(encoding="utf-8"))


def zone_for(address: Any, policy: Mapping[str, Any]) -> str | None:
    """Return the zone an address belongs to, or None when it is unzoned."""
    if not address:
        return None
    try:
        parsed = ipaddress.ip_address(str(address))
    except ValueError:
        return None
    for zone in policy["zones"]:
        if parsed in ipaddress.ip_network(zone["cidr"]):
            return zone["name"]
    return None


def _conduit(policy: Mapping[str, Any], src: str, dst: str) -> Mapping[str, Any] | None:
    for conduit in policy["conduits"]:
        if conduit["from"] == src and conduit["to"] == dst:
            return conduit
    return None


def match_conduit(
    rule: Mapping[str, Any], event: Mapping[str, Any], policy: Mapping[str, Any]
) -> bool:
    """Return True if ``event`` violates the policy in the way ``rule`` names."""
    config = rule.get(CONDUIT_KEY)
    if not isinstance(config, Mapping):
        raise UnsupportedConduitError(f"rule '{rule.get('title')}' has no conduit block")

    src = zone_for(event.get("src_ip"), policy)
    dst = zone_for(event.get("dst_ip"), policy)
    # Intra-zone traffic and traffic with an unzoned endpoint are out of scope:
    # the policy models zone-to-zone paths, not the inside of a zone.
    if src is None or dst is None or src == dst:
        return False

    conduit = _conduit(policy, src, dst)
    kind = config.get("type")
    if kind == "undeclared_path":
        return conduit is None
    if kind == "undeclared_service":
        if conduit is None:
            return False
        ports = conduit.get("ports")
        port = event.get("dst_port")
        if not ports or port is None:
            return False
        return int(port) not in ports
    raise UnsupportedConduitError(f"unsupported conduit type: {kind!r}")


def observed_conduits(
    policy: Mapping[str, Any], events: Iterable[Mapping[str, Any]]
) -> set[tuple[str, str]]:
    """Zone-to-zone pairs actually observed in ``events``."""
    observed: set[tuple[str, str]] = set()
    for event in events:
        src = zone_for(event.get("src_ip"), policy)
        dst = zone_for(event.get("dst_ip"), policy)
        if src and dst and src != dst:
            observed.add((src, dst))
    return observed


def unused_conduits(
    policy: Mapping[str, Any], events: Iterable[Mapping[str, Any]]
) -> list[list[str]]:
    """Declared conduits never observed — segmentation that is documented but unused."""
    observed = observed_conduits(policy, events)
    return [
        [conduit["from"], conduit["to"]]
        for conduit in policy["conduits"]
        if (conduit["from"], conduit["to"]) not in observed
    ]
