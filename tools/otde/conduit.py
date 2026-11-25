"""Evaluate a conduit rule against an event and the declared zone/conduit policy.

Sigma cannot reference an external segmentation policy, so drift from the
intended segmentation is its own small rule family (``rules/conduit``),
evaluated against ``metadata/ot-conduit-policy.yaml``. The policy is the
intended Purdue zones and the conduits between them; a rule names the kind of
deviation, and this module decides it per event.

Two properties matter for false positives:

- **Conduits are bidirectional.** A stateful firewall allows the return traffic
  on an allowed path. A policy that only checks the request direction flags
  every response on a legitimate conduit.
- **The policy models TCP/UDP services, not ICMP.** An ICMP health check or
  unreachable message carries no service port and is not a segmentation
  violation. ICMP is ignored rather than treated as an undeclared path.

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
ICMP_PROTOCOLS = {"icmp", "icmpv6", "ipv6-icmp", "1", "58"}

# Service to TCP port, used when an NDR event does not carry a transport port.
# The policy is port-based; a decoded DNP3 event still belongs to the DNP3
# conduit even though the decoder does not emit a port.
SERVICE_PORTS = {
    "modbus": 502,
    "dnp3": 20000,
    "opcua": 4840,
    "s7comm": 102,
}


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


def _conduits(
    policy: Mapping[str, Any], src: str, dst: str
) -> list[tuple[Mapping[str, Any], bool]]:
    """All conduits between two zones, with whether the flow is the reverse leg.

    There can be more than one conduit between the same zones (the lab has four
    ops-to-control paths, each with a different port and source scope). The
    caller selects the one that carries the service.
    """
    matches: list[tuple[Mapping[str, Any], bool]] = []
    for conduit in policy["conduits"]:
        if conduit["from"] == src and conduit["to"] == dst:
            matches.append((conduit, False))
        elif conduit["from"] == dst and conduit["to"] == src:
            matches.append((conduit, True))
    return matches


def _is_icmp(event: Mapping[str, Any]) -> bool:
    proto = event.get("proto")
    if proto is None:
        return False
    return str(proto).strip().lower() in ICMP_PROTOCOLS


def _initiator(event: Mapping[str, Any], reverse: bool) -> Any:
    """The host that initiated the flow, not the responder."""
    return event.get("dst_ip") if reverse else event.get("src_ip")


def _source_allowed(
    conduit: Mapping[str, Any], event: Mapping[str, Any], reverse: bool
) -> bool:
    sources = conduit.get("sources") or []
    if not sources:
        return True
    return str(_initiator(event, reverse)) in {str(source) for source in sources}


def _event_port(event: Mapping[str, Any], reverse: bool) -> int | None:
    field = "src_port" if reverse else "dst_port"
    value = event.get(field)
    if value is not None:
        try:
            return int(value)
        except (TypeError, ValueError):
            pass
    service = event.get("service")
    return SERVICE_PORTS.get(str(service).lower()) if service is not None else None


def _protocol_allowed(conduit: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    protocols = conduit.get("protocols")
    proto = event.get("proto")
    if not protocols or proto is None:
        return True
    return str(proto).strip().lower() in {str(protocol).lower() for protocol in protocols}


def _service_allowed(
    conduit: Mapping[str, Any], event: Mapping[str, Any], reverse: bool
) -> bool:
    if not _protocol_allowed(conduit, event):
        return False
    ports = conduit.get("ports")
    if not ports:
        return True
    port = _event_port(event, reverse)
    return port is not None and port in ports


def match_conduit(
    rule: Mapping[str, Any], event: Mapping[str, Any], policy: Mapping[str, Any]
) -> bool:
    """Return True if ``event`` violates the policy in the way ``rule`` names."""
    config = rule.get(CONDUIT_KEY)
    if not isinstance(config, Mapping):
        raise UnsupportedConduitError(f"rule '{rule.get('title')}' has no conduit block")

    # The policy models TCP/UDP services between zones. ICMP carries no service
    # and a health check is not a segmentation event.
    if _is_icmp(event):
        return False

    src = zone_for(event.get("src_ip"), policy)
    dst = zone_for(event.get("dst_ip"), policy)
    # Intra-zone traffic and traffic with an unzoned endpoint are out of scope:
    # the policy models zone-to-zone paths, not the inside of a zone.
    if src is None or dst is None or src == dst:
        return False

    conduits = _conduits(policy, src, dst)
    kind = config.get("type")
    if kind == "undeclared_path":
        return not conduits
    if kind == "unauthorized_source":
        carried = [
            (conduit, reverse)
            for conduit, reverse in conduits
            if _service_allowed(conduit, event, reverse)
        ]
        if not carried:
            # No conduit carries this service; the service rule owns it.
            return False
        return not any(
            _source_allowed(conduit, event, reverse)
            for conduit, reverse in carried
        )
    if kind == "undeclared_service":
        if not conduits:
            return False
        return not any(
            _service_allowed(conduit, event, reverse)
            for conduit, reverse in conduits
        )
    raise UnsupportedConduitError(f"unsupported conduit type: {kind!r}")


def observed_conduits(
    policy: Mapping[str, Any], events: Iterable[Mapping[str, Any]]
) -> set[tuple[str, str]]:
    """Zone-to-zone pairs actually observed in ``events`` (either direction)."""
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
    used = {
        (conduit["from"], conduit["to"])
        for conduit in policy["conduits"]
        if (conduit["from"], conduit["to"]) in observed
        or (conduit["to"], conduit["from"]) in observed
    }
    return [
        [conduit["from"], conduit["to"]]
        for conduit in policy["conduits"]
        if (conduit["from"], conduit["to"]) not in used
    ]
