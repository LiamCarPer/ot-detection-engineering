"""Keep the lab asset inventory in step with the rules and policy."""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ASSETS = REPO_ROOT / "metadata" / "assets.yaml"
POLICY = REPO_ROOT / "metadata" / "ot-conduit-policy.yaml"
CALENDAR = REPO_ROOT / "metadata" / "change-calendar.yaml"
SIGMA = REPO_ROOT / "rules" / "sigma" / "ot"
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _inventory() -> dict[str, dict]:
    data = yaml.safe_load(ASSETS.read_text(encoding="utf-8"))
    return {str(asset["ip"]): asset for asset in data["assets"]}


def test_every_asset_has_a_role_zone_and_criticality() -> None:
    inventory = _inventory()
    assert inventory
    for ip, asset in inventory.items():
        ipaddress.ip_address(ip)
        assert asset["role"], ip
        assert asset["zone"], ip
        assert asset["criticality"] in {"low", "medium", "high", "critical"}, ip


def test_sigma_ip_literals_are_in_the_inventory() -> None:
    inventory = _inventory()
    missing: list[str] = []
    for path in sorted(SIGMA.glob("*.yml")):
        if ".test." in path.name:
            continue
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"^\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$", text, re.MULTILINE):
            ip = match.group(1)
            if ip not in inventory:
                missing.append(f"{path.name}: {ip}")
    assert not missing, "Sigma allowlist IPs not in metadata/assets.yaml: " + ", ".join(missing)


def test_conduit_source_scopes_are_in_the_inventory() -> None:
    inventory = _inventory()
    policy = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    missing = [
        source
        for conduit in policy["conduits"]
        for source in conduit.get("sources", [])
        if source not in inventory
    ]
    assert not missing, f"conduit sources not in the inventory: {missing}"


def test_change_calendar_endpoints_are_in_the_inventory() -> None:
    inventory = _inventory()
    calendar = yaml.safe_load(CALENDAR.read_text(encoding="utf-8"))
    missing = [
        value
        for window in calendar["windows"]
        for value in (window["src_ip"], window["dst_ip"])
        if value not in inventory
    ]
    assert not missing, f"change-window endpoints not in the inventory: {missing}"


def test_every_conduit_zone_is_declared() -> None:
    policy = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    zones = {zone["name"] for zone in policy["zones"]}
    for conduit in policy["conduits"]:
        assert conduit["from"] in zones, conduit
        assert conduit["to"] in zones, conduit
