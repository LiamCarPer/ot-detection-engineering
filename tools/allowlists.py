"""Generate the detection allowlists from the asset inventory.

Every protocol rule that excludes an approved source carries an IP literal. That
literal is a policy statement, and it drifts: a host changes role, the inventory
is updated, and the rule still trusts the old address. This tool resolves each
declared allowlist against ``metadata/assets.yaml``, checks that every exclusion
in a Sigma or native rule is one of the declared sets, and writes the resolved
allowlist for review and for the site's firewall/EDR.

The inventory's ``services`` field records what a host *can* speak. An allowlist
records what a host is *authorized* to do. They are different questions, which is
why the HMI appears in the OPC UA write allowlist without listing ``opcua`` as a
service.

Usage:
    python tools/allowlists.py
    python tools/allowlists.py --check
"""

from __future__ import annotations

import argparse
import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ASSETS = REPO_ROOT / "metadata" / "assets.yaml"
DECLARED = REPO_ROOT / "metadata" / "allowlists.yaml"
GENERATED = REPO_ROOT / "metadata" / "allowlists.generated.yaml"
SIGMA = REPO_ROOT / "rules" / "sigma" / "ot"
NATIVE = REPO_ROOT / "rules" / "native" / "suricata"
IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
NEGATED_IP = re.compile(r"!(\d{1,3}(?:\.\d{1,3}){3})")


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def inventory() -> dict[str, dict[str, Any]]:
    return {str(asset["ip"]): asset for asset in _load(ASSETS)["assets"]}


def declared() -> list[dict[str, Any]]:
    return list(_load(DECLARED)["allowlists"])


def _as_set(value: Any) -> set[str]:
    if isinstance(value, list):
        return {str(item) for item in value}
    return {str(value)}


def extracted_sigma() -> list[dict[str, Any]]:
    """Every Sigma selection that excludes a source address."""
    found: list[dict[str, Any]] = []
    for path in sorted(SIGMA.glob("*.yml")):
        if ".test." in path.name:
            continue
        rule = _load(path)
        detection = rule.get("detection")
        if not isinstance(detection, dict):
            continue
        for name, selection in detection.items():
            if not isinstance(selection, dict) or "src_ip" not in selection:
                continue
            if not name.startswith("filter_"):
                continue
            members = _as_set(selection["src_ip"])
            if members and all(IPV4.match(member) for member in members):
                found.append(
                    {
                        "kind": "sigma",
                        "source": path.relative_to(REPO_ROOT).as_posix(),
                        "name": name,
                        "members": members,
                    }
                )
    return found


def extracted_native() -> list[dict[str, Any]]:
    """Every native rule whose source match negates an address."""
    found: list[dict[str, Any]] = []
    for path in sorted(NATIVE.glob("*.rules")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.startswith("alert "):
                continue
            members = set(NEGATED_IP.findall(line))
            if not members:
                continue
            sid = re.search(r"sid:(\d+);", line)
            found.append(
                {
                    "kind": "native",
                    "source": path.relative_to(REPO_ROOT).as_posix(),
                    "name": f"sid:{sid.group(1)}" if sid else "sid:unknown",
                    "members": members,
                }
            )
    return found


def _binding(item: dict[str, Any], use: dict[str, Any]) -> bool:
    detection = item.get("detection", {})
    if use["kind"] == "sigma":
        return use["source"] in detection.get("sigma", [])
    sid = use["name"].removeprefix("sid:")
    return sid.isdigit() and int(sid) in detection.get("native", [])


def build() -> dict[str, Any]:
    assets = inventory()
    sets = declared()
    errors: list[str] = []

    for item in sets:
        name = item["name"]
        members = _as_set(item["members"])
        for member in members:
            ipaddress.ip_address(member)
            asset = assets.get(member)
            if asset is None:
                errors.append(f"{name}: {member} is not in metadata/assets.yaml")
                continue
            if asset["role"] not in item["roles"]:
                errors.append(
                    f"{name}: {member} has role {asset['role']!r}, "
                    f"declared roles are {item['roles']}"
                )

    usage: dict[str, dict[str, list[str]]] = {
        item["name"]: {"sigma": [], "native": []} for item in sets
    }
    for use in extracted_sigma() + extracted_native():
        bound = [item for item in sets if _binding(item, use)]
        label = f"{use['source']} ({use['name']})"
        if not bound:
            errors.append(
                f"{label} excludes {sorted(use['members'])}, which is not bound "
                "to a declared allowlist in metadata/allowlists.yaml"
            )
            continue
        if len(bound) > 1:
            errors.append(f"{label} is bound to more than one allowlist")
            continue
        item = bound[0]
        if _as_set(item["members"]) != use["members"]:
            errors.append(
                f"{label} excludes {sorted(use['members'])}, but "
                f"{item['name']} declares {sorted(_as_set(item['members']))}"
            )
        usage[item["name"]][use["kind"]].append(label)

    for item in sets:
        detection = item.get("detection", {})
        if not detection.get("sigma") and not detection.get("native"):
            errors.append(f"{item['name']}: declared but no rule is bound to it")
        for source in detection.get("sigma", []):
            if not any(source in label for label in usage[item["name"]]["sigma"]):
                errors.append(f"{source} is bound to {item['name']} but has no filter")
        for sid in detection.get("native", []):
            if not any(f"sid:{sid}" in label for label in usage[item["name"]]["native"]):
                errors.append(f"sid:{sid} is bound to {item['name']} but is absent")

    if errors:
        return {"errors": errors, "allowlists": []}

    rendered = []
    for item in sorted(sets, key=lambda entry: entry["name"]):
        members = sorted(_as_set(item["members"]), key=ipaddress.ip_address)
        rendered.append(
            {
                "name": item["name"],
                "purpose": item.get("purpose", ""),
                "members": [
                    {
                        "ip": member,
                        "role": assets[member]["role"],
                        "zone": assets[member]["zone"],
                        "criticality": assets[member]["criticality"],
                    }
                    for member in members
                ],
                "used_by": {
                    "sigma": sorted(usage[item["name"]]["sigma"]),
                    "native": sorted(usage[item["name"]]["native"]),
                },
            }
        )
    return {"errors": [], "allowlists": rendered}


def render(built: dict[str, Any]) -> str:
    header = (
        "# Generated by tools/allowlists.py from metadata/assets.yaml and\n"
        "# metadata/allowlists.yaml. Do not edit by hand.\n"
    )
    return header + yaml.safe_dump(
        {"version": 1, "allowlists": built["allowlists"]},
        sort_keys=False,
        default_flow_style=False,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    built = build()
    if built["errors"]:
        print("allowlist validation failed:")
        for error in built["errors"]:
            print(f"  - {error}")
        return 1
    text = render(built)
    if args.check:
        if not GENERATED.exists() or GENERATED.read_text(encoding="utf-8") != text:
            print(f"generated allowlists are stale: run `make allowlists` ({GENERATED})")
            return 1
        print(f"allowlists are current: {len(built['allowlists'])} sets")
        return 0
    GENERATED.write_text(text, encoding="utf-8")
    print(f"wrote {len(built['allowlists'])} allowlists to {GENERATED}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
