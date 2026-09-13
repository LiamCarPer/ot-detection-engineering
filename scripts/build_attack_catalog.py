"""Build a reduced ATT&CK for ICS technique catalog from the upstream STIX bundle.

MITRE publishes the ATT&CK for ICS dataset as a STIX 2.1 collection (~4 MB) at
``mitre-attack/attack-stix-data``. Detection content only needs the technique
identifiers, names and tactic membership, so this script reduces the bundle to a
small, deterministic catalog that is committed to the repository. Keeping the
catalog in-tree means CI does not need network access to validate coverage.

Usage:
    python scripts/build_attack_catalog.py \
        --stix /tmp/ics-attack.json \
        --out metadata/attack_ics_catalog.json

If ``--stix`` is omitted the bundle is downloaded from the URL in
``STIX_SOURCE_URL``; the download is not cached by design, so re-running the
command always reflects the upstream release requested by ``--version``.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

STIX_SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/ics-attack/ics-attack.json"
)

CATALOG_VERSION = 1


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def _attack_url(technique_id: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique_id}/"


def build_catalog(stix: dict[str, Any]) -> dict[str, Any]:
    """Reduce a raw ATT&CK for ICS STIX bundle to the catalog structure."""
    objects = stix.get("objects", [])

    tactics: list[dict[str, Any]] = []
    for obj in objects:
        if obj.get("type") != "x-mitre-tactic":
            continue
        tactic_id = _external_id(obj)
        if not tactic_id:
            continue
        tactics.append(
            {
                "id": tactic_id,
                "name": obj["name"],
                "shortname": obj.get("x_mitre_shortname", ""),
            }
        )
    tactics.sort(key=lambda t: t["id"])

    shortname_to_tactic = {t["shortname"]: t for t in tactics}

    techniques: list[dict[str, Any]] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique_id = _external_id(obj)
        if not technique_id:
            continue

        tactic_ids: list[str] = []
        for phase in obj.get("kill_chain_phases", []):
            tactic = shortname_to_tactic.get(phase.get("phase_name", ""))
            if tactic and tactic["id"] not in tactic_ids:
                tactic_ids.append(tactic["id"])

        techniques.append(
            {
                "id": technique_id,
                "name": obj["name"],
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
                "tactics": tactic_ids,
                "url": _attack_url(technique_id),
            }
        )
    techniques.sort(key=lambda t: t["id"])

    collection = next(
        (o for o in objects if o.get("type") == "x-mitre-collection"), {}
    )

    return {
        "catalog_version": CATALOG_VERSION,
        "source": "MITRE ATT&CK for ICS",
        "attack_version": collection.get("x_mitre_version", "unknown"),
        "attack_release_date": collection.get("modified", "")[:10],
        "source_url": STIX_SOURCE_URL,
        "tactics": tactics,
        "techniques": techniques,
    }


def _load_stix(path: str | None) -> dict[str, Any]:
    if path:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    with urllib.request.urlopen(STIX_SOURCE_URL, timeout=120) as response:
        return json.loads(response.read().decode("utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stix", help="Path to a local ics-attack.json bundle")
    parser.add_argument(
        "--out",
        default="metadata/attack_ics_catalog.json",
        help="Destination catalog path",
    )
    args = parser.parse_args(argv)

    catalog = build_catalog(_load_stix(args.stix))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(catalog, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )

    print(
        f"Wrote {out} | ATT&CK for ICS v{catalog['attack_version']} | "
        f"{len(catalog['tactics'])} tactics | "
        f"{len(catalog['techniques'])} techniques"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
