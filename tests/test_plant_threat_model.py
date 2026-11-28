"""Keep the plant threat model tied to the inventory, catalogue and rules."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
MODEL = REPO_ROOT / "metadata" / "plant-threat-model.yaml"
POLICY = REPO_ROOT / "metadata" / "ot-conduit-policy.yaml"
ASSETS = REPO_ROOT / "metadata" / "assets.yaml"
CATALOGUE = REPO_ROOT / "metadata" / "attack_ics_catalog.json"


def _model() -> dict:
    return yaml.safe_load(MODEL.read_text(encoding="utf-8"))


def test_every_zone_and_asset_is_declared() -> None:
    model = _model()
    zones = {zone["name"] for zone in yaml.safe_load(POLICY.read_text())["zones"]}
    assets = {
        str(asset["ip"])
        for asset in yaml.safe_load(ASSETS.read_text(encoding="utf-8"))["assets"]
    }
    assert set(model["zones"]) == zones
    assert set(model["assets"]) <= assets
    for path in model["paths"]:
        assert path["entry_zone"] in zones
        assert path["target_zone"] in zones
        assert path["target_asset"] in assets


def test_every_technique_is_in_the_pinned_catalogue() -> None:
    catalogue = json.loads(CATALOGUE.read_text(encoding="utf-8"))
    known = {technique["id"] for technique in catalogue["techniques"]}
    for path in _model()["paths"]:
        assert set(path["techniques"]) <= known, path["id"]


def test_every_detection_exists_and_every_path_has_a_gap() -> None:
    for path in _model()["paths"]:
        assert path["detections"], path["id"]
        for detection in path["detections"]:
            assert (REPO_ROOT / detection).exists(), detection
        assert path["gaps"], path["id"]
