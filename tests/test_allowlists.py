"""Guard the generated detection allowlists."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from tools.allowlists import GENERATED, build, render  # noqa: E402

ASSETS = REPO_ROOT / "metadata" / "assets.yaml"


def test_every_exclusion_binds_to_one_declared_allowlist() -> None:
    built = build()
    assert built["errors"] == [], built["errors"]


def test_generated_file_is_current() -> None:
    assert GENERATED.read_text(encoding="utf-8") == render(build())


def test_members_resolve_to_the_declared_roles() -> None:
    assets = {
        str(asset["ip"]): asset
        for asset in yaml.safe_load(ASSETS.read_text(encoding="utf-8"))["assets"]
    }
    for allowlist in build()["allowlists"]:
        for member in allowlist["members"]:
            assert assets[member["ip"]]["role"] == member["role"]
            assert member["zone"]
