"""Tests for the Sigma-to-backend conversion pipeline."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "pipelines"))

from convert import BACKENDS, build_artifacts, main  # noqa: E402


def test_all_backends_convert_every_rule() -> None:
    for backend_name in BACKENDS:
        artifacts, manifest = build_artifacts(backend_name, Path("rules/sigma"))
        assert artifacts
        assert len(artifacts) == len(manifest["rules"])
        assert all(entry["queries"] for entry in manifest["rules"])


def test_manifest_sources_are_relative_to_repo() -> None:
    _, manifest = build_artifacts("loki", Path("rules/sigma"))
    for entry in manifest["rules"]:
        assert not Path(entry["source"]).is_absolute()
        assert (REPO_ROOT / entry["source"]).exists()
        assert len(entry["source_sha256"]) == 64


def test_conversion_is_deterministic() -> None:
    first, _ = build_artifacts("loki", Path("rules/sigma"))
    second, _ = build_artifacts("loki", Path("rules/sigma"))
    assert first == second


def test_check_mode_succeeds() -> None:
    assert main(["--backend", "loki", "--check"]) == 0
