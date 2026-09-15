"""Tests for the deployment bundle."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import yaml
from sigma.rule import SigmaRule

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "pipelines"))

from deploy import build_bundle, check_bundle  # noqa: E402
from tools.otde.rules import sigma_rule_paths  # noqa: E402
from tools.otde.suricata import read_rules  # noqa: E402

DEPLOY_DIR = REPO_ROOT / "deploy"


def test_committed_bundle_matches_the_rules() -> None:
    assert check_bundle(build_bundle(), DEPLOY_DIR) == []


def test_every_rule_has_artifacts_for_every_target() -> None:
    bundle = build_bundle()
    for rule_path in sigma_rule_paths():
        stem = rule_path.stem
        for target, extension in (
            ("loki/rules", "yaml"),
            ("splunk", "conf"),
            ("sentinel", "kql"),
            ("opensearch", "ppl"),
        ):
            assert f"{target}/{stem}.{extension}" in bundle


def test_manifest_provenance_is_correct() -> None:
    manifest = json.loads((DEPLOY_DIR / "manifest.json").read_text(encoding="utf-8"))
    for artifact in manifest["artifacts"]:
        source = REPO_ROOT / artifact["source"]
        assert source.exists(), artifact["source"]
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        assert digest == artifact["source_sha256"], artifact["source"]


def test_loki_rules_are_valid_ruler_yaml() -> None:
    for rule_file in sorted((DEPLOY_DIR / "loki" / "rules").glob("*.yaml")):
        document = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        assert "groups" in document, rule_file.name
        for group in document["groups"]:
            assert group["rules"], rule_file.name
            assert group["rules"][0]["expr"], rule_file.name


def test_loki_rules_route_by_logsource_service() -> None:
    # pySigma does not encode the Sigma logsource into the LogQL stream selector,
    # so the deploy pipeline sets it explicitly. Without it, {job=~".+"} would
    # let a rule match another protocol's events in a shared Loki instance.
    for rule_file in sorted((DEPLOY_DIR / "loki" / "rules").glob("*.yaml")):
        source = REPO_ROOT / "rules" / "sigma" / "ot" / f"{rule_file.stem}.yml"
        rule = SigmaRule.from_yaml(source.read_text(encoding="utf-8"))
        service = rule.logsource.service
        assert service, f"{rule_file.name} has no logsource service"
        document = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        expr = document["groups"][0]["rules"][0]["expr"]
        assert f'service="{service}"' in expr, f"{rule_file.name} does not route on {service}"


def test_loki_group_names_are_unique() -> None:
    # Loki keys rule groups by name within a namespace, so the files must not
    # all reuse the backend's default group name.
    names = []
    for rule_file in sorted((DEPLOY_DIR / "loki" / "rules").glob("*.yaml")):
        document = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        names.extend(group["name"] for group in document["groups"])
    assert len(names) == len(set(names)), f"duplicate Loki group names: {names}"


def test_suricata_bundle_contains_every_native_sid() -> None:
    bundle = (DEPLOY_DIR / "suricata" / "ot-detection.rules").read_text(encoding="utf-8")
    expected = set()
    for rule_path in (REPO_ROOT / "rules" / "native").rglob("*.rules"):
        for rule in read_rules(rule_path):
            if rule.sid is not None:
                expected.add(rule.sid)
    for sid in expected:
        assert f"sid:{sid};" in bundle, f"sid {sid} missing from bundle"
