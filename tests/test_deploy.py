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

from sigma.collection import SigmaCollection  # noqa: E402

from deploy import build_bundle, check_bundle  # noqa: E402
from tools.otde.rules import (  # noqa: E402
    correlation_rule_paths,
    is_correlation_rule,
    single_event_rule_paths,
)
from tools.otde.suricata import read_rules  # noqa: E402

DEPLOY_DIR = REPO_ROOT / "deploy"


def services_for_correlation(rule_path: Path) -> set[str]:
    """Loki streams a correlation's subquery must select, from its references."""
    collection = SigmaCollection.load_ruleset([REPO_ROOT / "rules" / "sigma"])
    for rule in collection.rules:
        if Path(rule.source.path) == rule_path:
            return {
                reference.rule.logsource.service
                for reference in rule.referenced_rules
                if reference.rule is not None
            }
    return set()


def test_committed_bundle_matches_the_rules() -> None:
    assert check_bundle(build_bundle(), DEPLOY_DIR) == []


# backend key, artifact directory, extension
TARGETS = (
    ("loki", "loki/rules", "yaml"),
    ("splunk", "splunk", "conf"),
    ("sentinel", "sentinel", "kql"),
    ("opensearch", "opensearch", "ppl"),
)


def test_every_single_event_rule_has_artifacts_for_every_target() -> None:
    bundle = build_bundle()
    for rule_path in single_event_rule_paths():
        stem = rule_path.stem
        for _, directory, extension in TARGETS:
            assert f"{directory}/{stem}.{extension}" in bundle


def test_every_rule_is_either_emitted_or_recorded_as_unsupported() -> None:
    # A correlation rule cannot be converted by every backend in the matrix, so
    # the ones that cannot must appear in the manifest as unsupported. An
    # artifact that is simply absent is the failure mode this guards against.
    bundle = build_bundle()
    manifest = json.loads((DEPLOY_DIR / "manifest.json").read_text(encoding="utf-8"))
    recorded = {(entry["source"], entry["backend"]) for entry in manifest["unsupported"]}

    correlation_paths = correlation_rule_paths()
    assert correlation_paths, "no correlation rules found"

    for rule_path in correlation_paths:
        source = rule_path.relative_to(REPO_ROOT).as_posix()
        for backend, directory, extension in TARGETS:
            artifact = f"{directory}/{rule_path.stem}.{extension}"
            if artifact in bundle:
                assert (source, backend) not in recorded, (
                    f"{artifact} is emitted and recorded as unsupported"
                )
            else:
                assert (source, backend) in recorded, (
                    f"{artifact} is missing from the bundle with no recorded reason"
                )


def test_unsupported_entries_name_a_real_reason() -> None:
    manifest = json.loads((DEPLOY_DIR / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["unsupported"]:
        assert (REPO_ROOT / entry["source"]).exists(), entry["source"]
        assert entry["reason"].strip(), entry
        assert entry["backend"] in {name for name, _, _ in TARGETS}, entry


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
    # let a rule match another protocol's events in a shared Loki instance. A
    # correlation has no logsource of its own and inherits the selector of the
    # rules it references, so it is checked against those.
    for rule_file in sorted((DEPLOY_DIR / "loki" / "rules").glob("*.yaml")):
        source = REPO_ROOT / "rules" / "sigma" / "ot" / f"{rule_file.stem}.yml"
        document = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        expr = document["groups"][0]["rules"][0]["expr"]

        if is_correlation_rule(source):
            services = services_for_correlation(source)
            assert services, f"{rule_file.name} has no referenced logsource service"
            for service in services:
                assert f'service="{service}"' in expr, (
                    f"{rule_file.name} does not route on {service}"
                )
        else:
            service = SigmaRule.from_yaml(source.read_text(encoding="utf-8")).logsource.service
            assert service, f"{rule_file.name} has no logsource service"
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
