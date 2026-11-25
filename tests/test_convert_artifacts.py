"""Structural tests for the generated correlation artifacts.

The conversion pipeline is only useful if an operator can install what it emits.
A query that looks plausible in a diff is not enough: a Splunk saved search has
to be a valid stanza, an OpenSearch aggregation has to keep the correlation's
window, and a Sentinel query has to name the table it runs against.

These tests build the artifacts in memory and parse their structure. They do not
need a live Splunk, OpenSearch or Sentinel instance.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationType

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "pipelines"))

from convert import SENTINEL_TABLE, build_artifacts, load_ruleset  # noqa: E402

RULES_DIR = Path("rules/sigma")


def correlation_rules() -> list[SigmaCorrelationRule]:
    collection = load_ruleset((REPO_ROOT / RULES_DIR).resolve())
    return [rule for rule in collection.rules if isinstance(rule, SigmaCorrelationRule)]


CORRELATIONS = correlation_rules()


def _artifact_name(rule: SigmaCorrelationRule, extension: str) -> str:
    return f"{Path(rule.source.path).stem}.{extension}"


def _without_header(text: str) -> str:
    return "\n".join(
        line for line in text.splitlines() if not line.startswith(("#", "//"))
    ).strip()


def _parse_conf(text: str) -> tuple[dict[str, list[str]], list[str]]:
    """Parse a savedsearches.conf fragment and report nested stanza headers.

    A stanza starts at a line whose first character is ``[``. A header that
    appears while the previous stanza line is still a backslash continuation is
    the signature of a stanza interpolated into another stanza's ``search =``
    value, which is the defect this guards against.
    """
    stanzas: dict[str, list[str]] = {}
    nested: list[str] = []
    current: str | None = None
    previous_continues = False

    for line in text.splitlines():
        if line.startswith("["):
            if previous_continues:
                nested.append(line)
            current = line.strip().strip("[]")
            stanzas.setdefault(current, [])
            previous_continues = False
        elif current is not None:
            stanzas[current].append(line)
            previous_continues = line.rstrip().endswith("\\")

    return stanzas, nested


def test_correlation_rules_are_discovered() -> None:
    assert CORRELATIONS, "no correlation rules found under rules/sigma"


def test_splunk_correlation_is_a_single_flat_saved_search() -> None:
    artifacts, _ = build_artifacts("splunk", RULES_DIR, output_format="savedsearches")
    assert artifacts, "no Splunk saved searches were generated"

    for rule in CORRELATIONS:
        name = _artifact_name(rule, "conf")
        assert name in artifacts, f"{name} missing from the Splunk artifacts"

        stanzas, nested = _parse_conf(artifacts[name])
        assert not nested, f"{name} has a stanza nested inside a stanza: {nested}"

        correlation = stanzas.get(rule.title)
        assert correlation is not None, (
            f"{name} has no saved-search stanza for {rule.title!r}; "
            f"found {sorted(stanzas)}"
        )

        # The nested-stanza defect truncated the correlation's search at the
        # nested header, so it had no aggregation and no threshold.
        body = "\n".join(correlation)
        assert "search =" in body, f"{name} has no search setting"
        assert "| stats " in body, f"{name} has no correlation aggregation"
        assert f"span={rule.timespan.spec}" in body, (
            f"{name} lost the correlation window {rule.timespan.spec!r}: {body}"
        )
        assert ">=" in body, f"{name} carries no threshold"


def test_every_splunk_artifact_is_a_flat_stanza_fragment() -> None:
    artifacts, _ = build_artifacts("splunk", RULES_DIR, output_format="savedsearches")
    for name, text in artifacts.items():
        stanzas, nested = _parse_conf(text)
        assert stanzas, f"{name} has no stanza"
        assert not nested, f"{name} has a nested stanza header: {nested}"


def test_opensearch_correlation_keeps_the_window_and_grouping() -> None:
    artifacts, _ = build_artifacts("opensearch", RULES_DIR)

    for rule in CORRELATIONS:
        name = _artifact_name(rule, "ppl")
        assert name in artifacts, f"{name} missing from the OpenSearch artifacts"
        query = _without_header(artifacts[name])

        timespan = rule.timespan.spec
        assert f"span(@timestamp, {timespan})" in query, (
            f"{name} lost the correlation window {timespan!r}: {query}"
        )
        assert rule.group_by, f"{rule.title} has no group-by field"

        stats = next((line for line in query.splitlines() if "| stats " in line), "")
        assert stats, f"{name} has no stats aggregation: {query}"
        grouping = stats[stats.index(" by ") + len(" by ") :]
        assert grouping.startswith("span("), (
            f"{name} does not group on the correlation window first: {stats}"
        )
        for field in rule.group_by:
            assert field in grouping, f"{name} lost the grouping field {field!r}: {stats}"


def test_sentinel_correlation_queries_reference_the_table() -> None:
    artifacts, manifest = build_artifacts("sentinel", RULES_DIR)
    unsupported = {(entry["source"], entry["backend"]) for entry in manifest["unsupported"]}

    for rule in CORRELATIONS:
        name = _artifact_name(rule, "kql")
        assert name in artifacts, f"{name} missing from the Sentinel artifacts"
        source = Path(rule.source.path).relative_to(REPO_ROOT).as_posix()
        assert (source, "sentinel") not in unsupported, (
            f"{name} is recorded as unsupported but a KQL correlation is expressible"
        )

        query = _without_header(artifacts[name])
        lines = query.splitlines()
        assert lines[0] == SENTINEL_TABLE, (
            f"{name} does not start at the {SENTINEL_TABLE!r} table: {query}"
        )
        assert lines[1].startswith("| where "), f"{name} has no KQL filter: {query}"
        assert f"bin(TimeGenerated, {rule.timespan.spec})" in query, (
            f"{name} lost the correlation window: {query}"
        )
        for field in rule.group_by:
            assert field in query, f"{name} lost the grouping field {field!r}: {query}"
        assert ">=" in query, f"{name} carries no threshold"


def test_every_sentinel_query_references_a_table() -> None:
    artifacts, _ = build_artifacts("sentinel", RULES_DIR)
    for name, text in artifacts.items():
        query = _without_header(text)
        assert query.startswith(SENTINEL_TABLE), (
            f"{name} is a bare predicate, not an executable KQL query: {query}"
        )


@pytest.mark.parametrize("backend_name", ["loki", "opensearch", "splunk", "sentinel"])
def test_correlations_are_emitted_or_recorded_as_unsupported(backend_name: str) -> None:
    extension = {"loki": "logql", "opensearch": "ppl", "splunk": "spl", "sentinel": "kql"}[
        backend_name
    ]
    artifacts, manifest = build_artifacts(backend_name, RULES_DIR)
    unsupported = {
        (entry["source"], entry["backend"]): entry["reason"]
        for entry in manifest["unsupported"]
    }

    for rule in CORRELATIONS:
        name = _artifact_name(rule, extension)
        source = Path(rule.source.path).relative_to(REPO_ROOT).as_posix()
        if name in artifacts:
            assert (source, backend_name) not in unsupported, (
                f"{name} is emitted and also recorded as unsupported"
            )
        else:
            assert (source, backend_name) in unsupported, (
                f"{name} is missing with no recorded reason"
            )
            assert unsupported[(source, backend_name)].strip(), name


def test_sentinel_value_count_uses_the_condition_field() -> None:
    """The count has to be a distinct count of the field the rule names."""
    artifacts, _ = build_artifacts("sentinel", RULES_DIR)
    for rule in CORRELATIONS:
        if rule.type != SigmaCorrelationType.VALUE_COUNT:
            continue
        query = _without_header(artifacts[_artifact_name(rule, "kql")])
        assert f"dcount({rule.condition.fieldref})" in query, (
            f"{rule.title} does not count {rule.condition.fieldref!r}: {query}"
        )
