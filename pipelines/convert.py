"""Convert Sigma rules into target query languages and record provenance.

The repository keeps a single source of truth for log-based detections: the
Sigma rule. This pipeline turns each rule into the query language of a target
platform and writes a manifest that links the generated artifact back to the
exact rule revision that produced it (source path and SHA-256).

Generated output is deterministic: no timestamps are written, so a change in the
diff always corresponds to a change in a rule.

Usage:
    python pipelines/convert.py --backend loki
    python pipelines/convert.py --backend opensearch
    python pipelines/convert.py --backend splunk
    python pipelines/convert.py --backend sentinel
    python pipelines/convert.py --backend splunk --check
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from sigma.backends.kusto import KustoBackend
from sigma.backends.loki import LogQLBackend
from sigma.backends.opensearch import OpenSearchPPLBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.conversion.state import ConversionState
from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationType
from sigma.rule import SigmaRule

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from loki_pipeline import LOKI_LOGSOURCE_PIPELINE  # noqa: E402


class ConversionError(RuntimeError):
    """Raised when a rule produces no output, which is almost always a mistake."""


# The Sentinel workspace table every generated KQL query reads. A bare Sigma
# predicate is not a KQL query: Kusto needs a table (or a stream/dataset
# expression) to run against. The deployment bundle writes plain queries, so the
# table is supplied here instead of being configured in deploy/.
SENTINEL_TABLE = "OTTelemetry"

# Correlation types the pipeline can render for Sentinel. The pinned Kusto
# backend has no correlation support at all, so these are built directly from
# the referenced rules' cached queries.
SENTINEL_CORRELATION_TYPES = {
    SigmaCorrelationType.EVENT_COUNT,
    SigmaCorrelationType.VALUE_COUNT,
}

_QUERY_OPERATORS = {
    "EQ": "==",
    "NE": "!=",
    "LT": "<",
    "LTE": "<=",
    "GT": ">",
    "GTE": ">=",
}


_PPL_LITERAL_RE = re.compile(r"LIKE\([^)]*\)|'[^']*'")


def unescape_ppl_equality(query: str) -> str:
    """Undo wildcard escaping where PPL compares literal values.

    pySigma escapes ``_`` because it is PPL's single-character wildcard. That is
    right inside ``LIKE()`` and wrong in ``field = "login_failure"`` and
    ``IN (...)``, where the value is literal: the escape turns a correct match
    into a search for a backslash. The generated artifact was executable but
    never matched its own test event until this ran.
    """
    literals: list[str] = []

    def keep(match: re.Match[str]) -> str:
        literals.append(match.group(0))
        return f"\x00{len(literals) - 1}\x00"

    masked = _PPL_LITERAL_RE.sub(keep, query)
    masked = masked.replace("\\_", "_")
    return re.sub(
        r"\x00(\d+)\x00", lambda match: literals[int(match.group(1))], masked
    )


class OpenSearchPPLWindowBackend(OpenSearchPPLBackend):
    """OpenSearch PPL backend that keeps a correlation's time window.

    The pinned backend's ``event_count`` and ``value_count`` aggregation
    templates group only by the correlation's ``group-by`` fields. They drop the
    correlation timespan entirely, which turns "ten exceptions in five minutes"
    into "ten exceptions, ever". ``span()`` is PPL's bucketed-time grouping, so
    adding it to the aggregation preserves the window and still leaves the
    group-by fields in place.
    """

    def finalize_query_default(
        self, rule: SigmaRule, query: str, index: int, state: ConversionState
    ) -> str:
        # Every PPL query, including a correlation's cached subqueries, passes
        # through here; correcting the escaping before caching keeps the emitted
        # artifact and the subqueries consistent.
        return unescape_ppl_equality(
            super().finalize_query_default(rule, query, index, state)
        )

    event_count_aggregation_expression = {
        "default": "count() as event_count by span({time_field}, {timespan}){groupby}"
    }
    value_count_aggregation_expression = {
        "default": "dc({field}) as value_count by span({time_field}, {timespan}){groupby}"
    }

    def convert_correlation_aggregation_groupby_from_template(
        self, group_by, method: str
    ) -> str:
        fields = super().convert_correlation_aggregation_groupby_from_template(group_by, method)
        # The window comes first in the aggregation, so a group-by list is a
        # comma-separated suffix rather than the leading value the parent
        # backend's template expects.
        return f", {fields}" if fields else ""


class SentinelKustoBackend(KustoBackend):
    """Kusto backend with Sentinel correlation conversion opted in.

    The backend's conversion of a correlation is supplied by this pipeline (see
    :func:`sentinel_correlation_query`), but declaring ``correlation_methods``
    is what makes ``backend_supports_correlation()`` accept the rule, so the
    artifact is emitted instead of being recorded as unsupported.
    """

    correlation_methods = {"default": "Sentinel correlation generated by the pipeline"}

    def convert_correlation_rule(
        self,
        rule: SigmaCorrelationRule,
        output_format: str | None = None,
        method: str | None = None,
        callback=None,
    ) -> list[str]:
        return [sentinel_correlation_query(rule)]


BACKENDS = {
    "loki": (LogQLBackend, "logql"),
    "opensearch": (OpenSearchPPLWindowBackend, "ppl"),
    "splunk": (SplunkBackend, "spl"),
    "sentinel": (SentinelKustoBackend, "kql"),
}


def make_backend(backend_name: str):
    """Instantiate a backend, applying the Loki logsource-routing pipeline.

    The Loki backend needs the pipeline so its queries select the rule's stream
    by the ``service`` label instead of matching every stream. Other backends
    route through their own index/source handling.

    ``finalize_correlation_subqueries`` is enabled so a rule that a correlation
    references is still finalised when it is emitted in its own right. Without
    it, a correlation with ``generate: true`` would emit the referenced rule
    *unfinalised* — a Splunk saved search would lose its stanza, for example —
    and the rule's own artifact would change the moment a correlation started
    referencing it.
    """
    backend_cls, _ = BACKENDS[backend_name]
    backend = (
        backend_cls(processing_pipeline=LOKI_LOGSOURCE_PIPELINE)
        if backend_name == "loki"
        else backend_cls()
    )
    backend.finalize_correlation_subqueries = True
    return backend


def rule_files(rules_dir: Path) -> list[Path]:
    # Sidecars are *.test.yaml; the guard keeps a *.test.yml sidecar out.
    return sorted(path for path in rules_dir.rglob("*.yml") if ".test." not in path.name)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_ruleset(rules_dir: Path) -> SigmaCollection:
    """Load every Sigma rule at once, with correlation references resolved.

    A correlation rule names rules that live in other files, so loading one file
    at a time cannot resolve it.
    """
    return SigmaCollection.load_ruleset([rules_dir])


def conversion_order(collection: SigmaCollection) -> list:
    """Order rules so a referenced rule is converted before its correlation.

    A correlation reads the conversion result of the rules it references, so the
    order is a real dependency, not a detail. pySigma sorts a collection by
    backreference but that comparison is not a total order, so the result still
    depends on the order the files were listed in — which differs between a
    developer's checkout and CI. This resolves the dependency explicitly, and
    refuses to guess when it cannot.
    """
    pending = list(collection.rules)
    ordered: list = []
    placed: set[int] = set()
    while pending:
        ready = [
            rule
            for rule in pending
            if all(
                reference.rule is None or id(reference.rule) in placed
                for reference in getattr(rule, "referenced_rules", [])
            )
        ]
        if not ready:
            raise ConversionError(
                "cannot order rules for conversion: a correlation references a rule that "
                "is not in the ruleset, or the references form a cycle"
            )
        for rule in ready:
            ordered.append(rule)
            placed.add(id(rule))
            pending.remove(rule)
    return ordered


def backend_supports_correlation(backend) -> bool:
    """Whether a backend implements correlation rule conversion.

    pySigma ships the correlation conversion methods on its base class, but a
    backend only opts in by declaring ``correlation_methods``. Loki, Splunk and
    OpenSearch declare it; the pinned Kusto backend does not, so
    :class:`SentinelKustoBackend` declares it and supplies the conversion here.
    A correlation a backend genuinely cannot express is recorded as unsupported
    rather than being silently dropped from the bundle or failing the build.
    """
    return backend.correlation_methods is not None


def correlated_query(reference) -> str:
    """Return the cached raw query for a rule referenced by a correlation."""
    result = reference.rule.get_conversion_result() if reference.rule is not None else None
    if not result:
        raise ConversionError(
            "correlation references a rule with no conversion result; the referenced "
            "rule must be converted before the correlation"
        )
    query = result[0]
    if not isinstance(query, str):
        raise ConversionError(
            "correlation references a rule whose conversion result is not a query"
        )
    return query


def sentinel_correlation_query(rule: SigmaCorrelationRule) -> str:
    """Render a Sentinel correlation as executable KQL.

    The pinned Kusto backend cannot convert correlation rules, and its output for
    an ordinary rule is a bare predicate. A Sentinel artifact therefore needs two
    things this pipeline adds: a table to run against and an aggregation that
    preserves the correlation's window and group-by fields.
    """
    if rule.type not in SENTINEL_CORRELATION_TYPES:
        raise ConversionError(
            f"Sentinel correlation type {rule.type.value!r} is not implemented"
        )

    condition = rule.condition
    fieldref = getattr(condition, "fieldref", None)
    if rule.type == SigmaCorrelationType.VALUE_COUNT and not fieldref:
        raise ConversionError("a value_count correlation must name the field it counts")

    searches = [correlated_query(reference) for reference in rule.referenced_rules]
    if not searches:
        raise ConversionError("a correlation must reference at least one rule")
    search = searches[0] if len(searches) == 1 else " or ".join(
        f"({query})" for query in searches
    )

    timespan = getattr(rule.timespan, "spec", None) or "5m"
    group_by = list(rule.group_by or [])
    grouping = ", ".join(["bin(TimeGenerated, " + timespan + ")"] + group_by)

    if rule.type == SigmaCorrelationType.VALUE_COUNT:
        metric = "value_count"
        aggregate = f"dcount({fieldref})"
    else:
        metric = "event_count"
        aggregate = "count()"

    try:
        operator = _QUERY_OPERATORS[condition.op.name]
    except KeyError as error:  # pragma: no cover - defensive
        raise ConversionError(f"unsupported correlation operator {condition.op.name!r}") from error

    return "\n".join(
        [
            SENTINEL_TABLE,
            f"| where {search}",
            f"| summarize {metric} = {aggregate} by {grouping}",
            f"| where {metric} {operator} {condition.count}",
        ]
    )


def correlation_unsupported_reason(backend, rule: SigmaCorrelationRule) -> str | None:
    """Return why a backend cannot emit this correlation, or ``None`` if it can."""
    if not backend_supports_correlation(backend):
        return "backend does not implement correlation conversion"
    if isinstance(backend, SentinelKustoBackend):
        if rule.type not in SENTINEL_CORRELATION_TYPES:
            return f"sentinel correlation type {rule.type.value!r} is not implemented"
        if rule.type == SigmaCorrelationType.VALUE_COUNT and not getattr(
            rule.condition, "fieldref", None
        ):
            return "a value_count correlation must name the field it counts"
    return None


def refresh_correlation_references(backend, rule, output_format: str | None) -> None:
    """Re-convert a correlation's references in the backend's default format.

    A correlation is built from the *cached* conversion results of its referenced
    rules. When the surrounding artifact is in a decorated output format, that
    cache holds decorated documents: for Splunk's ``savedsearches`` format it
    holds a complete saved-search stanza. Interpolating one of those into the
    correlation's ``search =`` value nests a stanza inside a stanza, which Splunk
    cannot parse. Converting the references again with the default format leaves
    a plain query in the cache, which is what the correlation needs.
    """
    if output_format in (None, backend.default_format):
        return
    for reference in rule.referenced_rules:
        if reference.rule is not None:
            backend.convert_rule(reference.rule, backend.default_format)
    backend.init_processing_pipeline(output_format)


def route_sentinel_query(query: str) -> str:
    """Prefix a bare Kusto predicate with the table it runs against."""
    if query.lstrip().startswith(f"{SENTINEL_TABLE}\n"):
        return query
    return f"{SENTINEL_TABLE}\n| where {query}"


def convert_rule_object(backend, rule, output_format: str | None = None) -> list[str]:
    """Convert one loaded rule into its finalized document(s).

    Correlation rules go through ``convert_correlation_rule``; everything else
    through ``convert_rule``. A rule that converts to nothing is an error rather
    than an empty artifact: the usual cause is a correlation that does not set
    ``generate: true``, which silently suppresses the rules it references and
    would quietly delete their alerts from the bundle.
    """
    if isinstance(rule, SigmaCorrelationRule):
        if not isinstance(backend, SentinelKustoBackend):
            refresh_correlation_references(backend, rule, output_format)
        queries = backend.convert_correlation_rule(rule, output_format)
    else:
        queries = backend.convert_rule(rule, output_format)
    if not queries:
        raise ConversionError(
            f"{rule.title!r} converted to no queries. If it is referenced by a correlation "
            "rule, set `generate: true` on that correlation so the referenced rule still "
            "produces output."
        )
    document = backend.finalize(queries, output_format or backend.default_format)
    documents = [document] if isinstance(document, str) else list(document)
    if isinstance(backend, SentinelKustoBackend):
        # Finalizing caches the raw predicate on the rule, which is exactly what
        # a later correlation needs. Routing to the table is therefore applied to
        # the emitted document, not to the cached conversion result.
        documents = [route_sentinel_query(query) for query in documents]
    return documents


def _relative(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def build_artifacts(
    backend_name: str, rules_dir: Path, output_format: str | None = None
) -> tuple[dict[str, str], dict]:
    _, extension = BACKENDS[backend_name]
    backend = make_backend(backend_name)
    output_format = output_format or backend.default_format
    backend.init_processing_pipeline(output_format)
    if backend_name == "splunk" and output_format == "savedsearches":
        # The Splunk backend's default format is a raw SPL query; the
        # savedsearches format is a stanza fragment installed as savedsearches.conf.
        extension = "conf"

    artifacts: dict[str, str] = {}
    manifest: list[dict] = []
    unsupported: list[dict] = []

    for rule in conversion_order(load_ruleset(rules_dir.resolve())):
        rule_path = Path(rule.source.path)
        relative = _relative(rule_path)
        if isinstance(rule, SigmaCorrelationRule):
            reason = correlation_unsupported_reason(backend, rule)
            if reason is not None:
                unsupported.append(
                    {"source": relative, "backend": backend_name, "reason": reason}
                )
                continue
        text = rule_path.read_text(encoding="utf-8")
        queries = convert_rule_object(backend, rule, output_format)
        artifact_name = f"{rule_path.stem}.{extension}"
        header = f"# source: {relative}\n# backend: {backend_name}\n"
        artifacts[artifact_name] = header + "\n".join(queries).rstrip("\n") + "\n"
        manifest.append(
            {
                "source": relative,
                "source_sha256": sha256(text),
                "artifact": artifact_name,
                "backend": backend_name,
                "queries": queries,
            }
        )

    return artifacts, {"backend": backend_name, "rules": manifest, "unsupported": unsupported}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", choices=sorted(BACKENDS), default="loki")
    parser.add_argument("--rules", default=str(REPO_ROOT / "rules" / "sigma"))
    parser.add_argument("--out", default=str(REPO_ROOT / "pipelines" / "out"))
    parser.add_argument(
        "--check",
        action="store_true",
        help="Convert without writing output; exit non-zero on failure.",
    )
    args = parser.parse_args(argv)

    artifacts, manifest = build_artifacts(args.backend, Path(args.rules))

    if args.check:
        print(f"{args.backend}: converted {len(manifest['rules'])} rules")
        return 0

    out_dir = Path(args.out) / args.backend
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, content in artifacts.items():
        (out_dir / name).write_text(content, encoding="utf-8")
    (Path(args.out) / f"manifest.{args.backend}.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )

    print(f"{args.backend}: wrote {len(artifacts)} artifacts to {out_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
