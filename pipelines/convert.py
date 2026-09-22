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
import sys
from pathlib import Path

from sigma.backends.kusto import KustoBackend
from sigma.backends.loki import LogQLBackend
from sigma.backends.opensearch import OpenSearchPPLBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from loki_pipeline import LOKI_LOGSOURCE_PIPELINE  # noqa: E402


class ConversionError(RuntimeError):
    """Raised when a rule produces no output, which is almost always a mistake."""


BACKENDS = {
    "loki": (LogQLBackend, "logql"),
    "opensearch": (OpenSearchPPLBackend, "ppl"),
    "splunk": (SplunkBackend, "spl"),
    "sentinel": (KustoBackend, "kql"),
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
    backend only opts in by declaring ``correlation_methods``, and of the pinned
    targets only Loki does. A correlation rule is therefore recorded as
    unsupported for the others rather than being silently dropped from the bundle
    or failing the whole build.
    """
    return backend.correlation_methods is not None


def convert_rule_object(backend, rule, output_format: str | None = None) -> list[str]:
    """Convert one loaded rule into its finalized document(s).

    Correlation rules go through ``convert_correlation_rule``; everything else
    through ``convert_rule``. A rule that converts to nothing is an error rather
    than an empty artifact: the usual cause is a correlation that does not set
    ``generate: true``, which silently suppresses the rules it references and
    would quietly delete their alerts from the bundle.
    """
    if isinstance(rule, SigmaCorrelationRule):
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
    return [document] if isinstance(document, str) else list(document)


def _relative(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def build_artifacts(backend_name: str, rules_dir: Path) -> tuple[dict[str, str], dict]:
    _, extension = BACKENDS[backend_name]
    backend = make_backend(backend_name)
    output_format = backend.default_format
    backend.init_processing_pipeline(output_format)

    artifacts: dict[str, str] = {}
    manifest: list[dict] = []
    unsupported: list[dict] = []

    for rule in conversion_order(load_ruleset(rules_dir.resolve())):
        rule_path = Path(rule.source.path)
        relative = _relative(rule_path)
        if isinstance(rule, SigmaCorrelationRule) and not backend_supports_correlation(backend):
            unsupported.append(
                {
                    "source": relative,
                    "backend": backend_name,
                    "reason": "backend does not implement correlation conversion",
                }
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
