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
    python pipelines/convert.py --backend loki --check
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from sigma.backends.loki import LogQLBackend
from sigma.backends.opensearch import OpenSearchPPLBackend
from sigma.collection import SigmaCollection

REPO_ROOT = Path(__file__).resolve().parents[1]

BACKENDS = {
    "loki": (LogQLBackend, "logql"),
    "opensearch": (OpenSearchPPLBackend, "ppl"),
}


def rule_files(rules_dir: Path) -> list[Path]:
    return sorted(
        path for path in rules_dir.rglob("*.yml") if not path.name.endswith(".test.yml")
    )


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def convert_rule(backend, text: str) -> list[str]:
    collection = SigmaCollection.from_yaml(text)
    return backend.convert(collection)


def build_artifacts(backend_name: str, rules_dir: Path) -> tuple[dict[str, str], dict]:
    backend_cls, extension = BACKENDS[backend_name]
    backend = backend_cls()
    artifacts: dict[str, str] = {}
    manifest: list[dict] = []

    for rule_path in rule_files(rules_dir):
        text = rule_path.read_text(encoding="utf-8")
        queries = convert_rule(backend, text)
        relative = rule_path.relative_to(REPO_ROOT).as_posix()
        artifact_name = f"{rule_path.stem}.{extension}"
        header = f"# source: {relative}\n# backend: {backend_name}\n"
        artifacts[artifact_name] = header + "\n".join(queries) + "\n"
        manifest.append(
            {
                "source": relative,
                "source_sha256": sha256(text),
                "artifact": artifact_name,
                "backend": backend_name,
                "queries": queries,
            }
        )

    return artifacts, {"backend": backend_name, "rules": manifest}


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
