"""Execute the converted queries in real engines and compare with the matcher.

`make convert-all` proves that every rule has a syntactically produced artifact.
It does not prove that the Splunk, OpenSearch or Kusto query selects the same
events as the repository matcher. This harness does.

The corpus is the committed held-out positives, the near-misses and the benign
corpus. Each event gets a ``parity_id``; the golden result for a rule is the set
of ids the repository matcher returns. The converted query is then executed in
the real engine and the returned id set is compared exactly.

Single-event rules only. Correlation rules aggregate over windows and are
covered by the local stateful/correlation harness and the live Loki run.

Engines:

- Splunk Free (``deploy/splunk/docker-compose.yml``) over the HEC-fed index.
- OpenSearch (any cluster with the PPL plugin) over ``*-parity`` indices.
- Kusto (``kustainer``) over the ``OTTelemetry`` table.

Loki is measured separately on live lab traffic by ``make lab-loki-check``.

Usage:
    python tools/engine_parity.py --out deploy/evidence/engine-parity
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sigma.rule import SigmaRule  # noqa: E402

from tools.otde.matcher import match  # noqa: E402
from tools.otde.rules import single_event_rule_paths  # noqa: E402

OUT_DIR = REPO_ROOT / "deploy" / "evidence" / "engine-parity"
DEPLOY = REPO_ROOT / "deploy"
HELDOUT = REPO_ROOT / "metrics" / "heldout"
BENIGN = REPO_ROOT / "metrics" / "baseline" / "benign-events.jsonl"

SPLUNK_REST = "https://127.0.0.1:18089"
SPLUNK_HEC = "https://127.0.0.1:18088"
OPEN_SEARCH = "http://127.0.0.1:19200"
KUSTO = "http://127.0.0.1:18080"
KUSTO_DB = "NetDefaultDB"
KUSTO_TABLE = "OTTelemetry"

CASE_INSENSITIVE_CTX = ssl.create_default_context()
CASE_INSENSITIVE_CTX.check_hostname = False
CASE_INSENSITIVE_CTX.verify_mode = ssl.CERT_NONE


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _corpus() -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in _jsonl(HELDOUT / "positives.jsonl"):
        events.append(row["event"])
    events.extend(_jsonl(HELDOUT / "near-misses.jsonl"))
    events.extend(_jsonl(BENIGN))
    normalized: list[dict[str, Any]] = []
    for index, event in enumerate(events):
        row = dict(event)
        row["parity_id"] = f"e{index:05d}"
        row["initiated"] = str(row["initiated"]).lower() if "initiated" in row else ""
        if "status" in row:
            row["status"] = str(row["status"])
        normalized.append(row)
    return normalized


def _rules() -> list[tuple[str, SigmaRule]]:
    return [
        (
            path.relative_to(REPO_ROOT).as_posix(),
            SigmaRule.from_yaml(path.read_text(encoding="utf-8")),
        )
        for path in single_event_rule_paths()
    ]


def _golden(events: list[dict], rules: list[tuple[str, SigmaRule]]) -> dict[str, set[str]]:
    golden: dict[str, set[str]] = {}
    for name, rule in rules:
        golden[name] = {
            event["parity_id"] for event in events if match(rule, event)
        }
    return golden


def _manifest() -> dict[str, str]:
    """Map a rule source path to its converted artifact, per backend."""
    manifest = json.loads((DEPLOY / "manifest.json").read_text(encoding="utf-8"))
    mapping: dict[str, str] = {}
    for artifact in manifest["artifacts"]:
        mapping.setdefault(artifact["source"], artifact["target"])
    return mapping


def _artifact_for(source: str, backend: str) -> Path | None:
    manifest = json.loads((DEPLOY / "manifest.json").read_text(encoding="utf-8"))
    for artifact in manifest["artifacts"]:
        if artifact["source"] == source and artifact["backend"] == backend:
            path = DEPLOY / artifact["target"]
            if path.exists():
                return path
    return None


# --------------------------------------------------------------------------- HTTP


def _http(
    url: str,
    payload: Any = None,
    *,
    method: str | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 120,
) -> Any:
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json", **(headers or {})}
    request = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    context = CASE_INSENSITIVE_CTX if url.startswith("https") else None
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:  # nosec B310
        body = response.read().decode()
    return json.loads(body) if body.strip().startswith(("{", "[")) else body


# ------------------------------------------------------------------------- Splunk


def _splunk_wait(timeout: int = 300) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            _http(
                f"{SPLUNK_REST}/services/server/info?output_mode=json",
                timeout=5,
            )
            return
        except (urllib.error.URLError, TimeoutError):
            time.sleep(5)
    raise RuntimeError("Splunk did not become ready")


def _splunk_create_index() -> None:
    try:
        _http(
            f"{SPLUNK_REST}/services/data/indexes/ot_parity?output_mode=json",
            method="DELETE",
        )
        time.sleep(3)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    form = urllib.parse.urlencode({"name": "ot_parity", "datatype": "event"}).encode()
    request = urllib.request.Request(
        f"{SPLUNK_REST}/services/data/indexes",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=60, context=CASE_INSENSITIVE_CTX)  # nosec B310
    except urllib.error.HTTPError as error:
        if error.code != 409:  # already exists
            raise


def _splunk_index(events: list[dict]) -> None:
    # HEC accepts newline-delimited events in one request; one request per event
    # would spend most of the run in TCP setup.
    for start in range(0, len(events), 500):
        batch = events[start : start + 500]
        body = "".join(
            json.dumps(
                {"event": event, "sourcetype": "ot:telemetry", "index": "ot_parity"}
            )
            + "\n"
            for event in batch
        ).encode()
        request = urllib.request.Request(
            f"{SPLUNK_HEC}/services/collector",
            data=body,
            headers={"Authorization": "Splunk otde-parity-hec"},
            method="POST",
        )
        urllib.request.urlopen(  # nosec B310
            request, timeout=60, context=CASE_INSENSITIVE_CTX
        )
    _splunk_wait_for_index(len(events))


def _splunk_count() -> int:
    form = urllib.parse.urlencode(
        {
            "search": "search index=ot_parity | stats count",
            "exec_mode": "oneshot",
            "output_mode": "json",
            "earliest_time": "0",
            "latest_time": "now",
        }
    ).encode()
    request = urllib.request.Request(
        f"{SPLUNK_REST}/services/search/jobs",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60, context=CASE_INSENSITIVE_CTX) as response:  # nosec B310
        payload = json.loads(response.read().decode())
    return int(payload["results"][0]["count"]) if payload.get("results") else 0


def _splunk_wait_for_index(expected: int, timeout: int = 120) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _splunk_count() >= expected:
            return
        time.sleep(3)
    raise RuntimeError(f"Splunk indexed fewer than {expected} events")


def _splunk_search(query: str) -> set[str]:
    form = urllib.parse.urlencode(
        {
            "search": query,
            "exec_mode": "oneshot",
            "output_mode": "json",
            "earliest_time": "0",
            "latest_time": "now",
        }
    ).encode()
    request = urllib.request.Request(
        f"{SPLUNK_REST}/services/search/jobs",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=120, context=CASE_INSENSITIVE_CTX) as response:  # nosec B310
        payload = json.loads(response.read().decode())
    ids: set[str] = set()
    for row in payload.get("results", []):
        value = row.get("parity_id")
        if isinstance(value, list):
            ids.update(item for item in value if item)
        elif value:
            ids.add(value)
    return ids


def _logsource(rule: SigmaRule, operator: str = "=") -> str:
    """Return the predicate a deployment's index/table mapping supplies.

    The emitted Splunk search and Sentinel KQL contain the rule's predicate, not
    its logsource: in a real deployment the saved search is installed against the
    right index/sourcetype and the Sentinel query against the table that holds
    that product. The parity harness indexes every event in one place, so it has
    to supply that mapping itself; without it the query matches other products'
    events with the same field names.
    """
    clauses = []
    if rule.logsource.product:
        clauses.append((rule.logsource.product, "product"))
    if rule.logsource.service:
        clauses.append((rule.logsource.service, "service"))
    if operator == "=":
        # Splunk needs no spaces around "=" (a spaced form is a phrase search)
        # and its boolean operators are case-sensitive: lowercase "and" returns
        # nothing here. Adjacent comparisons are ANDed implicitly.
        return " ".join(f'{field}="{value}"' for value, field in clauses)
    return " and ".join(f'{field} == "{value}"' for value, field in clauses)


def _splunk_query(source: str, rule: SigmaRule) -> str | None:
    path = _artifact_for(source, "splunk")
    if path is None:
        return None
    text = path.read_text(encoding="utf-8")
    match = re.search(r"^search = (.*?)(?:\n\[|\Z)", text, re.S | re.M)
    if not match:
        return None
    body = match.group(1).replace("\\\n", " ")
    body = re.sub(r"\s*\|\s*table\s+[^|]*$", "", body, flags=re.S).strip()
    return (
        f"search index=ot_parity {_logsource(rule)} {body} | fields parity_id"
    )


# ---------------------------------------------------------------------- OpenSearch


def _os_unblock() -> None:
    """Clear the disk-watermark create-index block on the parity cluster.

    OpenSearch blocks index creation above the 90% disk watermark. The parity
    corpus is a few hundred documents; this only runs when the caller passes
    ``--unblock-open-search`` and targets the container in services/parity.
    """
    _http(
        f"{OPEN_SEARCH}/_cluster/settings",
        {
            "persistent": {
                "cluster": {
                    "blocks": {"create_index": None},
                    "routing.allocation.disk.threshold_enabled": False,
                }
            }
        },
        method="PUT",
    )


def _os_indices(events: list[dict]) -> list[str]:
    indices = sorted({f"{event['product']}-{event['service']}-parity" for event in events})
    for index in indices:
        try:
            _http(f"{OPEN_SEARCH}/{index}", method="DELETE")
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise
        _http(
            f"{OPEN_SEARCH}/{index}",
            {"mappings": {"properties": {"timestamp": {"type": "date"}}}},
            method="PUT",
        )
    for event in events:
        index = f"{event['product']}-{event['service']}-parity"
        _http(f"{OPEN_SEARCH}/{index}/_doc/{event['parity_id']}?refresh=false", event, method="PUT")
    for index in indices:
        _http(f"{OPEN_SEARCH}/{index}/_refresh", {}, method="POST")
    return indices


def _os_cleanup(indices: list[str]) -> None:
    for index in indices:
        try:
            _http(f"{OPEN_SEARCH}/{index}", method="DELETE")
        except urllib.error.HTTPError as error:
            if error.code != 404:
                raise


def _os_query(source: str) -> str | None:
    path = _artifact_for(source, "opensearch")
    if path is None:
        return None
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    return " | ".join(lines) + " | fields parity_id | head 10000"


def _os_search(query: str) -> set[str]:
    payload = _http(f"{OPEN_SEARCH}/_plugins/_ppl", {"query": query})
    schema = [column["name"] for column in payload.get("schema", [])]
    if "parity_id" not in schema:
        raise RuntimeError(f"parity_id missing from PPL result: {schema}")
    position = schema.index("parity_id")
    return {row[position] for row in payload.get("datarows", []) if row[position]}


# -------------------------------------------------------------------------- Kusto


def _kusto_fields(events: list[dict]) -> list[tuple[str, str]]:
    types: dict[str, set[str]] = {}
    for event in events:
        for key, value in event.items():
            if isinstance(value, list):
                continue
            if key == "timestamp":
                types.setdefault(key, set()).add("datetime")
            elif isinstance(value, bool):
                types.setdefault(key, set()).add("bool")
            elif isinstance(value, int):
                types.setdefault(key, set()).add("int")
            elif isinstance(value, float):
                types.setdefault(key, set()).add("real")
            else:
                types.setdefault(key, set()).add("string")
    fields: list[tuple[str, str]] = []
    for key in sorted(types):
        seen = types[key]
        if seen == {"bool"}:
            kind = "string"  # normalized to "true"/"false" for the queries
        elif seen == {"int"} or seen == {"datetime"}:
            kind = "int" if key != "timestamp" else "datetime"
        elif seen == {"real"}:
            kind = "real"
        else:
            kind = "string"
        fields.append((key, kind))
    return fields


def _kusto_mgmt(csl: str, db: str = KUSTO_DB) -> Any:
    return _http(f"{KUSTO}/v1/rest/mgmt", {"db": db, "csl": csl})


def _kusto_query(csl: str) -> Any:
    return _http(f"{KUSTO}/v1/rest/query", {"db": KUSTO_DB, "csl": csl})


def _kusto_setup(fields: list[tuple[str, str]]) -> None:
    # Kusto column declarations reject type names as bare identifiers (``bytes``
    # is a type), so every column is bracketed.
    schema = ", ".join(f'["{name}"]:{kind}' for name, kind in fields)
    _kusto_mgmt(f".drop table {KUSTO_TABLE} ifexists")
    _kusto_mgmt(f".create table {KUSTO_TABLE} ({schema})")


def _kusto_csv(events: list[dict], fields: list[tuple[str, str]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n", quoting=csv.QUOTE_MINIMAL)
    for event in events:
        row = []
        for name, kind in fields:
            value = event.get(name, "")
            if value in ("", None):
                # An empty CSV field is null in Kusto. A default of 0 would make
                # a missing numeric field look present and satisfy
                # ``isnotempty(exception_code)``.
                row.append("")
            elif kind == "int":
                row.append(int(value))
            elif kind == "real":
                row.append(float(value))
            elif kind == "datetime":
                row.append(f"datetime({value})")
            else:
                row.append(str(value))
        writer.writerow(row)
    return buffer.getvalue()


def _kusto_ingest(events: list[dict], fields: list[tuple[str, str]]) -> None:
    body = _kusto_csv(events, fields)
    _kusto_mgmt(
        f'.ingest inline into table {KUSTO_TABLE} with (format="csv") <|\n{body}'
    )
    time.sleep(3)


def _kusto_query_path(source: str, rule: SigmaRule) -> str | None:
    path = _artifact_for(source, "sentinel")
    if path is None:
        return None
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("//")
    ]
    query = "\n".join(lines)
    return query.replace(
        f"{KUSTO_TABLE}\n", f"{KUSTO_TABLE}\n| where {_logsource(rule, '==')}\n", 1
    )


def _engine_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    try:
        info = _http(f"{SPLUNK_REST}/services/server/info?output_mode=json")
        versions["splunk"] = str(info["entry"][0]["content"]["version"])
    except (KeyError, IndexError, urllib.error.URLError):
        versions["splunk"] = "unknown"
    try:
        info = _http(f"{OPEN_SEARCH}/")
        versions["opensearch"] = str(info["version"]["number"])
    except (KeyError, urllib.error.URLError):
        versions["opensearch"] = "unknown"
    try:
        payload = _kusto_query(".show version")
        for table in payload.get("Tables", []):
            columns = [column["ColumnName"] for column in table.get("Columns", [])]
            if "ProductVersion" in columns and table.get("Rows"):
                versions["kusto"] = str(table["Rows"][0][columns.index("ProductVersion")])
                break
        else:
            versions["kusto"] = "unknown"
    except urllib.error.URLError:
        versions["kusto"] = "unknown"
    return versions


def _kusto_rows(csl: str) -> set[str]:
    payload = _kusto_query(csl)
    for table in payload.get("Tables", []):
        columns = [column["ColumnName"] for column in table.get("Columns", [])]
        if "parity_id" in columns:
            position = columns.index("parity_id")
            return {row[position] for row in table.get("Rows", []) if row[position]}
    return set()


# ------------------------------------------------------------------------- report


def build(
    *,
    splunk_enabled: bool,
    open_search_url: str,
    kusto_url: str,
    keep_indexes: bool,
    unblock_open_search: bool = False,
) -> dict[str, Any]:
    global SPLUNK_REST, OPEN_SEARCH, KUSTO  # noqa: PLW0603 - CLI overrides
    OPEN_SEARCH = open_search_url.rstrip("/")
    KUSTO = kusto_url.rstrip("/")

    events = _corpus()
    rules = _rules()
    golden = _golden(events, rules)
    results: dict[str, Any] = {}
    engines: list[str] = ["splunk", "opensearch", "kusto"]

    splunk_ready = False
    if splunk_enabled:
        _splunk_wait()
        _splunk_create_index()
        _splunk_index(events)
        splunk_ready = True

    if unblock_open_search:
        _os_unblock()
    indices = _os_indices(events)
    fields = _kusto_fields(events)
    _kusto_setup(fields)
    _kusto_ingest(events, fields)

    for name, _rule in rules:
        row: dict[str, Any] = {"expected": sorted(golden[name])}
        for engine in engines:
            if engine == "splunk":
                query = _splunk_query(name, _rule) if splunk_ready else None
                if query is None:
                    row[engine] = {"status": "skipped"}
                    continue
                observed = _splunk_search(query)
            elif engine == "opensearch":
                query = _os_query(name)
                if query is None:
                    row[engine] = {"status": "not-converted"}
                    continue
                observed = _os_search(query)
            else:
                query = _kusto_query_path(name, _rule)
                if query is None:
                    row[engine] = {"status": "not-converted"}
                    continue
                observed = _kusto_rows(query)
            missing = sorted(golden[name] - observed)
            extra = sorted(observed - golden[name])
            row[engine] = {
                "status": "pass" if not missing and not extra else "fail",
                "observed": sorted(observed),
                "missing": missing,
                "extra": extra,
            }
        results[name] = row

    if not keep_indexes:
        _os_cleanup(indices)
        _kusto_mgmt(f".drop table {KUSTO_TABLE} ifexists")

    def count(engine: str, status: str) -> int:
        return sum(
            1
            for row in results.values()
            if row.get(engine, {}).get("status") == status
        )

    versions = _engine_versions()
    summary = {
        "schema_version": 1,
        "corpus": {
            "events": len(events),
            "positives": len(_jsonl(HELDOUT / "positives.jsonl")),
            "near_misses": len(_jsonl(HELDOUT / "near-misses.jsonl")),
            "negatives": len(_jsonl(BENIGN)),
        },
        "engines": {
            "splunk": (
                f"Splunk {versions['splunk']} Free, index ot_parity"
                if splunk_ready
                else "not run"
            ),
            "opensearch": f"OpenSearch {versions['opensearch']} PPL at {OPEN_SEARCH}",
            "kusto": (
                f"Kusto {versions['kusto']} at {KUSTO} table {KUSTO_TABLE}"
            ),
            "loki": "measured live by make lab-loki-check",
        },
        "rules": results,
        "totals": {
            engine: {
                "pass": count(engine, "pass"),
                "fail": count(engine, "fail"),
                "not_converted": count(engine, "not-converted"),
                "skipped": count(engine, "skipped"),
            }
            for engine in engines
        },
    }
    return summary


def render(summary: dict[str, Any]) -> str:
    lines = [
        "# Engine parity",
        "",
        "The converted Splunk SPL, OpenSearch PPL and Kusto KQL are executed against",
        "the committed held-out positives, near-misses and benign corpus. A rule",
        "passes when the engine returns exactly the same `parity_id` set as the",
        "repository matcher.",
        "",
        f"Corpus: {summary['corpus']['events']:,} events "
        f"({summary['corpus']['positives']} positives, "
        f"{summary['corpus']['near_misses']} near-misses, "
        f"{summary['corpus']['negatives']:,} benign).",
        "",
        f"Engines: {summary['engines']['splunk']}; "
        f"{summary['engines']['opensearch']}; {summary['engines']['kusto']}.",
        "",
        "| Engine | Pass | Fail | Not converted | Skipped |",
        "| :-- | --: | --: | --: | --: |",
    ]
    for engine, totals in summary["totals"].items():
        lines.append(
            f"| {engine} | {totals['pass']} | {totals['fail']} | "
            f"{totals['not_converted']} | {totals['skipped']} |"
        )
    failures = [
        (name, engine, row[engine])
        for name, row in summary["rules"].items()
        for engine in ("splunk", "opensearch", "kusto")
        if row.get(engine, {}).get("status") == "fail"
    ]
    lines += ["", "## Failures", ""]
    if not failures:
        lines.append("- none")
    for name, engine, detail in failures:
        lines.append(
            f"- `{name}` in {engine}: missing {detail['missing']}, extra {detail['extra']}"
        )
    lines += [
        "",
        "## Limits",
        "",
        "- Single-event rules only. Correlation rules aggregate over windows and are",
        "  covered by the local stateful harness and the live Loki run.",
        "- Splunk search clauses are the converted search without the trailing",
        "  presentation `table`, plus `fields parity_id` so the result can be",
        "  compared. The selection logic is unchanged.",
        "- OpenSearch and Kusto receive one extra projection/limit clause to return",
        "  the id column; the selection logic is unchanged.",
        "- One lab corpus, not a production feed. The engine images are pinned by",
        "  digest in the compose file; the observed versions are recorded above.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--splunk",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Run the Splunk engine (services/parity/docker-compose.yml)",
    )
    parser.add_argument("--open-search", default=OPEN_SEARCH)
    parser.add_argument("--kusto", default=KUSTO)
    parser.add_argument("--keep-indexes", action="store_true")
    parser.add_argument(
        "--unblock-open-search",
        action="store_true",
        help="Clear the disk-watermark create-index block on the parity cluster",
    )
    parser.add_argument("--out", default=str(OUT_DIR))
    args = parser.parse_args(argv)
    summary = build(
        splunk_enabled=args.splunk,
        open_search_url=args.open_search,
        kusto_url=args.kusto,
        keep_indexes=args.keep_indexes,
        unblock_open_search=args.unblock_open_search,
    )
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "report.md").write_text(render(summary), encoding="utf-8")
    for engine, totals in summary["totals"].items():
        print(f"{engine}: {totals}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
