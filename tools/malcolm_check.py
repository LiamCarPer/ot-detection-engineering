"""Install the ruleset into a Malcolm pipeline and prove it fires.

This is the integration counterpart to ``tools/suricata_check.py``. Instead of
the stock ``jasonish/suricata`` container loading only our rules, it drops
``deploy/suricata/ot-detection.rules`` into a Malcolm installation's custom
rules directory and runs Malcolm's own Suricata image and generated
configuration over the committed captures, with Malcolm's full default ruleset
enabled. That is what verifies the ruleset loads alongside the rules Malcolm
ships and fires on real traffic.

It needs a Malcolm checkout (the ``MALCOLM_DIR`` environment variable or
``--malcolm-dir``) and its images, so CI does not run it; the committed evidence
under ``deploy/evidence/malcolm/`` is guarded by ``tests/test_malcolm_evidence.py``.

Usage:
    MALCOLM_DIR=/path/to/Malcolm python tools/malcolm_check.py
    python tools/malcolm_check.py --malcolm-dir /path/to/Malcolm
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.otde.evidence import EXPECTED_SIDS  # noqa: E402

CAPTURES_DIR = REPO_ROOT / "tests" / "captures"
RULES_FILE = REPO_ROOT / "deploy" / "suricata" / "ot-detection.rules"
EVIDENCE_DIR = REPO_ROOT / "deploy" / "evidence" / "malcolm"

# Where the runner writes inside the container; the compose file binds this to
# <malcolm>/suricata-logs.
CONTAINER_LOG_DIR = "/var/log/suricata/ot-proof"

_LOADED_RE = re.compile(r"(\d+) rules successfully loaded, (\d+) rules failed")
_DUPLICATE_RE = re.compile(r"Duplicate signature")
_VERSION_RE = re.compile(r"Suricata version ([\w.]+)")


def run_malcolm(malcolm_dir: Path) -> str:
    """Copy the ruleset in and run Malcolm's Suricata over every capture."""
    rules_dest = malcolm_dir / "suricata" / "rules" / "ot-detection.rules"
    shutil.copyfile(RULES_FILE, rules_dest)

    captures = " ".join(EXPECTED_SIDS)
    script = (
        f"rm -rf {CONTAINER_LOG_DIR} /var/log/suricata/config-test && "
        f"mkdir -p {CONTAINER_LOG_DIR} && "
        f"for c in {captures}; do "
        f"mkdir -p {CONTAINER_LOG_DIR}/$c && "
        f"suricata-offline -r /pcap/$c.pcap -l {CONTAINER_LOG_DIR}/$c >/dev/null 2>&1; "
        f"done && "
        # A dedicated configuration test loads the whole ruleset (Malcolm's
        # defaults plus ours) and logs the rule counts.
        f"mkdir -p /var/log/suricata/config-test && "
        f"suricata-offline -T -c /etc/suricata/suricata.yaml "
        f"-l /var/log/suricata/config-test >/dev/null 2>&1; "
        f"suricata-offline -V; echo MALCOLM_DONE"
    )
    command = [
        "docker", "compose", "run", "--rm", "--no-deps",
        "-v", f"{CAPTURES_DIR}:/pcap:ro",
        "suricata", "bash", "-c", script,
    ]
    result = subprocess.run(
        command,
        cwd=malcolm_dir,
        check=True,
        capture_output=True,
        text=True,
    )
    if "MALCOLM_DONE" not in result.stdout:
        raise RuntimeError("Malcolm Suricata run did not complete")
    return result.stdout + result.stderr


def read_alerts(eve_path: Path) -> list[dict]:
    alerts = []
    if not eve_path.exists():
        return alerts
    for line in eve_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        event = json.loads(line)
        if event.get("event_type") != "alert":
            continue
        alerts.append(
            {
                "sid": event["alert"]["signature_id"],
                "signature": event["alert"]["signature"],
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
            }
        )
    return alerts


def malcolm_revision(malcolm_dir: Path) -> str | None:
    """Short git revision of the Malcolm checkout, when it is a git repository."""
    try:
        result = subprocess.run(
            ["git", "-C", str(malcolm_dir), "rev-parse", "--short", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return result.stdout.strip() or None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--malcolm-dir", default=None)
    args = parser.parse_args(argv)

    malcolm_dir = args.malcolm_dir
    if not malcolm_dir:
        import os

        malcolm_dir = os.environ.get("MALCOLM_DIR")
    if not malcolm_dir:
        parser.error("set MALCOLM_DIR or pass --malcolm-dir")
    malcolm_dir = Path(malcolm_dir).expanduser().resolve()
    if not (malcolm_dir / "docker-compose.yml").is_file():
        parser.error(f"{malcolm_dir} does not look like a Malcolm installation")

    output = run_malcolm(malcolm_dir)

    log_dir = malcolm_dir / "suricata-logs" / "ot-proof"
    config_log = malcolm_dir / "suricata-logs" / "config-test" / "suricata.log"
    config_text = config_log.read_text(encoding="utf-8") if config_log.exists() else ""
    loaded = _LOADED_RE.search(config_text)
    version = _VERSION_RE.search(output)
    captures: dict[str, dict] = {}
    all_alerts: list[dict] = []
    failures: list[str] = []
    for name, expected in EXPECTED_SIDS.items():
        alerts = read_alerts(log_dir / name / "eve.json")
        observed = {alert["sid"] for alert in alerts}
        for alert in alerts:
            all_alerts.append({"capture": name, **alert})
        captures[name] = {"expected": sorted(expected), "observed": sorted(observed)}
        if observed != expected:
            failures.append(f"{name}: expected {sorted(expected)}, observed {sorted(observed)}")

    summary = {
        "meta": {
            "malcolm_revision": malcolm_revision(malcolm_dir),
            "suricata_version": version.group(1) if version else None,
            "rules_loaded": int(loaded.group(1)) if loaded else None,
            "rules_failed": int(loaded.group(2)) if loaded else None,
            "duplicate_signatures": len(_DUPLICATE_RE.findall(output)),
        },
        "captures": captures,
    }
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    (EVIDENCE_DIR / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (EVIDENCE_DIR / "alerts.json").write_text(
        json.dumps(all_alerts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    if failures:
        print("malcolm validation failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(
        f"malcolm validation passed for {len(EXPECTED_SIDS)} captures "
        f"({summary['meta']['rules_loaded']} rules loaded, "
        f"{summary['meta']['rules_failed']} failed)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
