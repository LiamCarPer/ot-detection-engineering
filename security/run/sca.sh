#!/usr/bin/env bash
# Dependency audit. PYSEC-2026-2447 (diskcache, transitive of pysigma) has no
# fix release; it is accepted and tracked in docs/VULNERABILITY_MANAGEMENT.md.
set -euo pipefail
pip-audit -r requirements.txt --ignore-vuln PYSEC-2026-2447
