#!/usr/bin/env bash
# Static analysis for the Python surface. Medium+ findings fail the run.
set -euo pipefail
bandit -q -ll -r tools collector pipelines coverage services -x '*/tests/*,tools/target'
