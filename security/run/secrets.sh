#!/usr/bin/env bash
# Secret scan over the working tree (not git history), with a pinned image.
set -euo pipefail
exec docker run --rm -v "$PWD:/repo:ro" \
  zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f \
  detect --source /repo --no-git --redact --exit-code 1
