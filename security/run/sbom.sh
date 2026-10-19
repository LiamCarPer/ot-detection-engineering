#!/usr/bin/env bash
# Emit a CycloneDX SBOM for the repository. Scheduled/on-demand.
set -euo pipefail
mkdir -p security/out
docker run --rm -v "$PWD:/src:ro" -v "$PWD/security/out:/out" \
  anchore/syft:latest dir:/src -o cyclonedx-json=/out/sbom.cdx.json
