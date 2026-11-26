#!/usr/bin/env bash
# Emit a CycloneDX SBOM for the repository. Scheduled/on-demand.
set -euo pipefail
mkdir -p security/out
docker run --rm -v "$PWD:/src:ro" -v "$PWD/security/out:/out" \
  anchore/syft@sha256:9c2563b5fb56e9f5e9cb5b6cf10b9ab0dc6a6d1c1b1e24165bcdf9c8c85a9584 dir:/src -o cyclonedx-json=/out/sbom.cdx.json
