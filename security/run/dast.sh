#!/usr/bin/env bash
# Build the hardened service and run the ZAP baseline against it.
# Scheduled/on-demand: it needs Docker and pulls the ZAP image.
set -euo pipefail
docker build -f services/ingest/Dockerfile -t ot-ingest:dast .
docker run -d --rm --name ot-ingest-dast -p 18080:8080 \
  -e INGEST_API_KEY=dast-key \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  ot-ingest:dast
trap 'docker rm -f ot-ingest-dast >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 30); do
  curl -fsS http://localhost:18080/healthz >/dev/null && break
  sleep 1
done
docker run --rm --network host -v "$PWD/security/zap:/zap/wrk:ro" \
  ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
  -t http://localhost:18080 -c /zap/wrk/baseline.conf -I
