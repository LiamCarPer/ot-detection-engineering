#!/usr/bin/env bash
# Wait for the 24-hour benign capture to finish, then measure the network
# detection families over it and replace the pilot evidence.
#
# Run with nohup so it survives the shell that starts it:
#   nohup scripts/finalize_benign_capture.sh > "${TMPDIR:-/tmp}/finalize-capture.log" 2>&1 &
#
# It never sends traffic; it only waits for the capture writer and then reads the
# saved PCAP.
set -euo pipefail
cd "$(dirname "$0")/.."

PCAP="${BENIGN_PCAP:-/media/liamcarvajal/Storage/code/ot-security-lab/detection/logs/benign-24h.pcap}"
IDLE_SECONDS="${IDLE_SECONDS:-300}"

if [ ! -f "$PCAP" ]; then
  echo "capture not found: $PCAP" >&2
  exit 1
fi

echo "[finalize] waiting for the capture writer to stop"
while pgrep -f "benign_capture.py" >/dev/null; do
  sleep 60
done

echo "[finalize] waiting for the PCAP to be idle for ${IDLE_SECONDS}s"
while [ $(( $(date +%s) - $(stat -c %Y "$PCAP") )) -lt "$IDLE_SECONDS" ]; do
  sleep 30
done

echo "[finalize] capture is stable: $(stat -c '%s bytes, mtime %y' "$PCAP")"
.venv/bin/python tools/benign_lab_check.py --pcap "$PCAP"
echo "[finalize] done at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
