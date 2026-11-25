#!/usr/bin/env bash
# Start the parity engines and install the Splunk config the image cannot mount.
#
# The official Splunk image rewrites /opt/splunk/etc at start, so a read-only
# app mount makes its Ansible playbook fail. Instead this script copies the app
# into the container's own etc volume, sets the Free-licence remote-management
# flag, and restarts Splunk.
set -euo pipefail
cd "$(dirname "$0")/../.."

docker compose -f services/parity/docker-compose.yml up -d

echo "waiting for Splunk to become healthy..."
for _ in $(seq 1 120); do
  if [ "$(docker inspect ot_splunk --format '{{.State.Health.Status}}' 2>/dev/null)" = "healthy" ]; then
    break
  fi
  sleep 3
done

docker exec -u root ot_splunk rm -rf /opt/splunk/etc/apps/otde_parity
docker cp services/parity/splunk-app ot_splunk:/opt/splunk/etc/apps/otde_parity
docker exec -u root ot_splunk chown -R splunk:splunk /opt/splunk/etc/apps/otde_parity

# Splunk Free disables authenticated remote management. The parity harness only
# reaches this container over 127.0.0.1, and the flag is required for the REST
# search API to answer.
docker exec -u splunk ot_splunk sh -c \
  "grep -q '^allowRemoteLogin' /opt/splunk/etc/system/local/server.conf || \
   sed -i '0,/^\\[general\\]$/s//[general]\\nallowRemoteLogin = always/' /opt/splunk/etc/system/local/server.conf"

docker restart ot_splunk >/dev/null
echo "waiting for Splunk to restart..."
for _ in $(seq 1 120); do
  if [ "$(docker inspect ot_splunk --format '{{.State.Health.Status}}' 2>/dev/null)" = "healthy" ]; then
    echo "parity engines ready"
    exit 0
  fi
  sleep 3
done
echo "Splunk did not become healthy" >&2
exit 1
