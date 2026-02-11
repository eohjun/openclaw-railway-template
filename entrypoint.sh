#!/bin/bash
# Handle existing root-owned /data volumes from prior deployments.
# The container now runs as 'node', so we need write access.
if [ -d "/data" ] && [ "$(stat -c '%u' /data)" = "0" ]; then
  sudo chown -R node:node /data 2>/dev/null || true
fi
exec "$@"
