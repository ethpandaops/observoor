#!/usr/bin/env bash
# wait-for-sync.sh - Wait for the beacon node to be synced.
#
# Usage:
#   ./e2e/scripts/wait-for-sync.sh [beacon_url] [max_wait_seconds]

set -euo pipefail

BEACON_URL="${1:-http://localhost:3500}"
MAX_WAIT="${2:-600}"

echo "Waiting for beacon node at $BEACON_URL to sync..."
echo "Max wait: ${MAX_WAIT}s"

ELAPSED=0
INTERVAL=10

while [ "$ELAPSED" -lt "$MAX_WAIT" ]; do
    RESPONSE=$(curl -sf "$BEACON_URL/eth/v1/node/syncing" 2>/dev/null || true)

    if [ -n "$RESPONSE" ]; then
        IS_SYNCING=$(echo "$RESPONSE" | jq -r '.data.is_syncing' 2>/dev/null || true)
        HEAD_SLOT=$(echo "$RESPONSE" | jq -r '.data.head_slot' 2>/dev/null || true)
        SYNC_DIST=$(echo "$RESPONSE" | jq -r '.data.sync_distance' 2>/dev/null || true)

        if [ "$IS_SYNCING" = "false" ]; then
            echo "Beacon node is synced at slot $HEAD_SLOT"
            exit 0
        fi

        echo "  Syncing... head_slot=$HEAD_SLOT sync_distance=$SYNC_DIST (${ELAPSED}s elapsed)"
    else
        echo "  Beacon node not responding yet (${ELAPSED}s elapsed)"
    fi

    sleep "$INTERVAL"
    ELAPSED=$((ELAPSED + INTERVAL))
done

echo "ERROR: Beacon node did not sync within ${MAX_WAIT}s"
exit 1
