#!/usr/bin/env bash
# run-e2e-tests.sh - Run end-to-end tests for observoor.
#
# Expects:
#   - docker-compose environment running (make e2e-up)
#   - observoor, geth, prysm, otel-collector, clickhouse all started

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== observoor E2E Tests ==="
echo ""

# Check that observoor is healthy.
echo "[1/4] Checking observoor health..."
HEALTH_RESPONSE=$(curl -sf http://localhost:9090/healthz || true)
if [ "$HEALTH_RESPONSE" != "ok" ]; then
    echo "FAIL: observoor health check failed"
    echo "  Response: $HEALTH_RESPONSE"
    exit 1
fi
echo "  PASS: observoor is healthy"

# Check that Prometheus metrics are served.
echo "[2/4] Checking Prometheus metrics..."
METRICS_RESPONSE=$(curl -sf http://localhost:9090/metrics || true)
if ! echo "$METRICS_RESPONSE" | grep -q "observoor_events_received_total"; then
    echo "FAIL: Expected observoor metrics not found"
    exit 1
fi
echo "  PASS: Prometheus metrics are served"

# Check that the beacon node is accessible via observoor's perspective.
echo "[3/4] Checking beacon node sync status..."
SYNC_METRIC=$(echo "$METRICS_RESPONSE" | grep "observoor_is_syncing" || true)
if [ -z "$SYNC_METRIC" ]; then
    echo "FAIL: observoor_is_syncing metric not found"
    exit 1
fi
echo "  PASS: Sync status metric present"

# Check that PIDs are being tracked.
echo "[4/4] Checking PID tracking..."
PIDS_METRIC=$(echo "$METRICS_RESPONSE" | grep "observoor_pids_tracked" || true)
if [ -z "$PIDS_METRIC" ]; then
    echo "FAIL: observoor_pids_tracked metric not found"
    exit 1
fi
echo "  PASS: PID tracking metric present"

echo ""
echo "=== All E2E tests passed ==="
