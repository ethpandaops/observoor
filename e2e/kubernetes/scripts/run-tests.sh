#!/bin/bash
# Run smoke tests against observoor in Kubernetes using port-forwarding.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$(dirname "$E2E_DIR")")"

SMOKE_TESTS="${REPO_ROOT}/e2e/client-detection/smoke-tests.sh"
LOCAL_PORT="${LOCAL_PORT:-8123}"
WAIT_TIME="${WAIT_TIME:-240}"

echo "=== Running K8s E2E tests ==="

# Check if observoor pods are running.
echo "Checking observoor pods..."
RUNNING=$(kubectl -n observoor-test get pods -l app.kubernetes.io/name=observoor \
    -o jsonpath='{.items[*].status.phase}' | tr ' ' '\n' | grep -c Running || echo "0")
if [[ "$RUNNING" -eq 0 ]]; then
    echo "ERROR: No observoor pods running"
    kubectl -n observoor-test get pods
    exit 1
fi
echo "Found $RUNNING observoor pod(s) running"

# Start port-forward in background.
echo "Starting ClickHouse port-forward..."
kubectl -n observoor-test port-forward svc/clickhouse "$LOCAL_PORT:8123" &
PORT_FORWARD_PID=$!

# Cleanup port-forward on exit.
cleanup() {
    echo "Cleaning up port-forward..."
    kill "$PORT_FORWARD_PID" 2>/dev/null || true
    wait "$PORT_FORWARD_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for port-forward to be ready.
echo "Waiting for port-forward to be ready..."
for i in $(seq 1 30); do
    if curl -sf "http://localhost:${LOCAL_PORT}/ping" > /dev/null 2>&1; then
        echo "Port-forward ready"
        break
    fi
    if [[ $i -eq 30 ]]; then
        echo "ERROR: Port-forward failed to become ready"
        exit 1
    fi
    sleep 1
done

# Wait for data collection.
echo "Waiting for data collection (${WAIT_TIME}s max)..."
for i in $(seq 1 $((WAIT_TIME / 10))); do
    COUNT=$(curl -sf "http://localhost:${LOCAL_PORT}" --data-binary "SELECT count() FROM sched_on_cpu" 2>/dev/null || echo "0")
    echo "  Attempt $i: $COUNT rows in sched_on_cpu"
    if [[ "$COUNT" -gt 100 ]]; then
        echo "Data collection ready"
        break
    fi
    sleep 10
done

# Run smoke tests.
echo ""
echo "=== Running smoke tests ==="
export CLICKHOUSE_HOST="localhost"
export CLICKHOUSE_PORT="$LOCAL_PORT"
"$SMOKE_TESTS"
