#!/bin/bash
# Run smoke tests against observoor in Kubernetes using port-forwarding.
#
# NOTE: In KIND, eBPF event capture doesn't work due to PID namespace mismatch.
# BPF programs run in the host kernel with host PIDs, but observoor inside KIND
# sees container PIDs. This test verifies infrastructure (deployment, migrations,
# PID discovery) rather than full eBPF event capture.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_PORT="${LOCAL_PORT:-8123}"

echo "=== Running K8s E2E tests ==="

# Check if observoor pods are running.
echo "1. Checking observoor pods..."
RUNNING=$(kubectl -n observoor-test get pods -l app.kubernetes.io/name=observoor \
    -o jsonpath='{.items[*].status.phase}' | tr ' ' '\n' | grep -c Running || echo "0")
if [[ "$RUNNING" -eq 0 ]]; then
    echo "FAIL: No observoor pods running"
    kubectl -n observoor-test get pods
    exit 1
fi
echo "   PASS: Found $RUNNING observoor pod(s) running"

# Check that observoor is healthy (readiness probe passing).
echo "2. Checking observoor health..."
READY=$(kubectl -n observoor-test get pods -l app.kubernetes.io/name=observoor \
    -o jsonpath='{.items[0].status.conditions[?(@.type=="Ready")].status}')
if [[ "$READY" != "True" ]]; then
    echo "FAIL: Observoor pod not ready"
    kubectl -n observoor-test describe pod -l app.kubernetes.io/name=observoor
    exit 1
fi
echo "   PASS: Observoor pod is healthy"

# Check that migrations completed by verifying schema exists.
echo "3. Checking ClickHouse migrations..."
kubectl -n observoor-test port-forward svc/clickhouse "$LOCAL_PORT:8123" &
PORT_FORWARD_PID=$!
cleanup() {
    kill "$PORT_FORWARD_PID" 2>/dev/null || true
    wait "$PORT_FORWARD_PID" 2>/dev/null || true
}
trap cleanup EXIT

# Wait for port-forward.
for i in $(seq 1 30); do
    if curl -sf "http://localhost:${LOCAL_PORT}/ping" > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Check that tables were created.
TABLE_COUNT=$(curl -sf "http://localhost:${LOCAL_PORT}" \
    --data-binary "SELECT count() FROM system.tables WHERE database = 'default' AND name NOT LIKE '%_local'" \
    2>/dev/null || echo "0")
if [[ "$TABLE_COUNT" -lt 10 ]]; then
    echo "FAIL: Expected at least 10 tables, got $TABLE_COUNT"
    exit 1
fi
echo "   PASS: Migrations completed ($TABLE_COUNT tables created)"

# Check that PID discovery is working by looking at logs.
echo "4. Checking PID discovery..."
PID_DISCOVERED=$(kubectl -n observoor-test logs -l app.kubernetes.io/name=observoor --tail=500 2>/dev/null | \
    grep -c "Discovered PIDs" || echo "0")
if [[ "$PID_DISCOVERED" -lt 1 ]]; then
    echo "FAIL: No PID discovery logs found"
    kubectl -n observoor-test logs -l app.kubernetes.io/name=observoor --tail=50
    exit 1
fi
echo "   PASS: PID discovery working ($PID_DISCOVERED discovery cycles)"

# Check that BPF map is being updated.
echo "5. Checking BPF map updates..."
BPF_UPDATES=$(kubectl -n observoor-test logs -l app.kubernetes.io/name=observoor --tail=500 2>/dev/null | \
    grep -c "Added PID to BPF map" || echo "0")
if [[ "$BPF_UPDATES" -lt 5 ]]; then
    echo "FAIL: Expected BPF map updates, got $BPF_UPDATES"
    kubectl -n observoor-test logs -l app.kubernetes.io/name=observoor --tail=50
    exit 1
fi
echo "   PASS: BPF map being updated ($BPF_UPDATES updates)"

# Note about BPF event capture.
echo ""
echo "=== K8s Infrastructure Tests Passed ==="
echo ""
echo "NOTE: eBPF event capture is not tested in KIND due to PID namespace"
echo "isolation between the host kernel and KIND containers. Full eBPF"
echo "functionality is verified in the Docker-based E2E tests."
echo ""
echo "Verified:"
echo "  - Observoor deployment and health"
echo "  - ClickHouse migrations"
echo "  - Ethereum client PID discovery"
echo "  - BPF map updates"
