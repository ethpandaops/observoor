#!/bin/bash
# Run smoke tests against observoor in Kubernetes using port-forwarding.
#
# K3s runs directly on the host (no nested containers like KIND),
# so eBPF programs can properly trace pod processes.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_PORT="${LOCAL_PORT:-8123}"
MAX_RETRIES="${MAX_RETRIES:-12}"
RETRY_DELAY="${RETRY_DELAY:-10}"

query() {
    curl -sf "http://localhost:${LOCAL_PORT}" --data-binary "$1"
}

retry_query() {
    local description="$1"
    local sql="$2"
    local check="$3"

    for i in $(seq 1 $MAX_RETRIES); do
        RESULT=$(query "$sql" 2>/dev/null || echo "")
        if eval "$check"; then
            return 0
        fi
        echo "  Retry $i/$MAX_RETRIES: $description (got: $RESULT)"
        sleep $RETRY_DELAY
    done
    return 1
}

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

# Set up port-forwarding for ClickHouse.
echo "3. Setting up ClickHouse connection..."
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
echo "4. Checking ClickHouse migrations..."
TABLE_COUNT=$(query "SELECT count() FROM system.tables WHERE database = 'default' AND name NOT LIKE '%_local'" \
    2>/dev/null || echo "0")
if [[ "$TABLE_COUNT" -lt 10 ]]; then
    echo "FAIL: Expected at least 10 tables, got $TABLE_COUNT"
    exit 1
fi
echo "   PASS: Migrations completed ($TABLE_COUNT tables created)"

# Check that PID discovery is working by looking at logs.
echo "5. Checking PID discovery..."
PID_DISCOVERED=$(kubectl -n observoor-test logs -l app.kubernetes.io/name=observoor --tail=500 2>/dev/null | \
    grep -c "Discovered PIDs" || echo "0")
if [[ "$PID_DISCOVERED" -lt 1 ]]; then
    echo "FAIL: No PID discovery logs found"
    kubectl -n observoor-test logs -l app.kubernetes.io/name=observoor --tail=50
    exit 1
fi
echo "   PASS: PID discovery working ($PID_DISCOVERED discovery cycles)"

# Check that BPF map is being updated.
echo "6. Checking BPF map updates..."
BPF_UPDATES=$(kubectl -n observoor-test logs -l app.kubernetes.io/name=observoor --tail=500 2>/dev/null | \
    grep -c "Added PID to BPF map" || echo "0")
if [[ "$BPF_UPDATES" -lt 1 ]]; then
    echo "FAIL: Expected BPF map updates, got $BPF_UPDATES"
    kubectl -n observoor-test logs -l app.kubernetes.io/name=observoor --tail=50
    exit 1
fi
echo "   PASS: BPF map being updated ($BPF_UPDATES updates)"

# Verify actual eBPF data capture (K3s supports this, unlike KIND).
echo ""
echo "=== Verifying eBPF Data Capture ==="
echo ""

# Check that data exists in sched_on_cpu (primary indicator).
echo -n "7. Data exists in sched_on_cpu... "
if retry_query "waiting for data" \
    "SELECT count() FROM sched_on_cpu" \
    '[[ -n "$RESULT" && "$RESULT" -gt 0 ]]'; then
    TOTAL=$(query "SELECT count() FROM sched_on_cpu")
    echo "PASS ($TOTAL rows)"
else
    echo "FAIL"
    echo "No scheduler events captured. Checking observoor logs..."
    kubectl -n observoor-test logs -l app.kubernetes.io/name=observoor --tail=100
    exit 1
fi

# Check wallclock_slot > 0.
echo -n "8. Wallclock slot > 0... "
MAX_SLOT=$(query "SELECT max(wallclock_slot) FROM sched_on_cpu")
if [[ -n "$MAX_SLOT" && "$MAX_SLOT" -gt 0 ]]; then
    echo "PASS (max slot: $MAX_SLOT)"
else
    echo "FAIL ($MAX_SLOT)"
    exit 1
fi

# Check scheduler metrics.
echo -n "9. Scheduler metrics... "
SCHED=$(query "SELECT count() FROM sched_on_cpu WHERE sum > 0 OR count > 0")
if [[ -n "$SCHED" && "$SCHED" -gt 0 ]]; then
    echo "PASS ($SCHED non-zero rows)"
else
    echo "FAIL"
    exit 1
fi

# Check syscall metrics.
echo -n "10. Syscall metrics... "
SYSCALL=$(query "SELECT count() FROM syscall_read")
if [[ -n "$SYSCALL" && "$SYSCALL" -gt 0 ]]; then
    echo "PASS ($SYSCALL rows)"
else
    echo "FAIL"
    exit 1
fi

# Check that 100ms interval is being used.
echo -n "11. 100ms interval... "
INTERVALS=$(query "SELECT DISTINCT interval_ms FROM sched_on_cpu")
if [[ "$INTERVALS" == "100" ]]; then
    echo "PASS"
else
    echo "FAIL (got: $INTERVALS)"
    exit 1
fi

echo ""
echo "=== All K8s E2E Tests Passed ==="
echo ""

# Summary across key tables.
echo "=== Summary by Table ==="
for table in sched_on_cpu sched_off_cpu syscall_read syscall_write net_io disk_latency; do
    COUNT=$(query "SELECT count() FROM $table" 2>/dev/null || echo "0")
    echo "$table: $COUNT rows"
done

echo ""
echo "=== Client Distribution (sched_on_cpu) ==="
query "
    SELECT client_type, countDistinct(pid) as pids, count() as rows
    FROM sched_on_cpu GROUP BY client_type ORDER BY client_type FORMAT PrettyCompact
"
