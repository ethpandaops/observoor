#!/bin/bash
set -euo pipefail

CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-localhost}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-8123}"
MAX_RETRIES="${MAX_RETRIES:-10}"
RETRY_DELAY="${RETRY_DELAY:-5}"

query() {
    curl -sf "http://${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}" --data-binary "$1"
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

EL_CLIENTS=("geth" "reth" "besu" "nethermind" "erigon")
CL_CLIENTS=("lighthouse" "prysm" "teku" "lodestar" "nimbus")
ALL_CLIENTS=("${EL_CLIENTS[@]}" "${CL_CLIENTS[@]}")

echo "=== Smoke Tests for Client Detection ==="
echo ""

# 1. Check data exists
echo -n "1. Data exists... "
if retry_query "waiting for data" \
    "SELECT count() FROM aggregated_metrics" \
    '[[ -n "$RESULT" && "$RESULT" -gt 0 ]]'; then
    TOTAL=$(query "SELECT count() FROM aggregated_metrics")
    echo "PASS ($TOTAL rows)"
else
    echo "FAIL"
    exit 1
fi

# 2. Check slot > 0
echo -n "2. Slot > 0... "
MAX_SLOT=$(query "SELECT max(slot) FROM aggregated_metrics")
if [[ -n "$MAX_SLOT" && "$MAX_SLOT" -gt 0 ]]; then
    echo "PASS (slot $MAX_SLOT)"
else
    echo "FAIL ($MAX_SLOT)"
    exit 1
fi

# 3. Each client has data
echo "3. Each client has data..."
MISSING=()
for client in "${ALL_CLIENTS[@]}"; do
    if retry_query "waiting for $client" \
        "SELECT count() FROM aggregated_metrics WHERE client_type = '$client'" \
        '[[ -n "$RESULT" && "$RESULT" -gt 0 ]]'; then
        COUNT=$(query "SELECT count() FROM aggregated_metrics WHERE client_type = '$client'")
        echo "   ✓ $client: $COUNT rows"
    else
        echo "   ✗ $client: MISSING"
        MISSING+=("$client")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "FAIL: Missing clients: ${MISSING[*]}"
    exit 1
fi

# 4. Scheduler metrics
echo -n "4. Scheduler metrics... "
SCHED=$(query "SELECT count() FROM aggregated_metrics WHERE metric_name = 'sched_on_cpu'")
if [[ -n "$SCHED" && "$SCHED" -gt 0 ]]; then
    echo "PASS ($SCHED)"
else
    echo "FAIL"
    exit 1
fi

# 5. Syscall metrics
echo -n "5. Syscall metrics... "
SYSCALL=$(query "SELECT count() FROM aggregated_metrics WHERE metric_name LIKE 'syscall_%'")
if [[ -n "$SYSCALL" && "$SYSCALL" -gt 0 ]]; then
    echo "PASS ($SYSCALL)"
else
    echo "FAIL"
    exit 1
fi

# 6. Network metrics
echo -n "6. Network metrics... "
NET=$(query "SELECT count() FROM aggregated_metrics WHERE metric_name = 'net_io'")
if [[ -n "$NET" && "$NET" -gt 0 ]]; then
    echo "PASS ($NET)"
else
    echo "FAIL"
    exit 1
fi

# 7. Non-zero values
echo -n "7. Non-zero values... "
NONZERO=$(query "SELECT count() FROM aggregated_metrics WHERE sum > 0 OR count > 0")
if [[ -n "$NONZERO" && "$NONZERO" -gt 0 ]]; then
    echo "PASS ($NONZERO)"
else
    echo "FAIL"
    exit 1
fi

# 8. Histogram consistency
echo -n "8. Histogram consistency... "
MISMATCH=$(query "
    SELECT count() FROM aggregated_metrics
    WHERE metric_name LIKE 'syscall_%' AND count > 0
    AND count != (hist_1us + hist_10us + hist_100us + hist_1ms + hist_10ms + hist_100ms + hist_1s + hist_10s + hist_100s + hist_inf)
")
if [[ "$MISMATCH" == "0" ]]; then
    echo "PASS"
else
    echo "FAIL ($MISMATCH mismatches)"
    exit 1
fi

# 9. 100ms interval
echo -n "9. 100ms interval... "
INTERVALS=$(query "SELECT DISTINCT interval_ms FROM aggregated_metrics")
if [[ "$INTERVALS" == "100" ]]; then
    echo "PASS"
else
    echo "FAIL ($INTERVALS)"
    exit 1
fi

echo ""
echo "=== All Tests Passed ==="
echo ""
query "
    SELECT client_type, countDistinct(metric_name) as metrics, countDistinct(pid) as pids, count() as rows
    FROM aggregated_metrics GROUP BY client_type ORDER BY client_type FORMAT PrettyCompact
"
