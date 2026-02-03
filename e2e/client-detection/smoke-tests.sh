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

# Clients that may not be detected in certain environments.
# Detection now works for all clients via cmdline keyword matching.
OPTIONAL_CLIENTS=()

echo "=== Smoke Tests for Client Detection ==="
echo ""

# 1. Check data exists (using sched_on_cpu as primary indicator)
echo -n "1. Data exists... "
if retry_query "waiting for data" \
    "SELECT count() FROM sched_on_cpu" \
    '[[ -n "$RESULT" && "$RESULT" -gt 0 ]]'; then
    TOTAL=$(query "SELECT count() FROM sched_on_cpu")
    echo "PASS ($TOTAL rows in sched_on_cpu)"
else
    echo "FAIL"
    exit 1
fi

# 2. Check wallclock_slot > 0
echo -n "2. Wallclock slot > 0... "
MAX_SLOT=$(query "SELECT max(wallclock_slot) FROM sched_on_cpu")
if [[ -n "$MAX_SLOT" && "$MAX_SLOT" -gt 0 ]]; then
    echo "PASS (wallclock_slot $MAX_SLOT)"
else
    echo "FAIL ($MAX_SLOT)"
    exit 1
fi

# Helper to check if client is optional
is_optional() {
    local client="$1"
    for opt in "${OPTIONAL_CLIENTS[@]}"; do
        [[ "$client" == "$opt" ]] && return 0
    done
    return 1
}

# 3. Each client has data (check across all tables)
echo "3. Each client has data..."
MISSING=()
OPTIONAL_MISSING=()
for client in "${ALL_CLIENTS[@]}"; do
    # Check if client has data in any of the metric tables
    if retry_query "waiting for $client" \
        "SELECT sum(cnt) FROM (
            SELECT count() as cnt FROM sched_on_cpu WHERE client_type = '$client'
            UNION ALL SELECT count() FROM syscall_read WHERE client_type = '$client'
            UNION ALL SELECT count() FROM net_io WHERE client_type = '$client'
        )" \
        '[[ -n "$RESULT" && "$RESULT" -gt 0 ]]'; then
        COUNT=$(query "SELECT sum(cnt) FROM (
            SELECT count() as cnt FROM sched_on_cpu WHERE client_type = '$client'
            UNION ALL SELECT count() FROM syscall_read WHERE client_type = '$client'
            UNION ALL SELECT count() FROM net_io WHERE client_type = '$client'
        )")
        echo "   ✓ $client: $COUNT rows"
    else
        if is_optional "$client"; then
            echo "   ⚠ $client: MISSING (optional)"
            OPTIONAL_MISSING+=("$client")
        else
            echo "   ✗ $client: MISSING"
            MISSING+=("$client")
        fi
    fi
done

if [[ ${#OPTIONAL_MISSING[@]} -gt 0 ]]; then
    echo "WARNING: Optional clients not detected: ${OPTIONAL_MISSING[*]}"
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo "FAIL: Missing required clients: ${MISSING[*]}"
    exit 1
fi

# 4. Scheduler metrics (sched_on_cpu table)
echo -n "4. Scheduler metrics... "
SCHED=$(query "SELECT count() FROM sched_on_cpu")
if [[ -n "$SCHED" && "$SCHED" -gt 0 ]]; then
    echo "PASS ($SCHED)"
else
    echo "FAIL"
    exit 1
fi

# 5. Syscall metrics (syscall_read table)
echo -n "5. Syscall metrics... "
SYSCALL=$(query "SELECT count() FROM syscall_read")
if [[ -n "$SYSCALL" && "$SYSCALL" -gt 0 ]]; then
    echo "PASS ($SYSCALL)"
else
    echo "FAIL"
    exit 1
fi

# 6. Network metrics (net_io table)
echo -n "6. Network metrics... "
NET=$(query "SELECT count() FROM net_io")
if [[ -n "$NET" && "$NET" -gt 0 ]]; then
    echo "PASS ($NET)"
else
    echo "FAIL"
    exit 1
fi

# 7. Non-zero values (check sched_on_cpu as representative)
echo -n "7. Non-zero values... "
NONZERO=$(query "SELECT count() FROM sched_on_cpu WHERE sum > 0 OR count > 0")
if [[ -n "$NONZERO" && "$NONZERO" -gt 0 ]]; then
    echo "PASS ($NONZERO)"
else
    echo "FAIL"
    exit 1
fi

# 8. Histogram consistency (syscall_read has histograms)
echo -n "8. Histogram consistency... "
MISMATCH=$(query "
    SELECT count() FROM syscall_read
    WHERE count > 0
    AND count != (hist_1us + hist_10us + hist_100us + hist_1ms + hist_10ms + hist_100ms + hist_1s + hist_10s + hist_100s + hist_inf)
")
if [[ "$MISMATCH" == "0" ]]; then
    echo "PASS"
else
    echo "FAIL ($MISMATCH mismatches)"
    exit 1
fi

# 9. 100ms interval (check sched_on_cpu)
echo -n "9. 100ms interval... "
INTERVALS=$(query "SELECT DISTINCT interval_ms FROM sched_on_cpu")
if [[ "$INTERVALS" == "100" ]]; then
    echo "PASS"
else
    echo "FAIL ($INTERVALS)"
    exit 1
fi

echo ""
echo "=== All Tests Passed ==="
echo ""

# Summary across key tables
echo "=== Summary by Table ==="
for table in sched_on_cpu sched_off_cpu sched_runqueue syscall_read syscall_write net_io tcp_retransmit disk_latency disk_bytes sync_state; do
    COUNT=$(query "SELECT count() FROM $table" 2>/dev/null || echo "0")
    echo "$table: $COUNT rows"
done

echo ""
echo "=== Client Distribution (sched_on_cpu) ==="
query "
    SELECT client_type, countDistinct(pid) as pids, count() as rows
    FROM sched_on_cpu GROUP BY client_type ORDER BY client_type FORMAT PrettyCompact
"
