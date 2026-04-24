#!/usr/bin/env bash
# run-bench.sh — CPU overhead benchmark for observoor.
#
# Measures the CPU seconds consumed by observoor while tracing a deterministic
# synthetic workload via eBPF. Outputs a JSON result to stdout.
#
# Usage: sudo bash bench-cpu/run-bench.sh [iterations] [observoor-binary]
#
# Requires: Linux, root (for eBPF), gcc, python3, bc.
set -euo pipefail

ITERATIONS="${1:-50000}"
OBSERVOOR_BIN="${2:-./target/release/observoor}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

MOCK_BEACON_PORT=15999
HEALTH_PORT=19090
READY_FILE="/tmp/stress-bench-ready"
STRESS_BIN="/tmp/stress-bench"

# Cleanup on exit.
cleanup() {
    set +e
    [ -n "${STRESS_PID:-}" ] && kill "$STRESS_PID" 2>/dev/null
    [ -n "${OBS_PID:-}" ] && kill "$OBS_PID" 2>/dev/null
    [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null
    rm -f "$READY_FILE" "$STRESS_BIN"
    wait 2>/dev/null
}
trap cleanup EXIT

# Read CPU time (utime + stime) from /proc/<pid>/stat in seconds.
read_cpu() {
    local pid=$1
    local clk_tck
    clk_tck=$(getconf CLK_TCK)
    local utime stime
    # Fields 14 and 15 of /proc/pid/stat are utime and stime.
    read -r utime stime < <(awk '{print $14, $15}' "/proc/$pid/stat")
    echo "scale=6; ($utime + $stime) / $clk_tck" | bc -l
}

# Wait for an HTTP endpoint to respond (up to timeout).
wait_for_http() {
    local url=$1
    local timeout=${2:-30}
    for i in $(seq 1 "$timeout"); do
        if curl -sf "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    echo "ERROR: timed out waiting for $url" >&2
    return 1
}

echo "=== observoor CPU overhead benchmark ===" >&2
echo "Iterations: $ITERATIONS (x4 threads)" >&2
echo "Binary: $OBSERVOOR_BIN" >&2

# 1. Compile the synthetic workload.
echo "Compiling stress-bench..." >&2
gcc -O2 -pthread -o "$STRESS_BIN" "$SCRIPT_DIR/stress-bench.c"

# 2. Start mock beacon.
echo "Starting mock beacon on :${MOCK_BEACON_PORT}..." >&2
python3 "$SCRIPT_DIR/mock-beacon.py" "$MOCK_BEACON_PORT" &
MOCK_PID=$!
wait_for_http "http://127.0.0.1:${MOCK_BEACON_PORT}/eth/v1/beacon/genesis" 20

# 3. Start stress-bench in wait mode (so observoor discovers it at startup).
#    Redirect stdout to stderr so "DONE" message doesn't pollute our JSON output.
echo "Starting stress-bench (waiting for signal)..." >&2
"$STRESS_BIN" --wait-for-signal "$ITERATIONS" 1>&2 &
STRESS_PID=$!

# Wait for ready file.
for i in $(seq 1 50); do
    [ -f "$READY_FILE" ] && break
    sleep 0.1
done
if [ ! -f "$READY_FILE" ]; then
    echo "ERROR: stress-bench did not create ready file" >&2
    exit 1
fi

# 4. Start observoor (redirect stdout to stderr so only our JSON goes to stdout).
echo "Starting observoor..." >&2
"$OBSERVOOR_BIN" --config "$SCRIPT_DIR/observoor-bench.yaml" 1>&2 &
OBS_PID=$!

# Wait for health endpoint.
wait_for_http "http://127.0.0.1:${HEALTH_PORT}/healthz" 60

echo "observoor ready (PID $OBS_PID), stress-bench ready (PID $STRESS_PID)" >&2

# 5. Record CPU before.
CPU_BEFORE=$(read_cpu "$OBS_PID")
WALL_BEFORE=$(date +%s%N)

# 6. Signal stress-bench to start the workload.
echo "Sending SIGUSR1 to stress-bench..." >&2
kill -USR1 "$STRESS_PID"

# 7. Wait for stress-bench to finish.
wait "$STRESS_PID" || true
STRESS_PID=""

# 8. Wait for ring buffer drain.
sleep 2

# 9. Record CPU after.
CPU_AFTER=$(read_cpu "$OBS_PID")
WALL_AFTER=$(date +%s%N)

# 10. Compute deltas.
CPU_DELTA=$(echo "scale=6; $CPU_AFTER - $CPU_BEFORE" | bc -l)
WALL_DELTA=$(echo "scale=3; ($WALL_AFTER - $WALL_BEFORE) / 1000000000" | bc -l)
GIT_COMMIT=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 11. Stop observoor gracefully.
kill "$OBS_PID" 2>/dev/null
wait "$OBS_PID" 2>/dev/null || true
OBS_PID=""

echo "Done. CPU: ${CPU_DELTA}s, Wall: ${WALL_DELTA}s" >&2

# 12. Output JSON result.
cat <<EOF
{
  "iterations": $ITERATIONS,
  "threads": 4,
  "observoor_cpu_seconds": $CPU_DELTA,
  "wall_clock_seconds": $WALL_DELTA,
  "git_commit": "$GIT_COMMIT",
  "timestamp": "$TIMESTAMP"
}
EOF
