#!/usr/bin/env bash
set -euo pipefail

ENCLAVE="${ENCLAVE:?ENCLAVE is required}"
EL_CLIENT="${EL_CLIENT:?EL_CLIENT is required}"
CL_CLIENT="${CL_CLIENT:?CL_CLIENT is required}"

CLICKHOUSE_HOST="${CLICKHOUSE_HOST:-localhost}"
CLICKHOUSE_PORT="${CLICKHOUSE_PORT:-8123}"
MEASUREMENT_SECONDS="${MEASUREMENT_SECONDS:-180}"
MAX_WAIT_SECONDS="${MAX_WAIT_SECONDS:-240}"
REL_TOLERANCE="${REL_TOLERANCE:-0.15}"
MAX_CORE_HEADROOM="${MAX_CORE_HEADROOM:-1.05}"
MIN_TRUTH_CORES="${MIN_TRUTH_CORES:-0.05}"
LOAD_WORKERS="${LOAD_WORKERS:-4}"

LOAD_PIDS=()

cleanup() {
    local exit_code=$?
    if [[ ${#LOAD_PIDS[@]} -gt 0 ]]; then
        kill "${LOAD_PIDS[@]}" >/dev/null 2>&1 || true
        wait "${LOAD_PIDS[@]}" >/dev/null 2>&1 || true
    fi

    if [[ $exit_code -ne 0 ]]; then
        echo ""
        echo "=== Failure Context ==="
        docker ps --format 'table {{.ID}}\t{{.Names}}\t{{.Status}}' || true
        echo ""
        echo "Recent cpu_utilization rows:"
        query "
            SELECT window_start, client_type, pid, total_on_cpu_ns, interval_ms, active_cores, system_cores
            FROM cpu_utilization
            WHERE client_type IN ('$EL_CLIENT', '$CL_CLIENT')
            ORDER BY window_start DESC
            LIMIT 20
            FORMAT PrettyCompact
        " || true
    fi

    exit "$exit_code"
}
trap cleanup EXIT

query() {
    curl -sf "http://${CLICKHOUSE_HOST}:${CLICKHOUSE_PORT}" --data-binary "$1"
}

retry_until() {
    local description="$1"
    local deadline=$((SECONDS + MAX_WAIT_SECONDS))
    shift

    until "$@"; do
        if (( SECONDS >= deadline )); then
            echo "Timed out waiting for ${description}" >&2
            return 1
        fi
        sleep 5
    done
}

logical_service_name() {
    local layer="$1"
    case "$layer" in
        el) printf 'el-1-%s-%s\n' "$EL_CLIENT" "$CL_CLIENT" ;;
        cl) printf 'cl-1-%s-%s\n' "$CL_CLIENT" "$EL_CLIENT" ;;
        *)
            echo "unknown layer: $layer" >&2
            return 1
            ;;
    esac
}

docker_container_name() {
    local logical_name="$1"
    local container_name
    container_name="$(docker ps --format '{{.Names}}' | grep "$logical_name" | head -1 || true)"
    if [[ -z "$container_name" ]]; then
        echo "failed to find docker container for ${logical_name}" >&2
        return 1
    fi
    printf '%s\n' "$container_name"
}

cpu_usage_ns_for_container() {
    local container_name="$1"
    local pid
    pid="$(docker inspect --format '{{.State.Pid}}' "$container_name")"
    if [[ -z "$pid" || "$pid" == "0" ]]; then
        echo "invalid container pid for ${container_name}" >&2
        return 1
    fi

    local cg_path
    cg_path="$(awk -F: '$1 == "0" { print $3 }' "/proc/${pid}/cgroup")"
    if [[ -n "$cg_path" && -f "/sys/fs/cgroup${cg_path}/cpu.stat" ]]; then
        awk '/^usage_usec / { print $2 * 1000 }' "/sys/fs/cgroup${cg_path}/cpu.stat"
        return 0
    fi

    local line controllers relpath
    while IFS=: read -r _ controllers relpath; do
        if [[ "$controllers" != *cpuacct* ]]; then
            continue
        fi
        for mount in /sys/fs/cgroup/cpuacct /sys/fs/cgroup/cpu,cpuacct; do
            if [[ -f "${mount}${relpath}/cpuacct.usage" ]]; then
                cat "${mount}${relpath}/cpuacct.usage"
                return 0
            fi
        done
    done < "/proc/${pid}/cgroup"

    echo "failed to resolve cpu accounting path for ${container_name}" >&2
    return 1
}

resolve_kurtosis_endpoint() {
    local service_name="$1"
    shift
    local port_name
    for port_name in "$@"; do
        if endpoint="$(kurtosis port print "$ENCLAVE" "$service_name" "$port_name" 2>/dev/null)"; then
            printf '%s\n' "$endpoint"
            return 0
        fi
    done
    return 1
}

spawn_el_load() {
    local endpoint="$1"
    (
        while true; do
            curl -sf \
                -H 'Content-Type: application/json' \
                --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
                "$endpoint" >/dev/null || true
            curl -sf \
                -H 'Content-Type: application/json' \
                --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",true],"id":2}' \
                "$endpoint" >/dev/null || true
            curl -sf \
                -H 'Content-Type: application/json' \
                --data '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":3}' \
                "$endpoint" >/dev/null || true
            curl -sf \
                -H 'Content-Type: application/json' \
                --data '{"jsonrpc":"2.0","method":"web3_clientVersion","params":[],"id":4}' \
                "$endpoint" >/dev/null || true
        done
    ) &
    LOAD_PIDS+=("$!")
}

spawn_cl_load() {
    local endpoint="$1"
    (
        while true; do
            curl -sf "${endpoint}/eth/v1/node/syncing" >/dev/null || true
            curl -sf "${endpoint}/eth/v1/node/identity" >/dev/null || true
            curl -sf "${endpoint}/eth/v1/beacon/headers/head" >/dev/null || true
            curl -sf "${endpoint}/eth/v1/beacon/states/head/fork" >/dev/null || true
        done
    ) &
    LOAD_PIDS+=("$!")
}

start_optional_load() {
    local cl_service el_service beacon_endpoint execution_endpoint
    cl_service="$(logical_service_name cl)"
    el_service="$(logical_service_name el)"

    beacon_endpoint="$(resolve_kurtosis_endpoint "$cl_service" http || true)"
    execution_endpoint="$(resolve_kurtosis_endpoint "$el_service" rpc http || true)"

    if [[ -n "$execution_endpoint" ]]; then
        echo "Starting ${LOAD_WORKERS} execution load workers against ${execution_endpoint}"
        for _ in $(seq 1 "$LOAD_WORKERS"); do
            spawn_el_load "$execution_endpoint"
        done
    fi

    if [[ -n "$beacon_endpoint" ]]; then
        echo "Starting ${LOAD_WORKERS} consensus load workers against ${beacon_endpoint}"
        for _ in $(seq 1 "$LOAD_WORKERS"); do
            spawn_cl_load "$beacon_endpoint"
        done
    fi
}

wait_for_cpu_rows() {
    local distinct_clients
    distinct_clients="$(query "
        SELECT uniqExact(client_type)
        FROM cpu_utilization
        WHERE client_type IN ('$EL_CLIENT', '$CL_CLIENT')
    " 2>/dev/null || echo 0)"
    [[ "$distinct_clients" =~ ^[0-9]+$ && "$distinct_clients" -eq 2 ]]
}

average_cores_from_ns() {
    local delta_ns="$1"
    awk -v ns="$delta_ns" -v secs="$MEASUREMENT_SECONDS" 'BEGIN { printf "%.6f", ns / 1000000000 / secs }'
}

relative_error() {
    local observed="$1"
    local truth="$2"
    awk -v observed="$observed" -v truth="$truth" '
        BEGIN {
            diff = observed - truth;
            if (diff < 0) diff = -diff;
            if (truth <= 0) {
                print (observed == 0 ? "0.000000" : "999999.000000");
                exit;
            }
            printf "%.6f", diff / truth;
        }
    '
}

assert_within_tolerance() {
    local label="$1"
    local observed="$2"
    local truth="$3"
    local rel_err
    rel_err="$(relative_error "$observed" "$truth")"

    awk -v label="$label" -v observed="$observed" -v truth="$truth" -v rel_err="$rel_err" -v tol="$REL_TOLERANCE" '
        BEGIN {
            if (truth > 0 && rel_err <= tol) {
                exit 0;
            }
            if (truth == 0 && observed == 0) {
                exit 0;
            }
            printf "%s outside tolerance: observed=%s truth=%s rel_err=%s tol=%s\n", label, observed, truth, rel_err, tol > "/dev/stderr";
            exit 1;
        }
    '
}

assert_minimum_truth_load() {
    local label="$1"
    local truth="$2"
    awk -v label="$label" -v truth="$truth" -v min_truth="$MIN_TRUTH_CORES" '
        BEGIN {
            if (truth >= min_truth) {
                exit 0;
            }
            printf "%s did not sustain enough CPU load for comparison: truth=%s min=%s\n", label, truth, min_truth > "/dev/stderr";
            exit 1;
        }
    '
}

assert_max_interval_cores() {
    local label="$1"
    local max_interval_cores="$2"
    local system_cores="$3"
    awk -v label="$label" -v interval_cores="$max_interval_cores" -v system_cores="$system_cores" -v headroom="$MAX_CORE_HEADROOM" '
        BEGIN {
            allowed = system_cores * headroom;
            if (interval_cores <= allowed) {
                exit 0;
            }
            printf "%s exceeded physical CPU envelope: max_interval_cores=%s allowed=%s system_cores=%s\n", label, interval_cores, allowed, system_cores > "/dev/stderr";
            exit 1;
        }
    '
}

observoor_cores_for_client() {
    local client="$1"
    local start_ts="$2"
    local end_ts="$3"
    local sum_ns
    sum_ns="$(query "
        SELECT toInt64(round(coalesce(sum(total_on_cpu_ns), 0)))
        FROM cpu_utilization
        WHERE client_type = '$client'
          AND window_start >= toDateTime64('$start_ts', 3, 'UTC')
          AND window_start < toDateTime64('$end_ts', 3, 'UTC')
    ")"
    average_cores_from_ns "$sum_ns"
}

max_interval_cores_for_client() {
    local client="$1"
    local start_ts="$2"
    local end_ts="$3"
    query "
        SELECT round(coalesce(max(total_on_cpu_ns / (interval_ms * 1000000.0)), 0), 6)
        FROM cpu_utilization
        WHERE client_type = '$client'
          AND window_start >= toDateTime64('$start_ts', 3, 'UTC')
          AND window_start < toDateTime64('$end_ts', 3, 'UTC')
    "
}

system_cores_for_client() {
    local client="$1"
    local start_ts="$2"
    local end_ts="$3"
    query "
        SELECT toUInt32(coalesce(max(system_cores), 0))
        FROM cpu_utilization
        WHERE client_type = '$client'
          AND window_start >= toDateTime64('$start_ts', 3, 'UTC')
          AND window_start < toDateTime64('$end_ts', 3, 'UTC')
    "
}

echo "=== CPU Accounting Validation ==="
echo "Enclave: ${ENCLAVE}"
echo "Pair: ${CL_CLIENT} + ${EL_CLIENT}"
echo "Measurement window: ${MEASUREMENT_SECONDS}s"
echo ""

retry_until "cpu_utilization rows" wait_for_cpu_rows

EL_CONTAINER="$(docker_container_name "$(logical_service_name el)")"
CL_CONTAINER="$(docker_container_name "$(logical_service_name cl)")"

echo "Execution container: ${EL_CONTAINER}"
echo "Consensus container: ${CL_CONTAINER}"

start_optional_load

START_TS="$(date -u +"%Y-%m-%d %H:%M:%S.000")"
EL_CPU_START="$(cpu_usage_ns_for_container "$EL_CONTAINER")"
CL_CPU_START="$(cpu_usage_ns_for_container "$CL_CONTAINER")"

echo "Measurement start: ${START_TS}"
sleep "$MEASUREMENT_SECONDS"

END_TS="$(date -u +"%Y-%m-%d %H:%M:%S.000")"
EL_CPU_END="$(cpu_usage_ns_for_container "$EL_CONTAINER")"
CL_CPU_END="$(cpu_usage_ns_for_container "$CL_CONTAINER")"

EL_TRUTH_CORES="$(average_cores_from_ns "$((EL_CPU_END - EL_CPU_START))")"
CL_TRUTH_CORES="$(average_cores_from_ns "$((CL_CPU_END - CL_CPU_START))")"

EL_OBSERVED_CORES="$(observoor_cores_for_client "$EL_CLIENT" "$START_TS" "$END_TS")"
CL_OBSERVED_CORES="$(observoor_cores_for_client "$CL_CLIENT" "$START_TS" "$END_TS")"

EL_MAX_INTERVAL_CORES="$(max_interval_cores_for_client "$EL_CLIENT" "$START_TS" "$END_TS")"
CL_MAX_INTERVAL_CORES="$(max_interval_cores_for_client "$CL_CLIENT" "$START_TS" "$END_TS")"

EL_SYSTEM_CORES="$(system_cores_for_client "$EL_CLIENT" "$START_TS" "$END_TS")"
CL_SYSTEM_CORES="$(system_cores_for_client "$CL_CLIENT" "$START_TS" "$END_TS")"

printf '\n%-12s %-12s %-12s %-12s %-12s\n' "client" "truth" "observoor" "rel_err" "max_window"
for client in "$EL_CLIENT" "$CL_CLIENT"; do
    if [[ "$client" == "$EL_CLIENT" ]]; then
        truth="$EL_TRUTH_CORES"
        observed="$EL_OBSERVED_CORES"
        max_window="$EL_MAX_INTERVAL_CORES"
    else
        truth="$CL_TRUTH_CORES"
        observed="$CL_OBSERVED_CORES"
        max_window="$CL_MAX_INTERVAL_CORES"
    fi
    printf '%-12s %-12s %-12s %-12s %-12s\n' \
        "$client" \
        "$truth" \
        "$observed" \
        "$(relative_error "$observed" "$truth")" \
        "$max_window"
done

assert_minimum_truth_load "$EL_CLIENT" "$EL_TRUTH_CORES"
assert_minimum_truth_load "$CL_CLIENT" "$CL_TRUTH_CORES"

assert_within_tolerance "$EL_CLIENT" "$EL_OBSERVED_CORES" "$EL_TRUTH_CORES"
assert_within_tolerance "$CL_CLIENT" "$CL_OBSERVED_CORES" "$CL_TRUTH_CORES"

assert_max_interval_cores "$EL_CLIENT" "$EL_MAX_INTERVAL_CORES" "$EL_SYSTEM_CORES"
assert_max_interval_cores "$CL_CLIENT" "$CL_MAX_INTERVAL_CORES" "$CL_SYSTEM_CORES"

echo ""
echo "CPU accounting validation passed"
