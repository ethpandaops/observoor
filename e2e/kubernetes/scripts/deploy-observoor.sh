#!/bin/bash
# Deploy ClickHouse and observoor to the KIND cluster.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(dirname "$SCRIPT_DIR")"
MANIFESTS_DIR="${E2E_DIR}/manifests"

BEACON_ENDPOINT="${BEACON_ENDPOINT:-}"

if [[ -z "$BEACON_ENDPOINT" ]]; then
    echo "ERROR: BEACON_ENDPOINT environment variable is required"
    exit 1
fi

echo "=== Deploying observoor to Kubernetes ==="
echo "Beacon endpoint: $BEACON_ENDPOINT"

# Create namespace.
echo "Creating namespace..."
kubectl apply -f "${MANIFESTS_DIR}/namespace.yaml"

# Deploy ClickHouse.
echo "Deploying ClickHouse..."
kubectl apply -f "${MANIFESTS_DIR}/clickhouse.yaml"

# Wait for ClickHouse deployment to be ready.
echo "Waiting for ClickHouse deployment to be ready..."
kubectl -n observoor-test rollout status deployment/clickhouse --timeout=180s

# Wait for ClickHouse to be fully accepting connections.
echo "Waiting for ClickHouse to accept connections..."
for i in $(seq 1 60); do
    if kubectl -n observoor-test exec deployment/clickhouse -- \
        clickhouse-client --query "SELECT 1" > /dev/null 2>&1; then
        echo "ClickHouse is ready"
        break
    fi
    if [ $i -eq 60 ]; then
        echo "ERROR: ClickHouse failed to become ready"
        kubectl -n observoor-test logs deployment/clickhouse --tail=50 || true
        exit 1
    fi
    echo "Waiting for ClickHouse... (attempt $i)"
    sleep 2
done

# Update ConfigMap with beacon endpoint.
echo "Configuring observoor with beacon endpoint..."
sed "s|\${BEACON_ENDPOINT}|${BEACON_ENDPOINT}|g" "${MANIFESTS_DIR}/configmap.yaml" | kubectl apply -f -

# Deploy observoor (using Deployment for E2E to avoid migration race).
echo "Deploying observoor..."
kubectl apply -f "${MANIFESTS_DIR}/daemonset.yaml"

# Wait for observoor pod to be ready.
echo "Waiting for observoor pod to be ready..."
kubectl -n observoor-test rollout status deployment/observoor --timeout=180s

echo "=== Deployment complete ==="
echo ""
echo "Pods:"
kubectl -n observoor-test get pods
echo ""
echo "Services:"
kubectl -n observoor-test get svc
