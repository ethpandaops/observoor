#!/bin/bash
# Teardown KIND cluster and Kurtosis enclave.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-observoor-e2e}"
ENCLAVE_NAME="${ENCLAVE_NAME:-observoor-k8s-test}"

echo "=== Tearing down K8s E2E environment ==="

# Delete Kurtosis enclave.
if kurtosis enclave ls 2>/dev/null | grep -q "$ENCLAVE_NAME"; then
    echo "Removing Kurtosis enclave: $ENCLAVE_NAME"
    kurtosis enclave rm -f "$ENCLAVE_NAME" || true
fi

# Delete KIND cluster.
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "Deleting KIND cluster: $CLUSTER_NAME"
    kind delete cluster --name "$CLUSTER_NAME"
fi

# Stop Kurtosis engine if running.
if kurtosis engine status 2>/dev/null | grep -q "running"; then
    echo "Stopping Kurtosis engine..."
    kurtosis engine stop || true
fi

echo "=== Teardown complete ==="
