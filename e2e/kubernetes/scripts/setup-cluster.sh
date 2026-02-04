#!/bin/bash
# Setup KIND cluster with eBPF support and load observoor image.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
E2E_DIR="$(dirname "$SCRIPT_DIR")"
REPO_ROOT="$(dirname "$(dirname "$E2E_DIR")")"

CLUSTER_NAME="${CLUSTER_NAME:-observoor-e2e}"
KIND_CONFIG="${E2E_DIR}/kind-config.yaml"

echo "=== Setting up KIND cluster with eBPF support ==="

# Check for required tools.
for tool in kind kubectl kurtosis docker; do
    if ! command -v "$tool" &> /dev/null; then
        echo "ERROR: $tool is required but not installed"
        exit 1
    fi
done

# Delete existing cluster if it exists.
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "Deleting existing cluster: $CLUSTER_NAME"
    kind delete cluster --name "$CLUSTER_NAME"
fi

# Create the cluster.
echo "Creating KIND cluster: $CLUSTER_NAME"
kind create cluster --name "$CLUSTER_NAME" --config "$KIND_CONFIG"

# Wait for nodes to be ready.
echo "Waiting for nodes to be ready..."
kubectl wait --for=condition=Ready nodes --all --timeout=120s

# Build observoor image if not already built.
if ! docker images | grep -q "observoor.*latest"; then
    echo "Building observoor Docker image..."
    (cd "$REPO_ROOT" && make docker-build)
fi

# Load the observoor image into KIND.
echo "Loading observoor image into KIND cluster..."
kind load docker-image observoor:latest --name "$CLUSTER_NAME"

echo "=== KIND cluster setup complete ==="
echo "Cluster: $CLUSTER_NAME"
kubectl get nodes
