#!/usr/bin/env bash
# generate-vmlinux.sh - Generate vmlinux.h from the running kernel's BTF.
#
# Usage:
#   ./scripts/generate-vmlinux.sh [output_path]
#
# Requires: bpftool, access to /sys/kernel/btf/vmlinux

set -euo pipefail

OUTPUT="${1:-bpf/headers/vmlinux.h}"

if ! command -v bpftool &> /dev/null; then
    echo "ERROR: bpftool is required but not found" >&2
    exit 1
fi

BTF_PATH="/sys/kernel/btf/vmlinux"
if [ ! -f "$BTF_PATH" ]; then
    echo "ERROR: $BTF_PATH not found. Kernel BTF is required." >&2
    echo "       Ensure CONFIG_DEBUG_INFO_BTF=y in your kernel config." >&2
    exit 1
fi

echo "Generating vmlinux.h from $BTF_PATH..."
bpftool btf dump file "$BTF_PATH" format c > "$OUTPUT"
echo "Written to $OUTPUT"
