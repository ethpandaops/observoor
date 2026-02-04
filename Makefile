.PHONY: all generate generate-amd64 generate-arm64 generate-all build test lint clean docker-build e2e-up e2e-down e2e-test e2e-k8s-up e2e-k8s-test e2e-k8s-down

BINARY := observoor
GO := go
GOFLAGS := -trimpath
LDFLAGS := -s -w
CLANG := clang

# Architecture detection for BPF compilation.
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
  BPF_TARGET := amd64
  BPF_TARGET_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
  BPF_TARGET := arm64
  BPF_TARGET_ARCH := arm64
else
  $(error Unsupported architecture: $(UNAME_M))
endif

BPF_CFLAGS := -O2 -g -Wall -Werror -D__TARGET_ARCH_$(BPF_TARGET_ARCH)

# BPF source
BPF_SRC := bpf/observoor.c

# Event types to export from BPF
BPF_TYPES := -type syscall_event \
	-type disk_io_event \
	-type net_io_event \
	-type sched_event \
	-type page_fault_event \
	-type fd_event \
	-type sched_runqueue_event \
	-type block_merge_event \
	-type tcp_retransmit_event \
	-type tcp_state_event \
	-type tcp_metrics_event \
	-type mem_latency_event \
	-type swap_event \
	-type oom_kill_event \
	-type process_exit_event

all: generate build

# Invoke bpf2go directly (avoids go generate package-loading chicken-and-egg).
generate:
	cd internal/tracer && $(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) \
		-cflags "$(BPF_CFLAGS)" \
		-go-package tracer \
		-target $(BPF_TARGET) \
		$(BPF_TYPES) \
		observoor ../../bpf/observoor.c -- \
		-I../../bpf/headers -I../../bpf/include

# Architecture-specific BPF generation for cross-compilation
generate-amd64:
	cd internal/tracer && $(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) \
		-cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" \
		-go-package tracer \
		-target amd64 \
		$(BPF_TYPES) \
		observoor ../../bpf/observoor.c -- \
		-I../../bpf/headers -I../../bpf/include

generate-arm64:
	cd internal/tracer && $(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) \
		-cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_arm64" \
		-go-package tracer \
		-target arm64 \
		$(BPF_TYPES) \
		observoor ../../bpf/observoor.c -- \
		-I../../bpf/headers -I../../bpf/include

# Generate BPF code for all architectures (used by goreleaser)
generate-all: generate-amd64 generate-arm64

build: generate
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/observoor

test:
	$(GO) test -race -count=1 ./...

lint:
	golangci-lint run --new-from-rev="origin/master" ./...

clean:
	rm -rf bin/
	rm -f internal/tracer/*_bpfel.go internal/tracer/*_bpfeb.go
	rm -f internal/tracer/*_bpfel.o internal/tracer/*_bpfeb.o

docker-build:
	docker build -t observoor:latest .

e2e-up:
	docker compose -f e2e/docker-compose.yml up -d

e2e-down:
	docker compose -f e2e/docker-compose.yml down -v

e2e-test:
	./e2e/scripts/run-e2e-tests.sh

# Kubernetes E2E testing with KIND.
e2e-k8s-up:
	./e2e/kubernetes/scripts/setup-cluster.sh

e2e-k8s-test:
	./e2e/kubernetes/scripts/run-tests.sh

e2e-k8s-down:
	./e2e/kubernetes/scripts/teardown.sh
