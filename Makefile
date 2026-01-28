.PHONY: all generate build test lint clean docker-build e2e-up e2e-down e2e-test

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

all: generate build

# Invoke bpf2go directly (avoids go generate package-loading chicken-and-egg).
generate:
	cd internal/tracer && $(GO) run github.com/cilium/ebpf/cmd/bpf2go \
		-cc $(CLANG) \
		-cflags "$(BPF_CFLAGS)" \
		-go-package tracer \
		-target $(BPF_TARGET) \
		-type syscall_event \
		-type disk_io_event \
		-type net_io_event \
		-type sched_event \
		-type page_fault_event \
		-type fd_event \
		observoor ../../bpf/observoor.c -- \
		-I../../bpf/headers -I../../bpf/include

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
