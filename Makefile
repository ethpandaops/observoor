.PHONY: all build test lint fmt clean docker-build bench bench-smoke perf-suite e2e-up e2e-down e2e-test e2e-k8s-up e2e-k8s-test e2e-k8s-down

BINARY := observoor
PERF_CARGO_ARGS ?= --no-default-features

all: build

build:
	cargo build --release

test:
	cargo test --all-features

lint:
	cargo fmt --check
	cargo clippy --all-features -- -D warnings

fmt:
	cargo fmt

clean:
	cargo clean

docker-build:
	docker build --build-arg GIT_COMMIT=$$(git rev-parse HEAD) -t observoor:latest .

bench:
	cargo bench $(PERF_CARGO_ARGS) --bench hot_paths

bench-smoke:
	cargo bench $(PERF_CARGO_ARGS) --bench hot_paths -- --warm-up-time 0.2 --measurement-time 0.4

perf-suite:
	cargo test $(PERF_CARGO_ARGS) --test blackbox_pipeline
	cargo test $(PERF_CARGO_ARGS) --test perf_alloc
	cargo bench $(PERF_CARGO_ARGS) --bench hot_paths -- --warm-up-time 0.2 --measurement-time 0.4

e2e-up:
	docker compose -f e2e/docker-compose.yml up -d

e2e-down:
	docker compose -f e2e/docker-compose.yml down -v

e2e-test:
	./e2e/scripts/run-e2e-tests.sh

# Kubernetes E2E testing with K3s.
e2e-k8s-up:
	./e2e/kubernetes/scripts/setup-cluster.sh

e2e-k8s-test:
	./e2e/kubernetes/scripts/run-tests.sh

e2e-k8s-down:
	./e2e/kubernetes/scripts/teardown.sh
