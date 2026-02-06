# Stage 1: Build the BPF programs and Rust binary.
FROM rust:1.88-bookworm AS builder

# Install BPF build dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency downloads by copying manifests first.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./

# Create a dummy main.rs so cargo can fetch dependencies.
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs
RUN cargo fetch

# Copy full source.
COPY . .

# Touch main.rs so cargo rebuilds with real source.
RUN touch src/main.rs

# Build release binary.
RUN cargo build --release

# Stage 2: Minimal runtime image.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/observoor /usr/local/bin/observoor

ENTRYPOINT ["observoor"]
CMD ["--config", "/etc/observoor/config.yaml"]
