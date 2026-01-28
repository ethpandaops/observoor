# Stage 1: Build the BPF programs and Go binary.
FROM golang:1.23-bookworm AS builder

# Install BPF build dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache Go module downloads.
COPY go.mod go.sum ./
RUN go mod download

# Copy source.
COPY . .

# Generate BPF code and build.
RUN make build

# Stage 2: Minimal runtime image.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/bin/observoor /usr/local/bin/observoor

ENTRYPOINT ["observoor"]
CMD ["--config", "/etc/observoor/config.yaml"]
