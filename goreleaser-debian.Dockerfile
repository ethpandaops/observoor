FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates \
  dmidecode \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
COPY observoor* /observoor
ENTRYPOINT ["/observoor"]
