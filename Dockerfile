FROM rust:1.87.0-bookworm AS builder

# Install protobuf compiler required for VLS dependencies
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*

COPY . .

# Build with release mode to reduce size and build time
RUN cargo build --release --features vls


FROM debian:bookworm-slim

COPY --from=builder ./target/release/rgb-lightning-node /usr/bin/rgb-lightning-node

RUN apt-get update && apt install -y --no-install-recommends \
    ca-certificates openssl \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ENTRYPOINT ["/usr/bin/rgb-lightning-node"]
