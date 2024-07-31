FROM rust:1.77.0-bookworm as builder

COPY . .

RUN cargo build

FROM debian:bookworm-slim

COPY --from=builder ./target/debug/rgb-lightning-node /usr/bin/rgb-lightning-node

RUN apt-get update && apt install -y --no-install-recommends \
    ca-certificates openssl wget s3fs \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY start.sh /

RUN chmod +x start.sh && mkdir /s3

ENTRYPOINT ["/start.sh"]
