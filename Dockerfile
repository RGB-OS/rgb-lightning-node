FROM rust:1.72.0-bookworm as builder

COPY . .

RUN cargo build

FROM debian:bookworm-slim

COPY --from=builder ./target/debug/rgb-lightning-node /usr/bin/rgb-lightning-node

RUN apt-get update && apt install -y --no-install-recommends \
    ca-certificates openssl wget \
    && wget https://s3.amazonaws.com/mountpoint-s3-release/latest/x86_64/mount-s3.deb \
    && apt-get install -y ./mount-s3.deb \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY start.sh /

ENTRYPOINT ["/start.sh"]
