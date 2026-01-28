FROM rust:1.91-slim-trixie AS builder

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY rust-lightning ./rust-lightning

RUN cargo build --release


FROM debian:trixie-slim

COPY --from=builder ./target/release/rgb-lightning-node /usr/bin/rgb-lightning-node

RUN apt-get update && apt install -y --no-install-recommends \
    ca-certificates openssl wget s3fs bash unzip curl nvme-cli \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install AWS CLI v2
RUN wget "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -O "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws/

COPY start.sh /

RUN chmod +x start.sh && mkdir /s3

ENTRYPOINT ["/start.sh"]
