FROM rust:1-bookworm AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p privacy-proxy

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /app/target/release/privacy-proxy /usr/local/bin/privacy-proxy
ENTRYPOINT ["/usr/local/bin/privacy-proxy"]
