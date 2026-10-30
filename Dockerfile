# syntax=docker/dockerfile:1
# ==============================================================================
# 🛡️ CYBERGLASS — Multi-Architecture Air-Gap Container (Linux x86_64 & ARM64)
# ==============================================================================

# Stage 1: Build binary using rust:alpine with musl for 100% static linking
FROM rust:1.80-alpine AS builder

RUN apk add --no-cache musl-dev protobuf-dev make gcc g++ zstd-dev

WORKDIR /app
COPY . .

# Compile self-contained release binary with strip
RUN cargo build --release --bin cyberglass-server && \
    strip target/release/cyberglass-server

# Stage 2: Minimal hardened runtime image
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S cyberglass && adduser -S cyberglass -G cyberglass

WORKDIR /opt/cyberglass

# Copy compiled binary and configuration
COPY --from=builder /app/target/release/cyberglass-server /opt/cyberglass/bin/cyberglass-server
COPY --from=builder /app/config/cyberglass.toml /opt/cyberglass/config/cyberglass.toml
COPY --from=builder /app/rules /opt/cyberglass/rules

# Setup persistent directory tree
RUN mkdir -p /opt/cyberglass/data \
             /opt/cyberglass/index \
             /opt/cyberglass/wal \
             /opt/cyberglass/ontology \
             /opt/cyberglass/models \
             /opt/cyberglass/logs && \
    chown -R cyberglass:cyberglass /opt/cyberglass && \
    chmod -R 750 /opt/cyberglass

USER cyberglass

ENV CYBERGLASS_HOME=/opt/cyberglass
ENV CYBERGLASS_CONFIG=/opt/cyberglass/config/cyberglass.toml

EXPOSE 9400 9401 9402 9403

ENTRYPOINT ["/opt/cyberglass/bin/cyberglass-server"]
CMD ["--home", "/opt/cyberglass"]
