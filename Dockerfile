# Quantaureum Node Dockerfile
# Multi-stage build for production
#
# The repo is a go.work multi-module workspace: the main module replace-directs
# to ./crypto, ./encoding, ./types and ./tools/tests/integration/testutil. Those
# sub-module go.mod/go.sum files must be present BEFORE `go mod download` runs,
# or replace resolution fails.

# Build stage
FROM golang:1.26.6-alpine AS builder

RUN apk add --no-cache git make gcc musl-dev

WORKDIR /build

# Cache dependencies — copy ALL module files of the workspace first
# (main module + the four replace-target submodules + workspace file).
COPY go.mod go.sum go.work go.work.sum ./
COPY crypto/go.mod crypto/go.sum crypto/
COPY encoding/go.mod encoding/go.sum encoding/
COPY types/go.mod types/go.sum types/
COPY tools/tests/integration/testutil/go.mod tools/tests/integration/testutil/
RUN go mod download

# Copy source and build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /qaud ./cmd/qaud
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /qauctl ./cmd/qauctl
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /qau-faucet ./cmd/faucet

# Runtime stage
FROM alpine:3.21

# L-8 FIX: Install curl for HEALTHCHECK.
# Previously the HEALTHCHECK used `wget`, but the runtime image only installed
# ca-certificates and tzdata. While Alpine's busybox provides a minimal wget,
# it is not guaranteed to be present in all minimal images and has limited
# flag support. curl is the standard tool for container health checks and
# provides reliable behavior with explicit timeout flags.
RUN apk add --no-cache ca-certificates tzdata curl

# Create non-root user
RUN addgroup -S qau && adduser -S qau -G qau

WORKDIR /app

# Copy binaries
COPY --from=builder /qaud /usr/local/bin/qaud
COPY --from=builder /qauctl /usr/local/bin/qauctl
COPY --from=builder /qau-faucet /usr/local/bin/qau-faucet

# Copy default configs
COPY --from=builder /build/configs/ /app/configs/

# Create data directory
RUN mkdir -p /app/data && chown -R qau:qau /app

USER qau

# P2P port
EXPOSE 9000
# RPC port
EXPOSE 8545
# WebSocket port
EXPOSE 8546
# Health check port
EXPOSE 8080

# Data volume
VOLUME ["/app/data"]

# Health check
# L-8 FIX: Use curl instead of wget for reliability.
# curl is explicitly installed in the runtime stage and provides better
# timeout and error handling than busybox wget.
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD curl -sf http://localhost:8080/health || exit 1

# Validator deployments must inject secrets via environment at runtime
# (QAU_VALIDATOR_KEY_PASSWORD / QAU_SESSION_KEY_FILE etc.), NEVER via build
# args or baked-in files.
ENV QAU_LOG_LEVEL=info

ENTRYPOINT ["qaud"]
CMD ["--config", "/app/configs/config.testnet.json"]
