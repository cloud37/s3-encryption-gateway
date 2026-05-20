# Build stage
FROM golang:1.26-alpine AS builder

# STRIP_SYMBOLS controls binary symbol-table stripping.
# Set to "false" to produce a symbolicated binary for pprof profiling.
# Default is "true" (stripped) for production images.
# V0.6-OBS-1: see docs/OBSERVABILITY.md §"Runtime Profiling" for usage.
ARG STRIP_SYMBOLS=true
ARG VERSION
ARG COMMIT

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary.
# When STRIP_SYMBOLS=false, -w -s is omitted so pprof shows function names.
# -trimpath is always applied (reproducible builds; does not strip symbols).
RUN if [ "${STRIP_SYMBOLS}" = "false" ]; then \
        LDFLAGS="-X main.version=${VERSION:-dev} -X main.commit=${COMMIT:-unknown}"; \
    else \
        LDFLAGS="-w -s -X main.version=${VERSION:-dev} -X main.commit=${COMMIT:-unknown}"; \
    fi && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="${LDFLAGS}" \
    -o /bin/s3-encryption-gateway \
    ./cmd/server && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="${LDFLAGS}" \
    -o /bin/s3-encryption-gateway-healthcheck \
    ./cmd/healthcheck

# Runtime stage
FROM alpine:3.23

# Install CA certificates for TLS
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 gateway && \
    adduser -D -u 1000 -G gateway gateway

WORKDIR /app

# Copy binary from builder
COPY --from=builder /bin/s3-encryption-gateway /app/s3-encryption-gateway
COPY --from=builder /bin/s3-encryption-gateway-healthcheck /app/healthcheck

# Change ownership
RUN chown -R gateway:gateway /app

# Switch to non-root user
USER gateway

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/app/healthcheck"]

# Run the binary
CMD ["/app/s3-encryption-gateway"]
