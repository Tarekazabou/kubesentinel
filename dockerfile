# ── Builder ────────────────────────────────────────────────────────────────
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Dependency layer — only invalidated when go.mod/go.sum change
COPY go.mod go.sum ./
RUN go mod download

# Source layers — config is runtime-mounted via bind-mount, no need to bake it in
COPY cmd/      ./cmd/
COPY internal/ ./internal/
COPY pkg/      ./pkg/

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -trimpath \
    -o kubesentinel \
    ./cmd/kubesentinel

# ── Runtime ────────────────────────────────────────────────────────────────
# distroless/static-debian12:nonroot: ~2 MB, includes CA certs + tzdata, no shell
# (ships with uid 65532 "nonroot" user pre-created)
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /app

# Copy binary with correct ownership in one operation
# distroless:nonroot runs as uid 65532 by default
COPY --from=builder --chown=65532:65532 /app/kubesentinel /app/kubesentinel

# Note: forensics/, reports/, config/ are bind-mounted at runtime (see docker-compose.yml).
# No need to mkdir them here; Docker creates them on the host before container starts.

USER nonroot

ENTRYPOINT ["/app/kubesentinel"]
CMD ["monitor-webhook", "--port", "8080"]
