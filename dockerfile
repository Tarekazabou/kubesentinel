FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY pkg/ ./pkg/
COPY config/ ./config/

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o kubesentinel \
    ./cmd/kubesentinel

FROM alpine:3.21

# Create a non-root user for the sentinel process.
RUN addgroup -S sentinel && adduser -S -G sentinel sentinel

WORKDIR /app
COPY --from=builder /app/kubesentinel /app/kubesentinel
RUN mkdir -p /app/forensics /app/reports /app/config/rules \
    && chown -R sentinel:sentinel /app

RUN chmod +x /app/kubesentinel

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/app/kubesentinel", "--help"]

USER sentinel

ENTRYPOINT [ "/app/kubesentinel" ]
CMD ["--help"]