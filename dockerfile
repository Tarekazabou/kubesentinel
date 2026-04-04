FROM golang:1.21-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY cmd/ ./cmd/
COPY internal/ ./internel/
COPY pkg/ ./pkg/

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o kubesentinel \
    ./cmd/kubesentinel

FROM alpine:3.18

WORKDIR /app
COPY --from=builder /app/kubesentinel /app/kubesentinel
RUN mkdir -p /app/forensics /app/reports /app/config

RUN chmod +x /app/kubesentinel

ENTRYPOINT [ "/app/kubesentinel" ]
CMD ["--help"]