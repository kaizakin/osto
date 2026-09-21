FROM golang:1.23-alpine AS builder

WORKDIR /build

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

COPY go.mod go.sum ./
COPY vendor/ vendor/

COPY . .
RUN go build \
      -mod=vendor \
      -ldflags="-s -w" \
      -trimpath \
      -o /app/osto \
      ./cmd/app

FROM alpine:latest

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN apk add --no-cache ca-certificates 2>/dev/null || true

WORKDIR /app

RUN mkdir -p /app/data && chown appuser:appgroup /app/data
COPY --from=builder /app/osto  /app/osto
COPY --from=builder /build/db/schema.sql /app/db/schema.sql

USER appuser

VOLUME ["/app/data"]

CMD ["./osto"]
