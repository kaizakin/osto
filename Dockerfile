# ── Stage 1: Builder ──────────────────────────────────────────────────────────
# Uses the official Go Alpine image so no C toolchain is present; that's fine
# because modernc.org/sqlite is pure Go (CGO_ENABLED=0).
FROM golang:1.23-alpine AS builder

WORKDIR /build

# Disable CGO and target Linux/amd64.
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Copy vendored dependencies first (no network access needed in builder).
# This layer is only invalidated when go.mod/go.sum or vendor/ change.
COPY go.mod go.sum ./
COPY vendor/ vendor/

# Copy the rest of the source and compile with size optimisations.
# -ldflags "-s -w" strips DWARF debug info and symbol table (~30% smaller).
# -mod=vendor tells the toolchain to use the vendor directory.
COPY . .
RUN go build \
      -mod=vendor \
      -ldflags="-s -w" \
      -trimpath \
      -o /app/auth-cli \
      ./cmd/app

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
# Minimal Alpine image — no Go toolchain, no shell tools beyond what Alpine
# ships by default.  The final image is typically <20 MB.
FROM alpine:latest

# Create a non-root user/group (Alpine builtins — no package needed).
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# ca-certificates: optional, allows future HTTPS; best-effort (ignore DNS failures).
RUN apk add --no-cache ca-certificates 2>/dev/null || true

WORKDIR /app

# Create the data directory that will be bind-mounted as a named volume.
RUN mkdir -p /app/data && chown appuser:appgroup /app/data

# Copy the compiled binary and schema from the builder stage.
COPY --from=builder /app/auth-cli  /app/auth-cli
COPY --from=builder /build/db/schema.sql /app/db/schema.sql

# Run as non-root for defence in depth.
USER appuser

# Declare the data volume so Docker knows it should be persisted.
VOLUME ["/app/data"]

# Default command — can be overridden at runtime.
CMD ["./auth-cli"]
