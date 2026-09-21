BINARY  := osto
PKG     := ./cmd/app
GO      ?= go
LDFLAGS := -s -w
GOFLAGS := -mod=vendor -trimpath

SQLC    ?= go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.29.0

.PHONY: all build test clean run sqlc generate

all: build

build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY) $(PKG)

test:
	$(GO) test $(GOFLAGS) ./... -count=1

clean:
	rm -f $(BINARY)

run: build
	./$(BINARY)

# Generate query structs and methods from db/schema.sql + db/queries/.
sqlc:
	$(SQLC) generate

generate: sqlc
