BINARY  := osto
PKG     := ./cmd/app
GO      ?= go
LDFLAGS := -s -w
GOFLAGS := -mod=vendor -trimpath

.PHONY: all build test clean run

all: build

build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY) $(PKG)

test:
	$(GO) test $(GOFLAGS) ./... -count=1

clean:
	rm -f $(BINARY)

run: build
	./$(BINARY)
