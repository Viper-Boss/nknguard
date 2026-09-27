# NKNGuard build.
#
#   make test        standard-library build: vet + test + race (works offline)
#   make deps        fetch the NKN and libp2p modules for the full build
#   make build       full binary for this machine (needs `make deps` once)
#   make release     linux amd64 + arm64 full binaries with SHA256SUMS

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
TAGS    ?= nknsdk libp2pdht
LDFLAGS := -s -w -X github.com/Viper-Boss/nknguard/internal/app.Version=$(VERSION)
GO      ?= go

.PHONY: all test vet race fmt-check deps build build-core release clean

all: test build

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

vet:
	$(GO) vet ./...

test: fmt-check vet
	$(GO) test ./...

race:
	$(GO) test -race ./...

deps:
	$(GO) mod download
	$(GO) mod tidy

build:
	CGO_ENABLED=0 $(GO) build -tags "$(TAGS)" -trimpath -ldflags "$(LDFLAGS)" -o bin/nknguard ./cmd/nknguard

# Stdlib-only binary: init/join/doctor work, `up` explains it needs NKN.
build-core:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/nknguard-core ./cmd/nknguard

release:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -tags "$(TAGS)" -trimpath -ldflags "$(LDFLAGS)" -o dist/nknguard-linux-amd64 ./cmd/nknguard
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -tags "$(TAGS)" -trimpath -ldflags "$(LDFLAGS)" -o dist/nknguard-linux-arm64 ./cmd/nknguard
	cd dist && sha256sum nknguard-linux-* > SHA256SUMS

clean:
	rm -rf bin dist
