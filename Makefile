.PHONY: build test verify all archive clean fmt vet

BIN := age-keygen-det
PKG := ./cmd/age-keygen-det
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.0.0")
SOURCE_DATE_EPOCH := $(shell git log -1 --format=%ct 2>/dev/null || echo 0)

# Reproducibility flags: trimpath strips path prefixes; -buildid= clears
# the random build ID; -s -w drops debug symbols. With CGO_ENABLED=0
# the binary is statically linked and has no libc dependency.
GOFLAGS := -trimpath -ldflags="-buildid= -s -w"

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -o $(BIN) $(PKG)

test:
	go test ./...

# verify runs the cross-validation tests against stock age v1.3.0+.
# Fails loudly if `age` or `age-keygen` is not in PATH.
verify:
	@command -v age-keygen >/dev/null || (echo "ERROR: age-keygen not in PATH; install age v1.3.0+" && exit 1)
	@command -v age >/dev/null || (echo "ERROR: age not in PATH; install age v1.3.0+" && exit 1)
	go test -v -run 'CrossValidate|RoundTrip' ./pkg/agekeygendet/

# Cross-compile targets. All four are reproducible: same source tree
# + same Go toolchain -> identical binaries.
TARGETS := linux-amd64 linux-arm64 darwin-amd64 darwin-arm64

define build_target
dist/$(BIN)-$(1):
	@mkdir -p dist
	GOOS=$$(word 1,$$(subst -, ,$(1))) \
	GOARCH=$$(word 2,$$(subst -, ,$(1))) \
	CGO_ENABLED=0 \
	go build $(GOFLAGS) -o $$@ $(PKG)
endef

$(foreach t,$(TARGETS),$(eval $(call build_target,$(t))))

all: $(foreach t,$(TARGETS),dist/$(BIN)-$(t))
	@echo "Built: $^"

# archive bundles source + cross-compiled binaries + test vectors
# into a single tarball intended for cold-storage alongside the vault.
# The tarball is mtime-pinned to the latest commit time so repeated
# `make archive` from the same commit produces byte-identical output.
archive: all
	@rm -rf dist/staging
	@mkdir -p dist/staging/$(BIN)-$(VERSION)
	cp -a LICENSE README.md Makefile go.mod go.sum cmd pkg dist/staging/$(BIN)-$(VERSION)/
	cp dist/$(BIN)-linux-amd64 dist/$(BIN)-linux-arm64 \
	   dist/$(BIN)-darwin-amd64 dist/$(BIN)-darwin-arm64 \
	   dist/staging/$(BIN)-$(VERSION)/
	tar --sort=name --mtime=@$(SOURCE_DATE_EPOCH) \
	    --owner=0 --group=0 --numeric-owner \
	    -czf dist/$(BIN)-$(VERSION)-archive.tar.gz \
	    -C dist/staging $(BIN)-$(VERSION)
	rm -rf dist/staging
	@echo ""
	@echo "Archive: dist/$(BIN)-$(VERSION)-archive.tar.gz"
	@sha256sum dist/$(BIN)-$(VERSION)-archive.tar.gz

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -f $(BIN)
	rm -rf dist/
