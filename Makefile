.PHONY: build test verify clean fmt vet

BIN := age-keygen-det
PKG := ./cmd/age-keygen-det

build:
	go build -trimpath -ldflags="-buildid= -s -w" -o $(BIN) $(PKG)

test:
	go test ./...

# verify runs the cross-validation tests against stock age v1.3.0+.
# Fails loudly if `age` or `age-keygen` is not in PATH.
verify:
	@command -v age-keygen >/dev/null || (echo "ERROR: age-keygen not in PATH; install age v1.3.0+" && exit 1)
	@command -v age >/dev/null || (echo "ERROR: age not in PATH; install age v1.3.0+" && exit 1)
	go test -v -run 'CrossValidate|RoundTrip' ./pkg/agekeygendet/

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -f $(BIN)
	rm -rf dist/
