.PHONY: build test clean fmt vet

BIN := age-keygen-det
PKG := ./cmd/age-keygen-det

build:
	go build -trimpath -ldflags="-buildid= -s -w" -o $(BIN) $(PKG)

test:
	go test ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -f $(BIN)
	rm -rf dist/
