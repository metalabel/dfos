VERSION ?= dev
BINARY = dfos
GOFLAGS = -ldflags "-X main.version=$(VERSION)"

.PHONY: build clean test

build:
	go build $(GOFLAGS) -o $(BINARY) ./cmd/dfos

clean:
	rm -f $(BINARY)

test:
	go test ./...
