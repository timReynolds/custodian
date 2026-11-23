GO ?= $(shell command -v go 2>/dev/null || echo /Users/tim/Code/github.com/timreynolds/forge/data/kind/tools/go/bin/go)
BIN_DIR ?= bin

.PHONY: all build test test-unit vet openapi-validate tidy clean

all: vet build test-unit

build:
	$(GO) build ./...
	@if [ -d cmd ]; then \
		mkdir -p $(BIN_DIR); \
		for d in cmd/*/; do \
			[ -d "$$d" ] && $(GO) build -o "$(BIN_DIR)/$$(basename $$d)" "./$${d%/}"; \
		done; \
	fi

vet:
	$(GO) vet ./...

test-unit:
	$(GO) test -race -short ./...

test:
	$(GO) test -race ./...

openapi-validate:
	$(GO) test -v -count=1 ./internal/api/openapi/...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN_DIR) coverage.out coverage.html
