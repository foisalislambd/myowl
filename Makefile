# myOwl — build helpers
# The version comes from VERSION.md (single source of truth); override with `make VERSION=x.y.z`.
VERSION ?= $(shell scripts/version.sh get)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := bin/myowl
DIST    := agent/internal/webui/dist

.PHONY: all web embed build build-go build-linux-amd64 build-linux-arm64 test test-go test-scripts lint version demo dev release clean

all: build

version:
	@echo $(VERSION)

web:
	cd web && pnpm install --frozen-lockfile && pnpm build

lint:
	cd web && pnpm lint && pnpm typecheck
	cd agent && go vet ./...

embed: web
	find $(DIST) -mindepth 1 ! -name '.gitkeep' ! -name 'index.html' -delete 2>/dev/null || true
	cp -r web/out/. $(DIST)/

build: embed
	cd agent && CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o ../$(BIN) ./cmd/myowl

# Build only the Go binary using whatever UI is already in $(DIST)
build-go:
	cd agent && CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o ../$(BIN) ./cmd/myowl

build-linux-amd64: embed
	cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o ../bin/myowl-linux-amd64 ./cmd/myowl

build-linux-arm64: embed
	cd agent && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o ../bin/myowl-linux-arm64 ./cmd/myowl

test: test-go test-scripts

test-go:
	cd agent && go vet ./... && go test ./...

test-scripts:
	scripts/test-version.sh
	bash -n install.sh

demo: build
	./$(BIN) --demo --listen 127.0.0.1:8787

# Run the Next.js dev server against an agent on :8787 (start `make demo` first)
dev:
	cd web && AGENT_URL=http://127.0.0.1:8787 pnpm dev

# Release archives for linux/amd64 and linux/arm64 + SHA256SUMS (same layout as the CI release).
release: build-linux-amd64 build-linux-arm64
	VERSION=$(VERSION) scripts/package.sh

clean:
	rm -rf bin release web/out web/.next
	find $(DIST) -mindepth 1 ! -name '.gitkeep' ! -name 'index.html' -delete 2>/dev/null || true
