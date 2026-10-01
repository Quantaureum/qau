.PHONY: build test lint vet race clean dev build-all \
       build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-windows-amd64 \
       cross-compile dist-clean \
       benchmark benchmark-tps benchmark-qpos benchmark-zkp \
       integration-test \
       lint staticcheck vulncheck fmt deps security-scan

GO := go
GO_BUILD_FLAGS := -trimpath -ldflags="-s -w"
VERSION := 0.1.0
BUILD_DIR := build
CMD_PACKAGES := ./cmd/qaud/ ./cmd/qau-cli/ ./cmd/qauctl/ ./cmd/qauaudit/ ./cmd/qaucold/ ./cmd/relayer/ ./cmd/genvalidators/ ./cmd/checkconfig/ ./cmd/tx-sender/

build:
	$(GO) build $(GO_BUILD_FLAGS) ./cmd/qaud/

build-all:
	@for cmd in $(CMD_PACKAGES); do \
		name=$$(basename $$cmd); \
		echo "Building $$name..."; \
		$(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$$name $$cmd; \
	done

define cross-compile-template
build-$(1)-$(2):
	@mkdir -p $(BUILD_DIR)/$(1)-$(2)
	@echo "Cross-compiling for $(1)/$(2)..."
	@for cmd in $(CMD_PACKAGES); do \
		name=$$(basename $$cmd); \
		echo "  $$name"; \
		GOOS=$(1) GOARCH=$(2) $(GO) build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/$(1)-$(2)/$$name $$cmd; \
	done
endef

$(eval $(call cross-compile-template,linux,amd64))
$(eval $(call cross-compile-template,linux,arm64))
$(eval $(call cross-compile-template,darwin,amd64))
$(eval $(call cross-compile-template,darwin,arm64))
$(eval $(call cross-compile-template,windows,amd64))

cross-compile: build-linux-amd64 build-linux-arm64 build-darwin-amd64 build-darwin-arm64 build-windows-amd64
	@echo "All cross-compilation targets built in $(BUILD_DIR)/"

dist: cross-compile
	@for os_arch in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64; do \
		cd $(BUILD_DIR)/$$os_arch && \
		tar czf ../quantaureum-$(VERSION)-$$os_arch.tar.gz * && \
		cd ../..; \
	done
	@echo "Distribution archives created in $(BUILD_DIR)/"

# R123-SCALE-GATE (2026-09-05): always -short. Heavy simulations
# (TestSim_200KNodes etc., ~108 GB commit charge on 2026-09-05, OOM-rebooted
# a 64 GB dev machine) are opt-in via QAU_SCALE_TESTS=1 only.
test:
	$(GO) test ./... -count=1 -short -timeout 10m

test-race:
	$(GO) test -race ./... -count=1 -short -timeout 10m

# Full-fat scale simulations: 200K nodes / 192K validators in memory.
# Run ONLY on a >=32 GB machine that can afford to be pegged.
test-scale:
	QAU_SCALE_TESTS=1 $(GO) test -v -count=1 -timeout 30m ./simulation/ ./consensus/ -run 'TestSim_|TestScale_|Test200K'

integration-test:
	$(GO) test -tags integration -v -count=1 -timeout 180s ./node/... ./consensus/...

benchmark:
	$(GO) test -bench=. -benchmem -count=1 -timeout 300s ./benchmark/... ./consensus/... ./quantum/...

benchmark-tps:
	$(GO) test -bench=BenchmarkTPS -benchmem -count=1 -timeout 120s ./benchmark/...

benchmark-qpos:
	$(GO) test -bench=BenchmarkQPOS -benchmem -count=1 -timeout 120s ./consensus/...

benchmark-zkp:
	$(GO) test -bench=BenchmarkZKP -benchmem -count=1 -timeout 300s ./quantum/...

lint:
	$(GO) vet ./...

staticcheck:
	staticcheck ./...

vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

# audit-fix LOW: comprehensive security-scan target combining multiple checks.
# Runs vulnerability scanning, vet, and static analysis in one command.
# Usage: make security-scan
security-scan: vet vulncheck staticcheck
	@echo "=== Security scan complete ==="
	@echo "Checked: go vet, govulncheck, staticcheck"
	@echo "For full audit, also run: make lint && make test"

vet:
	$(GO) vet ./...

race:
	$(GO) test -race -count=1 -timeout 10m ./...

fmt:
	@gofmt -s -w $$(find . -name '*.go' -not -path './vendor/*')

clean:
	rm -rf ./build/

dist-clean: clean

dev:
	$(GO) run ./cmd/qaud/ --dev --genesis testnet/genesis.json

deps:
	$(GO) mod tidy
	$(GO) mod download

docker-build:
	docker build -t quantaureum/qaud:$(VERSION) -t quantaureum/qaud:latest .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down
