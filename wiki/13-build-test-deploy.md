# 13 - Build / Test / Deploy

## 13.1 Environment Requirements

- Go `1.26.x` (go.work root module 1.26.3, sub-modules minimum 1.26.0)
- Unix toolchain (native on mac/Linux; on Windows use WSL or Git Bash)
- Optional: golangci-lint (`golangci-lint run ./...`)
- Optional: Rust toolchain (only for the HSM native layer `make rust-pq`)

## 13.2 Common Commands

```bash
# build all binaries to ./build/
make build

# build a single one
go build -o ./build/qaud ./cmd/qaud
go build -o ./build/qauctl ./cmd/qauctl

# test
make test                  # full
go test ./...              # full (equivalent)
go test -timeout 180s ./node/ ./qvm/ ./qaudb/block/ ./encoding/   # key packages
go test -run <TestName> ./package

# static analysis
go vet ./...
golangci-lint run ./...

# formatting
gofmt -l .                 # list unformatted files (should be empty)
gofmt -w <file>            # format

# coverage
go test -cover ./...

# Docker
make docker

# Rust HSM layer (optional)
make rust-pq
```

> The top-level [Makefile](../Makefile) is authoritative: specific targets are subject to `make help`.

### 13.2.1 Test tiers (audit M-08)

The suite is layered so the default gate stays fast and deterministic:

1. **Default gate** — `make test` = `go test ./... -count=1 -short -timeout 10m`.
   `-short` skips the heavy scale tests (200K validators/nodes). This is the
   commit gate and must be green.
2. **Scale tier (opt-in)** — `make test-scale` = `QAU_SCALE_TESTS=1 go test
   -v -count=1 -timeout 30m ./simulation/ ./consensus/ -run
   'TestSim_|TestScale_|TestLargeScale_'`. Run ONLY on a >=32 GB machine that
   is otherwise idle. The wall-clock latency guards
   (`TestLargeScale_CommitteeAllocationLatency`,
   `TestLargeScale_ProposerSelectionLatency`) assert per-slot/per-call budgets
   measured on an idle box; under concurrent package load the same code
   measures 14-136x slower, so these two tests skip unless
   `QAU_SCALE_TESTS=1`.
3. **Full non-short run** — `go test ./... -count=1 -timeout 30m` on an idle
   machine. Running all packages in parallel starves the latency guards and
   can time out the heavy packages (`node`, `p2p`, `privacy`,
   `privacy/confidential` need more than 10m each under load; CI runs them
   with 20-30m per-package budgets). Prefer the per-package form:
   `go test -count=1 -timeout 30m ./consensus/ ./node/ ./p2p/ ./privacy/...`.
4. **Race** — requires CGO + gcc (on Windows: msys2 mingw64 on PATH):
   `CGO_ENABLED=1 CC=gcc go test -race -count=1 -short -timeout 30m ./...`.

## 13.3 Run Modes

### 13.3.1 In-Memory Private Chain (fastest)

```bash
go run ./cmd/qaud
# default in-memory storage, no files, convenient for local development/testing.
# RPC at 127.0.0.1:8545.
```

### 13.3.2 File Persistence + Block Production

```bash
make build
./build/qaud --config configs/config.dev.json
```

### 13.3.3 Local Multi-Node Testnet

```bash
go run ./cmd/localnet --nodes 3
```

## 13.4 Mandatory Pre-Commit Self-Check (R40.D red line)

Any non-trivial change (fixing code, adding/modifying tests, modifying .qasm/.hex/.json that affects
contract logic)must run all of the following and have all PASS:

```bash
cd the Quantaureum repo
go build ./...                        # 1. full build
go vet ./node/... ./cmd/qauctl/...    # 2. static analysis (at least the packages touched)
go test -timeout 180s ./node/ ./qvm/ ./qaudb/block/ ./encoding/   # 3. key-package tests
gofmt -l <touched files>              # 4. should be empty; if not, use gofmt -w
```

- If golangci-lint is not installed, skip it; it does not block.
- Failing commands should be resolved before committing; **do not push red tests to the main branch**.

## 13.5 Code-Quality Goals

| Item | Requirement |
|----|------|
| Compilation | must pass (30s timeout) |
| Tests | all existing tests pass; add tests for new features |
| Formatting | gofmt |
| Lint | golangci-lint passes (.golangci.yml, 20+ linters) |

## 13.6 Blockchain Interface Validation (Quick Smoke Test)

```bash
# chain information
curl -X POST http://127.0.0.1:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# account balance
curl -X POST http://127.0.0.1:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0x<caddr>","latest"],"id":1}'

# staking
curl -X POST http://127.0.0.1:8545 -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_getStake","params":["0x<caddr>"],"id":1}'
```

## 13.7 Deployment (mainnet)

- Deployment tools: `qauctl` (validator deploy / account-remote / contract / genesis).
- Large transfers: `transfer_commit` (commit-reveal).
- **Bytecode authority**: the 512-byte bytecode in `qvm/vesting_test.go` (see 15-lessons § R40.B).
- Pre-deployment reconciliation: verify the validator set and allocation totals
  against the intended genesis supply before publishing a release.

## 13.8 Common Pitfalls

| Pit | Solution |
|----|------|
| `Text file busy` | stop the node through its service supervisor, replace the binary, then start it again |
| bash large-number overflow | `python3 -c "print(n)"` or string |
| system log buffering | use `log` (stderr, synchronous)instead of `fmt.Printf` |
| Windows SSH inline-JSON quote mangling | write a .sh script, upload via SCP, and execute |
