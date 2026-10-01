# Contributing to Quantaureum

Thank you for your interest in contributing to Quantaureum! This document outlines the process for contributing to the world's first quantum-resistant Layer 1 blockchain.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Security Vulnerability Reporting](#security-vulnerability-reporting)
- [Architecture Overview](#architecture-overview)

## Code of Conduct

Participation in this project is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Please be respectful and inclusive.

## Getting Started

### Prerequisites

- **Go 1.26+** (latest stable)
- **Git 2.30+**
- **Make** (for build scripts)
- Basic understanding of blockchain concepts and post-quantum cryptography

### Setup

```bash
# Clone the repository
git clone https://github.com/Quantaureum/qau.git
cd qau

# Build the node
make build

# Run tests
make test

# Start a local dev node
make dev
```

## Development Workflow

### 1. Fork and Branch

```bash
# Fork the repo on GitHub, then:
git remote add origin https://github.com/<your-username>/quantaureum.git
git checkout -b feature/your-feature-name
```

Use descriptive branch names:
- `feature/add-vesting-contract` — new features
- `fix/txpool-nonce-gap` — bug fixes
- `refactor/consensus-state-machine` — refactors
- `docs/api-reference` — documentation

### 2. Write Code

Follow the [Coding Standards](#coding-standards) below. Every change must:
- Pass `golangci-lint run` with zero warnings
- Include tests (see [Testing Requirements](#testing-requirements))
- Not introduce `panic()` in production code paths
- Not ignore errors without justification (`//nolint:errcheck` with comment)

### 3. Commit

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(consensus): add QTD finality gadget v2
fix(txpool): resolve nonce gap on state rebuild
refactor(p2p): consolidate compact block broadcasting
docs(rpc): update JSON-RPC API reference
test(crypto): add Dilithium3 signature fuzzing
chore(deps): bump circl to v1.6.3
```

### 4. Push and PR

```bash
git push origin feature/your-feature-name
```

Open a Pull Request against `main`. Fill out the PR template completely.

## Coding Standards

### Go Style

- Run `gofmt -s` and `goimports` before committing
- Follow [Effective Go](https://go.dev/doc/effective_go) and the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `golangci-lint` (config in `.golangci.yml`)

### Error Handling

**Never ignore errors silently.** If you must ignore an error, add a comment explaining why:

```go
// Good: explicit handling
if err := db.Put(key, value); err != nil {
    return fmt.Errorf("failed to persist state: %w", err)
}

// Acceptable: best-effort with justification
_ = conn.Close() //nolint:errcheck // best-effort cleanup on error path

// Bad: silent ignore
_ = db.Put(key, value)
```

### Concurrency

- Always protect shared state with `sync.Mutex` or `sync.RWMutex`
- Prefer channels for goroutine communication
- Never start a goroutine without a clear lifecycle (context cancellation or done channel)
- Use `go vet -race` and `-race` flag in tests

### Logging

- Use `zerolog` (structured logging) via the project's logger setup
- Never use `fmt.Println` in production code (use `log.Printf` if zerolog is unavailable)
- Log levels: `Error` (failures), `Warn` (recoverable issues), `Info` (lifecycle), `Debug` (diagnostics)
- Include relevant context (height, hash, peer ID) in log messages

### Cryptography

- **Never** hardcode private keys, seeds, or test vectors with real key material
- Use `memguard` for sensitive key material in memory
- Always `defer crypto.ZeroBytesSecure(keyMaterial)` after use
- Use Dilithium3 for signatures, Kyber768 for key encapsulation

## Testing Requirements

### Minimum Coverage

| Package | Minimum Coverage |
|---------|-----------------|
| `crypto/` | 90% |
| `consensus/` | 85% |
| `qaudb/` | 85% |
| `encoding/` | 85% |
| `node/` | 75% |
| `p2p/` | 75% |
| `rpc/` | 75% |
| `qvm/` | 80% |
| Overall | 80% |

### Test Types

1. **Unit tests** (`*_test.go`) — every public function must have tests
2. **Integration tests** (`node/integration_test.go`) — cross-module flows
3. **Fuzz tests** (`fuzz_test.go`) — cryptographic and parsing functions
4. **Benchmark tests** (`*_bench_test.go`) — hot paths (consensus, state DB, P2P)

### Running Tests

```bash
# All tests
make test

# With race detector
make test-race

# Coverage report
make test-coverage

# Specific package
go test -v -race ./crypto/...

# Benchmarks
go test -bench=. -benchmem ./qaudb/state/...
```

## Pull Request Process

### PR Checklist

Before submitting a PR, ensure:

- [ ] Code compiles: `make build`
- [ ] Tests pass: `make test`
- [ ] Lint passes: `golangci-lint run`
- [ ] Race detector passes: `make test-race`
- [ ] Coverage meets minimum for changed packages
- [ ] No `panic()` in production code
- [ ] No hardcoded secrets or IP addresses
- [ ] Commit messages follow Conventional Commits
- [ ] PR description explains the change and motivation
- [ ] Breaking changes are documented

### Review Process

1. Automated CI must pass (build, test, lint, coverage)
2. At least 2 maintainer approvals required for `main`
3. Security-sensitive changes (consensus, crypto, P2P) require review by a security team member
4. Breaking changes require a Quantaureum Improvement Proposal (QIP)

### Review Criteria

Reviewers will check:
- **Correctness**: Does the code do what it claims?
- **Security**: Are there vulnerabilities (reentrancy, overflow, timing attacks)?
- **Performance**: Is this on the hot path? Does it add latency?
- **Testability**: Are the tests meaningful (not just coverage padding)?
- **Maintainability**: Will this be understandable in 6 months?

## Security Vulnerability Reporting

**Do NOT open a public issue for security vulnerabilities.**

Instead, email security@quantaureum.com with:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We will acknowledge within 48 hours and provide a fix timeline. See [SECURITY.md](SECURITY.md) for the severity-based bounty table.

## Contributor Rewards

Following the Ethereum ecosystem's open-source model, Quantaureum does not run a public token airdrop. Instead, contributors are rewarded through a discretionary **contribution grant**:

- **Code**: merged pull requests that meaningfully improve the protocol
- **Security**: valid vulnerability reports (see the bounty table in [SECURITY.md](SECURITY.md))
- **Community**: significant, sustained contributions to the ecosystem

Rewards are denominated in **QAU** and paid from a **fixed, capped bug-bounty fund drawn from the on-chain Ecosystem Fund** (see the bounty table in [SECURITY.md](SECURITY.md)) and, for non-security contributions, through a governance-reviewed grant — never from user funds. Specific weights and criteria are announced separately; there is no fixed open airdrop schedule.

## Architecture Overview

Quantaureum uses a 7-layer architecture:

```
L7  Service Layer    — JSON-RPC, WebSocket, GraphQL, REST API
L6  Integration Layer — Node orchestration, Syncer, Snapshot, Adapters
L5  Consensus Layer   — QPOS, QTD Finality, Election, Slashing, Voting
L4  Execution Layer   — QVM (opcodes, JIT, parallel execution, precompiled)
L3  Network Layer     — P2P (GossipSub, RLPx, Discovery), Bridge, DeFi
L2  Storage Layer     — QauDB (bbolt), Verkle Trie, State DB, Block Store
L1  Cryptography Layer — Dilithium3, Kyber768, GM-QTD, Keystore
```

Key design principles:
- **Layer isolation**: lower layers never import from higher layers
- **Interface boundaries**: modules communicate through well-defined Go interfaces
- **Fail-safe defaults**: cryptographic verification fails closed
- **Post-quantum first**: all signature and key exchange operations use NIST-standardized PQ algorithms

## Questions?

- **GitHub Issues** — bugs and feature requests
- **GitHub Discussions** — questions and design discussions
- **Discord** — real-time community chat at https://discord.gg/MSctkBT5j
- **Email** — maintainers@quantaureum.com

Thank you for contributing to making blockchain quantum-safe!
