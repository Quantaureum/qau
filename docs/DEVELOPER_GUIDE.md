# Quantaureum Developer Guide

This document provides developers with an architecture overview and contribution guide for the Quantaureum blockchain.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Module Overview](#module-overview)
3. [Development Environment](#development-environment-setup)
4. [Code Conventions](#code-conventions)
5. [Testing Guide](#testing-guide)
6. [Contribution Guide](#contribution-guide)

---

## Architecture Overview

### System Architecture Diagram

```
+--------------------------------------------------------------+
|                      Quantaureum Node                          |
+--------------------------------------------------------------+
|  +-----------+  +-----------+  +-----------+  +-----------+  |
|  |  RPC API  |  | WebSocket |  |  Metrics  |  |   Admin   |  |
|  | (JSON-RPC)|  |  (Events) |  |(Prometheus)|  |   (gRPC)  |  |
|  +-----+-----+  +-----+-----+  +-----+-----+  +-----+-----+  |
|        +-----------+-----------+-----------+-----------+      |
|                            |                                  |
|  +-------------------------+-----------------------------+   |
|  |                        Core Engine                     |   |
|  |  +-----------+  +-----------+  +------------------------+|  |
|  |  |Transaction|  |   Block    |  |      State Manager     ||  |
|  |  |   Pool    |  |  Builder   |  |  (Account, Contract)   ||  |
|  |  +-----+-----+  +-----+-----+  +-----------+------------+|  |
|  +-----------+-----------+----------------+-----------------+   |
|                            |                                  |
|  +-------------------------+-----------------------------+   |
|  |                      Consensus (QPOS)                   |   |
|  |  +-----------+  +-----------+  +------------------------+|  |
|  |  |    VRF    |  | Validator |  |    Finality Engine      ||  |
|  |  | Election  |  |  Manager  |  |   (BFT Confirmation)    ||  |
|  |  +-----------+  +-----------+  +------------------------+|  |
|  +------------------------------------------------------+   |
|                            |                                  |
|  +-------------------------+-----------------------------+   |
|  |                    QVM (Virtual Machine)                |   |
|  |  +-----------+  +-----------+  +------------------------+|  |
|  |  | Bytecode  |  |  Runtime  |  |     State Access        ||  |
|  |  | Validator |  | Executor  |  |     (Gas Metering)      ||  |
|  |  +-----------+  +-----------+  +------------------------+|  |
|  +------------------------------------------------------+   |
|                            |                                  |
|  +-------------------------+-----------------------------+   |
|  |                        Storage Layer                    |   |
|  |  +-----------+  +-----------+  +------------------------+|  |
|  |  |State Trie |  |   Block   |  |    Transaction          ||  |
|  |  | (Verkle)  |  |   Store   |  |      Index              ||  |
|  |  +-----------+  +-----------+  +------------------------+|  |
|  +------------------------------------------------------+   |
|                            |                                  |
|  +-------------------------+-----------------------------+   |
|  |                    P2P Network (libp2p)                 |   |
|  |  +-----------+  +-----------+  +------------------------+|  |
|  |  | Discovery |  |   Gossip  |  |   Post-Quantum TLS      ||  |
|  |  |   (DHT)   |  | Protocol  |  |   (Dilithium + Kyber)   ||  |
|  |  +-----------+  +-----------+  +------------------------+|  |
|  +------------------------------------------------------+   |
|                            |                                  |
|  +-------------------------+-----------------------------+   |
|  |                       Crypto Layer                      |   |
|  |  +-----------+  +-----------+  +------------------------+|  |
|  |  |Dilithium3 |  |   Kyber   |  |      Hash (SHA3)        ||  |
|  |  | (Signing) |  |   (KEM)   |  |   Address Derivation    ||  |
|  |  +-----------+  +-----------+  +------------------------+|  |
|  +------------------------------------------------------+   |
+--------------------------------------------------------------+
```

### Design Principles

1. **Fully original**: independent of the Ethereum codebase, with full intellectual property rights
2. **Quantum-safe**: uses the Dilithium3 post-quantum signature algorithm
3. **High performance**: targeting 10,000+ TPS with 3-second finality
4. **Modular**: clear module boundaries for easy testing and maintenance

### Technology Stack

| Component | Choice | Description |
|------|---------|------|
| Language | Go 1.21+ | High performance, concurrency-friendly |
| Serialization | Protocol Buffers | Efficient binary encoding |
| Storage | Pebble | RocksDB-compatible, high-performance KV store |
| Networking | libp2p + TCP | Mature P2P networking library |
| Cryptography | cloudflare/circl | Dilithium3 + Kyber |
| Testing | rapid | Property-based testing library |

---

## Module Overview

### Project Structure

```
qau/
+-- cmd/                    # Command-line tools
|   +-- qaud/              # Node daemon
|   `-- qauctl/            # CLI management tool
+-- pkg/                    # Shared libraries (externally importable)
|   +-- crypto/            # Cryptographic primitives
|   +-- encoding/          # Serialization encoding
|   `-- types/             # Basic type definitions
+-- internal/               # Internal implementation (not publicly exposed)
|   +-- consensus/         # QPOS consensus
|   +-- core/              # Core data structures
|   +-- economics/         # Economic model
|   +-- ha/                # High-availability components
|   +-- lightclient/       # Light client support
|   +-- logging/           # Logging system
|   +-- metrics/           # Monitoring metrics
|   +-- node/              # Node management
|   +-- p2p/               # P2P networking
|   +-- profiling/         # Performance profiling
|   +-- qvm/               # Virtual machine
|   +-- rpc/               # RPC service
|   +-- security/          # Security components
|   +-- storage/           # Storage layer
|   +-- txpool/            # Transaction pool
|   `-- upgrade/           # Upgrade mechanism
+-- api/                    # API definitions
|   `-- proto/             # Protobuf definitions
+-- test/                   # Test utilities
|   +-- benchmark/         # Performance benchmarks
|   `-- integration/       # Integration tests
`-- docs/                   # Documentation
```

### Core Modules

#### 1. pkg/crypto - Cryptography Module

Provides post-quantum-safe cryptographic primitives:

```go
// Key generation
keyPair, err := crypto.GenerateKeyPair()

// Sign
signature, err := crypto.Sign(privateKey, message)

// Verify
valid := crypto.Verify(publicKey, message, signature)

// Address derivation
address := crypto.AddressFromPublicKey(publicKey)
```

**Key files**:
- `dilithium.go`: Dilithium3 signature implementation
- `address.go`: Address derivation and formatting
- `keystore.go`: Encrypted key storage

#### 2. pkg/types - Basic Types

Defines the core data structures of the blockchain:

```go
// Address type
type Address [20]byte

// Hash type
type Hash [32]byte

// Block header
type BlockHeader struct {
    Version     uint32
    Height      uint64
    Timestamp   int64
    ParentHash  Hash
    StateRoot   Hash
    TxRoot      Hash
    // ...
}

// Transaction
type Transaction struct {
    Version   uint32
    Type      TxType
    Nonce     uint64
    From      Address
    To        *Address
    Value     *big.Int
    // ...
}
```

#### 3. internal/consensus - QPOS Consensus

Implements VRF-based proof-of-stake consensus:

```go
// VRF election
proposer, proof, err := consensus.SelectProposer(seed, validators)

// Vote collection
votes := consensus.CollectVotes(block, timeout)

// Finality confirmation
if len(votes) > 2*len(validators)/3 {
    consensus.Finalize(block, votes)
}
```

**Key components**:
- `vrf.go`: VRF proof generation and verification
- `validator.go`: Validator management
- `finality.go`: Finality engine
- `slashing.go`: Slashing mechanism

#### 4. internal/qvm - Virtual Machine

Native virtual machine implementation:

```go
// Execute contract
result, err := qvm.Execute(ctx, code, input)

// Gas metering
gasUsed := result.GasUsed

// State access
value := ctx.StateDB.GetState(address, key)
```

**Instruction set**:
- Stack: PUSH, POP, DUP, SWAP
- Arithmetic: ADD, SUB, MUL, DIV, MOD
- Comparison: LT, GT, EQ
- Control flow: JUMP, JUMPI, CALL, RETURN
- State: SLOAD, SSTORE, BALANCE

#### 5. internal/storage - Storage Layer

State storage based on the Verkle Trie:

```go
// State operations
stateDB.SetBalance(address, balance)
stateDB.SetNonce(address, nonce)

// Snapshot and rollback
snapshot := stateDB.Snapshot()
stateDB.Revert(snapshot)

// Persistence
root, err := stateDB.Commit()
```

#### 6. internal/p2p - P2P Networking

Network layer built on libp2p:

```go
// Message broadcast
network.BroadcastBlock(block)
network.BroadcastTransaction(tx)

// Message subscription
blocks := network.SubscribeBlocks()
for block := range blocks {
    // Process block
}
```

#### 7. internal/rpc - RPC Service

JSON-RPC 2.0 and WebSocket service:

```go
// Register a method
rpc.RegisterMethod("eth_getBalance", getBalance)
rpc.RegisterMethod("eth_sendTransaction", sendTransaction)

// WebSocket subscription
ws.Subscribe("newHeads", handleNewHead)
ws.Subscribe("logs", handleLogs)
```

---

## Development Environment Setup

### Prerequisites

- Go 1.21+
- Protocol Buffers compiler (protoc)
- Make
- Docker (optional, for integration testing)

### Installation Steps

```bash
# 1. Clone the repository
git clone https://github.com/quantaureum/qau.git
cd qau

# 2. Install dependencies
go mod download

# 3. Install the protoc plugin
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

# 4. Generate protobuf code
make proto

# 5. Build
make build

# 6. Run tests
make test
```

### IDE Configuration

#### VS Code

Recommended extensions:
- Go (golang.go)
- Protocol Buffers (zxh404.vscode-proto3)
- EditorConfig

`.vscode/settings.json`:
```json
{
  "go.useLanguageServer": true,
  "go.lintTool": "golangci-lint",
  "go.lintFlags": ["--fast"],
  "editor.formatOnSave": true,
  "[go]": {
    "editor.defaultFormatter": "golang.go"
  }
}
```

#### GoLand

- Enable Go Modules support
- Configure golangci-lint as the linting tool
- Enable gofmt auto-formatting

---

## Code Conventions

### Go Code Style

Follows [Effective Go](https://golang.org/doc/effective_go) and [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments).

#### Naming Conventions

```go
// Package name: lowercase, concise
package consensus

// Interface name: a verb or a noun
type Validator interface {
    Validate(block *Block) error
}

// Struct: a noun
type BlockHeader struct {
    Height uint64
}

// Method: starts with a verb
func (b *Block) Hash() Hash {
    // ...
}

// Constant: camelCase or ALL_CAPS
const MaxBlockSize = 1024 * 1024
const (
    TxTypeTransfer TxType = iota
    TxTypeContract
)
```

#### Error Handling

```go
// Define error variables
var (
    ErrInvalidBlock     = errors.New("invalid block")
    ErrInsufficientGas  = errors.New("insufficient gas")
)

// Wrap the error
if err != nil {
    return fmt.Errorf("failed to validate block: %w", err)
}

// Error checking
if errors.Is(err, ErrInvalidBlock) {
    // Handle a specific error
}
```

#### Comment Conventions

```go
// Package consensus implements the QPOS consensus mechanism.
//
// QPOS (Quantum-safe Proof of Stake) uses VRF-based leader election
// and BFT-style finality confirmation.
package consensus

// Validator represents a consensus validator.
// It manages stake, voting power, and signing operations.
type Validator struct {
    // Address is the validator's unique identifier.
    Address Address
    
    // Stake is the amount of tokens staked.
    Stake *big.Int
}

// Sign signs a message using the validator's private key.
// It returns the signature or an error if signing fails.
func (v *Validator) Sign(msg []byte) ([]byte, error) {
    // ...
}
```

### Protobuf Conventions

```protobuf
syntax = "proto3";

package qau.v1;

option go_package = "github.com/quantaureum/qau/api/proto/v1";

// BlockHeader represents the header of a block.
message BlockHeader {
  // version is the protocol version.
  uint32 version = 1;
  
  // height is the block number.
  uint64 height = 2;
  
  // timestamp is the Unix timestamp in nanoseconds.
  int64 timestamp = 3;
}
```

### Linting

Use golangci-lint for code checking:

```bash
# Run the check
golangci-lint run

# Auto-fix
golangci-lint run --fix
```

`.golangci.yml` configuration:
```yaml
linters:
  enable:
    - gofmt
    - govet
    - errcheck
    - staticcheck
    - gosimple
    - ineffassign
    - unused
    - misspell

linters-settings:
  govet:
    check-shadowing: true
  errcheck:
    check-type-assertions: true
```

---

## Testing Guide

### Test Types

1. **Unit tests**: test a single function or method
2. **Property tests**: verify correctness properties
3. **Integration tests**: test interaction between modules
4. **Performance tests**: benchmarks and stress tests

### Unit Tests

```go
func TestAddressFromPublicKey(t *testing.T) {
    // Arrange
    keyPair, err := GenerateKeyPair()
    require.NoError(t, err)
    
    // Act
    addr := AddressFromPublicKey(keyPair.PublicKey)
    
    // Assert
    assert.True(t, strings.HasPrefix(addr.String(), "QAU"))
    assert.Len(t, addr.Bytes(), 20)
}
```

### Property Tests

Use the rapid library for property-based testing:

```go
// **Feature: native-blockchain, Property 1: Block Header Round-Trip**
func TestBlockHeaderRoundTrip(t *testing.T) {
    rapid.Check(t, func(t *rapid.T) {
        // Generate a random block header
        header := genBlockHeader().Draw(t, "header")
        
        // Serialize
        data, err := header.Marshal()
        require.NoError(t, err)
        
        // Deserialize
        var decoded BlockHeader
        err = decoded.Unmarshal(data)
        require.NoError(t, err)
        
        // Assert equality
        assert.Equal(t, header, decoded)
    })
}

func genBlockHeader() *rapid.Generator[*BlockHeader] {
    return rapid.Custom(func(t *rapid.T) *BlockHeader {
        return &BlockHeader{
            Version:   rapid.Uint32().Draw(t, "version"),
            Height:    rapid.Uint64().Draw(t, "height"),
            Timestamp: rapid.Int64().Draw(t, "timestamp"),
            // ...
        }
    })
}
```

### Running Tests

```bash
# Run all tests — R123-SCALE-GATE: use -short (default via `make test`).
# Heavy scale simulations (200K nodes / 192K validators in memory) are
# skipped in short mode AND gated behind QAU_SCALE_TESTS=1, because a bare
# `go test ./...` once OOM-rebooted a 64 GB dev machine (2026-09-05).
go test ./... -short

# Run tests for a specific package
go test ./internal/consensus/...

# Run tests with coverage
go test ./... -short -cover -coverprofile=coverage.out

# View the coverage report
go tool cover -html=coverage.out

# Run benchmarks
go test ./... -bench=. -benchmem

# Run property tests (more iterations)
go test ./... -rapid.checks=1000

# Run full-fat scale simulations (>=32 GB RAM machine ONLY; expect the
# 200K-node sim to commit ~100+ GB of virtual memory)
QAU_SCALE_TESTS=1 go test -v -run 'TestSim_200KNodes' ./simulation/
```

### Integration Tests

```bash
# Start the test network
cd test/integration
docker-compose up -d

# Run integration tests
go test ./test/integration/... -tags=integration

# Clean up
docker-compose down -v
```

---

## Contribution Guide

### Contribution Workflow

1. **Fork the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/qau.git
   ```

2. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Develop and test**
   ```bash
   # Write code
   # Add tests
   go test ./...
   
   # Code checks
   golangci-lint run
   ```

4. **Commit changes**
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```

5. **Push and create a PR**
   ```bash
   git push origin feature/your-feature-name
   ```

### Commit Conventions

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation update
- `style`: Code formatting (no functional impact)
- `refactor`: Refactoring
- `perf`: Performance optimization
- `test`: Testing
- `chore`: Build/tooling

Example:
```
feat(consensus): add VRF-based leader election

Implement VRF proof generation and verification using Dilithium3.
This enables unpredictable and verifiable leader selection.

Closes #123
```

### PR Requirements

- [ ] Code passes all tests
- [ ] Code passes lint checks
- [ ] New features have corresponding tests
- [ ] Relevant documentation is updated
- [ ] Commit messages follow the conventions
- [ ] PR description clearly explains the changes

### Code Review

Review focus:
1. **Correctness**: whether the code logic is correct
2. **Security**: whether there are security vulnerabilities
3. **Performance**: whether there are performance issues
4. **Readability**: whether the code is easy to understand
5. **Testing**: whether tests are sufficient

### Bug Reporting

When reporting a bug, please include:
1. Problem description
2. Reproduction steps
3. Expected behavior
4. Actual behavior
5. Environment information (OS, Go version, etc.)
6. Relevant logs

### Feature Requests

When submitting a feature request, please include:
1. Feature description
2. Use cases
3. Expected API or behavior
4. Possible implementation approach (optional)

---

## Resource Links

- [API Documentation](API.md)
- [Docker Deployment](DOCKER.md)
- [Installation Guide](INSTALL.md)
- [Validator Onboarding Guide](validator-onboarding-guide.md)

## Contact

- GitHub Issues: https://github.com/quantaureum/qau/issues
- Discord: https://discord.gg/MSctkBT5j
- Email: dev@quantaureum.com
