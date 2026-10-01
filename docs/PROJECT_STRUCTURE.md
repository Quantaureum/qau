# Quantaureum Project Structure

Quantaureum is a pure post-quantum blockchain project that uses the Dilithium3 + Kyber post-quantum cryptographic algorithms to implement a blockchain that is secure against quantum-computing attacks.

The project directory structure is modeled after go-ethereum (geth).

## Directory Structure

```
qau/
|-- abi/              # ABI encoding/decoding
|-- accounts/         # Account management, keystore
|-- audit/            # Security audit tools
|-- backup/           # Backup and recovery
|-- bridge/           # Cross-chain bridge
|-- cmd/              # Command-line program entry points
|   |-- qaud/        # Main node program
|   |-- qau-cli/     # Command-line tool
|   |-- qauctl/      # Node control tool
|   |-- qauaudit/    # Security audit tool
|   `-- checkconfig/ # Configuration check tool
|-- common/           # Common utility functions
|-- configs/          # Configuration files
|-- consensus/        # Consensus mechanism (QPOS)
|-- contract/         # Smart contract support
|-- core/             # Core components (block validation, etc.)
|-- crypto/           # Post-quantum cryptography
|-- data/             # Runtime data
|-- docs/             # Documentation
|-- economics/        # Token economics
|-- encoding/         # Encoding/decoding
|-- qaudb/            # Database storage layer
|   |-- block/       # Block storage
|   |-- state/       # State storage
|   |-- cache/       # Multi-level cache
|   `-- db/          # Database abstraction
|-- event/            # Event system
|-- faucet/           # Testnet faucet
|-- frontend/         # Frontend website (Next.js)
|-- graphql/          # GraphQL API
|-- ha/               # High availability components
|-- lightclient/      # Light client
|-- log/              # Logging system
|-- metrics/          # Monitoring metrics
|-- miner/            # Block production
|-- monitoring/       # Monitoring configuration (Prometheus/Grafana)
|-- node/             # Node core implementation
|-- p2p/              # P2P networking layer
|-- params/           # Network parameter configuration
|-- profiling/        # Performance profiling
|-- qvm/              # Quantaureum virtual machine
|-- rlp/              # RLP encoding
|-- rpc/              # JSON-RPC service
|-- safeconv/         # Safe type conversions
|-- scripts/          # Operations scripts
|-- security/         # Security module
|-- tests/            # Test files
|-- txpool/           # Transaction pool
|-- types/            # Basic type definitions
|-- upgrade/          # Upgrade management
|-- build/            # Build output
|-- Dockerfile
|-- docker-compose.yml
|-- go.mod
|-- go.sum
`-- README.md
```

## Core Module Overview

### 1. Node Core (`node/`)
- `node.go` - Main node logic, manages the lifecycle of all components
- `block_producer.go` - Block production
- `syncer.go` - Block synchronization
- `genesis.go` - Genesis block handling
- `config.go` - Node configuration

### 2. Consensus Mechanism (`consensus/`)
- QPOS (Quantum-resistant Proof of Stake) consensus
- Validator management
- Block production election

### 3. P2P Networking (`p2p/`)
- Node discovery
- Message broadcasting
- Block/transaction propagation

### 4. Post-Quantum Cryptography (`crypto/`)
- Dilithium3 digital signatures
- Kyber key encapsulation
- Quantum-resistant hash functions

### 5. Storage Layer (`qaudb/`)
- `block/` - Block storage
- `state/` - State storage
- `cache/` - Multi-level cache
- `db/` - Database abstraction

### 6. Virtual Machine (`qvm/`)
- Smart contract execution
- Parallel execution optimization

## Command-Line Tools

### qaud - Main Node Program
```bash
./qaud --config configs/config.json
```

### qau-cli - Command-Line Tool
```bash
./qau-cli account create          # Create an account
./qau-cli tx send                 # Send a transaction
./qau-cli blockchain status       # View chain status
./qau-cli node info               # Node information
```

### qauctl - Node Control
```bash
./qauctl status                   # Node status
./qauctl peers                    # Peer nodes
```

## Network Configuration

| Network | Chain ID | Description |
|------|----------|------|
| Mainnet | 1668 | Mainnet |
| Testnet | 1669 | Testnet |
| Devnet | 1333 | Devnet |

## Technical Features

- **Post-quantum security**: Dilithium3 + Kyber cryptography
- **High performance**: parallel transaction execution, multi-level caching
- **High availability**: graceful shutdown, automatic recovery
- **Observability**: Prometheus metrics, security alerts
- **Cross-chain**: bridge support (in development)

## Building

```bash
cd qau
go build -o build/qaud ./cmd/qaud
go build -o build/qau-cli ./cmd/qau-cli
go build -o build/qauctl ./cmd/qauctl
```

## Running

```bash
# Development mode
./build/qaud --dev

# Production mode
./build/qaud --config configs/config.production.json
```