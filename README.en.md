# Quantaureum (QAU)

A quantum-safe Layer 1 blockchain with threshold-signature finality and a QVM smart-contract engine.

## Overview

Quantaureum is a post-quantum Layer 1 public blockchain built from scratch in Go. It replaces ECDSA with **Dilithium3** (NIST FIPS 204) and **Kyber768** (NIST FIPS 203) for all signing and key exchange, and uses a custom **QPOS** consensus plus **QTD threshold signatures** to finalize blocks.

## Project Origin

The project was started single-handedly by its author on **February 28, 2025** (the day of the planetary alignment of seven planets), built from zero across the full stack — cryptography, consensus, virtual machine, networking, storage, and RPC — culminating in a post-quantum Layer 1 blockchain.

## Core Features

| Feature | Description |
|---------|-------------|
| **Post-quantum cryptography** | Dilithium3 signatures + Kyber768 KEM, NIST FIPS 204/203 compliant |
| **QTD threshold signatures** | Distributed key generation + threshold signing for block finality (GM-QTD) |
| **QPOS consensus** | Quantum Proof of Stake, verifiable randomness, slashing, multi-validator committee |
| **QVM + QASM** | Custom quantum virtual machine + QASM assembly smart contracts |
| **Parallel execution** | Block-STM style parallel transaction execution + MV memory |
| **Data availability** | Erasure coding + DAS + FRI commitments |
| **Sharding** | Multi-shard architecture + cross-shard messaging |
| **Rollup support** | Built-in Rollup sequencer + L1 bridge contracts (QASM) |
| **Cross-chain bridge** | Minimal-trust bridge based on Merkle proofs |
| **Multisig wallet** | Native Dilithium multisig wallet contracts |
| **Light client** | SPV light client based on Verkle tree proofs |
| **Multi-language SDK** | Go, Rust, C++, Java, Python, TypeScript |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  L7  rpc/  graphql/          (JSON-RPC 2.0 + WS)    │
├─────────────────────────────────────────────────────┤
│  L6  node/  txpool/          (node orchestration)   │
├─────────────────────────────────────────────────────┤
│  L5  consensus/  core/      (QPOS + QTD + block)    │
├─────────────────────────────────────────────────────┤
│  L4  qvm/                   (QVM + QASM + JIT)      │
├─────────────────────────────────────────────────────┤
│  L3  p2p/  economics/       (gossipsub + staking)   │
├─────────────────────────────────────────────────────┤
│  L2  qaudb/  encoding/  rlp/  (bbolt + verkle trie) │
├─────────────────────────────────────────────────────┤
│  L1  crypto/  types/  common/  (Dilithium3 + Kyber) │
└─────────────────────────────────────────────────────┘
```

## Quick Start

### Requirements

- **Go 1.26.4** or later
- Git

### Build

```bash
# Clone
git clone https://github.com/Quantaureum/qau.git
cd qau

# Build the node daemon
go build -o build/qaud ./cmd/qaud

# Build the CLI tool
go build -o build/qauctl ./cmd/qauctl
```

### Run a Development Node

```bash
# Development mode (auto-block production, chain ID 1333)
./build/qaud -dev -networkid 1333

# Custom block interval
./build/qaud -dev -networkid 1333 -blockinterval 12
```

### Run a Validator

```bash
# Generate a validator key
./build/qauctl validator generate --output validator.key

# Start a validator node
./build/qaud -networkid 1669 -validator -validatorkey ./validator.key
```

> **Want to run a validator on mainnet?** See the full **[Validator Onboarding Guide](docs/validator-onboarding-guide.md)** for hardware requirements (CPU / memory / storage / bandwidth), network ports, staking parameters, slashing risks, and the complete setup walkthrough.

## Network IDs

| Network | Chain ID | Purpose |
|---------|----------|---------|
| Mainnet | 1668 | Production |
| Testnet | 1669 | Public test network |
| Devnet | 1333 | Local development |

## Repository Layout

```
qau/
├── cmd/               # Command-line tools
│   ├── qaud/          # Node daemon
│   ├── qauctl/        # CLI client
│   ├── qasm/          # QASM assembler
│   ├── qaucold/       # Cold wallet
│   └── ...            # Key tools, faucet, benchmarks, etc.
├── crypto/            # Post-quantum cryptography (Dilithium3, Kyber768, GM-QTD)
├── types/             # Core types (blocks, transactions, addresses)
├── common/            # Utilities (hexutil, math, lru)
├── encoding/          # Wire formats, DAS, erasure coding, FRI
├── rlp/               # RLP serialization
├── abi/               # Contract ABI encoding
├── event/             # Pub-sub event system
├── qaudb/             # Storage: bbolt, block store, state DB, verkle trie
├── consensus/         # QPOS, QTD finality, election, slashing, sharding
├── core/              # Block building, block validation
├── qvm/               # QVM + QASM, JIT, parallel execution
├── node/              # Node orchestration, adapters, syncer, snapshot
├── rpc/               # JSON-RPC 2.0 (eth_* + qau_*), auth, rate limiting
├── graphql/           # GraphQL API
├── p2p/               # gossipsub, RLPx, encrypted transport, DHT discovery
├── txpool/            # Transaction pool
├── miner/             # Block sealing
├── wallet/            # Multisig wallet + TSS/QTD manager
├── economics/         # Staking, DeFi, governance, rewards
├── rollup/            # Rollup sequencer, L1 bridge, fraud proofs
├── bridge/            # Cross-chain bridge
├── privacy/           # Stealth addresses, private transactions
├── quantum/           # Quantum MPC, ZKP utilities
├── qzkp/              # Zero-knowledge proofs
├── qrng/              # Quantum random number generator
├── pedersen/          # Pedersen commitments
├── light/             # Light node
├── lightclient/       # Light client (SPV)
├── metrics/           # Prometheus metrics
├── log/               # Structured logging
├── params/            # Chain parameters
├── upgrade/           # Fork upgrades
├── security/          # HSM, key rotation, validation
├── audit/             # Built-in audit scanner
├── contracts/         # QASM contract examples
├── configs/           # Node configuration files
├── genesis/           # Genesis block configuration
└── docs/              # Documentation
```

## SDK

The node itself is a Go library — import any subpackage directly:

```go
import (
    "github.com/quantaureum/qau/crypto"
    "github.com/quantaureum/qau/common"
    "github.com/quantaureum/qau/types"
)
```

Standalone SDKs live in separate repositories:

| Language | Repository | Status |
|----------|------------|--------|
| Go | `github.com/quantaureum/go-sdk` | Active |
| TypeScript | `github.com/quantaureum/sdk-js` | Active |
| Rust | `github.com/quantaureum/sdk-rs` | Active |
| C++ | `github.com/quantaureum/sdk-cpp` | Active |
| Java | `github.com/quantaureum/sdk-java` | Active |
| Python | `github.com/quantaureum/sdk-py` | Active |

## JSON-RPC API

### Standard Methods (`eth_*` prefix)

Follows Ethereum JSON-RPC conventions: `eth_blockNumber`, `eth_getBalance`, `eth_sendRawTransaction`, `eth_call`, `eth_estimateGas`, etc.

### Quantaureum-Specific Methods (`qau_*` prefix)

| Category | Methods |
|----------|---------|
| Consensus | `qau_qposStatus`, `qau_getStake`, `qau_getStakingPools`, `qau_getStakingStats` |
| TSS / QTD | `qau_tss_status`, `qau_tss_getPublicKey` |
| Quantum | `qau_signQuantumTransaction`, `qau_verifyQuantumTransaction` |
| Multisig | `qau_isMultisigWallet`, `qau_getMultisigWallet` |
| Staking | `qau_getUserStakes`, `qau_getPendingRewards`, `qau_getStakingContracts` |
| Account Abstraction | `qau_supportedEntryPoints` |

Full API reference: [docs/api](docs/api/)

## Testing

```bash
# Run all tests
go test ./...

# Run specific modules
go test -v ./crypto/...
go test -v ./consensus/...
go test -v ./qvm/...
```

## Cryptographic Specification

| Primitive | Algorithm | Standard | Key Size | Signature Size |
|-----------|-----------|----------|----------|----------------|
| Signature | Dilithium3 | NIST FIPS 204 | 1952 B (pub) / 4000 B (priv) | 3293 B |
| Key exchange | Kyber768 | NIST FIPS 203 | 1184 B (pub) / 2400 B (priv) | - |
| Threshold signature | GM-QTD | Custom (NTT-domain based) | Group key: 1952 B | 3293 B |
| Hash | Blake2b-256 | RFC 7693 | - | 32 B |
| Keystore | AES-256-GCM + scrypt | N=2^18 | - | - |

HD wallet path: `m/44'/1668'/0'/0/{index}`

## Contributing

Pull requests and code improvements are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process. Contributors — merged PRs, valid security reports, and significant community contributions — may receive QAU rewards from the on-chain **Foundation Reserve / Ecosystem Fund** (see the bounty table in [SECURITY.md](SECURITY.md)).

## Security

**Do not open a public issue for security vulnerabilities.** Report privately via `security@quantaureum.com`. Rewards are paid in QAU by severity; see the bounty table and response timeline in [SECURITY.md](SECURITY.md).

## Documentation

- [Validator Onboarding Guide](docs/validator-onboarding-guide.md) — node hardware requirements, staking parameters, and validator setup
- [Developer Guide](docs/DEVELOPER_GUIDE.md)
- [API Reference](docs/API.md)
- [Multinode Setup](docs/MULTINODE_SETUP.md)
- [Docker Deployment](docs/DOCKER.md)
- [Whitepaper](docs/WHITEPAPER.md)
- [Token Economics](docs/TOKEN_ECONOMICS.md)

## License

[Apache License 2.0](LICENSE)
