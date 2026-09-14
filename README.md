# Quantaureum Node

English | [简体中文](README.zh-CN.md) | [日本語](README.ja-JP.md) | [한국어](README.ko-KR.md) | [Español](README.es.md) | [Русский](README.ru-RU.md)

Quantaureum is a quantum-safe Layer 1 blockchain with threshold-signature
finality and a QVM smart-contract engine.

## Overview

Quantaureum is a post-quantum Layer 1 public blockchain written in Go. It uses
**Dilithium3** (NIST FIPS 204) for signatures, **Kyber768** (NIST FIPS 203) for
key exchange, and a custom **QPOS** consensus with **QTD threshold signatures**
for block finality.

The project was started by its author on **February 28, 2025** and built from
zero across cryptography, consensus, the virtual machine, networking, storage,
and RPC.

## Core Features

| Feature | Description |
| --- | --- |
| Post-quantum cryptography | Dilithium3 signatures and Kyber768 key exchange |
| QTD threshold signatures | Distributed key generation and threshold finality signatures |
| QPOS consensus | Proof-of-stake BFT consensus, randomness, slashing, and committees |
| QVM and QASM | Custom virtual machine and assembly-level smart contracts |
| Parallel execution | Block-STM-style parallel transaction execution |
| Data availability | Erasure coding, sampling, and FRI commitments |
| Sharding | Multi-shard execution and cross-shard messaging |
| Rollup support | Built-in sequencer and L1 bridge contracts |
| Cross-chain bridge | Merkle-proof based bridge design |
| Multisig wallet | Native Dilithium multisig wallet support |
| Light client | Verkle-proof based light verification |
| SDK surface | Go library plus standalone Go, TypeScript, Rust, C++, Java, and Python SDKs |

## Architecture

```text
L7  rpc/ graphql/            JSON-RPC 2.0, WebSocket, and GraphQL
L6  node/ txpool/            Node orchestration and transaction pool
L5  consensus/ core/         QPOS, QTD finality, and block processing
L4  qvm/                     QVM, QASM, JIT, and parallel execution
L3  p2p/ economics/          Authenticated transport and chain economics
L2  qaudb/ encoding/ rlp/    Storage, wire formats, and serialization
L1  crypto/ types/ common/   Dilithium3, Kyber768, and core types
```

## Version Metadata

The source release version is `1.0.0` and the protocol version is `1.0.0`.
Both are defined in `internal/version/version.go`. Release builds can inject
the software version, Git commit, and UTC build timestamp:

```sh
VERSION=1.0.0
GIT_COMMIT=$(git rev-parse --short HEAD)
BUILD_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS="-X github.com/quantaureum/qau/internal/version.Version=$VERSION \
  -X github.com/quantaureum/qau/internal/version.GitCommit=$GIT_COMMIT \
  -X github.com/quantaureum/qau/internal/version.BuildTime=$BUILD_TIME"

go build -trimpath -ldflags "$LDFLAGS" -o bin/qaud ./cmd/qaud
go build -trimpath -ldflags "$LDFLAGS" -o bin/qau-cli ./cmd/qau-cli
go build -trimpath -ldflags "$LDFLAGS" -o bin/qauctl ./cmd/qauctl
go build -trimpath -ldflags "$LDFLAGS" -o bin/qau-visor ./cmd/qau-visor
```

## Quick Start

The project requires the Go version declared in `go.mod`.

```sh
git clone https://github.com/Quantaureum/qau.git
cd qau

go build ./...
go build -trimpath -o bin/qaud ./cmd/qaud
go build -trimpath -o bin/qau-cli ./cmd/qau-cli
go build -trimpath -o bin/qauctl ./cmd/qauctl
go build -trimpath -o bin/qau-visor ./cmd/qau-visor
```

On Windows, add the `.exe` suffix to output paths when explicit executable
names are needed.

Start a development node:

```sh
./bin/qaud --dev --network dev --datadir ./dev-data
```

Start a public-network node:

```sh
./bin/qaud --network mainnet --datadir ./mainnet-data
./bin/qaud --network testnet --datadir ./testnet-data
```

Mainnet and testnet genesis configurations and canonical bootnode records are
built into the client. See the network guide for genesis-hash verification and
connection checks.

## Network IDs

| Network | Chain ID / Network ID | Hex chain ID | Purpose |
| --- | ---: | --- | --- |
| Mainnet | 1668 | `0x684` | Production network |
| Testnet | 1669 | `0x685` | Public test network |
| Devnet | 1333 | `0x535` | Local development |

## Repository Layout

```text
cmd/            Node, CLI, tool, and benchmark commands
crypto/         Dilithium3, Kyber768, and QTD cryptography
types/          Blocks, transactions, addresses, and core types
common/         Shared utilities
encoding/       Wire formats, DAS, erasure coding, and FRI
rlp/ abi/       Serialization and contract ABI encoding
qaudb/          Storage, state, block store, and Verkle trie
consensus/      QPOS, finality, elections, slashing, and sharding
core/           Block building and validation
qvm/            QVM, QASM, JIT, and parallel execution
node/           Node orchestration and synchronization
rpc/ graphql/   JSON-RPC, WebSocket, and GraphQL APIs
p2p/            Encrypted transport, discovery, and gossip
txpool/ miner/  Transaction pool and block sealing
wallet/ economics/ Wallets, staking, rewards, and governance
rollup/ bridge/ Rollups and cross-chain bridge components
privacy/ qzkp/  Privacy and zero-knowledge components
light/ lightclient/ Light-node and verification components
metrics/ log/ tracing/ Observability
contracts/      QASM and Solidity source examples
docs/           Deployment, network, configuration, and usage guides
```

## JSON-RPC API

The node supports Ethereum-compatible JSON-RPC methods such as
`eth_chainId`, `eth_blockNumber`, `eth_getBalance`, `eth_getTransactionByHash`,
`eth_sendRawTransaction`, `eth_call`, and `eth_estimateGas`.

Quantaureum-specific methods use the `qau_` namespace, including:

| Category | Methods |
| --- | --- |
| Consensus | `qau_qposStatus`, `qau_getStake`, `qau_getStakingStats` |
| TSS / QTD | `qau_tss_status`, `qau_tss_getPublicKey` |
| Quantum signing | `qau_signQuantumTransaction`, `qau_verifyQuantumTransaction` |
| Multisig | `qau_isMultisigWallet`, `qau_getMultisigWallet` |
| Staking | `qau_getUserStakes`, `qau_getPendingRewards` |
| Account abstraction | `qau_supportedEntryPoints` |

## SDK

The node is directly importable as a Go library:

```go
import (
    "github.com/quantaureum/qau/crypto"
    "github.com/quantaureum/qau/common"
    "github.com/quantaureum/qau/types"
)
```

Standalone SDKs are included in this repository:

| Language | Path | Status |
| --- | --- | --- |
| Go | [`sdks/go-sdk`](sdks/go-sdk) | Included |
| TypeScript | [`sdks/ts-sdk`](sdks/ts-sdk) | Included |
| Rust | [`sdks/rust-sdk`](sdks/rust-sdk) | Included |
| C++ | [`sdks/cpp-sdk`](sdks/cpp-sdk) | Included |
| Java | [`sdks/java-sdk`](sdks/java-sdk) | Included |
| Python | [`sdks/python-sdk`](sdks/python-sdk) | Included |

## Testing

```sh
go test ./...
go test -race ./crypto/... ./consensus/... ./qvm/...
```

Run the genesis validation tests specifically:

```sh
go test ./node -run "TestDefaultGenesis|TestTestnetGenesis|TestBuiltinNetworkGenesisValidation|TestGenesisValidate"
```

## Cryptographic Specification

| Primitive | Algorithm | Standard | Key size | Signature size |
| --- | --- | --- | --- | ---: |
| Signature | Dilithium3 | NIST FIPS 204 | 1952-byte public / 4000-byte private | 3293 bytes |
| Key exchange | Kyber768 | NIST FIPS 203 | 1184-byte public / 2400-byte private | N/A |
| Threshold signature | GM-QTD | Quantaureum design | 1952-byte group public key | 3293 bytes |
| Hash | Blake2b-256 / SHA3-256 | RFC 7693 / FIPS 202 | N/A | 32 bytes |
| Keystore | AES-256-GCM and scrypt | NIST SP 800-38D / RFC 7914 | N/A | N/A |

HD wallet path: `m/44'/1668'/0'/0/{index}`.

## Source Release Scope

Included:

- Go node, consensus, cryptography, networking, RPC, database, and tool source code
- Built-in public mainnet and testnet presets and genesis configuration
- Solidity and QASM source files
- Go module manifests required for reproducible dependency resolution
- Tests and deterministic fixtures required by the test suite

Excluded:

- Runtime configuration files and external bootstrap peer records
- Private keys, certificates, password files, and other secrets
- Deployment scripts, container images, and generated build artifacts

Operators provide runtime configuration, data directories, secrets, and any
authorized non-built-in bootstrap peers outside this source tree.

## Documentation

- [Deployment guide](docs/DEPLOYMENT.md)
- [Network guide](docs/NETWORK.md)
- [Configuration guide](docs/CONFIGURATION.md)
- [Usage guide](docs/USAGE.md)

## Security Notes

Never commit private keys, mnemonics, passwords, certificates, or production
network topology to this repository. Keep runtime secrets in a dedicated secret
store or in files with restrictive permissions outside the source tree.

## Community

- [Discord](https://discord.com/invite/MSctkBT5j)
- [X (@ldf1570073)](https://x.com/ldf1570073)
- [GitHub](https://github.com/Quantaureum/qau)

## License

Apache License 2.0. See [LICENSE](LICENSE).
