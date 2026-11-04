# Quantaureum Whitepaper

*Version 2.0 — September 2026*

## Abstract

Quantaureum is a quantum-safe Layer-1 blockchain infrastructure designed to withstand attacks from both classical and quantum adversaries. The name derives from Ancient Greek, meaning "quantum gold". That is a naming metaphor only: QAU is not pegged to gold or to any fiat currency or commodity, and there are no gold reserves, vaults, insurance arrangements, physical redemption rights or reserve audits. Scarcity is a property of the protocol's issuance rules, not of any asset backing.

Built from the ground up with NIST-standardized post-quantum cryptography — Dilithium3 (ML-DSA-65) for signatures and Kyber-768 (ML-KEM-768) for key exchange — Quantaureum provides a secure foundation for decentralized applications in the post-quantum era.

This is an independent developer's technical exploration project, currently in testnet phase (chain ID 1669). Mainnet parameters (chain ID 1668) are configured in code; launch status will be announced officially. The repository also contains a browser extension wallet, an Android mobile wallet, a website with explorer, and SDKs.

The native utility token, QAU, pays for transaction processing (gas) and secures the network through staking and consensus participation. It is not a payment currency, not a stablecoin, and is not pegged to any fiat currency or commodity. Holding QAU does not confer governance voting rights; see GOVERNANCE.md.

## 1. Introduction

### 1.1 The Quantum Threat

Quantum computing poses an existential threat to current blockchain infrastructure. Most major blockchains rely on ECDSA (secp256k1) for transaction signing and ECIES for key exchange — both of which are vulnerable to Shor's algorithm on sufficiently powerful quantum computers.

NIST finalized its post-quantum cryptography standards in 2024, selecting CRYSTALS-Dilithium (FIPS 204) for digital signatures and CRYSTALS-Kyber (FIPS 203) for key encapsulation. The migration window for existing blockchain networks is measured in years, not decades.

### 1.2 Design Philosophy

Quantaureum takes a "quantum-first" approach: rather than retrofitting quantum-resistant cryptography onto a classical foundation, every component is designed with post-quantum security as a first principle.

Key design decisions:
- **No classical fallback.** secp256k1/ECDSA is permanently disabled by default. There is no hybrid mode.
- **No signature aggregation for consensus.** Dilithium3 signatures do not support BLS-style aggregation. We use batch verification with SHA-3 binding commitments instead.
- **Separation of concerns.** Kyber-768 is used exclusively for P2P transport encryption. Consensus uses Dilithium3 for block and attestation signatures.
- **Full-stack self-implementation.** The node is written from scratch in Go (1.26+) — cryptography, consensus, virtual machine, networking, storage, and RPC — not a fork of an existing chain.

## 2. Post-Quantum Cryptography

### 2.1 Dilithium3 (ML-DSA-65)

Dilithium3 is a lattice-based signature scheme providing NIST Security Level 3 (equivalent to AES-192).

| Parameter | Value |
|-----------|-------|
| Public key size | 1,952 bytes (~1.9 KB) |
| Private key size | 4,000 bytes (~4 KB) |
| Signature size | 3,293 bytes (~3.3 KB) |
| Implementation | Cloudflare circl, FIPS 204 aligned |

The signature size of 3,293 bytes represents approximately 50x the overhead of secp256k1 (64 bytes). This is a fundamental constraint that affects block size, network bandwidth, and state storage — and the reason several protocol-level optimizations below exist.

### 2.2 Kyber-768 (ML-KEM-768)

Kyber-768 provides post-quantum key encapsulation for secure communication between nodes.

| Parameter | Value |
|-----------|-------|
| Public key size | 1,184 bytes |
| Ciphertext size | 1,088 bytes |
| Shared secret size | 32 bytes |
| Security level | NIST Level 3 (AES-192 equivalent) |

### 2.3 Batch Verification

The BatchVerifier supports parallel verification of up to 10,000 Dilithium3 signatures with configurable worker threads. Batch verification throughput is linear in the number of workers up to the available CPU cores, and is used to amortize the cost of large attestation sets.

### 2.4 QTD Threshold Signing

QTD (Quantaureum Threshold Dilithium) is a two-round threshold signing protocol built on Dilithium3. It enables t-of-n signing without reconstructing the private key at any point.

Key properties:
- Produces standard Dilithium3-verifiable signatures
- Semi-honest security model (documented in the QTD specification)
- Coefficient-wise Shamir secret sharing over R_q for DKG
- Lagrange-based response computation leveraging Dilithium3's linear structure

GM-QTD, the production variant, participates in block finality and supports institutional custody and multi-signature wallet scenarios.

## 3. QPOS Consensus

### 3.1 Design

Quantum Proof of Stake (QPOS) is modeled after the Gasper consensus protocol (Casper FFG + LMD GHOST). It operates with:

| Parameter | Value |
|-----------|-------|
| Slot time | 12 seconds |
| Epoch length | 32 slots (~6.4 minutes) |
| Finality delay | 2 epochs (~13 minutes, Casper FFG) |
| Validator minimum stake | 32 QAU |
| Committee size (large-scale) | 128 per epoch |
| Attestation signature | Dilithium3 |

Blocks reach the chain within a 12-second slot. The base checkpoint path is Casper FFG finality across two consecutive epochs; when the QTD / GM-QTD committee-signed finality path is active it supersedes the checkpoint path. Both paths are implemented in `consensus/` (`block.go`, `checkpoint.go`). Checkpoint subjectivity protection prevents shallow-history fabrication for newly syncing nodes.

### 3.2 Validator Selection

Validators are selected via Verifiable Random Function (VRF) to ensure fair and unpredictable assignment. Committee assignment and proposer selection have been exercised at 200,000 validators in simulation to check for duplicate members; these are simulation results, not measurements from a deployed network.

### 3.3 Slashing

| Violation | Penalty |
|-----------|---------|
| Double signing | 100% slash + removal from validator set |
| Extended downtime | Progressive penalty proportional to offline duration |
| Malicious behavior | 10–100% based on severity |

### 3.4 Performance Considerations

Dilithium3 signatures are 3,293 bytes each. With N active validators, each slot carries N × 3,293 bytes of attestation data. The impact on consensus throughput at scale is mitigated via committee sampling, attestation pruning after finality, and batch verification; large-scale behavior is an active area of research and benchmarking (see §9).

## 4. QVM Smart Contract Engine & Block-STM

### 4.1 QVM + QASM

Quantaureum ships a custom quantum virtual machine (QVM) with a QASM assembly-level smart-contract language and JIT execution. Contracts are deterministic, sandboxed, and verified with the same post-quantum signature guarantees as ordinary transactions.

### 4.2 Block-STM Parallel Execution

Quantaureum implements Block-STM (Software Transactional Memory) for parallel transaction execution with state-conflict resolution:

- Multi-version memory (MVMemory) with read/write set tracking
- Optimistic execution with incarnation-based validation and retry
- Signature verification occurs before execution enters the Block-STM pipeline

Block-STM improves transaction execution throughput by parallelizing non-conflicting transactions. It does not affect signature verification — those are handled independently and are embarrassingly parallel by nature.

### 4.3 Commit-Reveal Anti-MEV

Transactions follow a commit-reveal pattern that prevents validators from exploiting pending transaction content (frontrunning/sandwiching), providing native MEV resistance at the protocol level.

## 5. Scalability Modules

The following scaling layers are design and roadmap items in this repository, not shipped feature claims. Their completion status and staged activation are tracked in ROADMAP.md:

- **Data availability:** erasure coding, data-availability sampling (DAS), and FRI commitments
- **Sharding:** multi-shard architecture with cross-shard messaging
- **Rollup support:** built-in rollup sequencer + L1 bridge contracts (QASM)
- **Cross-chain bridge:** minimal-trust bridge based on Merkle proofs
- **Light client:** SPV light client based on Verkle tree proofs

## 6. Network Architecture

### 6.1 P2P Layer

The P2P networking layer uses:
- mTLS with PKI hierarchy (Root CA → Intermediate CA → Node Certificate) for classical authentication
- Post-quantum RLPx handshake (protocol v5) for transport encryption:
  - Kyber-768 key encapsulation for shared secret derivation
  - HKDF-SHA3-256 for key derivation
  - Domain-separated session keys (sendKey, recvKey, macSecret, egressMACKey)
  - Dilithium3 identity binding on both initiator and responder

### 6.2 Key Management

- AES-256-GCM encryption at rest
- scrypt key derivation (N=262,144)
- Three-pass zeroization for private key material
- Configurable key rotation with lifecycle management
- Multi-signature approval for rotation operations

### 6.3 Scale Validation

The networking stack has been exercised at 200,000-node scale in simulation for DHT discovery, connection pools and rate limiting. These are simulation results, not measurements from a deployed network; no chain throughput, latency or availability figure is published.

## 7. Products & Ecosystem

| Product | Status |
|---------|--------|
| **Blockchain node** (`qaud`/`qauctl`, Go 1.26+) | Testnet phase (1669); mainnet config 1668; devnet 1333 |
| **Browser extension wallet** v1.0.1 | Chrome, Edge, Firefox |
| **Mobile wallet** v1.0 | Android (React Native, Dilithium3 keystore, BIP-39/BIP-44-style HD) |
| **Official website & explorer** | www.quantaureum.com — explorer, staking, developer docs |
| **SDKs** | Go, Rust, C++, Java, Python, JavaScript/TypeScript — unified API |
| **RPC / GraphQL** | JSON-RPC 2.0 (HTTPS + WS); verify `eth_chainId` before use (1668 / 1669 / 1333) |

Wallets support multi-network switching (mainnet/testnet/devnet), Commit-Reveal anti-MEV transaction flow, and real-time transaction status tracking.

## 8. Token Economics

QAU is the **native utility token** of the Quantaureum network. It is not a payment currency, not a stablecoin, and is not pegged to any fiat currency or commodity.

### 8.1 Utility

QAU serves two purposes:
1. **Network fuel (gas):** All on-chain operations require QAU
2. **Consensus participation:** Validators stake QAU to secure the network; delegators may delegate from 1 QAU

Holding QAU does not grant governance voting rights. Changes to protocol rules follow maintainer-led review and require a written design; see GOVERNANCE.md.

### 8.2 Genesis Allocation (20,000,000 QAU)

| Category | Amount | Share | Vesting |
|----------|--------|-------|---------|
| Community Contribution | 4,961,600 QAU | 24.81% | Free circulation |
| Team | 4,000,000 QAU | 20% | 4-year linear, 1-year cliff |
| Staking Incentive Pool | 4,000,000 QAU | 20% | 5-year linear |
| Development Fund | 2,000,000 QAU | 10% | 4-year linear, 1-year cliff |
| Ecosystem Fund | 2,000,000 QAU | 10% | 4-year linear |
| Foundation Reserve | 2,000,000 QAU | 10% | 4-year linear, 1-year cliff |
| Security & Compliance | 1,000,000 QAU | 5% | 3-year linear |
| Genesis Validators | 38,400 QAU | 0.19% | 6 × 6,000 QAU staked in consensus, 6 × 400 QAU account balance |
| **Total** | **20,000,000 QAU** | **100%** | |

All locked allocations are managed via smart contracts with on-chain verification. No manual minting capability exists beyond protocol-governed staking rewards. "Foundation Reserve" and "Ecosystem Fund" are on-chain allocation labels only; they do not establish a legal foundation, a council, a DAO, or token-holder governance. Governance follows maintainer-led review (GOVERNANCE.md).

### 8.3 Staking & Issuance

- Rewards are issued automatically by the protocol; no entity controls issuance
- Ethereum Altair-aligned formula: per-epoch base reward `stake × 31 / sqrt(total_staked)` (gwei); 87.5% to attesters, 12.5% to block proposers
- APY decays as `1/sqrt(total_staked)` — no manual adjustment, no governance vote on rates

| Total staked (QAU) | Validators | Annual issuance (QAU) | Staking APY |
|---|---|---|---|
| 36,000 (genesis) | 6 | 15,275 | 42.43% |
| 600,000 | 100 | 62,361 | 10.39% |
| 3,996,000 | 666 | 160,935 | 4.03% |
| 19,998,000 | 3,333 | 360,023 | 1.80% |

No supply cap; no manual minting; no admin-adjustable rate. The table above is produced by `go run ./cmd/econsim table -preset live`; it is an economic-model simulation, not an on-chain measurement, not a yield promise and not investment advice. See [QAU Token Economics](TOKEN_ECONOMICS.md) for full details.

## 9. Performance

The only published throughput figures come from a transaction serialization micro-benchmark (serialization + validation, Xeon E5-2680 v3, Go 1.26+): 384K–909K operations/sec, scaling to ~2.2x at 8 workers. These are **not chain TPS**. They exclude Dilithium3 signature verification, consensus, networking and state execution. No end-to-end chain throughput, latency or availability figure is published; distributed benchmarking under full PQC load remains an open item (ROADMAP.md).

Honest framing matters: the cost of quantum safety is larger signatures and slower verification. Quantaureum's position is that this trade-off is worth making today rather than migrating under duress tomorrow, and the protocol is engineered (batch verification, Block-STM, committee sampling) to absorb it.

## 10. Security

### 10.1 Cryptography

- All signatures: Dilithium3 (NIST FIPS 204)
- All key exchange: Kyber-768 (NIST FIPS 203)
- Hashing: SHA-256 / SHA-3
- Key derivation: HKDF-SHA3-256

### 10.2 Classical Security is Deprecated

The following are permanently disabled by default:
- secp256k1/ECDSA signatures
- ECIES encryption
- Legacy 65-byte signature formats

These may only be temporarily enabled for emergency migration scenarios.

### 10.3 Audit

No completed third-party audit, FIPS certification, security compliance certification or zero-vulnerability claim is made. Implementing the NIST FIPS 203 / FIPS 204 standard algorithms is not the same as holding a product certification. Source code alone does not establish production readiness (ROADMAP.md); known risks and experimental interfaces are listed in SECURITY.md.

See [SECURITY.md](../SECURITY.md) for the private vulnerability-reporting channel and the capped 25,000 QAU bounty pool.

## 11. Governance

Quantaureum uses maintainer-led review, not token-holder governance. Repository administrators control access, merge permissions and releases. Changes to protocol rules, cryptography, wire formats, storage compatibility or public APIs need a written design recording the problem, alternatives, security assumptions, migration impact and acceptance evidence before implementation. A merge is not authorization for a network upgrade or a production deployment.

This document does not establish a foundation, an elected council, a DAO, or token-holder voting. Holding QAU does not grant permissions. See [GOVERNANCE.md](../GOVERNANCE.md).

## 12. Roadmap

### Completed
- Core blockchain implementation (Go 1.26+), built from scratch
- Dilithium3 + Kyber-768 post-quantum cryptography
- QPOS consensus (Casper FFG finality) + QTD/GM-QTD threshold signing
- QVM + QASM smart-contract engine, Block-STM parallel execution
- Commit-Reveal anti-MEV transaction flow
- Batch signature verification, key rotation and management
- P2P networking with post-quantum transport; 200K-node scale validation in simulation
- Known risks and experimental interfaces documented in SECURITY.md
- **Testnet phase (chain ID 1669); mainnet parameters (1668) configured in code, launch status to be announced officially**
- Browser extension wallet (Chrome/Edge/Firefox) + Android mobile wallet
- SDKs and a website with explorer

### In Progress
- Cross-platform performance benchmarking (Dilithium3/ML-DSA across hardware)
- Distributed consensus throughput testing under PQC load
- Validator onboarding and network decentralization
- Contributor documentation and onboarding

### Planned
- Data availability, sharding and rollup module completion (design/roadmap items, not shipped features)
- Cross-chain bridge work and light-client proofs
- Independent review of cryptography and consensus (ROADMAP.md)

## 13. Disclaimer

This whitepaper describes the technical architecture and design of the Quantaureum protocol, an independent developer's technical exploration project currently in testnet phase. QAU is a utility token used to pay for network services and participate in consensus security. QAU is not a security, not a payment currency, not a stablecoin, and is not pegged to any fiat currency or commodity; there is no gold or other reserve backing. This document does not constitute investment advice, a solicitation, an offer to sell securities, or any price or return expectation. Participation in the Quantaureum network is subject to applicable laws and regulations in your jurisdiction.
