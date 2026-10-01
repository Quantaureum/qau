# Quantaureum Whitepaper

*Version 2.0 — September 2026*

## Abstract

Quantaureum is a quantum-safe Layer-1 blockchain infrastructure designed to withstand attacks from both classical and quantum adversaries. The name derives from Ancient Greek, meaning "quantum gold" — a reflection of our design philosophy: creating a digital asset with gold-like scarcity and unforgeability, backed not by physical reserves but by post-quantum cryptographic guarantees.

Built from the ground up with NIST-standardized post-quantum cryptography — Dilithium3 (ML-DSA-65) for signatures and Kyber-768 (ML-KEM-768) for key exchange — Quantaureum provides a secure foundation for decentralized applications in the post-quantum era.

The mainnet is live (chain ID 1668), alongside a browser extension wallet (Chrome/Edge/Firefox), a mobile wallet (Android), an official website with explorer, and six-language SDKs.

The native utility token, QAU, serves as network fuel for transaction processing, consensus participation, and protocol governance. It is not a payment currency, stablecoin, or commodity-pegged asset.

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

Blocks reach the chain within a 12-second slot; irreversibility is provided by Casper FFG finality across two consecutive epochs. Checkpoint subjectivity protection prevents shallow-history fabrication for newly syncing nodes.

### 3.2 Validator Selection

Validators are selected via Verifiable Random Function (VRF) to ensure fair and unpredictable assignment. At 200,000 simulated validators, committee assignment completes in ~234 ms per epoch and proposer selection in ~2.9 ms per call, with no duplicate committee members or proposers (verified over full epochs).

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

The protocol codebase implements the following scaling layers; mainnet activation is staged progressively via governance:

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

The networking stack has been validated at 200,000-node scale in simulation: DHT node discovery at 530K inserts/sec, connection pools for 200K peers in ~53 MB of memory, and rate limiting at ~12K peers/sec (42/42 tests passing).

## 7. Products & Ecosystem

| Product | Status |
|---------|--------|
| **Blockchain node** (`qaud`/`qauctl`, Go 1.26+) | Mainnet live (chain ID 1668), testnet & devnet |
| **Browser extension wallet** v1.0.1 | Chrome, Edge, Firefox |
| **Mobile wallet** v1.0 | Android (React Native, Dilithium3 keystore, BIP-39/BIP-44-style HD) |
| **Official website & explorer** | www.quantaureum.com — explorer, staking, developer docs |
| **SDKs** | Go, Rust, C++, Java, Python, JavaScript/TypeScript — unified API |
| **RPC / GraphQL** | JSON-RPC 2.0 (HTTPS + WS) at rpc.quantaureum.com |

Wallets support multi-network switching (mainnet/testnet/devnet), Commit-Reveal anti-MEV transaction flow, and real-time transaction status tracking.

## 8. Token Economics

QAU is the **native utility token** of the Quantaureum network. It is not a payment currency, not a stablecoin, and is not pegged to any fiat currency or commodity.

### 8.1 Utility

QAU serves three purposes:
1. **Network fuel (gas):** All on-chain operations require QAU
2. **Consensus participation:** Validators stake QAU to secure the network
3. **Protocol governance:** QAU holders vote on network proposals

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

All locked allocations are managed via smart contracts with on-chain verification. No manual minting capability exists beyond protocol-governed staking rewards.

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

No supply cap; no manual minting; no admin-adjustable rate. See [QAU Token Economics](TOKEN_ECONOMICS.md) for full details.

## 9. Performance

Micro-benchmarks (serialization + validation, Xeon E5-2680 v3, Go 1.26+) show 384K–909K TPS raw throughput, scaling to ~2.2x at 8 workers. These figures **exclude Dilithium3 signature verification** (~3,300 verifications/sec/core); end-to-end throughput under full PQC load is the subject of ongoing distributed benchmarks. 200,000-node network simulation results are reported in §6.3 and in the benchmark reports.

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

30 rounds of deep security auditing (plus 5 preliminary rounds) were conducted across the core chain and wallet extension, covering 43 packages. Result: **54 findings, all fixed** — 14 Critical, 12 High, 16 Medium, 12 Low. All 43 packages compile and pass tests with a 100% pass rate.

See [SECURITY.md](../SECURITY.md) for the vulnerability-reporting policy and bounty program; audit summary details are held in the internal audit archive.

## 11. Governance

Quantaureum uses community-driven governance through the QIP (Quantaureum Improvement Proposal) process, modeled after Ethereum's EIP process:

1. Community discussion
2. Formal QIP draft with technical specifications
3. Core developer technical review
4. Testnet implementation and testing
5. Community vote
6. Mainnet activation

A Foundation serves as the legal entity responsible for protocol maintenance and compliance, with a mandate to gradually transfer governance authority to community DAO.

## 12. Roadmap

### Completed
- Core blockchain implementation (Go 1.26+), built from scratch
- Dilithium3 + Kyber-768 post-quantum cryptography
- QPOS consensus (Casper FFG finality) + QTD/GM-QTD threshold signing
- QVM + QASM smart-contract engine, Block-STM parallel execution
- Commit-Reveal anti-MEV transaction flow
- Batch signature verification, key rotation and management
- P2P networking with post-quantum transport; 200K-node scale validation
- 30-round security audit (54 findings fixed, zero Critical/High remaining)
- **Mainnet live since September 2026 (chain ID 1668)** at rpc.quantaureum.com
- Browser extension wallet (Chrome/Edge/Firefox) + Android mobile wallet
- Six-language SDKs; website with explorer

### In Progress
- Cross-platform performance benchmarking (Dilithium3/ML-DSA across hardware)
- Distributed consensus throughput testing under PQC load
- Validator onboarding and network decentralization
- Contributor documentation and onboarding

### Planned
- Data availability, sharding, and rollup module mainnet activation (staged via governance)
- Cross-chain bridge deployments and DeFi ecosystem
- Enterprise BaaS offering
- Foundation establishment, legal structuring, and community governance transition

## 13. Disclaimer

This whitepaper describes the technical architecture and design of the Quantaureum protocol. QAU is a utility token used to pay for network services and participate in consensus. QAU is not a security, not a payment currency, and not a stablecoin. This document does not constitute investment advice, a solicitation, or an offer to sell securities. Participation in the Quantaureum network is subject to applicable laws and regulations in your jurisdiction.
