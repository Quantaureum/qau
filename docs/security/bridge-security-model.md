# Bridge Arbitration Security Model

> P4-3 · 2026-07-15 · Quantaureum Cross-Chain Bridge Security

## 1. Overview

This document describes the security model of the Quantaureum bridge arbitration subsystem, including threat analysis, security mechanisms, fixed vulnerabilities, and known limitations. Bridge arbitration is the core security layer for cross-chain asset transfer; its security relies on M-of-N BFT threshold signatures, post-quantum cryptography, and multi-layer verification mechanisms.

## 2. BRDG-01 Fix: Trusted Validator Public Keys

### Vulnerability Description

**BRDG-01 (original vulnerability)**: `SubmitMessage` accepts an arbitrary `QuantumPublicKey` for signature verification without checking whether that public key belongs to the trusted validator set. An attacker can self-generate a Dilithium3 key pair, sign a message with the private key, and then "verify successfully" using the self-generated public key.

**Risk level**: Critical — arbitrary cross-chain messages can be forged, allowing theft of locked assets.

### Fix

```go
// P0-1 BRDG-01 FIX (2026-07-13): Trusted Dilithium3 public keys for
// verifyQuantumSignature. Messages signed with keys NOT in this set are
// rejected at SubmitMessage time.
trustedValidatorKeys [][]byte
```

- `trustedValidatorKeys` is populated from the QPOS validator set at node startup
- **Fail-closed**: when the set is empty, all messages are rejected (until the keys are configured)
- Each key must be 1952 bytes (Dilithium3 public key size)
- `RefreshValidatorSet` updates this set in sync when the QPOS validator set changes

### Verification Flow

```
SubmitMessage →
  1. extract msg.QuantumPublicKey
  2. look it up in trustedValidatorKeys (constant-time compare)
  3. not in the set → reject "untrusted validator key"
  4. in the set → verify the signature with this public key
  5. invalid signature → reject
  6. valid signature → accept the message
```

## 3. Arbitration Network Security Model

### 3.1 M-of-N BFT Threshold Signature

```
┌──────────────────────────────────────────────────────┐
│         N validators (from the QPOS consensus set)    │
│                                                       │
│  threshold = ceil(2/3 × N)                            │
│                                                       │
│  V1 ──sign──→ ┐                                      │
│  V2 ──sign──→ │  SignatureAggregator                  │
│  V3 ──sign──→ ├─→ collect signatures → verify → count │
│  ...          │  → HasQuorumForHash(msgID, msgHash)   │
│  VN ──sign──→ ┘                                      │
│                                                       │
│  sig count >= threshold AND hash matches → allow exec │
└──────────────────────────────────────────────────────┘
```

**Security guarantees:**

| Property | Implementation |
|------|---------|
| **Single-point malice prevention** | Requires ≥ 2/3 validator signatures to execute a message |
| **Signature forgery prevention** | Every signature is verified with Dilithium3 (post-quantum secure) |
| **Payload substitution prevention** | Signatures bound to the message hash, not just the messageID (HIGH-08 FIX) |
| **Timing attack prevention** | Hash comparison uses `subtle.ConstantTimeCompare` |
| **Signature reuse prevention** | Each validator can sign each messageID only once |
| **Aggregation order attack prevention** | Aggregate signatures are sorted by address before hashing (BRIDGE-AGG-01 FIX) |

### 3.2 Signature Binding Mechanism (HIGH-08 FIX)

**Original vulnerability**: validators sign only `[]byte(messageID)` without including the message content. An attacker can collect validators' signatures over a benign message and then use the same messageID to execute a malicious message (different amount/recipient).

**Fix**: signatures are bound to the full message hash.

```go
// HasQuorumForHash checks (a) signature count >= threshold and (b) the
// messageHash provided by the caller matches the messageHash the validators
// actually signed.
func (sa *SignatureAggregator) HasQuorumForHash(messageID string, messageHash []byte) bool {
    if len(sa.signatures[messageID]) < sa.threshold {
        return false
    }
    stored, ok := sa.messageHashes[messageID]
    if !ok || len(stored) == 0 {
        return false // fail closed
    }
    return subtle.ConstantTimeCompare(stored, messageHash) == 1
}
```

## 4. SPV Header Verification

### 4.1 Two-Stage Merkle Root Verification

```
┌──────────────────────────────────────────────────────────┐
│  Stage 1: SetCommittedRoot                               │
│  ─────────────────────────                                │
│  the governance address sets the Merkle root via voting  │
│  caller must match the governanceAddress                 │
│  → committedRoot = root                                   │
│  → IncMerkleRootUpdate() + SetL1AnchorLag(0)             │
├──────────────────────────────────────────────────────────┤
│  Stage 2: FetchMerkleRootFromChain                       │
│  ─────────────────────────                                │
│  read the root directly from the on-chain contract       │
│  (eth_getStorageAt)                                      │
│  slot = keccak256("merkleRoot")                           │
│  → removes the trust assumption on the governance address│
│  → root is protected by on-chain consensus               │
│  → auto-update cache + SetL1AnchorLag(0)                 │
└──────────────────────────────────────────────────────────┘
```

### 4.2 Source-Chain Reorganization Detection

`BridgeHeaderVerifier` detects source-chain reorganizations through two interfaces:

| Interface | Method | Purpose |
|------|------|------|
| `HeaderLookup` | `GetHeader(height)` | Queries the source-chain block header |
| `HeaderLookup` | `GetLatestHeight()` | Gets the latest block height |
| `SyncCommitteeChecker` | `VerifySyncCommittee(header, sig)` | Verifies the sync committee signature |

**Verification flow:**
1. Query the source chain's current block header
2. Compare it with the block hash recorded at message submission time
3. If they do not match → the source chain was reorganized → reject the message
4. Verify the sync committee signature (light-client verification)

## 5. Replay Protection

### 5.1 Multi-Layer Replay Defense

```
┌─────────────────────────────────────────────────────┐
│  Layer 1: Per-sender Nonce                          │
│  usedNonces[sourceAddr][nonce] = timestamp          │
│  TTL: auto-cleared after 24 hours                   │
│  Max: 10000 per address                            │
├─────────────────────────────────────────────────────┤
│  Layer 2: Finalized ID Set                          │
│  finalizedIDs[messageID] = true                     │
│  permanently records executed/failed/expired msg IDs │
│  Max: 200000 (LRU evicts the oldest)                │
│  prevents replay after the message is evicted from  │
│  memory                                             │
├─────────────────────────────────────────────────────┤
│  Layer 3: Persistent Recovery                       │
│  BoltMessageStore restores usedNonces + finalizedIDs │
│  after restart                                      │
│  prevents replay attacks after node restart         │
└─────────────────────────────────────────────────────┘
```

### 5.2 Nonce Tracking Details

- Each `sourceAddress` maintains an independent Nonce set
- Nonces record a timestamp when stored and are automatically cleared after 24 hours (preventing unbounded growth)
- At most 10000 Nonces per address (new messages are rejected beyond this)
- Restored from `BoltMessageStore` after restart (P0-6 FIX)

## 6. Asset Lock Security Model

### 6.1 Lock → Mint → Burn → Unlock Lifecycle

```
       Lock              Mint
Pending ──→ Locked ──→ Minted
                          │
                    Burn  │
                      ↓   │
                    Burned │
                      │   │
                    Unlock │
                      ↓   │
                    Unlocked
```

| State | Meaning | Security guarantee |
|------|------|---------|
| Pending | The lock request has been submitted | Validates parameter integrity |
| Locked | The asset is locked on the source chain | Source-chain confirmations >= ConfirmationsRequired |
| Minted | The wrapped token has been minted on the target chain | Requires M-of-N quorum signature |
| Burned | The wrapped token has been burned | Requires M-of-N quorum signature |
| Unlocked | The original asset has been released | Requires M-of-N quorum signature |

### 6.2 Slippage Protection

```go
// R63-HIGH-slippage: prevents the user from receiving far less than
// expected due to price movement between submission and execution
SlippageTolerance uint64  // basis points (bps), 100 = 1%
Deadline          uint64  // target-chain block number deadline
MaxAmount         string  // minimum amount to receive
```

- `SlippageTolerance > 0`: rejects execution when slippage exceeds the tolerance
- `Deadline > 0`: rejects execution after the deadline block number
- `MaxAmount != ""`: rejects execution when the delivered amount is below this value

## 7. Rate Limiting and DoS Protection

| Protection layer | Parameter | Description |
|--------|------|------|
| Global rate limit | 10 msg/s, 100 burst | Token bucket, prevents message flooding |
| Concurrent processing limit | MaxConcurrentProcessing = 16 | Prevents goroutine explosion |
| Message size limit | ID ≤ 256, Data ≤ 1MB | Prevents memory exhaustion |
| Nonce set limit | 10000/address, 200000 total IDs | Prevents unbounded growth |
| HTTP header limit | MaxHeaderBytes = 1MiB | Prevents Slowloris |
| HTTP timeout | ReadHeaderTimeout = 10s | Prevents Slowloris |
| Adapter RPC timeout | 15s | Prevents unreachable nodes from blocking |
| Iteration limit | maxIterations = 100000 | Prevents OOM from corrupted data |

## 8. Fixed Vulnerability Index

| ID | Severity | Description | Fix date |
|----|---------|------|---------|
| BRDG-01 | Critical | Missing trusted validator public key check | 2026-07-13 |
| BRDG-03 | High | SignatureAggregator had no signature verification | 2026-07-13 |
| BRDG-04 | High | Missing SPV header verification | 2026-07-13 |
| BRDG-09 | Medium | Bootstrap mode enabled by default | 2026-07-13 |
| HIGH-08 | High | Signatures bound only to messageID, not payload | 2026-07-12 |
| HIGH-12 | High | Single point of trust for the Merkle root | 2026-07-13 |
| HIGH-15 | High | No source-chain reorganization detection | 2026-07-13 |
| BRIDGE-AGG-01 | Medium | Aggregate signature order was nondeterministic | 2026-07-12 |
| R63-HIGH | High | No slippage protection | 2026-07-14 |
| R64-B2 | Medium | No retry mechanism | 2026-07-14 |
| R68-BRIDGE-3 | Medium | Finalized ID eviction was unordered | 2026-07-14 |
| R69-GAS-1 | Medium | No per-message gas limit | 2026-07-14 |

## 9. Known Limitations

### 9.1 L1 Anchor Lag Tracking

Currently `SetL1AnchorLag` is reset to 0 when `SetCommittedRoot` / `FetchMerkleRootFromChain` succeed. However, the actual lag growth (current block height - last anchored block height) requires a background monitoring process to update periodically. Until a background lag tracker is implemented, the `bridge_l1_anchor_lag_high` alert is only reset when an actual anchoring operation occurs.

### 9.2 Validator Exit Handling

After a validator exits QPOS, it is marked `Active = false` in the bridge `ValidatorSet` but is **not removed** (retained for historical signature verification and reputation tracking). This means the `ValidatorSet` accumulates records of exited validators. In production, records of validators that have been exited for a long time should be periodically cleaned up to control memory usage.

### 9.3 Bootstrap Mode Risk

When `SetBootstrapMode(true)` is called, the empty event-signature whitelist accepts all cross-chain events. This mode is intended only for initial deployment and must be turned off (`SetBootstrapMode(false)`) immediately after the governance registers the event signatures. If forgotten, anyone can submit forged events. The alert rule `bootstrap_mode > 1h` can detect this situation.

### 9.4 Single Relayer Dependency

In the current implementation, `MessageRelayer` is a single instance. If the relayer process crashes, cross-chain messages accumulate in the PENDING state. The `bridge_relayer_disconnected` alert can detect this situation. Support for multi-relayer redundancy is planned for the future.

### 9.5 Quantum Signature Size

Dilithium3 signatures are 3293 bytes and public keys 1952 bytes, significantly larger than ECDSA (65-byte signature, 33-byte public key). This increases message size and storage cost. In bandwidth-constrained environments, compression or batch verification optimizations should be considered.

## 10. Cryptographic Contracts

Bridge arbitration follows the Quantaureum cryptographic contract (highest priority, must not be changed arbitrarily):

| Algorithm | Parameters | Size |
|------|------|------|
| Dilithium3 | NIST FIPS 204 | public key 1952B, private key 4000B, signature 3293B |
| Kyber768 | NIST FIPS 203 | public key 1184B, private key 2400B |
| SHA-256 | Merkle tree | 32B |
| Keccak-256 | Event signature | 32B |

**Two-side synchronization hard constraint**: the wallet's `dilithium3-circl.wasm` and the node's `crypto/dilithium.go` must use the same circl version. Changing any cryptographic constant will make the wallet and node incompatible.