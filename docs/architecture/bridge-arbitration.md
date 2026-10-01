# Bridge Arbitration Subsystem Architecture

> P4-1 · 2026-07-15 · Quantaureum Cross-Chain Bridge Arbitration

## 1. Overview

The Quantaureum Bridge Arbitration subsystem is the core security layer of the cross-chain bridge, responsible for securely transferring assets and messages between the Quantaureum L1 public chain and external blockchains (such as Ethereum). The system uses an **M-of-N BFT threshold signature** mechanism to ensure that cross-chain messages are only executed after being signed by a sufficient number of validators, preventing single-point malicious behavior.

**Core parameters:**
- Supported chain types: Quantaureum (ChainID 1668/1669/1333) + Ethereum-compatible chains
- Signature algorithm: Dilithium3 (post-quantum, NIST FIPS 204)
- Consensus threshold: ceil(2/3 × N) validator signatures
- Message states: PENDING → VERIFIED → EXECUTED (or FAILED / EXPIRED)
- Persistence: bbolt (messages.db)
- Monitoring: 5 Prometheus alert rules

## 2. Overall Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                     QuantumBridge (bridge.go)                         │
│  ┌──────────────┐  ┌──────────────────┐  ┌────────────────────────┐  │
│  │ SubmitMessage │  │ ProcessMessage   │  │  VerifyMessage         │  │
│  │ (submit)      │  │ (state flow)     │  │  (SPV + sig verify)    │  │
│  └──────┬───────┘  └────────┬─────────┘  └───────────┬────────────┘  │
│         │                   │                        │               │
│  ┌──────┴───────────────────┴────────────────────────┴────────────┐  │
│  │                    Chain Adapters                                │  │
│  │  ┌─────────────────────┐    ┌─────────────────────────────┐    │  │
│  │  │ QuantaureumChain    │    │ ExternalChainAdapter         │    │  │
│  │  │ Adapter             │    │ (Ethereum compatible)        │    │  │
│  │  │ (quantaureum_       │    │ (ethereum_adapter.go)        │    │  │
│  │  │  adapter.go)        │    │                              │    │  │
│  │  └─────────────────────┘    └─────────────────────────────┘    │  │
│  └─────────────────────────────────────────────────────────────────┘  │
│         │                                                             │
│  ┌──────┴──────────────────────────────────────────────────────┐     │
│  │              ValidatorNetwork (validator_network.go)         │     │
│  │  ┌─────────────┐  ┌──────────────────┐  ┌────────────────┐  │     │
│  │  │ ValidatorSet │  │ Signature        │  │ Signature      │  │     │
│  │  │ (validator   │  │ Aggregator       │  │ Verifier       │  │     │
│  │  │  set)        │  │ (sig aggregation)│  │ (Dilithium3)   │  │     │
│  │  │ SyncFromQPOS │  │ HasQuorumForHash │  │                │  │     │
│  │  └─────────────┘  └──────────────────┘  └────────────────┘  │     │
│  └─────────────────────────────────────────────────────────────┘     │
│         │                                                             │
│  ┌──────┴──────────────────────────────────────────────────────┐     │
│  │              MessageRelayer (relayer.go)                     │     │
│  │  SubmitRelayTask → relayWorker → processTask → ProcessMessage│     │
│  │  healthCheckLoop / retryLoop (exponential backoff)           │     │
│  └─────────────────────────────────────────────────────────────┘     │
│         │                                                             │
│  ┌──────┴──────────────────────────────────────────────────────┐     │
│  │              Persistence & Verification                      │     │
│  │  ┌─────────────────┐  ┌──────────────────────────────────┐  │     │
│  │  │ BoltMessageStore │  │ BridgeHeaderVerifier             │  │     │
│  │  │ (message_store   │  │ (header_verifier.go)             │  │     │
│  │  │  .go)            │  │ SPV header verify + sync comm check│  │     │
│  │  └─────────────────┘  └──────────────────────────────────┘  │     │
│  │  ┌─────────────────┐  ┌──────────────────────────────────┐  │     │
│  │  │ AssetLockManager │  │ BridgeMetrics                    │  │     │
│  │  │ (asset_lock.go)  │  │ (bridge_metrics.go)              │  │     │
│  │  │ Lock→Mint→Burn   │  │ 5 alerts + Prometheus metrics   │  │     │
│  │  └─────────────────┘  └──────────────────────────────────┘  │     │
│  └─────────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────────┘
         │
    ┌────┴─────────────────────────────────────────────┐
    │           QPOS consensus layer integration        │
    │  QPOS validator set → RefreshValidatorSet →       │
    │  ValidatorSet.SyncFromQPOS → threshold signature  │
    └───────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | File | Responsibility |
|------|------|------|
| QuantumBridge | `bridge.go` | Bridge core: message submission/verification/execution, state transitions |
| QuantaureumChainAdapter | `quantaureum_adapter.go` | Quantaureum chain adapter: RPC, event listening, Merkle root |
| ExternalChainAdapter | `ethereum_adapter.go` | External chain adapter (Ethereum compatible): RPC, event parsing |
| ValidatorNetwork | `validator_network.go` | Validator network: ValidatorSet + SignatureAggregator + signature verification |
| ValidatorSet | `validator_network.go` | Validator set management: add/remove, QPOS sync, threshold checks |
| SignatureAggregator | `validator_network.go` | Signature aggregation: collect + verify + constant-time compare + quorum check |
| MessageRelayer | `relayer.go` | Message relay: task queue, parallel relay, health check, exponential-backoff retry |
| BoltMessageStore | `message_store.go` | Persistent storage: bbolt, message + state index |
| BridgeHeaderVerifier | `header_verifier.go` | SPV header verification: source-chain reorganization detection + sync committee checks |
| AssetLockManager | `asset_lock.go` | Asset lock management: Lock → Confirm → Mint → Burn → Unlock |
| BridgeMetrics | `bridge_metrics.go` | Prometheus monitoring: 12 metrics + 5 alert rules |

## 3. Message Lifecycle

A cross-chain message passes through the following stages from submission to execution:

```
                    SubmitMessage
                         │
                         ▼
                    ┌─────────┐
                    │ PENDING │ ← message submitted, awaiting verification
                    └────┬────┘
                         │ VerifyMessage
                         │   ├─ 1. Nonce check (anti-replay)
                         │   ├─ 2. Expiration check
                         │   ├─ 3. Quantum signature verification (BRDG-01)
                         │   ├─ 4. SPV header verification (reorg detection)
                         │   ├─ 5. Merkle proof verification
                         │   └─ 6. Quorum check (HasQuorumForHash)
                         ▼
                    ┌──────────┐
                    │ VERIFIED │ ← message verified, awaiting execution
                    └────┬─────┘
                         │ ProcessMessage → ExecuteMessage
                         │   ├─ confirmation depth check
                         │   ├─ quorum re-verification
                         │   └─ target-chain execution
                         ▼
              ┌──────────────────┐
              │     EXECUTED     │ ← executed successfully
              └──────────────────┘
                    │    or
              ┌──────────────────┐
              │     FAILED       │ ← execution failed (exceeded MaxRetries)
              └──────────────────┘
                    │    or
              ┌──────────────────┐
              │     EXPIRED      │ ← message expired
              └──────────────────┘
```

### 3.1 Submission Stage (SubmitMessage)

- **Nonce anti-replay**: each source address maintains a set of used nonces (`usedNonces`), TTL 24 hours
- **Rate limiting**: token bucket, 10 msg/s sustained rate, 100 msg burst
- **Trusted public key check** (BRDG-01 FIX): the message's `QuantumPublicKey` must be in the `trustedValidatorKeys` set, otherwise it is rejected
- **Message size limits**: ID ≤ 256 chars, Amount ≤ 128 chars, Data ≤ 1MB
- **Persistence**: written to bbolt via `BoltMessageStore.SaveMessage`

### 3.2 Verification Stage (VerifyMessage)

- **Nonce replay check**: used nonces are restored from persistent storage even after a restart
- **Expiration check**: `Expiration > 0 && now > Expiration` → reject
- **Quantum signature verification**: verifies `QuantumSignature` using Dilithium3
- **SPV header verification** (P1-5): uses `BridgeHeaderVerifier` to check whether the source-chain header was reorganized
- **Merkle proof verification**: verifies that the message is included in the source chain's Merkle tree
- **Quorum check**: `HasQuorumForHash(messageID, messageHash)` — signatures are bound to the message hash (HIGH-08 FIX)

### 3.3 Execution Stage (ProcessMessage → ExecuteMessage)

- **Confirmation depth**: the source-chain block must reach `ConfirmationsRequired` confirmations
- **Quorum re-verification**: the quorum is re-checked before execution (TOCTOU prevention)
- **Target-chain execution**: calls the target-chain contract via the adapter
- **State update**: success → EXECUTED, failure → retry (exponential backoff), exceeding MaxRetries → FAILED
- **Metric update**: `SetLastMessageProcessedAt(now)` updates the processing timestamp

## 4. Arbitration Network Architecture

### 4.1 M-of-N BFT Threshold Signature

```
┌──────────────────────────────────────────────────────────┐
│                  QPOS validator set                       │
│  [V1] [V2] [V3] ... [VN]                                 │
│   │    │    │         │                                   │
│   ▼    ▼    ▼         ▼  RefreshValidatorSet              │
│  ┌─────────────────────────────────────────────────────┐ │
│  │           ValidatorSet.SyncFromQPOS                  │ │
│  │  - new validators: add                               │ │
│  │  - existing validators: update stake/pubkey/active   │ │
│  │  - exited validators: mark Active=false (keep history)│ │
│  │  - threshold = ceil(2/3 × N)                         │ │
│  └──────────────────────┬──────────────────────────────┘ │
│                         │                                 │
│  ┌──────────────────────┴──────────────────────────────┐ │
│  │         SignatureAggregator                          │ │
│  │                                                       │ │
│  │  validator sig → Verify(Dilithium3) → store          │ │
│  │                                                       │ │
│  │  HasQuorumForHash(messageID, messageHash):           │ │
│  │    1. sig count >= threshold?                        │ │
│  │    2. stored hash == caller-provided hash?           │ │
│  │       (subtle.ConstantTimeCompare)                   │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

**Security guarantees:**
- At least 2/3 of validators must sign before a message can be executed
- Signatures are bound to the message hash (not just the messageID), preventing payload substitution
- Signer public keys must come from the QPOS validator set; self-generated keys are not accepted
- Constant-time comparison prevents timing attacks

### 4.2 QPOS Integration Points

| Integration point | Trigger time | Implementation |
|--------|---------|------|
| `RefreshValidatorSet` | QPOS epoch switch / validator changes | `node.go` → `bridge.QuantumBridge.RefreshValidatorSet` |
| `SyncFromQPOS` | called internally by `RefreshValidatorSet` | `ValidatorSet.SyncFromQPOS(validators, threshold)` |
| `SetTrustedValidatorKeys` | called internally by `RefreshValidatorSet` | updates `trustedValidatorKeys` (BRDG-01 anti-forgery) |
| `SetArbitrationQuorum` | `SyncFromQPOS` / `SetThreshold` | updates the Prometheus gauge + threshold |

## 5. SPV Header Verification Architecture

```
┌──────────────────────────────────────────────────────────┐
│              BridgeHeaderVerifier                         │
│  (header_verifier.go)                                     │
│                                                            │
│  ┌──────────────────┐    ┌──────────────────────────┐    │
│  │ HeaderLookup     │    │ SyncCommitteeChecker     │    │
│  │ (interface)      │    │ (interface)              │    │
│  │                  │    │                          │    │
│  │ GetHeader(height)│    │ VerifySyncCommittee(     │    │
│  │ GetLatestHeight()│    │   header, signature)     │    │
│  └────────┬─────────┘    └───────────┬──────────────┘    │
│           │                          │                    │
│           ▼                          ▼                    │
│  ┌──────────────────────────────────────────────────┐    │
│  │ VerifyHeader(header):                             │    │
│  │  1. query source-chain header (HeaderLookup)      │    │
│  │  2. compare block hash (detect reorg)             │    │
│  │  3. verify sync committee signature (SyncCommChk) │    │
│  │  4. return OK / REORG / INVALID                   │    │
│  └──────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────┘
```

**Two-stage verification:**
1. **Stage 1 (SetCommittedRoot)**: the governance address sets the Merkle root through voting
2. **Stage 2 (FetchMerkleRootFromChain)**: reads the root directly from the on-chain contract (`eth_getStorageAt` at slot `keccak256("merkleRoot")`)

## 6. Persistence Architecture

```
┌─────────────────────────────────────────────────┐
│            BoltMessageStore                      │
│  (message_store.go, bbolt)                       │
│                                                   │
│  ┌─────────────────────┐  ┌──────────────────┐  │
│  │ bridge_messages     │  │ bridge_status_   │  │
│  │ (messages bucket)   │  │ index (status idx)│  │
│  │                     │  │                  │  │
│  │ key: messageID      │  │ key: status||ID  │  │
│  │ val: JSON(BridgeMsg)│  │ val: nil         │  │
│  └─────────────────────┘  └──────────────────┘  │
│                                                   │
│  path: <DataDir>/bridge/messages.db              │
│  perms: 0600 (file) / 0700 (dir)                 │
│  concurrency: bbolt file lock + MVCC             │
└─────────────────────────────────────────────────┘
```

**Persisted content:**
- All cross-chain messages (PENDING/VERIFIED/EXECUTED/FAILED/EXPIRED)
- Message state index (for fast per-state queries)
- Recovery after restart: usedNonces + finalizedIDs (anti-replay)

## 7. Monitoring and Alerts

5 Prometheus alert rules (P3-2):

| Alert rule | Level | Trigger condition | Meaning |
|---------|------|---------|------|
| `bridge_message_processing_stopped` | Critical | stalled > 300s | The processing loop may be deadlocked or panicking |
| `bridge_failed_messages_high` | Warning | failed > 100 | Target-chain problem or a persistent bug |
| `bridge_validator_quorum_lost` | Critical | active < threshold | Arbitration cannot be reached; messages cannot be finalized |
| `bridge_l1_anchor_lag_high` | Warning | lag > 20 blocks | Merkle root is stale; reorganization risk increases |
| `bridge_relayer_disconnected` | Critical | disconnected = 1 | Relayer disconnected; cross-chain transfer is impossible |

Metric namespace: `qau_bridge_*`, exposed via the `/metrics/prometheus` endpoint.

## 8. Key File Index

| File | Lines | Core functionality |
|------|------|---------|
| `bridge/bridge.go` | ~2300 | QuantumBridge core + BridgeLogger interface |
| `bridge/validator_network.go` | ~500 | ValidatorSet + SignatureAggregator |
| `bridge/relayer.go` | ~400 | MessageRelayer |
| `bridge/quantaureum_adapter.go` | ~950 | Quantaureum chain adapter |
| `bridge/ethereum_adapter.go` | ~1300 | Ethereum-compatible chain adapter |
| `bridge/message_store.go` | ~300 | bbolt persistence |
| `bridge/header_verifier.go` | ~500 | SPV header verification |
| `bridge/asset_lock.go` | ~600 | Asset lock management |
| `bridge/bridge_metrics.go` | ~430 | Prometheus metrics + BridgeMetricProvider |
| `bridge/bridge_api.go` | ~500 | HTTP API (7 endpoints) |
| `rpc/bridge_api.go` | ~200 | JSON-RPC (3 methods) |
| `node/node.go` (initBridge) | ~100 | Node assembly |