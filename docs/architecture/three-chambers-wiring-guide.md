# Three Chambers Finality Wiring Guide

> **Applicable versions**: P0-P4 all complete (2026-07-15)
> **Architecture layers**: L5 consensus layer (core) → L6 integration layer (orchestration) → L7 service layer (exposure)
> **Related modules**: `consensus/` · `node/` · `metrics/` · `rpc/`

---

## 1. Architecture Overview

Three Chambers Finality is Quantaureum's consensus finality architecture, inspired by the separation-of-powers idea of the ancient Chinese "Three Departments and Six Ministries"  political system:

```
┌─────────────────────────────────────────────────────────┐
│              Three Chambers Finality architecture         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────┐  │
│  │  Proposing      │   │  Review      │   │  Executive      │  │
│  │  Proposing  │   │  Review     │   │  Executive  │  │
│  │  Chamber    │   │  Chamber    │   │  Chamber    │  │
│  │             │   │             │   │             │  │
│  │ Propose     │──→│ Review/vote │──→│ QTD signing │  │
│  │ block       │   │ (Attesters) │   │ (Threshold) │  │
│  └─────────────┘   └─────────────┘   └─────────────┘  │
│                         │                   │          │
│                         ▼                   ▼          │
│                   pass/reject review    DKG + seal     │
│                                                │        │
│                                                ▼        │
│                                          block finality │
└─────────────────────────────────────────────────────────┘
```

### The Three Chambers' Responsibilities

| Chamber | English name | Responsibility | Code location |
|----|--------|------|----------|
| Proposing (Proposing Chamber) | Proposing Chamber | Proposes new blocks | `node/block_producer.go` |
| Review (Review Chamber) | Review Chamber | Reviews and attests blocks | `consensus/menxia_review.go` |
| Executive (Executive Chamber) | Executive Chamber | QTD threshold signing, achieving instant finality | `consensus/shangshu_committee.go` |

---

## 2. QTD Integration Path

QTD (Quantum Threshold Signature) is the core cryptographic component of Three Chambers Finality, implementing t-of-n threshold signatures:

```
wallet/tss/qtd (GM-QTD protocol implementation)
  → wallet/tss.TSSManager (DKG orchestration + partial signing + aggregation)
    → crypto.GMQTD_Sign (L1 crypto-layer signing entry point)
      → consensus.ThresholdKeySigner (L5 consensus-layer interface)
        → QPOS.tssSigner (injected at node startup)
          → RPC qau_tss_* (L7 service-layer exposure)
```

### Architecture Constraints

- `crypto` (L1) cannot import `wallet/tss/qtd` (a higher layer); it uses a callback injection pattern: `SetQTDSingleSigner()` registers the implementation at startup
- `TSSManager` is the sole orchestrator for all threshold operations
- Block sealing uses `AggregatePartialSignatures`, not `SignBlock`, to ensure threshold security

### Key Interface

```go
// consensus/threshold_signer.go
type ThresholdKeySigner interface {
    SignBlock(validatorIndex int, message []byte) ([]byte, error)
    SignVote(validatorIndex int, message []byte) ([]byte, error)
    VerifyBlock(pubKey []byte, message []byte, signature []byte) bool
    VerifyVote(pubKey []byte, message []byte, signature []byte) bool
    GroupPublicKey() []byte
    IsThresholdMode() bool
    AggregatePartialSignatures(sealers []int, partialSigs map[int][]byte, message []byte) ([]byte, error)
}
```

---

## 3. Executive Chamber State Machine

```
                 SetMembers()
  ExecutiveIdle ──────────────→ ExecutiveDKGRunning
       ↑                              │
       │ Reset()                      │ SetDKGComplete(groupPk)
       │                              ▼
  ExecutiveSealing ←────────── ExecutiveActive
                 StartSealing()
```

| State | Meaning | Trigger condition |
|------|------|----------|
| `ExecutiveIdle` | Initial state, no members | Node startup / `Reset()` |
| `ExecutiveDKGRunning` | DKG in progress, awaiting group public key | after `SetMembers()` is called |
| `ExecutiveActive` | DKG complete, can perform threshold signing | `SetDKGComplete(groupPk)` |
| `ExecutiveSealing` | Executing block sealing | `StartSealing()` |

### State Transition Code Path

```
TransitionExecutiveForEpoch()     ← epoch boundary trigger
  1. SelectExecutiveForEpoch()    ← stake-weighted random election
  2. SetMembers(members, epoch)   ← state → DKGRunning
  3. SetDKGComplete(groupPk)      ← state → Active (if group public key is available)
     OR
     TriggerDKG(groupPk)          ← delayed activation (waiting for TSSManager to complete)
```

---

## 4. Slot Tick Driven Flow

Each slot's (12 seconds) block lifecycle is driven by `ThreeChambersFlow`:

```
                    Slot Tick (12s)
                         │
                         ▼
              ┌─── CheckTimeout() ──── check timeout (log alert)
              │
              ▼
        ReviewBlock(slot) ────── Review Chamber review & vote
              │
              ▼
         SealBlock(slot) ────── Executive Chamber initiates QTD signing
              │                      │
              │               P2P: BroadcastQTDSealRequest
              │                      │
              │               each Executive member computes a partial signature
              │                      │
              │               P2P: BroadcastQTDPartialSeal
              │                      │
              ▼                      ▼
        CompleteSeal(slot) ← SubmitPartialSeal()
              │
              ▼ (threshold reached)
        FinalizeBlock(slot) ── block finality confirmation
```

### Code Path

| Step | File | Key function |
|------|------|----------|
| Slot Tick entry | `node/block_producer.go` | `threeChambersFlow.ProcessSlot()` |
| Review attestation | `consensus/menxia_review.go` | `ReviewChamber.ProcessReviewAttestation()` |
| Signature request | `node/qtd_seal.go` | `requestQTDSeal()` → `BroadcastQTDSealRequest()` |
| Partial signature handling | `node/qtd_seal.go` | `handleQTDPartialSeal()` → `SubmitPartialSeal()` |
| Signature aggregation | `consensus/qtd_finality.go` | `completeSealLocked()` → `AggregatePartialSignatures()` |
| Finality confirmation | `node/block_producer.go` | `flow.FinalizeBlock(slot)` |

---

## 5. Dependency Injection and Wiring

### 5.1 TSSManager Initialization

```
node.go: startTSSManager()
  ├── load TSSKeyShareFile (encrypted shares)
  ├── load TSSGroupKeyFile (group public key)
  ├── or GenerateKeyShares() (local DKG)
  ├── export encrypted shares to TSSKeyShareFile
  └── set up tssSigner adapter → QPOS.SetThresholdSigner()
```

### 5.2 Three Chambers Initialization

```
block_producer.go: SetQPOS()
  ├── qpos.InitChambers()
  │     ├── NewThreeChambersCoordinator(qpos)
  │     └── NewQTDFinalityState(qpos)
  ├── NewThreeChambersFlow(qpos, coordinator)
  └── set up SlashingManager
```

### 5.3 Epoch Boundary Wiring

```
node.go: block import/production path
  └── coordinator.TransitionExecutiveForEpoch(epoch, validators, randaoMix, groupPk)
        ├── SelectExecutiveForEpoch()  ← stake-weighted random election (without replacement)
        ├── SetMembers()               ← state → DKGRunning
        └── SetDKGComplete(groupPk)    ← state → Active (if group public key is available)
```

### 5.4 P2P Wiring

```
node.go: wireTSSDistributed()
  ├── broadcastKyberPublicKey()  ← broadcast Kyber public key for encrypted communication
  └── register P2P message handlers:
        ├── MsgTypeQTDSealRequest  → handleQTDSealRequest()
        ├── MsgTypeQTDPartialSeal  → handleQTDPartialSeal()
        └── TSS session messages    → handleTSSMessage()
```

### 5.5 Monitoring Wiring (P3-3)

```
node.go: startServices()
  └── coordinator := qpos.GetChambersCoordinator()
        └── metrics.Global().SetThreeChambersMetricProvider(coordinator)
              └── AlertManager can evaluate:
                    ├── three_chambers_evidence_queue_backlog (Warning, >100)
                    └── three_chambers_dkg_stuck (Critical, >1800s)
```

### 5.6 RPC Wiring

| RPC method | Information exposed | Implementation location |
|----------|-----------|----------|
| `qau_tss_status` | Overall TSS status | `rpc/tss_api.go` |
| `qau_tss_getPublicKey` | Group public key | `rpc/tss_api.go` |
| `qau_tss_requestSeal` | Requests a QTD signature (P1-7) | `rpc/tss_api.go` |
| `qau_tss_submitPartialSeal` | Submits a partial signature (P1-7) | `rpc/tss_api.go` |
| `qau_tss_getSealStatus` | Queries signature status (P1-7) | `rpc/tss_api.go` |
| `qau_stardust_getDKGStatus` | DKG progress (P1-9) | `rpc/stardust_api.go` |
| `qau_qposStatus` | QPOS + Three Chambers Finality status | `rpc/consensus_api.go` |

---

## 6. Cryptographic Contracts

### Dilithium3 Size Constants

| Key type | Size (bytes) |
|----------|-------------|
| Public key | 1952 |
| Private key | 4000 |
| Signature | 3293 |

### Kyber768 Size Constants

| Key type | Size (bytes) |
|----------|-------------|
| Public key | 1184 |
| Private key | 2400 |

### Security Constraints

- **WASM same source**: the wallet's `dilithium3-circl.wasm` and the node's `crypto/dilithium.go` must use the same circl version
- **Changing any cryptographic constant will make the wallet and node incompatible; both sides must be changed in sync**
- Key share files must be encrypted at rest with AES-256-GCM (audit P1-R2-04)

---

## 7. Configuration Parameters

### config.json Key Fields

| Field | Type | Default | Description |
|------|------|--------|------|
| `tssKeyShareFile` | string | `""` | Encrypted key share file path |
| `tssGroupKeyFile` | string | `""` | Group public key file path |
| `tssDistributedMode` | bool | `false` | Enables distributed TSS signing (P2P multi-party collaboration) |

### Environment Variables

| Variable | Description |
|------|------|
| `QAU_TSS_PASSWORD` | TSS key share encryption/decryption password |
| `QAU_VALIDATOR_KEY_PASSWORD` | validator.key encryption password |

---

## 8. Alert Rules (P3-3)

| Alert name | Level | Threshold | MetricFn | Description |
|----------|------|------|----------|------|
| `three_chambers_evidence_queue_backlog` | Warning | > 100 | `EvidenceQueueLengthValue()` | Evidence queue backlog; SlashingManager may be slow |
| `three_chambers_dkg_stuck` | Critical | > 1800s | `DKGElapsedSecondsValue()` | DKG stuck for more than 30 minutes; finality risk |

### Cold-Start Safety

Both alert rules are designed to be cold-start safe:
- When the provider is nil (Three Chambers Finality not enabled), MetricFn returns 0 and no alert fires
- When DKG is not in a running state (Idle/Active/Sealing), `DKGElapsedSecondsValue()` returns 0
- When the evidence queue is empty, `EvidenceQueueLengthValue()` returns 0

---

## 9. Code File Index

### consensus/ (L5 consensus layer)

| File | Responsibility |
|------|------|
| `threshold_signer.go` | `ThresholdKeySigner` interface definition + integration path comments |
| `provinces.go` | `ThreeChambersCoordinator` orchestrator + permission separation + DKG/health monitoring |
| `shangshu_committee.go` | `ExecutiveChamber` struct + state machine |
| `menxia_review.go` | `ReviewChamber` review attestation collection |
| `qtd_finality.go` | `QTDFinalityState` QTD finality state + partial signature aggregation |
| `block.go` | `QPOS` struct + `InitChambers()` + `GetGroupPublicKey()` |
| `qpos_slashing.go` | Evidence queue management + `GetEvidenceQueueLength()` |

### node/ (L6 integration layer)

| File | Responsibility |
|------|------|
| `block_producer.go` | `BlockProducer` + slot tick + `ThreeChambersFlow` driving |
| `qtd_seal.go` | P2P QTD signature message handling (request/partial signature) |
| `tss_distributed.go` | Distributed TSS signing (multi-round protocol) |
| `node.go` | Node orchestration + TSSManager initialization + dependency injection |
| `config.go` | TSS configuration field definitions |

### metrics/ (L7 service layer)

| File | Responsibility |
|------|------|
| `metrics.go` | `ThreeChambersMetricProvider` interface + alert rules + setter/getter |
| `three_chambers_alerts_test.go` | Alert rule tests (5 test cases) |

### rpc/ (L7 service layer)

| File | Responsibility |
|------|------|
| `tss_api.go` | `qau_tss_*` RPC endpoints |
| `stardust_api.go` | `qau_stardust_getDKGStatus` RPC endpoint |

---

## 10. Test Coverage

| Test file | Coverage |
|----------|----------|
| `consensus/provinces_dkg_test.go` | DKG timeout detection + DKG status queries |
| `consensus/provinces_test.go` | Three-chamber permission separation + member election |
| `metrics/three_chambers_alerts_test.go` | Alert rule triggering/suppression (P3-3) |
| `consensus/consensus_final_coverage_test.go` | End-to-end finality flow |

---

## 11. Related Documents

- QTD key-share operations and DKG-recovery-after-chain-reset runbooks are maintained in the operator's internal documentation (not part of the public repo).
- The "QTD threshold signature integration path" section in the project rules
- The "cryptographic contracts" section in the project rules