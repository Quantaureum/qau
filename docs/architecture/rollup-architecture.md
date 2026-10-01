# Rollup Subsystem Architecture

> W-P4-1 · 2026-07-15 · Quantaureum L2 Rollup

## 1. Overview

Quantaureum Rollup is a Layer-2 scaling solution built on the L1 public chain. It achieves high throughput and low latency by batch-processing L2 transactions and periodically anchoring them to the L1. The system is enabled via the `QAU_ENABLE_ROLLUP=1` environment variable.

**Core metrics:**
- L2 ChainID: 1670 (distinct from L1 1668/1669/1333, to prevent cross-chain replay)
- Default block time: 2 seconds
- Batch challenge period: 7 days (or 100 L1 blocks)
- Maximum batch size: 500 transactions / 128 KB

## 2. L2 Engine Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    RollupEngine (rollup.go)                  │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │  Sequencer   │  │ BatchManager │  │   StateManager      │ │
│  │ (sequencer   │  │ (batch.go)   │  │ (state_manager.go)  │ │
│  │    .go)      │  │              │  │                     │ │
│  │              │  │ BuildBatch   │  │ ProcessBatch        │ │
│  │ AcceptTx     │  │ SubmitBatch  │  │ computeStateRoot    │ │
│  │ IsCurrent    │  │ FinalizeBatch│  │ archiveStateSnapshot│ │
│  │  Sequencer   │  │ ChallengeBatch│  │ SimulateBatch       │ │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬──────────┘ │
│         │                 │                     │            │
│  ┌──────┴───────┐  ┌─────┴──────┐  ┌───────────┴──────────┐ │
│  │ Sequencer    │  │ FraudProver│  │   L1Anchor            │ │
│  │ Elector      │  │ (fraud_    │  │ (l1_anchor.go)        │ │
│  │ (sequencer_  │  │  proof.go) │  │                       │ │
│  │  elector.go) │  │            │  │ AnchorBatch           │ │
│  │              │  │ SubmitProof│  │ GetAnchor             │ │
│  │ QPOS integration │  │ VerifyProof│  GetCurrentHeight      │  │
│  └──────────────┘  └────────────┘  └───────────────────────┘ │
│         │                                          │          │
│  ┌──────┴──────────────────────────────────────────┴───────┐ │
│  │              L1↔L2 Bridge (bridge.go)                    │ │
│  │  L1Bridge (deposit/release)  ←→  L2Bridge (mint/withdraw)│ │
│  └──────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | File | Responsibility |
|------|------|------|
| RollupEngine | `rollup.go` | Engine orchestration: batchLoop + finalizeLoop, injection management |
| Sequencer | `sequencer.go` | Transaction validation + signature check + sequencer election check |
| BatchManager | `batch.go` | Batch build/submit/challenge/finalize, pending transaction queue |
| StateManager | `state_manager.go` | L2 state execution (QVM), state root computation, historical snapshots |
| FraudProver | `fraud_proof.go` | Fraud proof submit/verify, challenger signature verification |
| L1Anchor | `l1_anchor.go` | Anchors batches to L1 (batchHash → postRoot, submitHeight) |
| SequencerElector | `sequencer_elector.go` | Decentralized sequencer election (QPOS integration) |
| L1Bridge/L2Bridge | `bridge.go` | Cross-layer asset bridging (deposit/withdrawal) |
| Persistence | `persistence.go` | L2 state persistence (bbolt) |
| Metrics | `metrics.go` | Prometheus monitoring metrics (12) |

## 3. Batch Lifecycle

```
    ┌─────────┐    BuildBatch     ┌──────────┐   SubmitBatch    ┌───────────┐
    │ Pending  │ ──────────────→  │ Pending  │ ──────────────→  │ Submitted │
    │ (txQueue)│                  │ (built)  │                  │           │
    └─────────┘                  └──────────┘                  └─────┬─────┘
                                                                       │
                    ┌──────────────────────────────────────────────────┤
                    │                                                  │
              ChallengeBatch                                    FinalizeBatch
                    │                                                  │
                    ▼                                                  ▼
             ┌───────────┐                                    ┌───────────┐
             │ Challenged│                                    │ Finalized │
             └─────┬─────┘                                    └───────────┘
                   │
              (verification passed?)
              ┌────┴────┐
              ▼         ▼
        ┌──────────┐ ┌──────────┐
        │ Rejected │ │ Finalized│
        └──────────┘ └──────────┘
```

### State Descriptions

| State | Value | Description |
|------|---|------|
| Pending | 0 | Batch has been built; awaiting state root computation and submission |
| Submitted | 1 | Submitted (postStateRoot written); awaiting the end of the challenge period |
| Finalized | 2 | Challenge period ended; irreversible |
| Challenged | 3 | Fraud proof received; awaiting arbitration |
| Rejected | 4 | Fraud proof verified; the batch is rejected |

### Detailed Flow

1. **Build**: the Sequencer takes transactions from the pending queue and builds a batch (PrevStateRoot = the previous batch's PostStateRoot)
2. **ProcessBatch**: StateManager executes the L2 transactions one by one, computing PostStateRoot and GasUsed
3. **SubmitBatch**: writes PostStateRoot and generates SubmitTxHash (deterministic hash)
4. **AnchorBatch**: anchors to L1 (records batchHash → postRoot, txDataHash, submitHeight)
5. **ChallengePeriod**: waits out the challenge period (7 days or 100 L1 blocks)
6. **FinalizeBatch**: challenge period ends, the batch is finalized → triggers withdrawal processing
7. **ChallengeBatch**: a challenger submits a fraud proof → if verification passes, the batch is rejected

## 4. State Root Computation Flow

```
ProcessBatch(batchIndex, prevStateRoot, txs)
    │
    ├─ 1. verify prevStateRoot == current stateRoot (tamper-proof)
    │
    ├─ 2. archive pre-state snapshot (stateHistory[prevStateRoot])
    │     └─ FIFO eviction (maxStateHistoryEntries = 1000)
    │
    ├─ 3. processBatchLocked: execute transactions one by one
    │     ├─ balance check (totalCost = Value + GasPrice*GasLimit)
    │     ├─ Nonce increment
    │     ├─ QVM contract call (if tx.Data present)
    │     └─ SparseMerkleTree update
    │
    ├─ 4. computeStateRoot: compute state root from SparseMerkleTree
    │
    ├─ 5. stateRoots[batchIndex] = newRoot (stored by batch index)
    │
    └─ 6. archiveStateSnapshot(newRoot): archive post-state snapshot
          └─ used for the next batch's fraud proof verification
```

**Historical snapshot mechanism:**
- `stateHistory[stateRoot] → map[Address]*RollupAccount`
- `stateHistoryOrder[]` tracks insertion order, FIFO eviction
- Maximum 1000 entries (covering challenge_period / batch_interval)

## 5. Fraud Proof Flow

```
Challenger node                          RollupEngine
    │                                    │
    │  1. observes an incorrect PostStateRoot for the batch
    │     (re-execution yields a different root)
    │                                    │
    │  2. constructs a FraudProof        │
    │     ├─ Type (StateTransition/      │
    │     │   InvalidBatch/DoubleSpend)  │
    │     ├─ BatchIndex                  │
    │     ├─ PreStateRoot                │
    │     ├─ PostStateRoot (correct)     │
    │     ├─ InvalidTx (problem tx)      │
    │     ├─ ChallengerSig (signature)   │
    │     └─ ChallengerPubKey            │
    │                                    │
    │  3. SubmitFraudProof ─────────────→│
    │                                    │
    │                            4. verify challenger signature
    │                               (pubKey → address, sig verify)
    │                                    │
    │                            5. SimulateBatch: use PreStateRoot
    │                               to restore state from history, re-execute
    │                                    │
    │                            6. compare results:
    │                               ├─ match → reject fraud proof
    │                               └─ mismatch → accept, mark Challenged
    │                                    │
    │  7. BatchManager.ChallengeBatch ←──│
    │     (batch state → Challenged/Rejected)│
```

## 6. L1 Anchoring Mechanism

### Current Implementation: MemoryL1Anchor
- Maintains an in-memory `batchHash → AnchorRecord` mapping
- Used for development and testing
- The challenge period uses the L1 block height (submitHeight + challengeBlocks)

### Production Replacement: QASM Contract
```go
// L1Anchor interface (rollup/l1_anchor.go)
type L1Anchor interface {
    AnchorBatch(batchHash, postStateRoot, txData) (submitHeight, err)
    GetAnchor(batchHash) (*AnchorRecord, bool)
    GetCurrentHeight() uint64
}
```

**AnchorRecord structure:**
| Field | Description |
|------|------|
| BatchHash | Batch hash |
| PostStateRoot | Post-batch state root |
| TxDataHash | Transaction data hash (sha256), used for integrity verification |
| SubmitHeight | L1 submission height |
| ChallengeBlocks | Number of challenge period blocks (default 100) |

**Challenge deadline height:** `submitHeight + challengeBlocks`

## 7. Verifier Injection Mechanism

Production deployments must inject the signature verifier in `node.go initRollup()`:

```
txpool.SigningVerifier
    │
    ├─→ rollupTxSigVerifier (node/rollup_adapters.go)
    │    implements rollup.TxSignatureVerifier
    │   ├─ pubKey → address derivation verification
    │   └─ Dilithium3 signature verification
    │   injection: engine.SetTxSignatureVerifier()
    │
    └─→ rollupFraudProofSigVerifier (node/rollup_adapters.go)
         implements rollup.SignatureVerifier
        ├─ pubKey → address derivation verification
        └─ Dilithium3 signature verification
        injection: engine.SetFraudProofVerifier()
```

**Fail-closed strategy:**
- `requireTxSig = true` (default): rejects all L2 transactions when no verifier is injected
- `requireSigVerifier = true` (default): rejects all fraud proofs when no verifier is injected
- Tests may bypass via `SetRequireTxSig(false)` / `SetRequireSignatureVerifier(false)`

## 8. Decentralized Sequencer Architecture (W-P1-7)

### Design: PoS Sequencer Election (Option B)

Reuses the QPOS consensus validator rotation mechanism to implement a decentralized sequencer:

```
┌──────────────────────────────────────────────────────────┐
│                    QPOS consensus layer                    │
│  ┌──────────────────┐  ┌───────────────────────────┐     │
│  │ ValidatorSet      │  │ GetCurrentEpoch()         │     │
│  │ (validator set)   │  │ GetValidatorSet()         │     │
│  └────────┬─────────┘  └───────────┬───────────────┘     │
│           │                        │                      │
└───────────┼────────────────────────┼──────────────────────┘
            │                        │
    ┌───────┴────────────────────────┴───────┐
    │  qposSequencerAdapter (node/rollup_    │
    │  adapters.go)                          │
    │  implements rollup.ValidatorSetProvider│
    └───────────────────┬────────────────────┘
                        │
    ┌───────────────────┴────────────────────┐
    │  QPOSSequencerElector                  │
    │  (rollup/sequencer_elector.go)         │
    │                                        │
    │  GetCurrentSequencer(epoch)            │
    │    = validators[epoch % len(valids)]   │
    │  GetNextSequencer(epoch)               │
    │    = validators[(epoch+1) % len]       │
    │  IsCurrentSequencer(addr, epoch)       │
    └───────────────────┬────────────────────┘
                        │
    ┌───────────────────┴────────────────────┐
    │  RollupEngine.shouldBuildBatch()       │
    │                                        │
    │  1. no elector → always build (legacy) │
    │  2. local == current sequencer → build │
    │  3. current sequencer timeout → next   │
    │     sequencer takes over               │
    │     (missedBatchCount >= SequencerTimeout) │
    └────────────────────────────────────────┘
```

### Election Rules

- **Current epoch sequencer** = `validators[epoch % len(validators)]`
- **Next epoch sequencer** = `validators[(epoch+1) % len(validators)]`
- Sequencer rotation is synchronized with QPOS epoch boundaries

### Failure Recovery

| Phase | Behavior |
|------|------|
| Normal | The current sequencer builds batches; missedBatchCount = 0 |
| Timeout detection | Non-sequencer nodes increment missedBatchCount every tick |
| Failure takeover | missedBatchCount >= SequencerTimeout → the next sequencer begins building |
| Recovery | missedBatchCount is reset to 0 when the sequencer changes |

**Configuration:**
- `SequencerTimeout` (default 3): triggers takeover after this many consecutive missed batch periods
- Setting it to 0 disables failure takeover (the current sequencer must produce, otherwise the chain stalls)

### Backward Compatibility

- No elector configured (`SetSequencerElector(nil)`) → legacy single-sequencer mode
- `localAddress` is zero → legacy mode (always builds batches)
- Existing tests do not set an elector, so behavior is unchanged

## 9. L1↔L2 Bridge Architecture

### Deposit Flow (L1 → L2)

```
User                L1Bridge              L2Bridge            StateManager
 │                     │                     │                     │
 │  1. Deposit(QAU)    │                     │                     │
 │ ──────────────────→ │                     │                     │
 │                     │ lock QAU            │                     │
 │                     │ record Deposit      │                     │
 │                     │ (hash, depositor,   │                     │
 │                     │  amount, minted=F)  │                     │
 │                     │                     │                     │
 │  2. observe L1 deposit│                  │                     │
 │ ──────────────────────────────────────→  │                     │
 │                     │                     │ check minted==false │
 │                     │                     │ mint L2 balance     │
 │                     │                     │ ──────────────────→ │
 │                     │                     │                     │ accountStates
 │                     │                     │                     │ [depositor]
 │                     │                     │                     │ .Balance += amount
 │                     │                     │ minted = true       │
 │                     │                     │                     │
 │  3. L2 balance available│                │                     │
 │ ←─────────────────────────────────────────│                     │
```

### Withdrawal Flow (L2 → L1)

```
User                L2Bridge              L1Bridge             L1Chain
 │                     │                     │                     │
 │  1. L2 transfer to  │                     │                     │
 │     bridge address  │                     │                     │
 │ ──────────────────→ │                     │                     │
 │                     │ burn L2 balance     │                     │
 │                     │ record Withdrawal   │                     │
 │                     │ (hash, withdrawer,  │                     │
 │                     │  amount, batchIdx)  │                     │
 │                     │                     │                     │
 │  2. batch finalization│                  │                     │
 │     (finalizeLoop)  │                     │                     │
 │                     │ ProcessFinalizedBatch                    │
 │                     │ ├─ generate Merkle proof │               │
 │                     │ │  (SparseMerkleTree)│                     │
 │                     │ ├─ submit to L1Bridge │                 │
 │                     │ ──────────────────→ │                     │
 │                     │                     │ verify Merkle proof │
 │                     │                     │ release locked QAU  │
 │                     │                     │ ──────────────────→ │
 │                     │                     │                     │ transfer to user
 │                     │ processed = true    │                     │
 │                     │                     │                     │
 │  3. L1 QAU credited │                     │                     │
 │ ←─────────────────────────────────────────────────────────────│
```

### Bridge Components

| Component | Interface | Implementation |
|------|------|------|
| L1Bridge | `rollup.L1Bridge` | MemoryL1Bridge / BboltL1Bridge |
| L2Bridge | `*rollup.L2Bridge` | Implements the WithdrawalProcessor interface |
| Bridge address | `config.L1BridgeAddress` | L2 withdrawal target address |

**Idempotency guarantees:**
- Deposit.Minted prevents duplicate minting
- Withdrawal.Processed prevents duplicate release
- ProcessFinalizedBatch can be safely called multiple times

## 10. Persistence Architecture

```
<DataDir>/rollup/l2.db (bbolt)
    │
    ├─ "s:latest"           → latest state snapshot (all accounts + stateRoots)
    ├─ "b:<batchIndex>"     → Batch JSON (with transactions)
    ├─ "b:meta:nextIndex"   → next batch index
    ├─ "b:meta:lastRoot"    → last state root
    ├─ "f:<batchIndex>"     → FraudProof JSON
    └─ "a:all"              → all AnchorRecords (hex key encoded)
```

**Crash recovery flow:**
1. `RestoreState()`: load snapshot → restore account state + stateRoots
2. `RestoreBatches()`: load all batches → restore the BatchManager
3. `RestoreMeta()`: restore nextIndex + lastStateRoot
4. `LoadAllFraudProofs()`: restore fraud proofs
5. `LoadAnchors()`: restore L1 anchor records

## 11. Monitoring Metrics

| Metric | Type | Description |
|------|------|------|
| `qau_rollup_status` | Gauge | Engine status (0=stopped, 1=running) |
| `qau_rollup_batches_total` | Counter | Total number of successfully submitted batches |
| `qau_rollup_transactions_total` | Counter | Total number of processed L2 transactions |
| `qau_rollup_pending_transactions` | Gauge | Number of pending transactions |
| `qau_rollup_batch_build_duration_seconds` | Histogram | Batch build duration |
| `qau_rollup_batch_submit_duration_seconds` | Histogram | Batch submit duration |
| `qau_rollup_batch_process_duration_seconds` | Histogram | Batch process duration |
| `qau_rollup_fraud_proofs_submitted_total` | Counter | Number of submitted fraud proofs |
| `qau_rollup_fraud_proofs_verified_total` | Counter | Number of verified fraud proofs |
| `qau_rollup_l1_anchor_lag` | Gauge | L1 anchor lag (in blocks) |
| `qau_rollup_consecutive_batch_failures` | Gauge | Consecutive batch failures (>5 alerts) |
| `qau_rollup_batch_loop_panics_total` | Counter | batchLoop panic count (>0 critical) |

## 12. Dependency Injection Overview

```
node.go initRollup()
    │
    ├─ engine.SetExecutor(qvm.NewExecutor())           // QVM executor
    ├─ engine.SetTxSignatureVerifier(txVerifier)        // L2 tx signature verification
    ├─ engine.SetFraudProofVerifier(fpVerifier)         // fraud proof signature verification
    ├─ engine.SetPersistence(persistence)               // bbolt persistence
    ├─ engine.SetL1Anchor(l1Anchor)                     // L1 anchoring
    ├─ engine.SetWithdrawalProcessor(l2Bridge)          // L2 withdrawal processing
    ├─ engine.SetMetrics(rollupMetrics)                 // Prometheus metrics
    ├─ engine.SetSequencerElector(elector)              // decentralized sequencer election (W-P1-7)
    ├─ engine.SetLocalAddress(validatorAddr)            // local validator address (W-P1-7)
    └─ engine.Start()
```