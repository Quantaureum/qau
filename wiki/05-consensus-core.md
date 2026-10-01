# 05 - L5 Consensus + Core Layer — `consensus/` `core/`

> Quantaureum's consensus is **QPOS** (Quantum Proof of Stake): validators stake QAU,
> a slot proposer is selected via VRF (quantum), and blocks are finalized after being
> endorsed by multi-validator threshold signatures (QTD). This section is the core layer
> behind "why Quantaureum is not Ethereum".

## 5.1 `consensus/` — Consensus State Machine

| File | Key Exports | Responsibility |
|------|---------|------|
| [consensus/qpos.go](../consensus/qpos.go) | `QPOS`, `NewQPOS`, `Start/Stop`, `Propose`, `SetValidatorManager`, `mu sync.RWMutex` | QPOS main state machine: slot advancement, proposer rotation, block-trigger conditions |
| [consensus/election.go](../consensus/election.go) | `ElectProposer`, `Election` | Select the slot leader from the validator set using VRF |
| [consensus/vrf.go](../consensus/vrf.go) | `VRFProof`, `VRFOutput` | VRF primitive (keyed randomness) |
| [consensus/pqvrf.go](../consensus/pqvrf.go) | `PQVRFProof`, `PQVRFOutput` | Post-quantum VRF primitives |
| [consensus/random_beacon.go](../consensus/random_beacon.go) | `RandomBeacon`, `BeaconChain` | Multi-party verifiable randomness beacon |
| [consensus/finality.go](../consensus/finality.go) | `FinalityState`, `Finalize` | Finality determination (multisig confirmation) |
| [consensus/threshold_signer.go](../consensus/threshold_signer.go) | `ThresholdKeySigner` interface (`:42`) | **Key interface contract**: QTD threshold-signing abstraction |
| [consensus/validator.go](../consensus/validator.go) | `ValidatorManager`, `GetValidatorSet` | Validator-set management (staking/slashing/rotation) |
| [consensus/slashing.go](../consensus/slashing.go) | `Slash`, `SlashingCondition` | Slashing logic |
| [consensus/security.go](../consensus/security.go) | `SecurityCheck` | Consensus security validation |
| [consensus/voting.go](../consensus/voting.go) | `Vote`, `VoteManager` | Consensus voting |
| [consensus/checkpoint.go](../consensus/checkpoint.go) | `Checkpoint` | Checkpoints (light-node anchors) |
| [consensus/epoch.go](../consensus/epoch.go) | `Epoch`, `EpochManager` | Epoch management |
| [consensus/shard.go](../consensus/shard.go) | `ShardManager`, `Shard` | Sharding (cross-shard messages) |
| [consensus/ministry.go](../consensus/ministry.go), `provinces.go` | `Ministry`, `Provinces` | Governance house model (proposals/voting) |
| [consensus/bls.go](../consensus/bls.go) | `BLS` | BLS aggregate signatures (optional) |
| [consensus/sealed_bid.go](../consensus/sealed_bid.go) | `SealedBid` | Sealed bids (block auctions) |
| [consensus/da_metrics.go](../consensus/da_metrics.go) | DA metrics | Sampling-rate monitoring |

### 5.1.1 `ThresholdKeySigner` Interface (Key Contract)

Defined in [consensus/threshold_signer.go:42](../consensus/threshold_signer.go#L42)

```go
type ThresholdKeySigner interface {
    SignThreshold(message []byte) ([]byte, error)   // triggers threshold signing
    VerifyThreshold(message, sig []byte) bool
    PublicKey() []byte
    // ... depends on the committed version
}
```

**Implementer**: `wallet/tss.TSSManager` (see [09-wallet-tss.md](./09-wallet-tss.md)).
**Injection targets**: `QPOS.tssSigner`, `QTDFinalityState`.

> This is the core decoupling point of the QTD threshold-signing integration path:
> `consensus` depends only on this interface, not on any concrete multisig implementation.

### 5.1.2 QPOS Main Flow (Schematic)

```go
func (q *QPOS) Start(ctx context.Context) { go q.runLoop() }

func (q *QPOS) runLoop() {
    for {
        select{
        case <-ctx.Done(): return
        case <-time.After(q.SlotsUntilNext()):
            q.AdvanceSlot()
            if q.IsProposer() {
                q.Propose()          // triggers core.BlockBuilder.BuildBlock
                q.SignAndBroadcast() // threshold signing via ThresholdKeySigner
            }
        }
    }
}
```

- `Propose(ctx)`: calls `core.BlockBuilder.BuildBlock` to create a candidate block.
- `SignAndBroadcast`: hands the block hash to `tssSigner.SignThreshold`; broadcasts once the threshold is reached.
- `ValidateBlock`: validators validate with `BlockValidator` (including QTD multisig).

## 5.2 `core/` — Block Production and Validation

| File | Key Exports | Responsibility |
|------|---------|------|
| [core/block_builder.go](../core/block_builder.go) | `BlockBuilder`, `NewBlockBuilder(chainID, gasLimit)`, `BuildBlock(parent,txs,proposer,vrfProof,vrfValue)`, `SetDankshardingEngine`, `SetBlockTime` | Deterministically construct blocks from pending txs |
| [core/block_validator.go](../core/block_validator.go) | `BlockValidator`, `NewBlockValidator`, `ValidateBlock(header, body)` | Full block validation (structure, transactions, state root, signatures) |
| [core/danksharding.go](../core/danksharding.go) | `DankshardingEngine` | Consistent with the consensus DA engine; handles blob transactions |

### 5.2.1 BlockBuilder Construction and Dependencies

```go
func NewBlockBuilder(chainID, gasLimit uint64) *BlockBuilder
func (b *BlockBuilder) SetDankshardingEngine(engine *DankshardingEngine)
func (b *BlockBuilder) SetBlockTime(ts uint64)   // deterministic timestamp (consensus-critical)
func (b *BlockBuilder) BuildBlock(
    parent *encoding.BlockHeader,
    txs []*encoding.Transaction,
    proposer types.Address,
    vrfProof []byte,
    vrfValue types.Hash,
) *encoding.Block
```

- **Deterministic timestamp**: `SetBlockTime` injects a unified timestamp so that all nodes
  produce the same block hash ([block_builder.go:52](../core/block_builder.go#L52)). The production
  path must call it; the fallback to `time.Now()` before `SetBlockTime` is intended only for tests
  (see `R49-CS-03`).
- **Danksharding**: once `SetDankshardingEngine` is injected, BuildBlock extracts blob transactions
  and calls `ProcessBlobsForBlock` to store the erasure-coded matrix (`SetDankshardingEngine` @
  [block_builder.go:42](../core/block_builder.go#L42)).

### 5.2.2 ValidatorLookup Interface

`BlockValidator` depends on a "validator lookup" interface (defined in [core/block_validator.go](../core/block_validator.go)):

```go
type ValidatorLookup interface {
    GetValidator(addr types.Address) (*Validator, bool)
    IsValidator(addr types.Address) bool
    ValidatorCount() int
}
```

Implementer: `consensus.ValidatorManager`.
Injection target: `core.BlockValidator`.

## 5.3 Consensus-Core Collaboration Data Flow

```
QPOS (slot N)
   │  IsProposer()
   ▼
core.BlockBuilder.BuildBlock(parent, txs, proposer, vrfProof, vrfValue)
   │  deterministic timestamp (SetBlockTime)
   ▼
candidate block header/body
   │
   ▼ tssSigner.SignThreshold(blockHash)      ← ThresholdKeySigner
   ▼ (threshold reached)
   ▼
broadcast (p2p)→ each node
   │
   ▼ core.BlockValidator.ValidateBlock(header, body)
   │   ├─ ValidatorLookup.GetValidator(proposer)   signature validation
   │   ├─ state root validation (qaudb)
   │   └─ QTD multisig validation
   ▼
finality (multisig confirmation)→ finalize → persist
```

## 5.4 Density Risks and Mitigations

| Risk | Mitigation |
|------|------|
| Timestamp desync causes hash inconsistency | `SetBlockTime` forces a deterministic timestamp |
| Validator-rotation boundary race | `ValidatorManager` guarded by `mu` + atomic epoch-boundary switch |
| Threshold signing does not reach the threshold | Timeout fallback to single-sign + retry; monitor `qau_tss_status` |
| DA blob validation fails | `DankshardingEngine` sampling + `da_metrics` alerting |

## 5.5 Test Discipline

- Any change affecting **block-hash determinism** must run `TestBlockBuilderDeterminism`.
- Any change affecting **the validator set/staking** must run the full `economics/staking_test.go`.
- Any change affecting **the threshold-signing interface** must run the full `wallet/tss/*_test.go`
  (including `TestTSSManagerSignReachesThreshold`).
