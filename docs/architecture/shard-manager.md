# ShardManager Subsystem Architecture

> P4-1 · 2026-07-15 · Quantaureum Sharding Subsystem

## 1. Overview

Quantaureum ShardManager is the sharding scaling layer of the L1 public chain. It improves overall throughput by dividing the validator set into multiple shards that process transactions in parallel. The system is enabled via the `QAU_ENABLE_SHARDING=1` environment variable and is disabled by default.

**Core metrics:**
- Maximum shard count: 64 (`ShardMaxCount`)
- Minimum validators per shard: 3 (`ShardMinValidators`)
- Shard block interval: 12 seconds (`ShardBlockInterval`, consistent with the main chain)
- Finality quorum: 2/3 supermajority (rounded up)
- Maximum cross-shard message payload: 64 KB (`ShardCrossMsgMaxSize`)

**Design goals:**
- Horizontal scaling: N shards provide theoretical throughput close to N×
- Cross-shard security: cross-shard messages require signature verification + receipt anti-replay
- Main-chain anchoring: shard blocks are anchored to the main chain via commitments, supporting fraud proofs
- Fault isolation: a single shard failure does not affect other shards or the main chain

## 2. Position in the Seven-Layer Architecture

ShardManager spans the L5 consensus layer and the L6 integration layer, following the project's seven-layer architecture discipline (upper layers depend on lower layers; reverse dependencies are forbidden):

```
┌─────────────────────────────────────────────────────────────────┐
│ L7 Service Layer  rpc/shard_api.go                              │
│            qau_shardGetShardCount / GetShard / GetBlock / ...   │
│            (8 RPC methods, 7 read-only + 1 admin-gated)         │
├─────────────────────────────────────────────────────────────────┤
│ L6 Integration   node/node.go (initSharding)                    │
│            node/shard_producer.go (ShardBlockProducer)          │
│            Orchestration: create DB → create Manager →          │
│            inject deps → start producer                         │
├─────────────────────────────────────────────────────────────────┤
│ L5 Consensus     consensus/shard.go (ShardManager + ShardChain) │
│            consensus/shard_committer.go (MainChainCommitter)    │
│            consensus/shard_store.go (ShardStateStore)           │
│            consensus/shard_metrics.go (ShardMetrics)            │
│            consensus/shard_health.go (ShardHealthChecker)       │
│            QPOS election verification + 2/3 quorum + cross-shard│
├─────────────────────────────────────────────────────────────────┤
│ L3 Network       p2p/host.go (BroadcastShardBlock / *)          │
│            P2P broadcast & subscription of shard blocks /       │
│            votes / cross-shard messages                         │
├─────────────────────────────────────────────────────────────────┤
│ L2 Storage       qaudb (bbolt) — <DataDir>/shard/state.db       │
│            shard DB is independent of the L1 chain DB           │
├─────────────────────────────────────────────────────────────────┤
│ L1 Crypto        crypto/ (Dilithium3)                           │
│            block sig verification + vote sig verification +     │
│            cross-shard msg sig verification                     │
└─────────────────────────────────────────────────────────────────┘
```

### Module Responsibilities

| Module | File | Layer | Responsibility |
|------|------|-----|------|
| ShardManager | `consensus/shard.go` | L5 | Shard lifecycle management + validator assignment + cross-shard message routing |
| ShardChain | `consensus/shard.go` | L5 | Single-shard chain: block production/receiving/finalization/commitment/receipt |
| ShardBlockProducer | `node/shard_producer.go` | L6 | 4-goroutine block production loop + P2P message handling |
| MainChainCommitter | `consensus/shard_committer.go` | L5 | Submits shard commitments to the main chain |
| ShardStateStore | `consensus/shard_store.go` | L5 | Persistence: blocks/receipts/nonces/assignment tables |
| ShardQPOSAdapter | `consensus/shard.go` | L5 | Election verifier: delegates to QPOS to verify the legitimacy of proposer election |
| ShardMetrics | `consensus/shard_metrics.go` | L5 | 8 Prometheus monitoring metrics |
| ShardHealthChecker | `consensus/shard_health.go` | L5 | Structured health check reports |
| ShardAPI | `rpc/shard_api.go` | L7 | 8 JSON-RPC methods |

## 3. Core Component Interaction Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│                         node/node.go (initSharding)                  │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────────────┐ │
│  │ ShardDB     │  │ ShardState   │  │ ShardQPOSAdapter            │ │
│  │ (bbolt)     │  │ Store        │  │ (ElectionVerifier)          │ │
│  └──────┬──────┘  └──────┬───────┘  └──────────────┬──────────────┘ │
│         │                │                          │                │
│  ┌──────┴──────────────────────────────────────────┴──────────────┐ │
│  │                    ShardManager                                  │ │
│  │  shards map[uint64]*ShardChain  assignments map[uint64]*Assignment│
│  │  CreateShard / ActivateShard / DeactivateShard / ReactivateShard │ │
│  │  ReassignValidators (auth-gated) / AssignValidatorsToShards      │ │
│  │  RelayCrossShardMessage / CommitShardBlock                       │ │
│  └──────┬──────────────────────────────────────────┬───────────────┘ │
│         │                                           │                │
│  ┌──────┴───────────────┐          ┌────────────────┴──────────────┐ │
│  │    ShardChain (×N)    │          │    MainChainCommitter         │ │
│  │  ┌────────────────┐  │          │  SubmitShardCommitment        │ │
│  │  │ ProposeBlock   │  │          │  VerifyShardCommitment        │ │
│  │  │ ReceiveBlock   │  │          │  GetLatestSlot                │ │
│  │  │ FinalizeBlock  │  │          └───────────────────────────────┘ │
│  │  │ CommitBlock    │  │                                           │
│  │  │ SubmitCrossMsg │  │          ┌───────────────────────────────┐ │
│  │  │ RelayReceipt   │  │          │    ShardMetrics (P3-1)        │ │
│  │  │ SpendReceipt   │  │          │  8 Prometheus metrics         │ │
│  │  └────────────────┘  │          └───────────────────────────────┘ │
│  └──────────────────────┘                                            │
│         │                                                            │
│  ┌──────┴────────────────────────────────────────────────────────┐  │
│  │              ShardBlockProducer (4 goroutines)                 │  │
│  │  ┌──────────────┐ ┌──────────────┐ ┌────────────┐ ┌─────────┐ │  │
│  │  │produceLoop   │ │incomingBlock │ │attestation │ │crossMsg │ │  │
│  │  │(per-slot     │ │Loop(receive+ │ │Loop(accum- │ │Loop(cross│ │  │
│  │  │ block)       │ │ vote)        │ │ late votes │ │-shard   │ │  │
│  │  │              │ │              │ │ →Finalize) │ │ relay)  │ │  │
│  │  └──────────────┘ └──────────────┘ └────────────┘ └─────────┘ │  │
│  └────────────────────────────────────────────────────────────────┘  │
│         │                                                            │
│  ┌──────┴────────────────────────────────────────────────────────┐  │
│  │              p2p/host.go (P2P broadcast & subscription)       │  │
│  │  BroadcastShardBlock / SubscribeShardBlocks                    │  │
│  │  BroadcastShardAttestation / SubscribeShardAttestations        │  │
│  │  BroadcastCrossShardMessage / SubscribeCrossShardMessages      │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
         │
┌────────┴────────────────────────────────────────────────────────────┐
│                    rpc/shard_api.go (L7 Service Layer)             │
│  qau_shardGetShardCount / GetActiveShardCount / GetShard / GetBlock │
│  / GetCommitment / SubmitCrossShardMessage / GetReceipt /           │
│  IsReceiptSpent                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## 4. Shard Lifecycle and State Machine

```
                  CreateShard(validators)
                          │
                          ▼
                   ┌──────────────┐
                   │ Initializing │ ← initial state of a new shard
                   └──────┬───────┘
                          │ ActivateShard
                          │ (precondition: validator public keys
                          │  registered + election verifier configured)
                          ▼
                   ┌──────────────┐
        ┌─────────│   Active     │─────────┐
        │         └──────────────┘         │
        │ DeactivateShard            ReactivateShard
        │ (Warn log)                (Info log)
        ▼                                ▲
   ┌──────────────┐                      │
   │   Inactive   │──────────────────────┘
   └──────────────┘
```

**State descriptions:**
- `Initializing`: newly created but not activated; does not produce blocks or process cross-shard messages
- `Active`: normal block production, receives cross-shard messages, submits commitments
- `Inactive`: deactivated, does not produce blocks; `ReactivateShard` can restore it

## 5. Block Production Flow (Sequence Diagram)

```
 Validator A (elected proposer)    Validator B/C (voters)         ShardChain
      │                                │                            │
      │  QPOS.GetProposerForSlot       │                            │
      │────────────────────────────────│                            │
      │  elected → sign block          │                            │
      │                                │                            │
      │  ProposeBlock(proposer, sig)   │                            │
      │──────────────────────────────────────────────────────────→  │
      │                                │  verify:                    │
      │                                │  1. shard Active           │
      │                                │  2. proposer is a validator│
      │                                │  3. public key registered  │
      │                                │  4. ElectionVerifier verify│
      │                                │  5. signature verify (Dil  │
      │                                │  6. store block + persist  │
      │  ←────────────────────────────────────────────────────────  │
      │  block                         │                            │
      │                                │                            │
      │  P2P.BroadcastShardBlock       │                            │
      │───────────────────────────────→│                            │
      │                                │  ReceiveBlock(block)       │
      │                                │──────────────────────────→│
      │                                │  verify:                   │
      │                                │  1. height = latest+1      │
      │                                │  2. parentHash matches     │
      │                                │  3. election + sig verify │
      │                                │  4. store + persist       │
      │                                │  ←────────────────────────│
      │                                │                            │
      │                                │  sign vote (attestation)   │
      │                                │  P2P.BroadcastAttestation  │
      │  ←────────────────────────────│                            │
      │  attestation                  │                            │
      │                                │                            │
      │  accumulate attestations       │                            │
      │  reach 2/3 quorum              │                            │
      │  FinalizeBlock(height, atts)  │                            │
      │──────────────────────────────────────────────────────────→  │
      │                                │  verify vote sigs + count  │
      │                                │  ≥ ceil(N*2/3) → Finalized │
      │                                │  Info log: "block finalized"│
      │                                │                            │
```

## 6. Cross-Shard Message Flow

```
  Shard A (source)                 ShardManager                Shard B (target)
     │                               │                              │
     │  SubmitCrossShardMessage      │                              │
     │  (signature + nonce monotonicity verify)                     │
     │  → add to pendingMsgs queue   │                              │
     │  → IncCrossShardMessages      │                              │
     │  → SetPendingMessages         │                              │
     │                               │                              │
     │  P2P.BroadcastCrossShardMsg   │                              │
     │──────────────────────────────→│                              │
     │                               │  RelayCrossShardMessage      │
     │                               │  (verify signature + canonical ID)│
     │                               │─────────────────────────────→│
     │                               │  CreateReceipt               │
     │                               │  RelayReceipt (slot)         │
     │                               │  ←──────────────────────────│
     │                               │  receipt (relayed=true)      │
     │  ←───────────────────────────│                              │
     │  receipt                      │                              │
     │                               │                              │
     │                               │  (after B processes)         │
     │                               │  SpendReceipt(messageID)     │
     │                               │  ←──────────────────────────│
     │                               │  mark spent=true             │
     │                               │  prevent receipt replay      │
```

**Security guarantees:**
- Message signature verification (Dilithium3) — prevents forged senders
- Nonce monotonicity (HIGH-17) — prevents replay
- Canonical ID (GOV-R2-01) — prevents ID tampering
- Receipt single-use consumption — prevents duplicate relay

## 7. Main-Chain Anchoring Flow

```
  ShardChain                    MainChainCommitter              L1 main chain
     │                               │                          │
     │  CommitBlockToMainChain       │                          │
     │  (precondition: block.Finalized +                        │
     │   stateRoot != 0)             │                          │
     │  → generate ShardCommitment   │                          │
     │──────────────────────────────→│                          │
     │                               │  SubmitShardCommitment    │
     │                               │─────────────────────────→│
     │                               │  (anchored to a main-chain block)│
     │                               │  ←────────────────────────│
     │  ←──────────────────────────│                          │
     │  commitment                   │                          │
```

**Commitment fields:** shardID, blockHeight, blockHash, stateRoot, crossMsgRoot, signature, committedSlot

## 8. Persistence and Crash Recovery

```
┌─────────────────────────────────────────────────────────┐
│              <DataDir>/shard/state.db (bbolt)           │
│                                                         │
│  ┌─────────────────┐  ┌──────────────────────────────┐ │
│  │ MainChainCommitter│ │ ShardStateStore              │ │
│  │ (prefix: committer_)│ │ (prefix: shard_)            │ │
│  │                  │ │                              │ │
│  │ SubmitShardCommit│ │ PutBlock / GetBlock           │ │
│  │ VerifyShardCommit│ │ PutLatestHeight               │ │
│  │ GetLatestSlot    │ │ PutReceipt / GetReceipt       │ │
│  │                  │ │ PutSpentReceipt               │ │
│  │                  │ │ PutSenderNonce (HIGH-17)      │ │
│  │                  │ │ PutAssignment / GetAllAssign  │ │
│  └─────────────────┘ └──────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Restart recovery order (initSharding):**
1. Open the shard database
2. Create `ShardStateStore` + `MainChainCommitter` + `ShardQPOSAdapter`
3. `LoadAssignments()` restores the validator assignment table (Info log records the number recovered)
4. `SetStateStore` + `SetAuthorizer` + `SetMetrics`
5. `ShardBlockProducer.Start()` injects dependencies + starts the 4 goroutines

## 9. Monitoring and Health Checks

### Prometheus Metrics (8)

See section 7 of `docs/operations/runbooks/shard-operations.md`.

### Health Checker (P3-2)

`ShardHealthChecker.Check(now)` returns a structured report:
- Overall status: `ok` / `degraded` / `unhealthy`
- Per-shard status: Active/Initializing/Inactive + stalled detection + message backlog level

**Thresholds:**
- Stalled detection: no block produced within 5 slots (60 seconds) → stalled
- Message backlog: > 100 → warn, > 1000 → critical

## 10. Key Interface Contracts

| Interface | Definition location | Implementer | Injection target |
|------|---------|--------|---------|
| `MainChainCommitter` | `consensus/shard.go` | `MainChainCommitterImpl` | `ShardManager.mainChain` |
| `ElectionVerifier` | `consensus/shard.go` | `ShardQPOSAdapter` | `ShardChain.electionVerifier` |
| `ShardAuthorizer` | `consensus/shard.go` | `SystemShardAuthorizer` | `ShardManager.authorizer` |

**Interface responsibilities:**
- `MainChainCommitter`: submits/verifies shard commitments to the main chain, gets the latest slot
- `ElectionVerifier`: verifies whether a proposer was elected via VRF (prevents unauthorized proposals)
- `ShardAuthorizer`: verifies whether a caller is authorized to rotate validators (prevents malicious manipulation of the validator set)

## 11. Security Design Points

| Threat | Mitigation | Implementation location |
|------|---------|---------|
| Unauthorized proposal | ElectionVerifier verifies the VRF election result | `ProposeBlock` / `ReceiveBlock` |
| Forged signature | Dilithium3 signature verification (public keys must be registered) | `ProposeBlock` / `FinalizeBlock` |
| Single-node finalization | 2/3 supermajority quorum (rounded up) | `FinalizeBlock` |
| Cross-shard message forgery | Sender signature verification | `SubmitCrossShardMessage` |
| Cross-shard message replay | Nonce monotonicity + receipt single-use consumption | `SubmitCrossShardMessage` / `SpendReceipt` |
| Validator set manipulation | `ReassignValidators` requires system caller authorization | `ShardAuthorizer` |
| Zero stateRoot submission | Rejects block submission with stateRoot=0 | `CommitBlockToMainChain` |
| Conflicting blocks | Same height but different hash → reject + Warn | `ReceiveBlock` |