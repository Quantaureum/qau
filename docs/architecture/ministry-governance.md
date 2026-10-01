# Six Ministries Governance (Ministry Governance) Subsystem Architecture

> P4-T1 · 2026-07-15 · Quantaureum Consensus Layer Governance Module

## 1. Overview

Six Ministries Governance (Ministry Governance) is the on-chain governance framework built into the Quantaureum QPOS consensus layer. Inspired by the ancient Chinese "Three Departments and Six Ministries" model, it splits validator governance responsibilities into six independent but collaborative modules: Personnel , Revenue , Rites , Defense , Justice , and Works . Each ministry is responsible for one vertical governance domain, orchestrated uniformly through the `MinistryRegistry`, and deeply integrated with QPOS consensus and the Three Chambers Coordinator.

**Core design principles:**
- **Separation of concerns**: each ministry handles only one domain, avoiding god objects
- **Interface decoupling**: ministries refer to each other indirectly through the `MinistryRegistry`, without direct dependencies
- **Authorization first**: all state-changing methods must pass GOV-03 system-caller authentication
- **Auditable traceability**: key state changes are recorded as structured audit logs via the `AuditLogger`
- **Persistent recovery**: key state (blacklist, slashing records) is persisted to BoltDB via `MinistryStateStore`, surviving restarts

**Key constraints:**
- The six ministries' state **does not affect stateRoot** (non-consensus-critical state), stored using JSON serialization
- The blacklist is the **only state that affects consensus security** — blacklisted validators cannot propose/attest/seal

## 2. Six Ministries Responsibility Matrix

| Ministry | MinistryID | Native name | Core responsibility | Key state | Consensus impact |
|----|-----------|--------|---------|---------|---------|
| Personnel | 1 | Personnel | Validator registration, reputation management, block-production/attestation statistics | Reputation record table | No (read-only statistics) |
| Revenue | 2 | Revenue | Reward distribution, slashing execution, financial records | Reward records, slashing records | No (read-only statistics) |
| Justice | 3 | Justice | Dispute submission, evidence verification, dispute resolution | Dispute case table | No (read-only statistics) |
| Defense | 4 | Defense | Quantum attack detection, network partition detection, blacklist management | Security alerts, blacklist | **Yes** (blacklist blocks consensus participation) |
| Rites | 5 | Rites | Operational counter (proposal functionality transferred to economics after P1-T6) | Operation counts | No |
| Works | 6 | Works | Shard management, cross-chain bridge registration, cross-chain transaction records | Shard table, bridge table | No (read-only statistics) |

### Key Methods of Each Ministry

**Personnel** — `consensus/ministry_personnel.go`
- `RegisterValidator` — validator registration (requires authorization)
- `RecordBlockProduced` — records block production (automatically called)
- `RecordAttestation` — records attestation (automatically called)
- `GetReputation` — queries validator reputation

**Revenue** — `consensus/ministry_revenue.go`
- `DistributeEpochRewards` — epoch reward distribution (requires authorization)
- `ExecuteSlashing` — executes slashing (requires authorization)
- `GetFinancialSummary` — queries financial summary

**Justice** — `consensus/ministry_justice.go`
- `SubmitDispute` — submits a dispute (requires authorization)
- `VerifyEvidence` — verifies evidence
- `ResolveDispute` — resolves a dispute (requires authorization)

**Defense** — `consensus/ministry_defense.go`
- `DetectQuantumAttack` — quantum attack detection (requires authorization)
- `DetectNetworkPartition` — network partition detection (requires authorization)
- `AddToBlacklist` / `RemoveFromBlacklist` — blacklist management (requires authorization)
- `IsBlacklisted` — blacklist query (injected into the QPOS consensus check)

**Rites** — `consensus/ministry_rites.go`
- `GetStatus` — returns the operational counter (only the counter remains after P1-T6)

**Works** — `consensus/ministry_works.go`
- `RegisterShard` / `RegisterBridge` — shard/bridge registration (requires authorization)
- `RecordCrossChainTx` — records cross-chain transactions

## 3. Architecture Interaction Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                        MinistryRegistry                          │
│                   (consensus/ministry.go)                        │
│                                                                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐          │
│  │ Personnel     │ │ Revenue     │ │ Justice     │ │ Defense     │          │
│  │Personnel │ │ Revenue  │ │ Justice  │ │ Defense  │          │
│  │          │ │          │ │          │ │          │          │
│  │ Reputation│ │ Rewards/ │ │ Dispute  │ │ Blacklist│          │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └─────┬────┘          │
│       │            │            │              │                │
│  ┌────┴─────┐ ┌────┴───────────┴──────────────┴────┐          │
│  │ Rites     │ │ Works                                │          │
│  │ Rites    │ │ Works                               │          │
│  │ Counter  │ │ Shards/Bridge/Cross-chain           │          │
│  └──────────┘ └─────────────────────────────────────┘          │
│                                                                  │
│  Injected: metrics *MinistryMetrics (P3-T1)                     │
│            audit   AuditLogger      (P3-T2)                     │
└──────────────┬───────────────────────────────────┬──────────────┘
               │                                   │
               ▼                                   ▼
┌──────────────────────┐              ┌──────────────────────────┐
│       QPOS consensus │              │  ThreeChambersCoordinator │
│  (consensus/qpos.go) │              │  (three-chamber coord.)   │
│                      │              │                          │
│  SetBlacklistCheck ◄─┤  Defense     │  Executive / Review /     │
│  (CanPropose/Attest/ │  blacklist   │  Seal three-chamber       │
│   CanSeal reject     │  injected    │  finality                │
│   blacklisted)       │  into consensus│                        │
└──────────┬───────────┘              └──────────────────────────┘
           │
           ▼
┌──────────────────────┐              ┌──────────────────────────┐
│   SlashingManager    │              │     MinistryStateStore   │
│  (slashing manager)  │              │  (consensus/ministry_    │
│                      │              │   store.go)              │
│  SetMinistryRevenue ◄┤  Revenue     │                          │
│  SetMinistryPersonnel│  records     │  SaveAll / LoadAll       │
│  (validatorMgr)      │  slashing    │  JSON → BoltDB           │
└──────────────────────┘              │  Version: V2 (P4-T3)     │
                                      └──────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────────────────────────┐
│                        RPC layer (rpc/stardust_api.go)          │
│                                                                  │
│  qau_stardust_getMinistryStatus → MinistryRegistry.GetStatus()  │
│  returns the six-ministry status snapshot (read-only)           │
└──────────────────────────────────────────────────────────────────┘
```

## 4. Authorization Model (GOV-03)

### 4.1 System Caller Mechanism

All state-changing methods of the six ministries (validator registration, reward distribution, blacklist operations, etc.) require the caller to pass the GOV-03 authorization check. The authorization check is implemented via the `isSystemCaller` function:

```
Caller ──→ isSystemCaller(caller) ──→ true: allowed to execute
                                  └─→ false: returns "unauthorized" error
```

**System caller registration:**
- `RegisterSystemCaller(addr)` — adds an address to the `systemCallers` whitelist
- The whitelist is stored in an in-memory map, protected by `sync.RWMutex`
- In production, system caller addresses are registered at node startup (typically the consensus engine's own address)

**Some methods allow a "self-authorization" exception:**
- `RegisterValidator`: a validator can register itself (`caller == addr`), or be registered on its behalf by a system caller

### 4.2 Authorization Check Locations

| Method | Authorization check | Exception |
|------|---------|------|
| `Personnel.RegisterValidator` | `isSystemCaller(caller)` | `caller == addr` (self-registration) |
| `Revenue.DistributeEpochRewards` | `isSystemCaller(caller)` | None |
| `Revenue.ExecuteSlashing` | `isSystemCaller(caller)` | None |
| `Justice.SubmitDispute` | `isSystemCaller(caller)` | None |
| `Defense.AddToBlacklist` | `isSystemCaller(caller)` | None |
| `Defense.RemoveFromBlacklist` | `isSystemCaller(caller)` | None |
| `Works.RegisterShard` | `isSystemCaller(caller)` | None |

### 4.3 Consensus Security Integration

The Defense Ministry's blacklist is the only six-ministry state that directly affects consensus security:

```
QPOS.SetBlacklistCheck(md.IsBlacklisted)
  → CanPropose(validatorIndex) checks IsBlacklisted
  → CanAttest(validatorIndex) checks IsBlacklisted
  → CanSeal(validatorIndex) checks IsBlacklisted
```

Blacklisted validators are rejected at the consensus propose, attest, and seal stages.

## 5. Persistence Strategy

### 5.1 Storage Design

The six ministries' state is persisted to BoltDB via `MinistryStateStore` (`consensus/ministry_store.go`). It uses a write-through pattern: the in-memory map is the primary data structure (read path), while `MinistryStateStore` persists changes to disk for crash recovery.

**Storage key prefixes:**

| Ministry | Key prefix | Format |
|----|--------|------|
| Personnel  | `min_per:` | JSON |
| Revenue  | `min_rev:` | JSON |
| Justice  | `min_jus:` | JSON |
| Defense  | `min_def:` | JSON |
| Rites  | `min_rit:` | JSON |
| Works  | `min_wrk:` | JSON |
| Checkpoint | `min_ckpt` | 8-byte BE uint64 (last persisted epoch) |

### 5.2 Why JSON Instead of RLP

The six ministries' state is **not consensus-critical state** (does not affect stateRoot). The `state_db.go` rule prohibiting JSON applies only to consensus-critical state. The reasons the six ministries' state uses JSON:
- The structures contain `time.Time`, nested maps, and variable-length slices, which JSON supports natively
- Keeps a consistent storage pattern with `shard_store.go`
- No need for compact encoding (state volume is small; the blacklist is usually < 100 entries)

### 5.3 Persistence Timing

- `SaveAll(registry, epoch)` — called at every epoch boundary (node epoch loop)
- `LoadAll(registry)` — called at node startup (before consensus begins)
- Blacklist changes are **persisted immediately** (`AddToBlacklist`/`RemoveFromBlacklist` are followed by an immediate SaveDefense)

### 5.4 Versioning and Migration (P4-T3)

Each state struct contains a `Version uint8` field; the current version is `2`:

```go
const ministryStateVersion uint8 = 2
```

**Version history:**
- V1 (Version=0): data before P4-T3, no `version` field in JSON, defaults to 0 on deserialization
- V2 (Version=2): P4-T3 adds the `version` field for forward compatibility

**Migration function `migrateV1ToV2`:**
- V1 (0) → V2 (2): automatic upgrade, no data conversion needed (P4-T3 did not change the field layout)
- V2 (2) → V2 (2): idempotent, no-op
- Future versions (>2): left unchanged, warning log recorded

Migration runs automatically in the `Load` method — old node data loads correctly after an upgrade without manual intervention.

### 5.5 Non-Atomic Writes

`SaveAll` writes are non-atomic (each ministry is Put independently). This is acceptable because:
- The six ministries' state is non-consensus-critical (does not affect stateRoot)
- The checkpoint epoch records the time of the last successful save; `LoadAll` can verify state freshness
- Worst case: some ministries fail to save, and the next epoch boundary retries

## 6. Monitoring and Alerts

### 6.1 Prometheus Metrics (P3-T1)

12 metrics under the `qau_ministry_*` namespace, refreshed at epoch boundaries via `RefreshMetrics()`:

| Metric | Type | Description |
|------|------|------|
| `qau_ministry_personnel_active_validators` | Gauge | Personnel : number of active validators |
| `qau_ministry_personnel_avg_reputation` | Gauge | Personnel : average reputation score |
| `qau_ministry_revenue_total_distributed` | Counter | Revenue : cumulative distributed rewards (computed incrementally) |
| `qau_ministry_revenue_total_slashed` | Counter | Revenue : cumulative slashed amount (computed incrementally) |
| `qau_ministry_justice_pending_cases` | Gauge | Justice : number of pending disputes |
| `qau_ministry_justice_resolved_cases` | Gauge | Justice : number of resolved disputes |
| `qau_ministry_defense_active_alerts` | Gauge | Defense : number of active security alerts |
| `qau_ministry_defense_blacklist_size` | Gauge | Defense : blacklist size |
| `qau_ministry_defense_critical_alerts` | Gauge | Defense : number of critical alerts (alerting support) |
| `qau_ministry_defense_partition_detected` | Gauge | Defense : network partition flag (alerting support) |
| `qau_ministry_works_active_shards` | Gauge | Works : number of active shards |
| `qau_ministry_works_pending_txs` | Gauge | Works : number of pending cross-chain transactions |

### 6.2 Alert Rules (P3-T3)

4 alert rules are registered in `metrics/metrics.go`:

| Alert name | Level | Condition | Threshold |
|---------|------|------|------|
| `ministry_quantum_attack_detected` | Critical | critical alerts > 0 | > 0.5 |
| `ministry_network_partition_detected` | Critical | partition flag = 1 | > 0.5 |
| `ministry_blacklist_spike` | Warning | blacklist too large | > 10 |
| `ministry_pending_cases_backlog` | Warning | pending dispute backlog | > 50 |

### 6.3 Audit Logs (P3-T2)

The `AuditLogger` interface records structured audit entries for key state changes, using the who/what/when/result pattern:

| Event | Ministry | action |
|------|----|----|
| Reward distribution | Revenue  | `distribute_rewards` |
| Slashing execution | Revenue  | `execute_slashing` |
| Slashing record | Revenue  | `record_slashing` |
| Quantum attack detection | Defense  | `detect_quantum_attack` |
| Network partition detection | Defense  | `detect_network_partition` |
| Blacklist add | Defense  | `blacklist_add` |
| Dispute submission | Justice  | `submit_dispute` |
| Dispute resolution | Justice  | `resolve_dispute` |

## 7. File Index

| File | Responsibility |
|------|------|
| `consensus/ministry.go` | MinistryRegistry orchestration, AuditLogger interface, RefreshMetrics |
| `consensus/ministry_personnel.go` | Personnel : reputation management |
| `consensus/ministry_revenue.go` | Revenue : rewards/slashing |
| `consensus/ministry_justice.go` | Justice : dispute resolution |
| `consensus/ministry_defense.go` | Defense : security detection/blacklist |
| `consensus/ministry_rites.go` | Rites : operational counter |
| `consensus/ministry_works.go` | Works : shard/bridge/cross-chain |
| `consensus/ministry_store.go` | Persistent storage, version migration |
| `consensus/ministry_metrics.go` | Prometheus metrics (P3-T1) |
| `metrics/metrics.go` | Alert rules (P3-T3) |
| `rpc/stardust_api.go` | RPC endpoint `qau_stardust_getMinistryStatus` |
| `node/node.go` | Node startup injection (metrics + store) |