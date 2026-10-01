# DA (Data Availability) Subsystem Architecture

> Document ID: P4-1 · Module: 04 DA aggregation (DA Aggregation)
> Applicable version: Quantaureum L1 mainnet (ChainID 1668)
> Status: production-ready (disabled by default, fail-closed)

---

## 1. Subsystem Positioning

The DA (Data Availability) subsystem provides accessibility guarantees for block data on the Quantaureum L1: without requiring full nodes to hold the complete block body, it allows light nodes and L2 Rollups to verify that block data has been publicly published through sampling.

DA is the shared foundation for the upper-layer Rollup, Sharding, and Consensus, but it does not introduce new trust assumptions itself — all guarantees are built on top of QPOS consensus and QTD threshold signatures.

### 1.1 Relationship to the Seven-Layer Architecture

DA spans multiple layers but strictly follows the "upper layers depend on lower layers; reverse dependencies are forbidden" architecture discipline:

| Layer | Module | DA responsibility |
|----|------|---------|
| L5 consensus layer | `consensus/da_committee.go` `core/danksharding.go` | DA committee election / block-production DA gate / aggregate signatures |
| L4 execution layer | `qvm/` | Blob transaction type parsing and execution |
| L3 network layer | `p2p/das_protocol.go` | DAS sampling and cell distribution P2P protocol |
| L2 storage layer | `encoding/blob_*.go` `encoding/das.go` `qaudb/` | Blob matrix storage, erasure coding, sampling client |

DA does not expose a dedicated RPC namespace at L7 (service layer); its status is exposed through `qau_qposStatus` and the existing `eth_*` block interfaces.

---

## 2. Data Flow

### 2.1 Block Production Path (BlockBuilder → Finalize)

```
┌──────────────┐
│  BlockBuilder │  consensus/block_builder.go
└──────┬───────┘
       │ extract blob txs (qvm blob tx)
       ▼
┌──────────────────────┐
│ ProcessBlobsForBlock │  core/danksharding.go
└──────┬───────────────┘
       │ organize blobs into an m×m matrix
       ▼
┌──────────────┐
│ ExtendBlobs2D │  GF(2^16) Lagrange interpolation (P0-1)
└──────┬───────┘
       │ extend into a 2m×2m erasure matrix
       ▼
┌──────────────┐
│  StoreMatrix  │  encoding/blob_storage.go
└──────┬───────┘
       │ persist to PersistentBlobStorage (bbolt, P0-9)
       │ broadcast cells to the subnet
       ▼
┌──────────────────┐
│ DAS Sampling     │  p2p/das_protocol.go (P0-10)
│ (light nodes/    │  encoding/das.go
│  committee)      │
└──────┬───────────┘
       │ sample a subset of cells
       ▼
┌──────────────────────────┐
│ DAAttestationCollector   │  consensus/da_committee.go
└──────┬───────────────────┘
       │ collect committee signatures
       ▼
┌──────────────────┐
│ Aggregate (QTD)  │  QTD threshold signature (P0-3)
│ fallback: multi  │  ≤ DAMaxTransitionSignatures (64)
└──────┬───────────┘
       │ generate the aggregate attestation
       ▼
┌──────────────────────────────┐
│ BlockValidator               │  core/block_validator.go
│ VerifyBlockDAAvailability    │  core/danksharding.go
└──────┬───────────────────────┘
       │ DA gate passes → vote
       ▼
┌──────────────────┐
│ QPOS FinalizeBlock│  consensus/qpos.go
└──────────────────┘
```

### 2.2 Verification Path (Light Nodes)

A light node need not download the complete block body; it only needs to randomly sample `c` cells to confirm data availability with confidence `1 - (1/2)^c`. Sampling is initiated via the `DASClient` (`encoding/das.go`) and requests cells from nodes in the corresponding subnet through the `BlobNetworkManager` (`encoding/blob_network.go`).

---

## 3. Interaction with Other Subsystems

### 3.1 Rollup (L2 Data Availability Foundation)

DA is the data availability layer for L2 Rollups: Rollup submits calldata / state diff as blobs to the L1, and the DA subsystem guarantees that these blobs can be sampled and recovered by any node once the committee signature threshold is reached. The Rollup's fraud proof / validity proof window depends on DA finality time.

- Dependency direction: Rollup → DA (one-way; DA does not depend on Rollup in reverse)
- Interfaces: blob transactions + `eth_getBlobByIndex` (standard interfaces go through L7)

### 3.2 Sharding (Cross-Shard Data Availability)

Cross-shard state access for shard blocks requires data availability guarantees: the target shard must be able to recover referenced blobs from the DA layer. DA provides shards with a unified erasure matrix and sampling protocol, avoiding a per-shard implementation.

- Dependency direction: Sharding → DA (one-way)
- Interfaces: shard blocks reuse ExtendBlobs2D / StoreMatrix via `core/danksharding.go`

### 3.3 Consensus (QPOS DA Gate)

QPOS enforces DA availability before `FinalizeBlock`: `BlockValidator.VerifyBlockDAAvailability` must return `true` before vote aggregation is allowed. This is a fail-closed design — if the DA committee does not reach the threshold within the slot period, the block is not finalized and moves to the next proposal round.

- Dependency direction: Consensus → DA (the DA gate is a finality precondition)
- Interfaces: `core/block_validator.go` calls `DankshardingEngine.VerifyBlockDAAvailability`

---

## 4. Key Components

### 4.1 DankshardingEngine

- File: `core/danksharding.go`
- Role: the main orchestrator of the DA subsystem
- Responsibilities:
  - `ProcessBlobsForBlock`: extracts blob transactions from the block and builds an m×m matrix
  - `ExtendBlobs2D`: GF(2^16) Lagrange interpolation to extend into a 2m×2m erasure matrix (P0-1)
  - `VerifyBlockDAAvailability`: the external DA gate, called by BlockValidator
- Constraint: all cryptographic operations are delegated to `crypto/`; this component does not directly hold keys

### 4.2 DACommitteeManager

- File: `consensus/da_committee.go`
- Role: committee election + shuffle
- Responsibilities:
  - Shuffles committee members based on the VRF beacon (P1-12); RANDAO fallback
  - Default committee size 512, subnet count 32
- Boundary: only decides "who is on the committee"; does not collect signatures

### 4.3 DAAttestationCollector

- File: `consensus/da_committee.go`
- Role: signature collection and aggregation
- Responsibilities:
  - Collects committee members' attestations for each extended matrix
  - Aggregated signatures preferentially use QTD threshold signatures (P0-3)
  - When QTD is unavailable, falls back to multi-signature, capped at `DAMaxTransitionSignatures` (≤64)
- Constraint: fail-closed when aggregate signing fails; does not fabricate a threshold

### 4.4 BlobStorage / PersistentBlobStorage

- File: `encoding/blob_storage.go`
- Role: blob matrix storage
- Responsibilities:
  - `BlobStorage`: in-memory view, hot-path queries
  - `PersistentBlobStorage`: bbolt backend persistence (P0-9)
- Capacity constraints: `MaxBlobsPerBlock=6`, `BlobSize=128KB`
- GC: `BlobGarbageCollector` reclaims expired matrices after finality

### 4.5 DASClient

- File: `encoding/das.go`
- Role: sampling client
- Responsibilities: randomly selects cell coordinates → requests via `BlobNetworkManager` → verifies cell consistency → outputs availability confidence
- Callers: light nodes, committee members, BlockValidator

### 4.6 BlobNetworkManager

- File: `encoding/blob_network.go`
- Role: P2P cell request layer
- Responsibilities:
  - Routes cell requests to the corresponding subnet
  - Underlying protocol registered in `p2p/das_protocol.go` (P0-10)
- Dependency: L3 network layer gossipsub channel

### 4.7 BlobGarbageCollector

- File: `encoding/blob_network.go`
- Role: GC
- Responsibilities: after block finality is reached, reclaims matrices in `PersistentBlobStorage` that exceed the retention window
- Constraint: GC only triggers after `FinalizeBlock`, avoiding accidental deletion of unfinalized data

### 4.8 DAMetrics

- File: `consensus/da_metrics.go`
- Role: Prometheus metrics
- Namespace: `qau_da_*` (10 metrics total)
- Exposure: via the node's existing metrics endpoint; no separate port

---

## 5. Cryptographic Contracts (DA-specific)

| Item | Implementation | Status |
|----|------|------|
| Erasure coding | GF(2^16) Lagrange interpolation | P0-1 |
| Commitment scheme | Keccak256 (KZG downgrade) | P0-2 documented downgrade |
| Aggregate signature | QTD threshold signature | P0-3 |
| Multi-signature fallback | ≤ `DAMaxTransitionSignatures` (64) | when QTD is unavailable |
| Shuffle seed | VRF beacon → RANDAO fallback | P1-12 |

> ⚠️ The KZG → Keccak256 downgrade is a documented technical decision (P0-2), recorded here rather than in the `crypto/` contract because Keccak256 does not belong to the quantum cryptography layer. Modifying this downgrade requires a synchronous evaluation of the lightweight-node verification cost of the DA commitment.

---

## 6. Default Configuration and Time Constants

| Item | Default | Description |
|----|--------|------|
| `Enabled` | `false` | DA disabled by default, fail-closed |
| Committee size | 512 | `DACommitteeSize` |
| Subnet count | 32 | `DASubnetCount` |
| 1 epoch | 256 slots × 12s ≈ 51min | Aligned with the QPOS epoch |
| `MaxBlobsPerBlock` | 6 | Maximum number of blobs per block |
| `BlobSize` | 128 KB | Size of a single blob |
| `DAMaxTransitionSignatures` | 64 | Multi-signature fallback cap |

DA defaults to `Enabled=false`: when a node does not explicitly enable DA, the BlockBuilder does not package blob transactions and the BlockValidator skips the DA gate (treated as available). Once enabled, blocks must satisfy the committee threshold to be released — this is fail-closed semantics, not fail-open.

---

## 7. Configuration Entry Points

### 7.1 Node Configuration

- Main entry: `node/config.go` → `DankshardingNodeConfig`
- Example file: `configs/da.example.json`

`DankshardingNodeConfig` fields correspond one-to-one with the constants in section 6; any new field must synchronously update `configs/da.example.json` and this file, keeping documentation and code consistent.

### 7.2 Enablement Flow

1. Copy `configs/da.example.json` to `configs/da.json`
2. Set `Enabled: true` and configure the committee parameters
3. At node startup, `node/` reads the config and injects the `DankshardingEngine`
4. After enabling, the node must participate in the committee or have access to committee signature aggregation

---

## 8. Monitoring and Alerts

### 8.1 Metrics

- Entry: `consensus/da_metrics.go`
- Namespace: `qau_da_*`
- Count: 10 Prometheus metrics
- Exposure path: the node's metrics endpoint (shared with consensus metrics)

### 8.2 Alert Rules

- Rule file: `ops/alerts.yaml`
- Runbook: `ops/runbook-da.md`

| Alert | Severity | Trigger condition |
|------|--------|----------|
| `da_committee_unavailable` | Critical | The committee cannot reach a threshold |
| `da_sampling_confidence_low` | Warning | Sampling confidence below threshold |
| `da_blob_storage_large` | Warning | Blob storage exceeds capacity |
| `da_verifier_rejections` | Warning | DA gate verification rejection rate rising |
| `da_attestation_collection_low` | Warning | Attestation collection rate insufficient |

`da_committee_unavailable` is Critical: it means blocks cannot be finalized and requires immediate intervention (see `ops/runbook-da.md`).

---

## 9. Invariants and Boundaries

1. **fail-closed**: once DA is enabled, blocks that do not reach the threshold are forbidden from finalization, even at the cost of liveness.
2. **No new trust assumptions**: the DA committee is produced from the QPOS validator set via VRF shuffle; no new roles are introduced.
3. **Does not bypass the quantum cryptography layer**: all signatures go through `crypto/`; DA components do not directly hold keys.
4. **GC only triggers after finality**: `BlobGarbageCollector` must wait for `FinalizeBlock` before reclaiming.
5. **Downgrades are documented**: the three downgrades KZG→Keccak256 (P0-2), QTD→multi-signature (≤64), and VRF→RANDAO all have documented records and fallback caps.

---

## 10. Related Documentation and Code Index

| Type | Path |
|------|------|
| Orchestrator | `core/danksharding.go` |
| Committee / collector | `consensus/da_committee.go` |
| Metrics | `consensus/da_metrics.go` |
| Blob storage | `encoding/blob_storage.go` |
| DAS client | `encoding/das.go` |
| P2P network | `encoding/blob_network.go` `p2p/das_protocol.go` |
| Node configuration | `node/config.go` `DankshardingNodeConfig` |
| Example configuration | `configs/da.example.json` |
| Alerts | `ops/alerts.yaml` |
| Runbook | `ops/runbook-da.md` |
| Block verification DA gate | `core/block_validator.go` `VerifyBlockDAAvailability` |
| QPOS finality | `consensus/qpos.go` `FinalizeBlock` |