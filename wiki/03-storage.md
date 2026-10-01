# 03 - L2 Storage Layer — `qaudb/` `encoding/` `rlp/`

> This layer provides transactional KV storage, state snapshots, the Verkle trie,
> and cross-node codec protocols. From the node's perspective:
> **world state = `qaudb/state` + `qaudb/trie/verkle`**.

## 3.1 `qaudb/` — Storage Abstraction

Subdirectory overview:

```
qaudb/
├── db/        # KV-layer abstraction (bbolt is the default impl; in-memory impl used for testnet/CI)
├── block/     # Persistence of blocks/transactions/receipts (PutBlock / GetReceipt / IndexTransactions)
├── state/     # Account / storage state DB (geth-style StateDB)
├── cache/     # LRU wrapper layer (provides in-memory "read-through" cache)
└── trie/      # Verkle trie: QAU's state commitment
```

### 3.1.1 `qaudb/db/`

`db.go` defines the interface:

```go
type DB interface {
    Get(key []byte) ([]byte, error)
    Put(key, value []byte) error
    Delete(key []byte) error
    NewBatch() Batch
    Close() error
    // + Iter / Has / Compact ...
}
```

- Default implementation: [qaudb/db/boltdb.go](../qaudb/db/boltdb.go) (bbolt Mmap mode + periodic compact)
- In-memory test implementation: convenient for executor unit tests.
- Disk-space protection: `diskspace.go` checks the data-directory space on startup;
  if insufficient, it refuses to start and degrades to read-only.

### 3.1.2 `qaudb/block/`

- Provides **composite indexes oriented around Block/Receipt/Transaction**.
- `StoreReceipts` and `PutBlock` are written strictly in order (see [15-lessons.md § R40.R](./15-lessons.md#153-r40r---transaction-receipt-persistence-window)).
- Exposes **read-only** semantic interfaces such as `GetReceipt(hash)`, `GetBlockByHash`, `GetBlockByNumber`.

### 3.1.3 `qaudb/state/`

- `state_db.go`: account state tree & MPT (verkle) View.
- `state_access_list.go`: state-side implementation of EIP-2930-style access lists.
- `pruner.go`: state pruning policy.

### 3.1.4 `qaudb/trie/`

[trie/verkle.go](../qaudb/trie/verkle.go) maintains a single-layer verkle trie:

- Pedersen commitment serves as the commitment scheme, together with `ipa.go` (Inner Product Argument).
- The root is updated once per block commit and written into the block header's state_root.
- Used for RPC `eth_getProof` / cross-chain bridge proof generation.

### 3.1.5 `qaudb/cache/`

LRU cache entry point; all reads in the outer layers (rpc / p2p) go through the cache
first and access bolt only on a miss.

## 3.2 `encoding/` — Wire Format and Protocol Messages

| File | Key Exports | Purpose |
|------|---------|------|
| `encoding/block.go` | `Block`, `BlockHeader`, `BlockBody`, `EncodeBlock / DecodeBlock` | Main block structures + Protobuf persistence |
| `encoding/transaction.go` | `Transaction` (incl. Dilithium3 sig), `EncodeTransaction/DecodeTransaction` | Transaction wire-format |
| `encoding/receipt.go` | `Receipt` (incl. logs, status), `EncodeReceipt/DecodeReceipt` | Receipts |
| `encoding/wire.go` | `WireMessage` and its codec | p2p communication envelope |
| `encoding/blob_tx.go`, `encoding/das.go` | Danksharding BlobTx + DAS (data availability sampling) | DA-layer protocol transport |
| `encoding/proto.go` | Protobuf message helpers | wire message schema |
| `encoding/validation.go` | Input constraints (size, field length, signature verification) | Defensive reading |
| `encoding/proposal_data.go` | BlockProposal / Vote message wrapper | Cross-node consensus messages |
| `encoding/blox_tx.go` | Blob transaction-specific container | blob transactions |
| `encoding/light_encoding.go` | Light client serialization subset | bridging / SPV |

### 3.2.1 Key Conventions

- Blocks / transactions / receipts preferentially use **protobuf + binary** serialization.
- Transactions **support multiple signature fields** (including `QuantumSignature`, `RecoveryID`),
  but Portal submission accepts only a single **Dilithium3** authority.
- All `Encode*` / `Decode*` are **thread-safe** and **zero-copy** (reuse buffers whenever possible).

## 3.3 `rlp/` — Ethereum RLP Compatibility

- Serves as a compatibility layer in the EVM cross-chain bridge (rollup module).
- **Not on the main-chain consensus critical path**; used only for contract calls and cross-domain messages.

## 3.4 Read-Path Diagram

```
RPC eth_call / eth_getBalance / eth_getStorageAt
   │
   ▼
StateReader (node/adapters.go)
   │
   ▼
Cache (qaudb/cache) ────hit────▶ result
   │ miss
   ▼
State (qaudb/state)
   │ account/storage view
   ├─→ Verkle Trie (qaudb/trie/verkle)
   │      ────▶ pedersen commitment match
   │
   └─→ KV(qaudb/db, bbolt)
```

## 3.5 Write-Path Diagram

```
BlockProducer collects transactions -> core.BlockBuilder.BuildBlock
   │
   ▼
qvm.Executor executes each transaction → generates receipts
   │
   ▼
blockStore.PutBlock(header, body)          # see R40.R ordering constraint
   ├─ block/index.go   (indexed by number, hash)
   ├─ block/receipts   (StoreReceipts written synchronously)
   └─ trie.Commit (verkle root)
   │
   ▼
consensus.finalize → validator multisig → qtd_seal.go
   │
   ▼
broadcast to p2p → other nodes' BlockValidator → repeat the above process
```

## 3.6 Deployment/Operations Recommendations

- Recommend mounting the data directory on an SSD (prefer NVMe SSD + write-cache).
- A single bbolt file defaults to a maximum of ~1 GiB; exceed that by configuring `db.max_file_size`.
- A slow disk can make `PutBlock` slower than `BlockTime`, ultimately showing up as
  RPC `eth_blockNumber` not advancing for a long time.
- "Why is RPC slow" troubleshooting: first look at `qaudb`'s `db.Stats()`, then confirm the cache hit rate.

## 3.7 Key Anti-Patterns (Don't Write It Like This)

```go
// Wrong: directly calling bolt without going through the cache — poor performance
// + leaks storage details across modules
import "github.com/quantaureum/qau/qaudb/db"

func (a *SomeAPI) Get(key []byte) ([]byte, error) {
    return a.DB.Get(key)   // should use the BlockReader exposed by node/adapters
}

// Wrong: Lock() again inside state_db.Lock() (violates lock_order.go)
```

> `trie/verkle.go` and `trie/ipa.go` are **crypto-critical territory**;
> before modifying them you must first read [crypto/dilithium.go](../crypto/dilithium.go) and
> [trie/pedersen.go](../qaudb/trie/pedersen.go), and run the full regression.
