# 08 - L6 Integration Layer — `node/` `txpool/`

> `node/` is the **only integration layer allowed to depend on almost all modules**.
> It bridges L1-L5 via Adapters and exposes read-only interfaces to RPC. `txpool/`
> manages transactions awaiting packaging.

## 8.1 `node/` — Node Orchestrator

| File | Key Exports | Responsibility |
|------|---------|------|
| [node/node.go](../node/node.go) | `Node`, `New(cfg, logger)`, `Start(ctx)`, `Stop()`, `IsProposer` | Root coordinator: assembles components + lifecycle |
| [node/adapters.go](../node/adapters.go) | `StateReader`, `BlockReader`, `ReceiptReader`, `TxPoolAPI` etc. bridge-interface implementations | Adapter layer for RPC ↔ storage/state |
| [node/block_producer.go](../node/block_producer.go) | `BlockProducer`, `Run()` | Block-casting loop (calls core.BlockBuilder) |
| [node/qtd_seal.go](../node/qtd_seal.go) | `QTDSeal`, `SealBlock`, `RequestSeal` | QTD threshold-signing block wrapper |
| [node/snap_sync.go](../node/snap_sync.go), `snapshot.go`, `syncer.go` | Snap sync/client | Fast synchronization |
| [node/config.go](../node/config.go) | `Config` (BlockTime, EpochLength, ChainID…) | Node configuration model |
| [node/genesis.go](../node/genesis.go) | `Genesis`, `InitializeGenesis` | Genesis initialization |
| [node/dev_accounts.go](../node/dev_accounts.go) | Dev account fill | Devnet pre-provisioned accounts |
| [node/fee_history.go](../node/fee_history.go), `history_expiry.go` | `eth_feeHistory` support, history expiry | Fee history |
| [node/shard_producer.go](../node/shard_producer.go) | Shard block production | Sharding |
| [node/da_r5_03_seed.go](../node/da_r5_03_seed.go) | DA seed | DA-layer seed |

### 8.1.1 Node Startup Sequence (Schematic)

```go
func (n *Node) Start(ctx context.Context) {
    // 1. Open and initialize storage
    n.db.Open()                       // qaudb
    // 2. Genesis initialization
    n.genesis.InitializeGenesis()
    // 3. Assemble consensus
    n.qpos = consensus.NewQPOS(...)
    n.qpos.SetTSSSigner(n.tssManager) // ThresholdKeySigner injection
    // 4. Assemble core
    n.blockBuilder = core.NewBlockBuilder(chainID, gasLimit)
    n.blockBuilder.SetDankshardingEngine(n.daEngine)
    n.blockValidator = core.NewBlockValidator(...)
    // 5. Network
    n.p2p.Start()
    // 6. Start consensus
    n.qpos.Start(ctx)
    // 7. Block-casting loop
    n.blockProducer.Run()
    // 8. RPC
    n.rpc.Start()
}
```

### 8.1.2 Adapters (Bridging Interfaces)

`adapters.go` abstracts the "read capabilities" RPC needs into interfaces, preventing RPC
from depending directly on storage details:

```go
type StateReader interface {
    GetBalance(addr types.Address) (*big.Int, error)
    GetNonce(addr types.Address) (uint64, error)
    GetCode(addr types.Address) ([]byte, error)
    GetStorageAt(addr types.Address, key types.Hash) ([]byte, error)
    // ...
}

type BlockReader interface {
    GetBlockByNumber(num uint64) (*encoding.Block, error)
    GetBlockByHash(hash types.Hash) (*encoding.Block, error)
    // ...
}

type ReceiptReader interface {
    GetReceipt(txHash types.Hash) (*encoding.Receipt, error)
    // ...
}
```

**R40.R fix**: `GetTransactionReceipt` enters a bounded retry loop (10×50ms) when the priority
path (blockStore.GetReceipt) misses, then degrades to the fallback (inferring status via `GetCode`)
within the transient window where the receipt is not yet persisted. See [15-lessons.md § R40.R](./15-lessons.md#153-r40r---transaction-receipt-persistence-window).

### 8.1.3 QTD Seal (`node/qtd_seal.go`)

- `QTDSeal` encapsulates the integration logic for "sealing a block with a threshold signature".
- On block production: `blockHash` → `tssSigner.SignThreshold` → multiple parties collect
  partial seals → threshold reached → full seal → written into the block + broadcast.
- On the RPC side, driven by `qau_tss_requestSeal` / `qau_tss_submitPartialSeal` and
  `qau_tss_getSealStatus` in `qtd_api.go` (admin-gated).

## 8.2 `txpool/` — Transaction Pool

| File | Key Exports | Responsibility |
|------|---------|------|
| [txpool/pool.go](../txpool/pool.go) | `TxPool`, `Add`, `Recall`, `Pending`, `NewTxPool` | Tx-pool main structure: pending/queued buckets |
| [txpool/list.go](../txpool/list.go) | `priceList`, `nonceList` | Sorted by gas price / nonce |
| [txpool/validator.go](../txpool/validator.go) | `ValidateTx` | Transaction validation (signature, nonce, balance, commit-reveal) |
| [txpool/executor.go](../txpool/executor.go) | `ExecuteTx` | Execution (delegated to qvm) |
| [txpool/bundler.go](../txpool/bundler.go) | `Bundler` | Batch bundling |

### 8.2.1 commit-reveal Front-Running Protection

- `validator.go` enforces the commit-reveal path for transfers **with value ≥ the threshold**.
- A bare `eth_sendTransaction` sending a large amount directly is rejected:
  `transaction requires commitment for front-running protection: value=...`.
- Correct path: `qau_submitCommitment` (commit)→ reveal → into the pool.
- See [15-lessons.md § R40.T](./15-lessons.md#154-r40t---high-value-transfer-protection).

## 8.3 Node Logging and Monitoring

- Core components use `log` (stderr, synchronous)to avoid systemd buffering issues.
- Health check: `:8080/health` (public).
- RPC/WS: `127.0.0.1:8545 / 8546` (local only).

## 8.4 Integration-Layer Notes

- **Do not** `new Node` outside `node/`; only in `cmd/qaud/main.go`.
- `Node` is the only type allowed to `import` all layers; new components must be injected
  to lower layers via `node`.
