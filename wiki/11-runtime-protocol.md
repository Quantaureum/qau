# 11 - Runtime Data Flow, Network Topology, and Configuration

## 11.1 Genesis and Chain Configuration

Three networks under the `genesis/` directory:

| File | ChainID | Validators | Genesis Pre-Allocation |
|------|---------|--------|-----------|
| `genesis/mainnet.json` | 1668 | 6 (mainnet) | 20,000,000 QAU |
| `genesis/testnet.json` | 1669 | per configuration | testnet allocation |
| `genesis/dev.json` | 1333 | few/single | dev allocation |

- In genesis, validators are listed as a `validator` array (incl. public key, amount, delegation).
- Pre-allocation (alloc)is recorded as `address → amount`.
- The mainnet genesis reconciliation invariants are in [15-lessons.md § R40.G](./15-lessons.md#155-r40g---genesis-reconciliation).

## 11.2 Node Configuration (`configs/`)

Key fields of `node.Config` ([node/config.go](../node/config.go)): 

```go
type Config struct {
    ChainID      uint64
    DataDir      string
    BlockTime    time.Duration   // block interval (default 3s)
    EpochLength  uint64          // number of slots per epoch (default 100)
    RPCAddr      string          // 127.0.0.1:8545
    WSAddr       string          // 127.0.0.1:8546
    P2PAddr      string          // :9000
    CommitAuthSecret string      // front-running-protection HMAC key
    ValidatorKeyPath string      // /var/lib/quantaureum/validator.key
    // ...
}
```

## 11.3 Network Topology

```
            ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
            │  Validator A  │   │  Validator B  │   │  Validator C  │
            │  (proposer)   │   │              │   │              │
            └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
                   │                  │                  │
                   └──────────┬───────┴──────────┬───────┘
                              │    gossipsub mesh   │
                    ┌─────────▼─────────┬─────────▼─────────┐
                    │  Full node (RPC)  │  Lightnode / Wallet│
                    └───────────────────┘────────────────────┘
```

- Validators communicate over mTLS-encrypted P2P (:9000, public).
- Wallets/full nodes access via HTTP/WS RPC (127.0.0.1:8545/8546).
- Health check `:8080/health` is exposed publicly.

## 11.4 Full Lifecycle of a Transaction

```
wallet (quantaureum-wallet)
  ├─ Dilithium3 client-side signing (tx-utils.ts)
  ├─ large amounts then qau_submitCommitment (commit-reveal)
  └─ eth_sendRawTransaction
        │
        ▼
node RPC (rpc/api.go) → txpool.ValidateTx
        │  signature/balance/nonce/commit-reveal validation
        ▼
txpool.Pending → BlockProducer selects transactions
        │
        ▼
core.BlockBuilder.BuildBlock (deterministic timestamp SetBlockTime)
        │
        ▼
qvm.Executor executes → receipts + state changes
        │
        ▼
consensus: proposer threshold signing (ThresholdKeySigner)→ broadcast
        │
        ▼
each validator validates BlockValidator.ValidateBlock → validates QTD multisig/state root
        │
        ▼
finality → persist (qaudb)→ wallet eth_getTransactionReceipt
```

## 11.5 RPC Return-Format Adaptation

- The node may return numbers directly rather than hex; the wallet normalizes with
  `hexifyResponse()` (see the wallet wiki).
- When adding a new read field, evaluate format drift.

## 11.6 Security Boundaries

| Boundary | Protection |
|------|------|
| Large transfers | commit-reveal front-running protection |
| Admin RPC | HMAC authentication (admin_* 401) |
| Private-key share export | allowed only on the devChain dev network |
| Transport | mTLS between validators |
| state | verkle commitment + state-root validation |
