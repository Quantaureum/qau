# 01 - Overall Architecture

> Quantaureum node = quantum-secure L1 public-chain node. The code is organized
> along "seven layers", each layer may only use the APIs of the layers below it;
> **upward dependencies are forbidden**.

## 1.1 Seven-Layer Architecture Diagram

```text
┌─────────────────────────────────────────────────────────────────────┐
│ L7 Service Layer        rpc/   graphql/                            │
│   - JSON-RPC 2.0 + eth_* / qau_* / admin_* / personal_*            │
│   - HMAC auth / rate limiting / WebSocket / Subscriptions          │
└─────────────────────────────────────────────────────────────────────┘
                            ▲ Depends only on L6 "interface adapters" (not on concrete consensus impl)
┌─────────────────────────────────────────────────────────────────────┐
│ L6 Integration Layer    node/   txpool/                            │
│   node/    - Node orchestration, Adapters (StateReader/BlockReader/...)│
│            - block_producer / qtd_seal / snap_sync / shard_producer │
│   txpool/  - Tx pool: validation, commit-reveal, Pending/Queue     │
└─────────────────────────────────────────────────────────────────────┘
                            ▲
┌─────────────────────────────────────────────────────────────────────┐
│ L5 Consensus & Core      consensus/  core/                         │
│   consensus/ - QPOS / election / finality / QTD threshold signing / slashing / Danksharding │
│   core/      - BlockBuilder (deterministic block production)       │
│              - BlockValidator (full block validation flow)         │
└─────────────────────────────────────────────────────────────────────┘
                            ▲
┌─────────────────────────────────────────────────────────────────────┐
│ L4 Execution Layer       qvm/                                      │
│   - QVM: custom quantum-native bytecode VM (assembly = QASM)       │
│   - Account Abstraction (ERC-4337 EntryPoint)                      │
│   - JIT compiler (disabled by default, see executor.go:21 jitEnabled:false) │
└─────────────────────────────────────────────────────────────────────┘
                            ▲
┌─────────────────────────────────────────────────────────────────────┐
│ L3 Network & Economics   p2p/  economics/                          │
│   p2p/       - libp2p + gossipsub / mTLS / compact-block / snap    │
│   economics/ - staking / rewards / inflation / gas / governance / DeFi liquidity │
└─────────────────────────────────────────────────────────────────────┘
                            ▲
┌─────────────────────────────────────────────────────────────────────┐
│ L2 Storage Layer         qaudb/  encoding/  rlp/                   │
│   qaudb/    - bbolt persistence / state / cache / verkle trie      │
│   encoding/ - Block/Transaction/Receipt/Wire codec + DAS blobs     │
│   rlp/      - Ethereum-style RLP codec                              │
└─────────────────────────────────────────────────────────────────────┘
                            ▲
┌─────────────────────────────────────────────────────────────────────┐
│ L1 Crypto + Types        crypto/  types/  common/                  │
│   crypto/  - Dilithium3 / Kyber768 / GM-QTD Wrapper / Keystore     │
│   types/   - Address / Hash / Transaction / Block / *Signer interfaces │
│   common/  - atomic quantities / lock ordering / LRU cache         │
└─────────────────────────────────────────────────────────────────────┘
```

> Design rationale: **abstract at the bottom, compose at the top**.
> The consensus layer only calls the `ThresholdKeySigner`/`QuantumSigner` interfaces and
> **does not know** whether the key is Dilithium3, Shroomi, or GM-QTD;
> the network layer only calls `ValidatorLookup`/`StateReader` and **does not know**
> how QVM is executed.

## 1.2 Top-Level Directory Quick Reference

| Directory | Layer | Primary Responsibility | Key Packages/Entry Points |
|------|----|---------|-------------|
| `cmd/` | —  | All executable binary entry points | `cmd/qaud`, `cmd/qauctl`, `cmd/qasm`, `cmd/qau-cli` |
| `crypto/` | L1 | Cryptographic primitives | `dilithium.go`, `kyber.go`, `gmqtd_sign.go`, `keystore.go`, `batch_verify.go` |
| `types/` | L1 | Core types + interface contracts | `types.go` (`Address`, `Hash`, `QuantumSigner`, `Transaction`, `Receipt`), `multisig_v2.go`, `staking_v2.go` |
| `common/` | L1 | Atomic quantities, coexisting locks, LRU | `common.go`, `lock_order.go`, `lru/lru.go` |
| `qaudb/` | L2 | Storage abstraction | `db/db.go` interface, `db/boltdb.go`, `block/`, `state/state_db.go`, `cache/cache.go`, `trie/verkle.go` |
| `encoding/` | L2 | Codec | `block.go`, `transaction.go`, `receipt.go`, `wire.go`, `blob_tx.go`, `das.go`, `proto.go`, `validation.go` |
| `rlp/` | L2 | RLP codec | `rlp/*.go` |
| `consensus/` | L5 | Consensus | `qpos.go` (QPOS main struct), `election.go`, `finality.go`, `threshold_signer.go` (QTD interface), `validator.go`, `slashing.go`, `voting.go`, `shard.go`, `epoch.go`, `checkpoint.go`, `ministry.go`, `provinces.go`, `pqvrf.go`, `vrf.go`, `random_beacon.go`, `bls.go`, `sealed_bid.go`, `security.go`, `da_metrics.go` |
| `core/` | L5 | Block production/validation | `block_builder.go`, `block_validator.go`, `danksharding.go` |
| `qvm/` | L4 | Execution | `executor.go`, `qvm.go`, `call.go`, `opcodes.go`, `operations.go`, `gas.go`, `environment.go`, `entrypoint.go`, `evm_translate.go`, `jit_adapter.go`, `paymaster.go`, `validator.go`, `memory.go`, `stack.go` |
| `p2p/` | L3 | Network | `host.go`, `protocol.go`, `message.go`, `broadcast.go`, `connpool.go`, `mtls.go`, `crypto.go`, `snap_sync.go`, `das_protocol.go`, `ratelimit.go`, `peer_score.go`, `penalty.go`, `bloom.go`, `compact_block.go`, `compact_tx.go`, `compress.go` |
| `economics/` | L3 | Economics | `staking.go`, `rewards.go`, `defi.go`, `inflation.go`, `gas_fees.go`, `fee_distribution.go`, `governance.go`, `model/*` |
| `node/` | L6 | Integration | `node.go` (`Node`), `adapters.go` (bridging interfaces), `block_producer.go`, `qtd_seal.go`, `snap_sync.go`, `snapshot.go`, `syncer.go`, `config.go`, `genesis.go`, `dev_accounts.go`, `fee_history.go`, `history_expiry.go`, `shard_producer.go`, `da_r5_03_seed.go` |
| `txpool/` | L6 | Tx validation + queue | `pool.go`, `list.go`, `validator.go`, `executor.go`, `bundler.go` |
| `rpc/` | L7 | JSON-RPC service | `server.go`, `api.go`, `auth.go`, `ratelimit.go`, `websocket.go`, `qtd_api.go`, `quantum_api.go`, `multisig_api.go`, `defi_api.go`, `economics_api.go`, `bridge_api.go`, `rollup_api.go`, `governance_api.go`, `shard_api.go`, `blob_api.go`, `builder_api.go`, `proof_api.go`, `debug_api.go`, `fee_api.go`, `stardust_api.go`, `personal.go`, `advanced.go`, `access_list_api.go` |
| `graphql/` | L7 | GraphQL | `handler.go`, `schema.go`, `resolver.go`, `complexity.go`, `auth.go` |
| `light/` | — | Light node (disk) | `light_node.go`, `state_provider.go`, `das_provider.go` |
| `lightclient/` | — | SPV/bridge light client | `lightclient/*.go` |
| `wallet/multisig/` | — | Multisig wallet | `wallet.go`, `config.go`, `state.go`, `executor.go`, `signing.go`, `aggregator.go` |
| `wallet/tss/` | — | Threshold signing (QTD integration) | `manager.go` (`TSSManager`), `distributed_signer.go`, `dkg.go`, `dkg_ceremony.go`, `dkg_transport.go`, `signing.go`, `refresh.go`, `config.go`, `types.go` |
| `wallet/tss/qtd/` | — | GM-QTD protocol | `qtd_protocol.go`, `qtd_dkg.go`, `dkg_runner.go`, `dkg_distributed.go`, `qtd_keys.go`, `qtd_refresh.go`, `qtd_security.go`, `qtd_role_separation.go` (details in 09) |
| `params/` | — | Chain parameters | `config.go` (`ChainConfig`), `params.go` |
| `upgrade/` | — | Chain upgrade | `upgrade.go`, `governance.go` |
| `qauntvm/` | — | Experimental VM | (not integrated into the main path) |
| `rust/hsm-pq-native/` | — | Hardware crypto Rust layer | Only Rust submodule callable under CGO via `Makefile.rust-pq` |
| `sdks/` + `examples/` + `tools/` | — | SDK / examples / tools | see each directory |
| `genesis/` | — | Genesis JSON | `mainnet.json`, `testnet.json`, `dev.json` |
| `configs/` | — | Node configuration | `config.json`, `config.dev.json` |
| `contracts/` | — | Contract QASM sources | `*.qasm` (after build become `contracts/*.hex`, excluded by .gitignore) |

> Note: `.local-only/` is the isolated directory introduced by R50 and is
> **never tracked by git**; see [15-lessons.md](./15-lessons.md).

## 1.3 Process View: What Happens on Startup

```
main()                               cmd/qaud/main.go
  └── loadConfig()                   cmd/qaud/main.go:148
  └── resolveGenesis()               embed genesis/*.json
  └── ensureDevKeys()                dev-account fill
  └── logger.Setup()
  └── metrics.StartMetricsServer()   → /metrics (optional)
  └── node.New(cfg, logger)          node/node.go
        ├── open bbolt storage: qaudb/
        ├── prepare txpool / qvm / consensus
        └── wire adapters (Node → RPC ↔ consensus)
  └── node.Start(ctx)                node/node.go
        ├── p2p host start (gossipsub)
        ├── qpos.Start()             (Dilithium3 threshold keygen if validator)
        ├── blockProducer.Run()      → block-casting loop calling BlockBuilder.BuildBlock
        ├── rpc.Server.Start()       → 8545/8546 (registers eth_* + qau_*)
        └── graphql up (optional)
  └── browser/wallet                → JSON-RPC → rpc/api.go Handler → StateReader/BlockReader
                                              → TxPool / QVM execution
                                              → BlockBuilder → QPOS consensus → KV persist
```

## 1.4 Module Dependency Matrix

> Key rule: upper layers depend on lower-layer interfaces; lower layers **never**
> import upper layers.

```
                  ┌──────────┐
                  │  types/  │ ◁──┐
                  │  common/ │ ◁──┤
                  └────▲─────┘    │
                       │          │
   ┌───────────────────┼──────────┼─────────────┐
   │                   │          │             │
┌──┴───┐         ┌─────┴────┐  ┌──┴───┐   ┌─────┴──────┐
│crypto│         │ encoding │  │ qvm/ │   │ economics/ │
└──▲───┘         └─────▲────┘  └──▲───┘   └─────┬──────┘
   │                   │          │             │
   │      ┌────────────┴────┐     │             │
   │      │  qaudb/         │     │             │
   │      │   db            │     │             │
   │      │   block         │     │             │
   │      │   state         │     │             │
   │      │   trie (verkle) │     │             │
   │      │   cache         │     │             │
   │      └────────┬────────┘     │             │
   │               │              │             │
   │   ┌─────┬─────┴──────┐       │             │
   │   │ core│  txpool/   │       │             │
   │   └──┬──┴─────┬──────┘       │             │
   │      │        │              │             │
   │   ┌──┴────────┴──┐    ┌──────▼──────┐      │
   │   │ consensus/   │    │  p2p/       │      │
   │   └──────▲───────┘    └──────┬──────┘      │
   │          │                   │             │
   │   ┌──────┴───────────────────▼──────────┐  │
   │   │  node/  (adapters + Node + qtd_seal)│  │
   │   └──────▲───────────────────────────────┘  │
   │          │                                  │
   │   ┌──────┴──────┐            ┌──────────┐   │
   └───┤  rpc/       ├────────────┤ graphql/ │◁──┘
       └─────────────┘            └──────────┘
```

| Upper ↓ / Lower → | crypto | types | common | encoding | qaudb | qvm | consensus | core | txpool | p2p | economics | node | rpc |
|----------------|--------|-------|--------|----------|-------|-----|-----------|------|--------|-----|-----------|------|-----|
| consensus      | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | — |  | | ✔ | | | |
| core           | ✔ | ✔ | | ✔ | ✔ | ✔ | ✔ | — | | | | | |
| node           | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | — | |
| rpc            | | ✔ | | ✔ | ✔ | | | | | | ✔ | ✔ | — |
| txpool         | ✔ | ✔ | | ✔ | | | | | — | ✔ | | | |
| p2p            | ✔ | ✔ | | ✔ | | | | | | — | | | |
| qvm            | ✔ | ✔ | | ✔ | ✔ | | | | | | | | |

> The full "why this direction is allowed" is explained via interface decoupling in
> [12-key-interfaces.md](./12-key-interfaces.md).

## 1.5 Key Runtime Constants (remember before writing code)

| Name | Value | Defined At |
|------|---|---------|
| Dilithium3 `PublicKeySize` | 1952 B | [crypto/dilithium.go#L21](../crypto/dilithium.go#L21) |
| Dilithium3 `PrivateKeySize` | 4000 B | [crypto/dilithium.go#L22](../crypto/dilithium.go#L22) |
| Dilithium3 `SignatureSize` | 3293 B | [crypto/dilithium.go#L23](../crypto/dilithium.go#L23) |
| Dilithium3 `SeedSize` | 32 B | [crypto/dilithium.go#L24](../crypto/dilithium.go#L24) |
| Keystore | AES-256-GCM | [crypto/keystore.go#L31-L43](../crypto/keystore.go#L31-L43) |
| scrypt | N=2^18, r=8, p=1 | [crypto/keystore.go#L34-L36](../crypto/keystore.go#L34-L36) |
| Mainnet ChainID | 1668 | `genesis/mainnet.json` |
| Testnet ChainID | 1669 | `genesis/testnet.json` |
| Devnet ChainID | 1333 | `genesis/dev.json` |
| BIP-44 coin_type | 1668 (`= mainnet chainID`) | wallet + BIP-44 metadata |
| QAU total supply | 20,000,000 QAU (18 decimals) | `quantum_api.go` etc. |
| Genesis pre-allocation | 20,000,000 QAU | sum of `genesis/mainnet.json` alloc |
| Block interval (default) | 3 seconds | `node.Config.BlockTime` / `qpos.go:180` |
| Epoch length | 100 slots | `node.Config.EpochLength` / `qpos.go:181` |

## 1.6 Main In-Process "Singletons"

- `node.Node` — the root coordinator of the whole node; only created and Started in `cmd/qaud/main.go`.
- `consensus.QPOS` — consensus state machine (thread-safe via `mu sync.RWMutex`).
- `txpool.TxPool` — in-memory tx pool (production for pending orders + commit-reveal constraint).
- `qvm.VM` — invoked by qvm.Executor; one per node.
- `core.BlockBuilder` / `core.BlockValidator` — one held each within the `node` factory.
- `rpc.Server` / `rpc.API` / `rpc.QTDSealAPI` / `rpc.TSSAPI` — the RPC bus.

## 1.7 Key Hidden Rules

1. **No reverse dependencies allowed** (`crypto` must not import `consensus`/`rpc`).
2. **`node/` is the only integration layer "allowed to depend on all modules"**. Other modules may depend only on lower-layer interfaces.
3. **Files involving real addresses/IPs/keys must go into `.local-only/`**,
   see the R50 section of [15-lessons.md](./15-lessons.md#157-r50---public-repository-hygiene).
4. **Every commit must pass the full R40.D run** (see [13-build-test-deploy § 4](./13-build-test-deploy.md#134-mandatory-pre-commit-self-check-r40d-red-line)).
5. **Wallet-node "same-source" crypto implementation** (same circl version) — upgrading circl/circl-wasm on
   either side requires an equivalent upgrade on the other side and comparison of all keygen + sign + verify test vectors.
