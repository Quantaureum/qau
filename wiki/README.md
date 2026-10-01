# Quantaureum Node - Code Wiki

> Quantaureum is an **independent quantum-secure Layer 1 public chain**, not an Ethereum fork.
> This Wiki systematically reviews the architecture, modules, dependencies, and operation of the node-side source code.

- Code root: the Quantaureum node repository
- Module path: `github.com/quantaureum/qau` (see [go.mod](../go.mod))
- Go version: `1.26.x` (see [go.work](../go.work), root module uses 1.26.3, sub-modules minimum 1.26.0)
- Consensus mechanism: **QPOS** (Quantum Proof of Stake)
- Quantum cryptography: **Crystals-Dilithium3** (NIST FIPS 204, signing) + **Crystals-Kyber768** (NIST FIPS 203, KEM)
- Native token: **QAU**, 18 decimals, genesis pre-allocation 20,000,000 QAU
- Chain IDs: mainnet `1668` / testnet `1669` / devnet `1333`

---

## 1. Document Navigation

| Chapter | Content |
|------|------|
| [01-architecture.md](./01-architecture.md) | Seven-layer architecture overview / module dependency direction / top-level repo directory explanation |
| [02-crypto-types.md](./02-crypto-types.md) | L1 crypto layer: `crypto/`, `types/`, `common/` |
| [03-storage.md](./03-storage.md) | L2 storage layer: `qaudb/` (bbolt/verkle/state/cache), `encoding/`, `rlp/` |
| [04-vm.md](./04-vm.md) | L4 execution layer: `qvm/` (QVM executor + QASM) + EntryPoint/AA |
| [05-consensus-core.md](./05-consensus-core.md) | L5 consensus layer: `consensus/` (QPOS, election, finality, threshold signing, sharding) + `core/` (BlockBuilder / BlockValidator) |
| [06-network.md](./06-network.md) | L3 network layer: `p2p/` (gossipsub, mTLS, compact tx), `economics/` (staking, rewards, DeFi, governance) |
| [07-rpc.md](./07-rpc.md) | L7 service layer: `rpc/` (`eth_*` / `qau_*` routing, HMAC auth, rate limiting, WebSocket, Subscriptions), `graphql/` |
| [08-integration.md](./08-integration.md) | L6 integration layer: `node/` (adapters, Node, QTD Seal, snap sync, sharding wiring) + `txpool/` |
| [09-wallet-tss.md](./09-wallet-tss.md) | Wallet multisig, threshold-signing manager, and GM-QTD protocol |
| [10-entrypoints.md](./10-entrypoints.md) | All binaries under `cmd/` (`qaud`, `qauctl`, `qasm`, `qau-cli`, …) and one-command startup methods |
| [11-runtime-protocol.md](./11-runtime-protocol.md) | Data flow (block production/transactions/signing/persistence), network topology, genesis and configuration |
| [12-key-interfaces.md](./12-key-interfaces.md) | Interface contracts: `ThresholdKeySigner` / `QuantumSigner` / `ValidatorLookup` / `StateReader` / `BlockReader` |
| [13-build-test-deploy.md](./13-build-test-deploy.md) | Build, test, lint, security audit, deployment (incl. a Makefile target quick reference) |
| [14-rpc-surface.md](./14-rpc-surface.md) | Full table of `eth_* / qau_* / net_* / web3_* / txpool_* / personal_* / admin_*`, incl. public/Admin markers |
| [15-lessons.md](./15-lessons.md) | Important fixes: R40-DEPLOY, R40-A/R40.B/R40.R, R41-KEYFILE-FIX, R50-OPEN-SOURCE |
| [16-wallet-node-sync.md](./16-wallet-node-sync.md) | **Cross-repository coordination reconciliation Checklist**: node ↔ wallet dual-side sync hard constraints |

> Purpose of the chapter index: to let you **start from the problem** rather than from the directory.
> When you read the module chapters 02-09, you'll see a three-part description of
> "how to locate the code / entry symbols / main artifacts".

---

## 2. One-Minute Overview

```text
command-line input              dependencies (inner→outer)
─────────────  →  ───────────────────────────────────────────────
qaud (cmd/qaud)   →  node.Node (integration layer)
        │
        ▼
                  ┌──────────────────────────────┐
                  │ L7 rpc/graphql               │
                  │ L6 node/adapters (integration)│
                  │ L5 consensus (QPOS + QTD)    │
                  │  + core (BlockBuilder)       │
                  │  + txpool                    │
                  │ L4 qvm (quantum-native VM)   │
                  │ L3 p2p + economics           │
                  │ L2 qaudb (bbolt/verkle)      │
                  │ L1 crypto / types / common   │
                  └──────────────────────────────┘
```

The "wallet" is a separate repository: quantaureum-wallet (TypeScript/React, a MetaMask fork).
The two are tightly coupled via **JSON-RPC (8545/8546) + Dilithium3 cryptographic same-source**, see
the cryptographic contracts in [02-crypto-types.md](./02-crypto-types.md).

---

## 3. 30-Second Quick Start (shortest path)

```bash
# 1. Install Go 1.26+ (see INSTALL_GO.md)
go version        # expected: go1.26.x

# 2. Start a local private chain with one command (in-memory, no files)
go run ./cmd/qaud

# 3. Open a new terminal and probe with RPC
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

If you need file persistence + block production, use `make build` and start with a config instead;
see [13-build-test-deploy.md § 3](./13-build-test-deploy.md#133-run-modes).

---

## 4. Essential "Big Picture": Two-Way Coupling

| Dimension | Node (this repo) | Wallet (`quantaureum-wallet`) | Sync Requirement |
|------|----------------|------------------------------|----------|
| ChainID | `genesis/*.json` → `config.ChainID` | `shared/constants/quantaureum.ts` | must match |
| Signing algorithm | `crypto/dilithium.go` (circl Go) | `lib/quantum-crypto/dilithium3.ts` (circl→WASM) | same-source same-version |
| Public/private key sizes | 1952 / 4000 / 3293 bytes | same-left | must not drift |
| Keystore | `crypto/keystore.go` (AES-256-GCM + scrypt N=2^18) | same format serialization prefix `dilithium3:` | must be mutually importable |
| HD derivation | `m/44'/1668'/0'/0/{index}` | same-left | coin type = mainnet ChainID |
| RPC methods | `RegisterHandler("...")` in `rpc/api.go` | whitelist in `network-controller-init.ts` | new `qau_*` dual-side sync |
| Return format | node may return numbers directly | wallet `hexifyResponse()` converts to hex | fields must be complete |
| Token properties | QAU/18 decimals/20M genesis | `QUANTAUREUM_TOKEN` | must match |

**Any change** affecting any of the above rows requires a **dual-side synchronized PR**, otherwise
on-chain interop fails.

---

## 5. How to "Find Answers" in the Wiki

- Want to understand "**how the node produces blocks**" → first see [architecture](./01-architecture.md) → then
  the QPOS chapter of [consensus](./05-consensus-core.md) + [node/qtd_seal](./08-integration.md).
- Want to understand "**how a transaction goes from a client to the chain**" →
  [this wiki's txpool / rpc](./07-rpc.md) → [p2p broadcast](./06-network.md).
- Want to understand "**the end-to-end lifecycle of a Dilithium3 private key**" →
  [keystore flow](./02-crypto-types.md#212-keystore-encryptdecrypt-flow) →
  [wallet multisig and TSS](./09-wallet-tss.md).
- Want to understand "**which JSON-RPC methods the node exposes**" → look directly at
  [the rpc-surface full table](./14-rpc-surface.md).
- Before changing code → read [build-test-deploy § pre-commit self-check](./13-build-test-deploy.md#134-mandatory-pre-commit-self-check-r40d-red-line)
  before starting implementation.

---

## 6. Documentation Maintenance Conventions

- This wiki **must stay correct against the code**: after every structural change run `make full`, so the
  line numbers / function signatures / routing methods / dependency directions above do not go stale.
- References to specific code uniformly use the **line-number** format (supported by both VSCode / GoLand):
  `[dilithium.go](../crypto/dilithium.go#L21-L23)`.
- When adding a module:
  1. Append a "module location/entry/dependencies" subsection under any of 02-09;
  2. Add a row to the dependency-matrix table in [01-architecture.md](./01-architecture.md#14-module-dependency-matrix);
  3. Supplement [14-rpc-surface.md](./14-rpc-surface.md) if applicable (if there are RPC endpoints).
