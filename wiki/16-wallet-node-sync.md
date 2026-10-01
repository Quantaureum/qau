# 16 - Cross-Repository Coordination Reconciliation Checklist (Node ↔ Wallet)

> This document is the operational checklist for the **dual-side synchronization hard constraints**.
> Any change that touches any row in the tables below must be modified synchronously on the
> corresponding other side + tested on both sides, otherwise on-chain interop fails.
> Scope: the Quantaureum node repository and the quantaureum-wallet repository.

## 16.1 Six Core Dimensions (check before changing)

| # | Dimension | Node Side | Wallet Side | Synced? |
|---|------|--------|--------|-----------|
| 1 | ChainID | `genesis/*.json` (1668/1669/1333) | `shared/constants/network.ts` + `quantaureum.ts` | ☐ |
| 2 | RPC endpoints | `configs/*.json` | `QUANTAUREUM_RPC_ENDPOINTS` (`quantaureum.ts`) | ☐ |
| 3 | Signing algorithm | `crypto/dilithium.go` (circl Go) | `quantum-crypto/dilithium3.ts` + `dilithium3-circl.wasm` (circl→WASM) | ☐ |
| 4 | RPC methods | `rpc/api.go` / `qtd_api.go` registration | `QUANTAUREUM_RPC_METHOD_WHITELIST` (`network-controller-init.ts`) | ☐ |
| 5 | Return format | node may return numbers | `hexifyResponse()` converts to hex | ☐ |
| 6 | Token properties | QAU / 18 decimals / genesis 20M | `QUANTAUREUM_TOKEN` | ☐ |

## 16.2 Crypto Contract (highest priority)

| # | Item | Node Value | Wallet Value | Verified |
|---|-----|--------|--------|--------|
| 1 | Dilithium3 public key | 1952 B (`crypto/dilithium.go`) | 1952 (`wasm-types.ts` DILITHIUM3_PARAMS) | ☐ |
| 2 | Dilithium3 private key | 4000 B | 4000 | ☐ |
| 3 | Dilithium3 signature | 3293 B | 3293 | ☐ |
| 4 | Dilithium3 seed | 32 B | 32 | ☐ |
| 5 | Kyber768 public key | 1184 B | 1184 | ☐ |
| 6 | Kyber768 private key | 2400 B | 2400 | ☐ |
| 7 | Keystore encryption | AES-256-GCM | `quantum-encryptor.ts` | ☐ |
| 8 | Keystore KDF | scrypt N=2^18, r=8, p=1 | same-left | ☐ |
| 9 | Keystore prefix | `dilithium3:` | same-left | ☐ |
| 10 | HD derivation path | BIP-44 `m/44'/1668'/0'/0/{index}` | `QUANTAUREUM_HD_PATH` / keyring | ☐ |
| 11 | Address derivation | `sha3_256(pub)[12:32]` | `Dilithium3.deriveAddress` | ☐ |
| 12 | WASM/Go same-source | circl Go | circl→WASM (same version) | ☐ |

> **Key**: modifying any crypto constant requires a synchronized dual-side release, otherwise wallet keys
> become unusable on the node.

## 16.3 RPC Method Whitelist Reconciliation

When the node adds/removes any `qau_*` (or adds a standard `eth_*`)method:

- [ ] Node side: register in `rpc/api.go` / `qtd_api.go` with `RegisterHandler("method", api.X)`
- [ ] Node side: if an admin method, additionally `RegisterAdminMethod("method")`
- [ ] Node side: if a sensitive method (e.g. `qau_signQuantumTransaction`), add a QPS cap in `ratelimit.go`
- [ ] Wallet side: add the same-named method to `QUANTAUREUM_RPC_METHOD_WHITELIST`
- [ ] Wallet side: update `QUANTAUREUM_RPC_METHODS` in `shared/constants/quantaureum.ts` (if a constant name is needed)
- [ ] If the return contains numeric fields: the wallet-side `HEXIFY_FIELDS_*` of `hexifyResponse` covers the new field
- [ ] Add a row to the full table `14-rpc-surface.md`
- [ ] Run a smoke test on both sides: the wallet can call the method and get correct results

**Naming-rule self-check**:
- Standard JSON-RPC → `eth_*` (check go-ethereum source to confirm what is standard)
- Specific functionality → `qau_*`
- If a historically leftover `qau_`-prefixed standard method is found → immediately change it to `eth_*`

## 16.4 Front-Running Protection / Security Key Reconciliation

| # | Item | Node Side | Wallet Side | Synced? |
|---|-----|--------|--------|--------|
| 1 | commit-reveal key | `qaud --commit.auth.secret` (systemd drop-in) | `QUANTAUREUM_COMMIT_AUTH_SECRET` (`quantaureum.ts`) | ☐ |
| 2 | Large-transfer threshold | ≥1 QAU uses commit-reveal (txpool rejects direct sends) | large amounts use `qau_submitCommitment` | ☐ |
| 3 | Network lock | — | `ALLOWED_CHAIN_IDS` only 1668/1669/1333 | ☐ |
| 4 | Signature switches | — | `quantumSignatures:true` / `ecdsaSignatures:false` | ☐ |

> Modifying `QUANTAUREUM_COMMIT_AUTH_SECRET` must synchronize the node's systemd drop-in, 
> otherwise `qau_submitCommitment` returns 401.

## 16.5 Key Import / Unlock Reconciliation

- [ ] The wallet-exported key format (`dilithium3:` + hex)can be parsed by the node's `crypto/keystore.go`
- [ ] The node's `personal_importRawKey` and `personal_unlockAccount` passwords are consistent
- [ ] The address derived by the wallet's HD matches the address parsed by the node-side `qauctl validator info`
- [ ] The mnemonic → Dilithium3 seed algorithm is identical on both sides (HKDF domain-separation)

## 16.6 Final Pre-Release/Deployment Reconciliation

```bash
# Node side (R40.D red line)
cd the Quantaureum repo
go build ./...
go vet ./node/... ./cmd/qauctl/...
go test -timeout 180s ./node/ ./qvm/ ./qaudb/block/ ./encoding/
gofmt -l <touched files>

# Wallet side
cd the quantaureum-wallet repo
yarn lint
yarn test
```

- [ ] Both the node's and wallet's go.mod / package.json dependencies have been committed
- [ ] Files involving private keys/IPs/server information go into `.local-only/private/`
- [ ] Genesis reconciliation (mainnet) total equals the intended supply (see [15-lessons.md § R40.G](./15-lessons.md#155-r40g---genesis-reconciliation))
- [ ] `git status --short` on both sides contains only expected files; don't use `git add -A`

## 16.7 New Coordination-Dimension Checklist (when adding features)

For any new feature (e.g., adding sharding, bridges, staking methods)you must answer:

1. Which layer of the node does it belong to? (L1-L7 → assigned to the corresponding module)
2. Does it need a new RPC method? → follow the 16.3 whitelist reconciliation
3. Does it involve signing/keys? → follow the 16.2 crypto contract
4. Does it involve network/ChainID/token? → follow the 16.1 core dimensions
5. Does it involve security (front-running protection/permissions)? → follow the 16.4 security reconciliation
6. Does the wallet UI need a new page/entry point?

> A cross-repository feature is complete only after all items are checked.
