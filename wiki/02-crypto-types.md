# 02 - L1 Crypto Layer — `crypto/` `types/` `common/`

> The "root of trust" for the entire Quantaureum node: all signatures, keys, and
> address definitions originate here. Every crypto constant in the wallet (TS)
> must align with this directory, otherwise the two sides' keys cannot interoperate.

## 2.1 `crypto/` — Quantum Primitives and Keystore

| File | Key Exports | Responsibility |
|------|---------|------|
| [crypto/dilithium.go](../crypto/dilithium.go) | `PublicKeySize=1952`, `PrivateKeySize=4000`, `SignatureSize=3293`, `SeedSize=32`, `PrivateKey`, `PublicKey`, `GenerateKey()` / `GenerateKeyFromSeed(seed)` / `Sign/Verify` | Thin wrapper around the Dilithium3 algorithm (based on `cloudflare/circl`); the single entry point for all signing/verification |
| [crypto/kyber.go](../crypto/kyber.go) | `KyberPrivateKey/ PublicKey` / KEM `Encapsulate/Decapsulate` | Kyber768 (NIST FIPS 203) key encapsulation |
| [crypto/batch_verify.go](../crypto/batch_verify.go) | Batch verification utility | Heavily reused by the consensus driver |
| [crypto/gmqtd_types.go](../crypto/) | `GMQTD_PrivateKey`, `GMQTD_PublicKey`, `GMQTD_GroupPubKey` | Native GM-QTD threshold-signing types |
| [crypto/gmqtd_sign.go](../crypto/gmqtd_sign.go) | `GMQTD_Sign`, `GMQTD_Verify` etc. | GM-QTD signing API invoked by both wasm / native sides |
| [crypto/keystore.go](../crypto/keystore.go) | `EncryptPrivateKey(priv,password)` / `DecryptPrivateKey(file bytes,password)` | AES-256-GCM + scrypt(N=2^18,r=8,p=1); format `dilithium3:` + hex priv + hex pub |
| [crypto/sign.go](../crypto/sign.go), `verify.go` | `Sign/Verify` convenience entry points | Serialize + call dilithium |
| [crypto/generate.go](../crypto/generate.go) | `GenerateKeyFromSeed` | Derive the master key from a mnemonic |
| [crypto/logger.go](../crypto/logger.go) | Audit logger | Logs critical key operations |

> **End-to-end requirement**: byte-size constants related to "crypto" in the
> source are centralized in `dilithium.go`, and only the `QuantumSigner` interface
> in `types/` specifies how they are used. Any idea to "add another parameter"
> must first return to this directory to check whether existing constants can be reused.

### 2.1.1 PrivateKey Internal Structure

- Length is **4000 bytes** (circl `dilithium3.PrivateKey`); the serialized version is the
  hexadecimal of `dilithium3:8B salt + 32B nonce + [priv+pub encrypted]`.
- **The public key is automatically derived from the private key** — legacy fields left
  over from serialization are ignored.
- Derivation rule: `Address = sha3_256(pubKey)[12:32]` (EVM-compatible length).

### 2.1.2 Keystore Encrypt/Decrypt Flow

```
password
   │
   ▼
scrypt(pass=password, salt=random 8B, N=2^18, r=8, p=1, dkLen=32) → aesKey
   │
   ▼
AES-256-GCM(key=aesKey, nonce=random 12B)                          → ciphertext
   │
   ▼
serialize as "dilithium3:" + hex(salt) + hex(nonce) + hex(ciphertext)
```

> Kept in sync with the wallet-side `quantum-encryptor.ts` implementation; both sides
> share the same scrypt/AES parameters. Changing N=2^18 would break interop between
> the two sides and must be released in a synchronized dual-side release.

## 2.2 `types/` — Blockchain Base Types + Interface Contracts

| File | Main Exports | Notes |
|------|---------|------|
| [types/types.go](../types/types.go) | `Address`, `Hash`, `BlockHeader`, `Transaction`, `Receipt`, `Log`, `Account`, `QuantumSigner` | The "single source of truth" for all cross-module shared structures |
| [types/multisig_v2.go](../types/multisig_v2.go) | Multisig types | Shared by the multisig implementation |
| [types/staking_v2.go](../types/staking_v2.go) | Staking types | Reused by `economics/staking.go` |

### 2.2.1 Quantum Signer (`QuantumSigner`)

Defined in [types/types.go](../types/types.go)

```go
type QuantumSigner interface {
    Sign(priv *crypto.PrivateKey, msg []byte) (*Signature, error)
    Verify(pub *crypto.PublicKey, msg []byte, sig *Signature) bool
    PublicKeyFromPrivate(priv *crypto.PrivateKey) *crypto.PublicKey
    Address(pub *crypto.PublicKey) Address
    SignatureSize() int           // = crypto.SignatureSize = 3293
}
```

> Upper layers (consensus/core/txpool) **only hold the `QuantumSigner` interface**
> and do not directly reference the concrete types of `crypto/dilithium`. This way,
> when a second implementation appears in the future (e.g., HSM mode), only the
> implementation needs to be swapped.

### 2.2.2 Core Type List

```
Address     [20]byte
Hash        [32]byte
Transaction Supports multiple types + Dilithium3 signature
Receipt     Transaction receipt (logs, status, gasUsed, effectiveGasPrice)
Log         EVM-style log (reserved for QVM / cross-chain bridge)
Account     Account structure: balance + Nonce + CodeHash + StorageRoot
```

**Signatures are strongly bound to the payload**: when `Transaction` is serialized,
the Dilithium3 public key and signature are packed together into the wiretx, so that
the node can re-verify without depending on an external database.

## 2.3 `common/` — Atomic Quantities / Lock Ordering / LRU

- `common.go`: base types `Atomic*`, byte comparison utilities.
- `lock_order.go`: defines the lock-order of all mutexes in the system, used for
  cross-lock static analysis via `go vet` + custom tests.
- `lru/lru.go`: LRU cache (used by `qaudb/cache` and `p2p/bloom.go`).

## 2.4 "Hard Constraints" for Coordination with the Wallet Side

| Constraint | Description | Wallet-Side File |
|------|------|-----------|
| Byte sizes | 1952 / 4000 / 3293 / 32 | `quantaureum-wallet/app/scripts/lib/quantum-crypto/dilithium3.ts` |
| scrypt parameters | N=2^18, r=8, p=1 | `quantaureum-wallet/app/scripts/lib/quantum-crypto/quantum-encryptor.ts` |
| Keystore prefix | `dilithium3:` | wallet keystore serialization |
| HD derivation | `m/44'/1668'/0'/0/{index}` | `quantaureum-wallet/.../quantum-hd-keyring.ts` |
| Address derivation | `sha3_256(pub)[12:32]` | wallet `Dilithium3.deriveAddress` |
| Signed message | BLAKE3(tx) + chainID | `cmd/qaud`, wallet `tx-utils.ts` |

## 2.5 When Tests Must Be Added

Any modification to functions in this layer (especially `dilithium.go` and `keystore.go`)
must add:
- Unit tests (covering normal + boundary + error cases)
- If serialization, derivation, or keystore handling changes, extend the focused
  tests in [crypto/generate_verify_test.go](../crypto/generate_verify_test.go) and
  [crypto/keystore_test.go](../crypto/keystore_test.go). Account-level derivation
  has additional coverage in `cmd/qau-cli/account_create_test.go`.

## 2.6 Known Prohibitions

| Prohibition | Reason |
|------|------|
| Changing the `PrivateKeySize / PublicKeySize / SignatureSize` constants | The entire ecosystem immediately becomes non-interoperable |
| Adding more "global loggers" above `crypto/` | This layer may only perform pure function computation |
| `types` must not depend on `consensus` / `qvm` | Types must be forward-compatible for all modules |
| Printing the private key with `fmt.Sprintf("%x", priv)` | Always treated as a security audit failure |
