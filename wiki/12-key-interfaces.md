# 12 - Key Interface Contracts

> Modules are decoupled through **interface contracts**; the vast majority of cross-layer
> dependencies are "interface dependencies" rather than "concrete-implementation dependencies".
> This table is the "wiring diagram" when adding a new module.

## 12.1 Interface Summary

| Interface | Defined At | Implementer | Injection Target |
|------|---------|--------|---------|
| `ThresholdKeySigner` | [consensus/threshold_signer.go:42](../consensus/threshold_signer.go#L42) | [wallet/tss.TSSManager](../wallet/tss/manager.go) | `QPOS.tssSigner` / `QTDFinalityState` |
| `QuantumSigner` | [types/types.go](../types/types.go) | `crypto.PrivateKey` | consensus / core signature validation |
| `ValidatorLookup` | [core/block_validator.go](../core/block_validator.go) | `consensus.ValidatorManager` | `core.BlockValidator` |
| `StateReader` | [rpc/api.go](../rpc/api.go) | `node/adapters.go` | `rpc.API` |
| `BlockReader` | [rpc/api.go](../rpc/api.go) | `node/adapters.go` | `rpc.API` |
| `ReceiptReader` | [rpc/api.go](../rpc/api.go) | `node/adapters.go` | `rpc.API` |

## 12.2 `ThresholdKeySigner` (QTD threshold signing)

```go
// consensus/threshold_signer.go:42
type ThresholdKeySigner interface {
    Sign(message []byte) ([]byte, error)
    Verify(message, sig []byte) bool
    PublicKey() []byte
}
```

- Implementer: `wallet/tss.TSSManager` (distributed threshold-signing orchestration).
- Use: QPOS block seal, QTDFinalityState finality endorsement.
- Benefit: consensus does not need to know whether the key is single-signed or threshold;
  solutions such as BLS can be swapped in the future.

## 12.3 `QuantumSigner`

```go
// types/types.go
type QuantumSigner interface {
    Sign(priv *crypto.PrivateKey, msg []byte) (*Signature, error)
    Verify(pub *crypto.PublicKey, msg []byte, sig *Signature) bool
    PublicKeyFromPrivate(priv *crypto.PrivateKey) *crypto.PublicKey
    Address(pub *crypto.PublicKey) Address
    SignatureSize() int // = 3293
}
```

- Implementer: `crypto.PrivateKey` (Dilithium3).
- Use: transaction signing/verification, consensus signature validation.

## 12.4 `ValidatorLookup`

```go
// core/block_validator.go
type ValidatorLookup interface {
    GetValidator(addr types.Address) (*Validator, bool)
    IsValidator(addr types.Address) bool
    ValidatorCount() int
}
```

- Implementer: `consensus.ValidatorManager`.
- Use: `core.BlockValidator` validates whether the proposer is in the validator set and verifies signatures.

## 12.5 StateReader / BlockReader / ReceiptReader

```go
// rpc/api.go
type StateReader interface {
    GetBalance(addr types.Address) (*big.Int, error)
    GetNonce(addr types.Address) (uint64, error)
    GetCode(addr types.Address) ([]byte, error)
    GetStorageAt(addr types.Address, key common.Hash) ([]byte, error)
}
type BlockReader interface {
    GetBlockByNumber(num uint64) (*encoding.Block, error)
    GetBlockByHash(hash types.Hash) (*encoding.Block, error)
}
type ReceiptReader interface {
    GetReceipt(txHash types.Hash) (*encoding.Receipt, error)
}
```

- Implementer: `node/adapters.go` (bridges storage/consensus to RPC).
- Use: keeps `rpc.API` from directly touching storage details.

## 12.6 Constraints and Discipline

1. Upper layers may depend on lower-layer interfaces; **reverse (concrete) dependencies are forbidden**.
2. `crypto` must not reference `consensus`/`rpc`.
3. A new module must explicitly state which layer it belongs to and which interfaces it depends on.
4. Modifying an interface's method set must synchronously update the implementer + all callers + related tests.