# 09 - Wallet Multisig and QTD Threshold Signing

> This chapter describes the current wallet signing stack: multisig
> coordination in `wallet/multisig`, the threshold-signing manager in
> `wallet/tss`, and the GM-QTD protocol in `wallet/tss/qtd`.

## 9.1 Integration Path Overview

```text
wallet/multisig          proposal collection and execution policy
  -> wallet/tss          share management, signing sessions, aggregation
    -> wallet/tss/qtd    GM-QTD protocol, distributed DKG, and signing math
      -> crypto          GMQTD_Sign callback and Dilithium3 primitives
        -> node/adapters.go   consensus.ThresholdKeySigner adapter
          -> consensus        QPOS threshold sealing
            -> rpc            qau_tss_* and qau_stardust_* APIs
```

The layering is deliberate: `crypto` does not import `wallet/tss/qtd`.
`TSSManager` registers `qtd.GMQTD_SingleSign` with `crypto.SetQTDSingleSigner`
during construction, so the low-level crypto entry point can delegate upward
without creating a reverse dependency.

## 9.2 Multisig Wallet

The `wallet/multisig` package implements the wallet-side proposal lifecycle.
It is separate from QTD: a multisig wallet collects individual or combined
threshold signatures for a proposal, while QTD produces one group signature.

| File | Key exports | Responsibility |
|------|-------------|----------------|
| [wallet/multisig/wallet.go](../wallet/multisig/wallet.go) | `MultiSigWallet`, `ProposeTransaction`, `CollectSignature`, `CollectTSSSignature`, `IsReadyToExecute`, `Revoke`, `UpdateSigners` | Proposal lifecycle, signer policy, revocation, and signer-set updates |
| [wallet/multisig/config.go](../wallet/multisig/config.go) | `MultiSigConfig`, `TSSVerifier` | Wallet configuration and optional threshold-signature verification |
| [wallet/multisig/state.go](../wallet/multisig/state.go) | `MultisigStateStore`, `Proposal`, `WalletConfig` | Pending and executed proposal state, canonical hashes, serialization |
| [wallet/multisig/executor.go](../wallet/multisig/executor.go) | `MultiSigExecutor`, `Execute` | Policy-checked execution after enough signatures are collected |
| [wallet/multisig/signing.go](../wallet/multisig/signing.go) | `SigningSession`, `SignWithAccount`, `VerifySignature` | Individual-account signing and signature verification |
| [wallet/multisig/aggregator.go](../wallet/multisig/aggregator.go) | `MultiSigAggregator`, `VerifyMultiSigSignature` | Signature aggregation and threshold verification |

`GenerateMultiSigAddress` derives a deterministic address from the sorted
public keys and threshold. The order of the input keys therefore does not
change the resulting wallet address.

## 9.3 Threshold-Signing Manager

`wallet/tss` owns key-share import and export, participant signing sessions,
partial-signature aggregation, and verification against a group public key.

| File | Key exports | Responsibility |
|------|-------------|----------------|
| [wallet/tss/manager.go](../wallet/tss/manager.go) | `TSSManager`, `NewTSSManager`, `GroupPublicKey`, `CreateParticipantSession`, `CombineSignatures`, `SignWithRetry`, `ZeroizeAllShares` | Thread-safe share state, signing sessions, and cleanup |
| [wallet/tss/config.go](../wallet/tss/config.go) | `TSSConfig`, `DefaultTSSConfig`, `Validate` | Threshold and participant limits; rejects a threshold below 2 |
| [wallet/tss/types.go](../wallet/tss/types.go) | `KeyShare`, `PartialSignature`, `ValidateForBroadcast` | Share and partial-signature data contracts |
| [wallet/tss/dkg.go](../wallet/tss/dkg.go) | `GenerateKeyShares`, `GenerateKeySharesTrustedDealer`, `VerifyShare`, `ReconstructPublicKey` | Default and ceremony key-generation paths |
| [wallet/tss/dkg_transport.go](../wallet/tss/dkg_transport.go) | `DKGTransport`, `SetDKGTransport` | Transport abstraction for distributed DKG messages |
| [wallet/tss/distributed_signer.go](../wallet/tss/distributed_signer.go) | `DistributedSigner`, `DistributedSession`, `InitiateSession` | Two-round distributed signing and wire encoding |
| [wallet/tss/signing.go](../wallet/tss/signing.go) | `SignMessage`, `CombinePartialSignatures`, `VerifyCombinedSignature`, `VerifySignatureWithPublicKey` | Partial signing, aggregation, and verification |
| [wallet/tss/refresh.go](../wallet/tss/refresh.go) | `RefreshShares`, `AddParticipant`, `RemoveShare` | Share refresh and participant-set changes |

`TSSManager` supports encrypted share bundles. Plaintext export is disabled by
default and must be enabled explicitly by the process that owns the shares.
`ZeroizeAllShares` should be called when a manager no longer needs its
in-memory secret material.

### 9.3.1 Consensus Adapter

`TSSManager` does not directly implement `consensus.ThresholdKeySigner`.
The node layer provides the adapter in
[node/adapters.go](../node/adapters.go):

```go
type tssSignerAdapter struct {
    tss  *tss.TSSManager
    node *Node
}
```

The adapter implements the interface declared in
[consensus/threshold_signer.go](../consensus/threshold_signer.go):

- `SignBlock`
- `SignVote`
- `VerifyBlock`
- `VerifyVote`
- `GroupPublicKey`
- `IsThresholdMode`
- `AggregatePartialSignatures`

Block sealing uses `AggregatePartialSignatures`, not a single-signer
`SignBlock` call. This preserves the threshold guarantee: enough validators
must contribute partial signatures before the final group signature can be
produced.

## 9.4 GM-QTD Protocol

`wallet/tss/qtd` contains the threshold protocol and lattice-polynomial
implementation used by the manager.

| File | Key exports | Responsibility |
|------|-------------|----------------|
| [wallet/tss/qtd/qtd_protocol.go](../wallet/tss/qtd/qtd_protocol.go) | `QTDSession`, `Round1Commitment`, `Round2Reveal`, `QTDSignature` | Commit/reveal signing rounds and final signature assembly |
| [wallet/tss/qtd/qtd_dkg.go](../wallet/tss/qtd/qtd_dkg.go) | `QTDShare`, `QTDPublicKey`, `QTDManager`, `GenerateDKGShares` | Share representation, manager, and key-generation algorithms |
| [wallet/tss/qtd/dkg_runner.go](../wallet/tss/qtd/dkg_runner.go) | `DistributedDKGRunner` | Multi-round DKG message and result contracts |
| [wallet/tss/qtd/dkg_distributed.go](../wallet/tss/qtd/dkg_distributed.go) | `NewRealDistributedDKGRunner` | Concrete multi-round runner implementation |
| [wallet/tss/qtd/qtd_keys.go](../wallet/tss/qtd/qtd_keys.go) | `FullKeyShareFromMode3` | Extract a partial share from a mode3 key for ceremony tooling |
| [wallet/tss/qtd/qtd_refresh.go](../wallet/tss/qtd/qtd_refresh.go) | `RefreshDeltas`, `ApplyRefreshDeltas`, `AddParticipant`, `RemoveParticipant` | Share refresh, integrity checks, and resharing |
| [wallet/tss/qtd/qtd_security.go](../wallet/tss/qtd/qtd_security.go) | `PedersenVerifier`, `ShareIntegrityCheck`, `SecurelyZeroMemory` | Share verification, proof bundles, and secret cleanup |
| [wallet/tss/qtd/qtd_role_separation.go](../wallet/tss/qtd/qtd_role_separation.go) | `RoleAssignment`, `DeriveRoleAssignment` | Session-bound aggregation-role separation |

Role separation splits W, Z, and hint aggregation across distinct participants.
No single aggregator observes all transcript components required to reconstruct
secret key material. `Round2Reveal.IsPrivate` and
`PartialSignature.ValidateForBroadcast` are the transport-layer checks that
prevent private signing contributions from being broadcast.

## 9.5 RPC Surface

[rpc/qtd_api.go](../rpc/qtd_api.go) exposes manager operations:

| Method | Access | Description |
|--------|--------|-------------|
| `qau_tss_generateKeyShares` | Admin | Generate shares; responses expose share hashes, not raw shares |
| `qau_tss_getPublicKey` | Public | Return the current group public key |
| `qau_tss_getShare` | Admin and dev mode | Return a salted share hash; raw share export remains disabled outside dev mode |
| `qau_tss_signMessage` | Admin | Run threshold signing with bounded message and participant inputs |
| `qau_tss_verifySignature` | Admin | Verify a combined signature against the group key |
| `qau_tss_status` | Public | Report threshold, share count, and key availability |

[rpc/stardust_api.go](../rpc/stardust_api.go) exposes finality and seal
orchestration:

| Method | Access | Description |
|--------|--------|-------------|
| `qau_tss_getSealStatus` | Public | Report finalized state or pending partial-signature count |
| `qau_tss_requestSeal` | Admin | Request QTD sealing for an approved slot and block hash |
| `qau_tss_submitPartialSeal` | Admin | Submit an executive participant's partial seal |
| `qau_stardust_getDKGStatus` | Public | Report executive-chamber DKG status |

Public seal status intentionally reports counts rather than the concrete list
of submitting validator indices.

## 9.6 Threshold Parameters

`TSSConfig.Validate` requires:

- `Threshold >= 2`
- `TotalShares > 0`
- `Threshold <= TotalShares`
- `Threshold <= 100` and `TotalShares <= 100`

The default configuration is 3-of-5. Threshold selection is a liveness and
security tradeoff: it must remain high enough to require multiple independent
participants, but low enough for the validator set to make progress after
expected failures.
