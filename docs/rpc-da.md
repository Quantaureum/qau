# DA RPC API Documentation (P4-2)

> Scope: the Quantaureum node repository
> Status: the existing methods are implemented; `qau_da_*` are P4-2 planned methods (DoD requires pre-specification)
> Related code: `rpc/qtd_api.go` · `rpc/stardust_api.go` · `rpc/api.go` · `rpc/auth.go`

---

## 1. Existing DA-Related RPC Methods

The following methods are already registered on the RPC Server and are directly related to DA (data availability) / TSS / consensus. Code search confirms that **no `qau_da_*` method currently exists**; DA capabilities are for now exposed indirectly through the TSS + QPOS status.

### 1.1 `qau_tss_status` — TSS Status Query

| Item | Content |
|----|------|
| Registration location | `rpc/qtd_api.go:49` |
| Handler | `TSSAPI.Status` |
| Permission | **public read-only** (already listed in `auth.go` PublicMethods) |
| Parameters | none (`params` may be an empty array `[]`) |
| Returns | `initialized`(bool), `threshold`(int), `totalShares`(int), `shareCount`(int), `hasThreshold`(bool); when the key is ready, additionally `publicKey`(hex) |

Request example:
```json
{"jsonrpc":"2.0","id":1,"method":"qau_tss_status","params":[]}
```
Response example:
```json
{"jsonrpc":"2.0","id":1,"result":{
  "initialized": true,
  "threshold": 2,
  "totalShares": 3,
  "shareCount": 3,
  "hasThreshold": true,
  "publicKey": "0x..."
}}
```

### 1.2 `qau_tss_getPublicKey` — TSS Group Public Key

| Item | Content |
|----|------|
| Registration location | `rpc/qtd_api.go:51` |
| Handler | `TSSAPI.GetPublicKey` |
| Permission | **public read-only** (PublicMethods) |
| Parameters | none |
| Returns | `publicKey`(hex); if not generated, returns `ErrCodeInternal: no public key available — run qau_tss_generateKeyShares first` |

Request/response example:
```json
{"jsonrpc":"2.0","id":2,"method":"qau_tss_getPublicKey","params":[]}
{"jsonrpc":"2.0","id":2,"result":{"publicKey":"0x..."}}
```

### 1.3 `qau_qposStatus` — QPOS Consensus Status (including the DA committee context)

| Item | Content |
|----|------|
| Registration location | `rpc/api.go:681` |
| Handler | `API.QPOSStatus` → `chainInfo.GetQPOSStatus()` (implemented in `node/adapters.go:663`) |
| Permission | **public read-only** (PublicMethods) |
| Parameters | none |
| Returns | `consensus`="QPOS", `slotDuration`, `slotsPerEpoch`, `currentSlot`, `currentEpoch`, `slotInEpoch`, `justifiedEpoch`, `finalizedEpoch`, `validatorCount`, `validators[]`, `currentProposer`, `epochSummary`, `finality`, `lastEpochRewards` |

> Note: `qpos_status` (lowercase with underscore) **does not exist**; the standard name is `qau_qposStatus`. In the future, the DA committee information could be extended in this structure via a `daCommittee` field.

### 1.4 Related QTD Sealing Methods (registered, but not DA-specific)

| Method | Registration location | Permission | Description |
|------|---------|------|------|
| `qau_tss_getSealStatus` | `stardust_api.go:76` | read-only handler, **not listed in PublicMethods** (requires API Key) | Queries the seal status by slot. Always returns the independent finality facts (`finalized`, `consensusSealFinalized`, `sealRecorded`, `canonical`, `canonicalState`, `epochFinalized`); a seal record adds `blockHash`/`sealerCount`/`sealedAt`; a seal in progress adds `pending`/`partialSigCount`/`requiredCount`/`completed`. See §1.5 for the field semantics |
| `qau_stardust_getDKGStatus` | `stardust_api.go:82` | read-only, **not listed in PublicMethods** | Returns `available`(bool), `reason`, or the DKG progress |
| `qau_tss_requestSeal` | `stardust_api.go:77-78` | **admin** | Externally triggers a QTD joint signature; parameters `{slot, blockHash, slotHex}` |
| `qau_tss_submitPartialSeal` | `stardust_api.go:79-80` | **admin** | Submits a partial signature |

> ⚠️ Finding: `qau_tss_getSealStatus` and `qau_stardust_getDKGStatus` are read-only queries but are not in PublicMethods, which is inconsistent with how `qau_tss_status` is handled. It is recommended to add them to the whitelist during P4-2 (see section 3).

### 1.5 QTD finality facts reported by the RPCs

`qau_stardust_getFinality` and `qau_tss_getSealStatus` report the finality of a slot as **independent facts** instead of one collapsed boolean. A QTD seal over a block that is not the canonical block of its slot is a quorum agreement, not a finality — collapsing the two made the node report a side-branch block as finalized.

Both endpoints read the status and the record as ONE snapshot (R24, 2026-10-29), and the consensus-layer boolean is derived from that same snapshot too (R26, 2026-10-30), so the fields of a single response can never mix two different records or two different moments.

| Field | `getFinality` | `getSealStatus` | Meaning |
|-------|---------------|-----------------|---------|
| `isFinalized` / `finalized` | yes | yes | The **block-level** answer: the sealed block is the canonical block of its slot. False when the canonical root is known and differs from the sealed hash — and also false while the root is unknown/unproven (a concurrent head switch, or a root not yet recorded): the fail-closed rule is `true` only for `canonicalState == matches` |
| `sealRecorded` | yes | yes | A threshold seal agreement exists for the slot. The agreement is kept even when its block is not canonical — it is the proof that the executive chamber reached quorum |
| `canonical` | yes | yes | The sealed block **is** the canonical root of the slot |
| `canonicalState` | yes | yes | `matches` (canonical), `differs` (provably a side-branch block) or `unknown` (the canonical root is not known yet). When the live per-slot root has been pruned (QPOS keeps only a few epochs of slot roots), the classification persisted with the seal record answers instead — a canonical seal stays `matches` and a side-branch seal stays `differs` after pruning (R24, 2026-10-29). Two cases override that fallback (R26/R28, 2026-10-30): a reorg that ABANDONS the slot — the new chain has no block there, or a different one — resets the persisted classification to `unknown` (the sealed block is no longer canonical), and a canonical-head switch observed between two root reads is reported as `unknown` for that one call rather than as a stale classification |
| `epochFinalized` | yes | yes | The QPOS consensus finality marker has reached the epoch that contains the slot. At epoch 0 this requires a named finalized root (the restored-checkpoint / genesis convention) |
| `consensusSealFinalized` | yes | yes | The **consensus-layer** view (R24, 2026-10-29): a seal agreement is recorded for the slot AND the epoch marker has caught up to the slot's epoch — the cross-check is performed for every epoch, epoch 0 included. It makes no claim about the canonical block: a side-branch seal never advances the marker itself, but the marker can still reach its epoch through other slots' canonical seals. Use the block-level answer to decide finality. Computed inside the same snapshot as the other fields (R26, 2026-10-30) |
| `blockHash`, `sealerCount`, `sealedAt` | yes | yes | The sealed record. `blockHash` is the block the agreement covers, which may be a side-branch block. `sealedAt` is the seal time as **Unix seconds (a JSON number)** in both endpoints (R24, 2026-10-29 — previously `getSealStatus` emitted an RFC3339 string) |
| `pendingBlockHash`, `pendingSealerCount` | – | yes | The seal that is still collecting signatures. Present only when a record and a pending seal coexist (a re-seal of a slot whose previous agreement covered a non-canonical block); the legacy `blockHash`/`sealerCount` keys stay bound to the record in that case |

`qau_tss_submitPartialSeal` (admin) reports the same `finalized` semantics as the block-level answer above (R24, 2026-10-29): the canonical block of the slot carries a threshold agreement.

A client must use the block-level answer (`isFinalized` / `finalized`) to decide whether a block is final, and the other fields to explain *why*. `qau_stardust_verifyFinality` follows the same split (R29, 2026-10-30): its `valid` field states only that the presented signature proves a threshold seal over the block, and it now reports `canonicalState` / `isFinalized` next to it so the two questions cannot be conflated.

The invalidation above is scoped to the abandoned range the node can actually observe (R29, 2026-10-30): the common-ancestor walk covers up to `maxReorgDepth` (64 slots), the range is bounded by the head switch that triggered it, and a reorg that reaches finalized history is refused outright instead of being applied. A record for a slot outside that range keeps the classification it was last given — `matches` there means "confirmed canonical the last time this node looked", not "re-confirmed after the latest head switch".

---

## 2. Future `qau_da_*` RPC Method Specifications (P4-2 Planning)

The following methods are planned APIs whose documentation is required to be pre-written by the P4-2 DoD. Naming follows the "proprietary methods use the `qau_*` prefix" convention. All methods are **read-only** and should all be listed in PublicMethods.

### 2.1 `qau_da_status` — DA Subsystem Status

| Item | Content |
|----|------|
| Parameters | none |
| Returns | `enabled`(bool), `committeeAvailable`(bool), `samplingConfidence`(float 0~1), `attestationCount`(int), `lastSlot`(hex), `mode`("full"\|"light") |
| Permission | public read-only |
| Implementation notes | Adds `DAAPI.Status`, aggregating the state of DAManager (to be created in P4-2); if there is no DAManager it returns `enabled:false` |

Request/response example:
```json
{"jsonrpc":"2.0","id":3,"method":"qau_da_status","params":[]}
{"jsonrpc":"2.0","id":3,"result":{
  "enabled": true,
  "committeeAvailable": true,
  "samplingConfidence": 0.98,
  "attestationCount": 3,
  "lastSlot": "0x1f4",
  "mode": "full"
}}
```

### 2.2 `qau_da_committee` — Current DA Committee

| Item | Content |
|----|------|
| Parameters | `[epoch?]` (optional; defaults to the current epoch if omitted) |
| Returns | `epoch`(hex), `members[]` (each item contains `validatorIndex`(int), `address`(checksummed hex), `subnetID`(int)) |
| Permission | public read-only |
| Implementation notes | Calls `QPOS.GetDACommittee(epoch)` (to be added at the consensus layer in P4-2); addresses must be checksummed |

Request/response example:
```json
{"jsonrpc":"2.0","id":4,"method":"qau_da_committee","params":["0x5"]}
{"jsonrpc":"2.0","id":4,"result":{
  "epoch": "0x5",
  "members": [
    {"validatorIndex": 0, "address": "0xB74A...313D0", "subnetID": 0},
    {"validatorIndex": 1, "address": "0xCf52...6B8c", "subnetID": 1}
  ]
}}
```

### 2.3 `qau_da_blobCount` — Number of Blobs for a Specified Slot

| Item | Content |
|----|------|
| Parameters | `[slot]` (hex or decimal number) |
| Returns | `slot`(hex), `blobCount`(hex), `totalBytes`(hex) |
| Permission | public read-only |
| Implementation notes | Calls `DAManager.GetBlobCount(slot)`; reuses `parseSlotParam` (`stardust_api.go`) to parse the slot |

### 2.4 `qau_da_attestations` — Collected Attestations for a Specified Slot

| Item | Content |
|----|------|
| Parameters | `[slot]` |
| Returns | `slot`(hex), `count`(hex), `attestations[]` (each item contains `validatorIndex`, `available`(bool), `signature`(hex)) |
| Permission | public read-only |
| Implementation notes | Calls `DAManager.GetAttestations(slot)`; does not expose attester private shares, only the aggregate signature and availability bitmap |

### 2.5 `qau_da_samplingResult` — DAS Sampling Result

| Item | Content |
|----|------|
| Parameters | `[slot]` |
| Returns | `slot`(hex), `available`(bool), `confidence`(float 0~1), `sampled`(hex), `required`(hex), `completedAt`(unix hex) |
| Permission | public read-only |
| Implementation notes | Calls `DASampler.GetResult(slot)`; when `confidence` is below the threshold, `available:false` |

Request/response example:
```json
{"jsonrpc":"2.0","id":5,"method":"qau_da_samplingResult","params":["0x1f4"]}
{"jsonrpc":"2.0","id":5,"result":{
  "slot": "0x1f4",
  "available": true,
  "confidence": 0.98,
  "sampled": "0x40",
  "required": "0x40",
  "completedAt": "0x6699aabb"
}}
```

---

## 3. Authentication and Permissions

The permission model is determined jointly by the `PublicMethods` whitelist and `RegisterAdminMethod` in `rpc/auth.go`:

- **Public read-only**: methods listed in `PublicMethods` do not require an API Key and are for external monitoring/wallet queries. All `qau_da_*` methods plus `qau_tss_status`, `qau_tss_getPublicKey`, and `qau_qposStatus` fall into this category.
- **API Key authentication**: non-admin methods not listed in PublicMethods (e.g., `qau_tss_getSealStatus`, `qau_stardust_getDKGStatus`) require `X-API-Key` + HMAC. It is recommended to add these two read-only methods to the whitelist.
- **Admin**: methods marked by `RegisterAdminMethod` (`qau_tss_generateKeyShares`, `qau_tss_getShare`, `qau_tss_signMessage`, `qau_tss_verifySignature`, `qau_tss_requestSeal`, `qau_tss_submitPartialSeal`) trigger signature/consensus write operations and require Admin authentication.
- **devMode restriction**: `qau_tss_getShare` exports raw shares and is only available on ChainID=1333 (devMode).

> The DA methods are all state queries with no side effects and **should not** be set to admin.

---

## 4. Return Format

- **Numbers**: all integers are returned as hex strings (e.g., `"0x1f4"`), compatible with the wallet's `hexifyResponse` (`controller-init/network-controller-init.ts`). On the Go side, use `fmt.Sprintf("0x%x", v)` or `hex.EncodeToString`.
- **Addresses**: returned as checksummed hex (EIP-55 mixed case), consistent with `currentProposer` in the existing `qau_qposStatus`.
- **Booleans/floats**: bool values are returned directly as `true`/`false`; ratios such as `confidence` are returned as floats.
- **Time**: Unix timestamps are returned as hex.
- **Errors**: uniformly use `NewError`/`NewErrorWithData`, with error codes following `ErrCodeInvalidParams`/`ErrCodeInternal`/`ErrCodeNotFound`/`ErrCodeUnauthorized`.

---

## 5. Synchronization with the Wallet Whitelist

After adding any new `qau_da_*` method, the wallet side must be synchronously updated:

- File: `QUANTAUREUM_RPC_METHOD_WHITELIST` in `quantaureum-wallet/shared/constants/quantaureum-only.ts`
- Principle: the node's `rpc/auth.go` PublicMethods and the wallet whitelist correspond **one-to-one**; when the node adds a public method, the wallet whitelist is appended in sync, otherwise wallet calls are blocked by its own whitelist.
- Currently pending synchronization items (after P4-2 is implemented):
  - `qau_da_status`
  - `qau_da_committee`
  - `qau_da_blobCount`
  - `qau_da_attestations`
  - `qau_da_samplingResult`
- Also fill in the missing ones: `qau_tss_getSealStatus`, `qau_stardust_getDKGStatus` (if decided to make public).

> One of the six-dimensional wallet-node coordination constraints is "RPC methods: node registration ↔ wallet whitelist sync"; any change on either side must be synchronized with the other.