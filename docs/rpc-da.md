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
| `qau_tss_getSealStatus` | `stardust_api.go:73` | read-only handler, **not listed in PublicMethods** (requires API Key) | Queries seal status by slot: `slot`/`finalized`; when complete includes `blockHash`/`sealerCount`/`sealedAt`; when in progress includes `pending`/`partialSigCount`/`requiredCount`/`completed`/`sealers` |
| `qau_stardust_getDKGStatus` | `stardust_api.go:79` | read-only, **not listed in PublicMethods** | Returns `available`(bool), `reason`, or the DKG progress |
| `qau_tss_requestSeal` | `stardust_api.go:74-75` | **admin** | Externally triggers a QTD joint signature; parameters `{slot, blockHash, slotHex}` |
| `qau_tss_submitPartialSeal` | `stardust_api.go:76-77` | **admin** | Submits a partial signature |

> ⚠️ Finding: `qau_tss_getSealStatus` and `qau_stardust_getDKGStatus` are read-only queries but are not in PublicMethods, which is inconsistent with how `qau_tss_status` is handled. It is recommended to add them to the whitelist during P4-2 (see section 3).

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