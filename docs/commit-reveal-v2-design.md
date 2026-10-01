# Commit-Reveal V2 Design

- Status: approved
- Date: 2026-08-26
- Scope: node, wallet clients, and deployment tooling
- Deployment model: new genesis and fresh chain data

## 1. Background and Motivation

The previous commitment design kept commitments outside the transaction
system. It required a shared HMAC secret, local replay caches, brute-force
lockouts, in-memory commitment tables, and a separate commitment broadcast
path. That duplicated transaction security and made multi-node consistency
harder to reason about.

CRV2 represents a commitment as a micro-transaction. Existing transaction
security and consensus propagation therefore cover the commitment lifecycle:

| Previous problem | CRV2 behavior |
|---|---|
| Secret distribution | Removed; the transaction signature identifies the sender |
| Address impersonation | Rejected by the standard signature check |
| Sybil mass spam | Bounded by transaction gas and admission checks |
| In-memory commitment tables | Replaced by an on-chain commitment index |
| Multi-node consistency | Handled by block propagation and consensus |
| Replay and substitution | Bounded by nonce and signature validation |

## 2. Core Design

### 2.1 Commitment Transaction

```go
CommitType TransactionType = 0x06
```

| Field | Value |
|---|---|
| Type | `0x06` |
| Nonce | The sender's normal transaction nonce |
| ChainID | The destination chain ID |
| To | The zero address |
| Value | `0` |
| Data | The 32-byte commitment hash |
| GasLimit | A small fixed value |
| Signature / PublicKey | A standard Dilithium3 signature |

The transaction uses the normal signature, nonce, balance, and chain-ID
validation path. Execution deducts gas and increments the nonce, but makes no
other state change.

### 2.2 Commitment Binding

```text
commitHash = SHA3(recipient || value || salt)
```

`recipient` is the 20-byte address, `value` is the 32-byte big-endian amount,
and `salt` is 32 random bytes.

The reveal transaction is a transfer at or above the threshold. Its `Data`
field contains the salt. The transaction pool checks that the sender has an
unconsumed, unexpired on-chain commitment whose hash matches the recipient,
value, and salt.

Binding the commitment to business content avoids a circular hash dependency:
the reveal nonce depends on the commitment consuming a nonce first, so the
reveal transaction hash cannot be known when the commitment is created.

### 2.3 Lifecycle

```text
commitment transaction
        |
        v
 included and indexed
        |
        v
reveal transfer with salt
        |
        v
 commitment consumed

unrevealed commitment expires after the configured window
```

An expired commitment loses only its gas cost.

### 2.4 Threshold

`ThresholdValue = 10 QAU` (`10^19` wei). Transfers below the threshold do not
require commit-reveal. Contract calls are not affected by this mechanism.

The threshold is defined centrally so networks can tune it without changing
the transaction format.

## 3. Component Changes

### 3.1 Node

Added:

- `types`: `CommitType=0x06`, validity checks, encoding, and decoding.
- `encoding/transaction.go`: commitment transaction encoding and decoding.
- `txpool`: commitment admission, reveal verification, and an on-chain
  commitment index.
- `core`: commitment execution semantics.
- `rpc`: submission through the standard raw-transaction endpoint.

Removed:

- The old `qau_submitCommitment` endpoint.
- Commitment HMAC authentication, replay caches, and secret handling.
- Dedicated commitment P2P messages and backfill logic.
- The `COMMIT_AUTH_SECRET` environment variable.

### 3.2 Mobile Wallet

- Build a commitment transaction and a salt-bearing reveal transaction.
- Send the commitment, wait for inclusion, then send the reveal.
- Remove the old commitment-secret UI and credential handling.
- Keep the combined history view and test vectors aligned with the new
  transaction layout.

### 3.3 Wallet Extension

- Remove the old commitment-secret header and environment variable.
- Submit commitment transactions through the standard transaction endpoint.
- Keep displayed token supply constants synchronized with chain
  configuration.

### 3.4 Deployment Tooling

Genesis generation must support the CRV2 threshold. Deployment tooling must
produce a new binary and a new genesis without retaining incompatible chain
data.

## 4. Validation Requirements

### 4.1 Single-Node Integration

A single-node integration network must verify:

1. A threshold transfer completes the commitment and reveal sequence.
2. A threshold transfer without a commitment is rejected at admission.
3. A below-threshold transfer is admitted directly.
4. A reveal with an already consumed commitment is rejected.
5. A commitment expires after the configured window.
6. Commitment encoding, authorization, execution, and indexing all recognize
   `TxTypeCommit`.

### 4.2 Multi-Node Consistency

A multi-node test network must verify:

1. A commitment submitted to one RPC endpoint and a reveal submitted to a
   different endpoint are both accepted after the commitment block is applied.
2. Every node indexes the commitment once the block is applied.
3. The same commitment cannot be consumed twice.
4. A restarted node rebuilds enough commitment state to continue validating
   reveals, or the client retries safely with a new salt.

No dedicated commitment gossip protocol is required: block application is the
authoritative source of the commitment index.

### 4.3 Authorization and RPC Policy

Staking and DeFi RPC methods must use explicit user-allowlist configuration.
The default is permissionless access with canonical signature verification.
An operator can configure a restrictive allowlist, and invalid allowlist
entries must fail startup rather than silently widening or narrowing policy.

The transaction path and the RPC path must not implement contradictory
authorization policies.

### 4.4 Pool Hygiene

A transaction that cannot execute because its commitment was already consumed
must eventually leave the transaction pool. Validation tests should cover:

- duplicate reveal rejection,
- nonce-hole cleanup,
- zombie eviction,
- behavior after commitment expiry,
- behavior after node restart.

### 4.5 Genesis and Key Handling

Deployment tooling must accept all documented Dilithium3 key encodings,
including concatenated private and public key material. Generated genesis
timestamps must fall inside the node's accepted time range.

### 4.6 Finality Tests

Tests that consume finality must poll until the finality state is visible
instead of assuming that record publication and aggregate publication happen
atomically. The documented behavior is:

1. A query inside the publication window may conservatively return false.
2. Once the record and aggregate epoch agree, the query converges to true.
3. Finalized state is monotonic.
4. No false window exists within an already-finalized epoch.

## 5. Implementation Order

1. Transaction type, encoding, execution, and pool validation.
2. On-chain commitment indexing and reveal verification.
3. Single-node integration tests.
4. Multi-node consistency tests.
5. Mobile wallet and extension updates.
6. Deployment tooling and configuration validation.

## 6. Deployment Preconditions

1. Generate a new genesis with the required validator keys, allocations,
   chain ID, threshold, and timestamp.
2. Distribute the new binary and per-node credentials through a secure
   out-of-band process.
3. Start nodes with fresh chain data.
4. Verify peer connectivity and advancing block height on every node.
5. Run commitment, reveal, missing-commitment, and duplicate-reveal checks.
6. Reconcile the expected ledger total before opening public access.

Automated deployment jobs must be manual-trigger, canary-capable, and gated by
health checks. They must never be able to replace an entire running network
without explicit authorization.
