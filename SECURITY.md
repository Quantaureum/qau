# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security vulnerabilities seriously. Please **do not** open a public GitHub issue for security vulnerabilities.

### How to Report

1. Email security@quantaureum.com with a description of the vulnerability
2. Include steps to reproduce if possible
3. We will acknowledge receipt within 48 hours

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Fix or Mitigation**: Depends on severity (Critical: 24h, High: 72h, Medium: 7d, Low: 30d)

### Disclosure Policy

- We follow responsible disclosure
- We will credit reporters in release notes (unless they prefer to remain anonymous)
- Please do not disclose the vulnerability publicly until a fix is released

## Bug Bounty

Modeled on the Ethereum Foundation's early bounty program — which allocated a **fixed, capped pool** of 25,000 ETH for security researchers — Quantaureum allocates a **fixed bug-bounty fund of 25,000 QAU** (0.125% of the 20,000,000 QAU supply), drawn from the on-chain **Ecosystem Fund**. The pool is capped: each reward draws down the balance and payouts stop once it is exhausted. Funds are never taken from user balances.

| Severity | Examples | Reward (QAU) |
|----------|----------|--------------|
| Critical | Consensus compromise, direct theft of funds, remote code execution | Up to 5,000 |
| High | Broad loss of funds, stake/protocol integrity compromise | Up to 2,500 |
| Medium | Limited impact, information disclosure, denial of service | Up to 1,000 |
| Low | Low-impact issues, missing best practices | 200 |

Eligibility: issues must be previously undisclosed, reproducible, and not already known to the team. Rewards are the upper bounds above, assessed case-by-case and paid in QAU from the capped bounty fund.

## Security Features

### Post-Quantum Cryptography

Quantaureum uses NIST-standardized post-quantum cryptography:

- **Dilithium3** (FIPS 204) — Digital signatures replacing ECDSA
- **Kyber768** (FIPS 203) — Key encapsulation for encrypted P2P channels
- **GM-QTD** — Gaussian-masked threshold distance signing for distributed key shares

### Threshold Signatures (TSS)

- Private key shares are never stored in a single location
- ScShare (private key material) is transmitted only via encrypted P2P channels
- Kyber768 + AES-256-GCM encryption for all private TSS communications

### Wallet Security

- Network-locked: Only ChainID 1668/1669/1333 are allowed
- Custom network addition is disabled
- ECDSA signatures are disabled; only quantum signatures are accepted

### RPC Authorization Model

The JSON-RPC server enforces two independent authorization layers:

1. **Server-level API key / HMAC** (`rpc/auth.go`). When an API key is configured, every method outside `PublicMethods` requires that key (and, when enabled, an HMAC-signed request body). This gates administrative and node-control APIs.
2. **Per-request account signatures** (`verifyDeFiSignature`, `verifyStakingSignature`). State-mutating DeFi and staking methods are listed in `PublicMethods` on purpose: they are relayed by end-user wallets that hold the user's Dilithium3 key but never the node operator's API key. Each call must carry `nonce`, `signature`, and `publicKey`; the node verifies that the signature covers `QAU-<method> | chainID | address | nonce | params` (governance additionally binds an explicit deadline), that the public key derives the claimed address, and that the nonce is fresh and unused. Stake/unstake instead use the canonical `types.ComputeStakeAuthorizationHash` digest, which binds every consensus-affecting field. Nonces embed a signed deadline and are persisted in the replay store when one is configured, so captured requests cannot be replayed, not even across restarts.

When `enforceAdminAuth` is enabled (production default), the authorized-user allowlist additionally restricts these methods, and an empty allowlist fails closed.

**Residual risk (accepted):** these state-mutating methods are reachable without an API key. The signature proves control of the account being mutated, not that the caller is an authorized operator, and the endpoint remains exposed to unauthenticated traffic subject only to the node's rate limiter. Operators who need defense in depth should require authentication at a reverse proxy in front of the RPC port or keep the port on a private network.

### Light-Client State Proofs

A state proof on this network proves claims about the **Verkle state trie**, whose leaves are accounts (`nonce`, `balance`, `codeHash`, `storageRoot`). It does not prove contract storage values:

- `StateDB.Commit` writes the account leaf into the state trie and each storage slot into the key-value store under a separate prefix. No committed slot ever appears as a state-trie key, and state reconstruction from disk iterates accounts only.
- Consequently `StateDB.ProveStorage` can only ever return an *exclusion* proof for a slot that has a non-zero value. Bound to the state root it verifies cleanly, which is precisely why it must not be shipped next to the value it contradicts.
- `qau_light_getStateProof` / `qau_light_getMultiStateProof` / `qau_light_getCompactProof` refuse a non-empty `storageKeys` list with `-32603` and name the gap in `data`; they never return a storage entry. The account proof they do return comes from `StateDB.ProveAccount` and is verified against the live state root before it is handed out — a proof that does not verify, a tip header that disagrees with that root, or a backend that cannot prove is reported as a failure, never as a pseudo-proof.
- `eth_getProof` still answers `storageKeys` from the key-value store, because callers expect the values; every such entry is labelled `"unverified": true` and the result carries a top-level `"unverified": true` while any storage entry is present. Treat those entries as node-asserted data, not as state-root-bound proofs, until a per-account storage trie is committed into state.

Integrators consuming proof material must re-verify it against a state root they obtained from a trusted header. Absence of an account *is* provable (exclusion proofs are returned as a success with `account == null`); absence of a storage slot from the state trie proves nothing about the slot.

## Experimental Surfaces (Registered But Not Live)

A method being dispatchable is not a promise that it works. Surfaces in this
section are reachable on the RPC endpoint, are covered by tests, and must not be
integrated against.

- **Account abstraction (ERC-4337).** The node implements a `Bundler` with
  per-sender admission limits, account validation at admission (R4-01) and
  overflow-safe bundle gas budgeting (R5-06), and it registers the standard
  `eth_*` plus `qau_*` user-operation methods. What it does *not* have is a
  consumer for the bundles the bundler produces — no block producer reads
  `BundleChannel()`, so `HandleOps` never runs on the bundled operations. As of
  the R5-05 audit fix, `eth_sendUserOperation` and `qau_sendUserOperation` return
  `account abstraction is not live: user operations are not bundled on chain yet`
  (`-32603`) and `txpool.TxPool.AddUserOperation` returns
  `txpool.ErrUserOpsNotLive`, because accepting an operation and then dropping it
  silently was the more dangerous behaviour: a caller handed an operation hash has
  no way to tell from that response that the operation will never be included.
  Do not build flows on the AA surface. The `qau_aa_bundles_dropped_total` metric
  is the signal that a bundle was discarded, if a future build re-enables
  admission without a consumer.
- **EVM state snapshots.** `evm_snapshot` and `evm_revert` are registered on the
  admin namespace but every call fails with `evm state snapshot/restore is not
  supported: block-height snapshots cannot be restored on this node` (`-32603`). `StateDB.Snapshot()`/`RevertToSnapshot(id)` address positions
  in the current journal, whereas the RPC layer exposed height-keyed snapshot
  identifiers that were never read back, so `evm_revert(<id>)` could not have the
  semantics its name implies. Rolling state back to a height is a
  rewind-and-replay operation (`node.RollbackToFork`), not a snapshot revert, and
  is not exposed over RPC. No integration may depend on these two methods.

## Known Vulnerabilities and Accepted Risks

| ID | Package | Status | Rationale |
|----|---------|--------|-----------|
| GO-2026-5932 | `golang.org/x/crypto/openpgp` (legacy OpenPGP, unmaintained upstream) | Accepted | The package is present only as a transitive module dependency; no Quantaureum code imports it, so `govulncheck` reports module-level exposure with no reachable call paths. If OpenPGP support is ever required, use `github.com/ProtonMail/go-crypto/openpgp` instead of the deprecated `x/crypto` package. Re-evaluate after each `golang.org/x/crypto` upgrade. |

## Security Considerations for Developers

- **Never** commit private keys, mnemonics, or keystore files
- **Always** use `qauctl` for key management (never handle raw private keys in code)
- **Review** all changes to `crypto/`, `consensus/`, and `qvm/` with extra scrutiny
- **Test** with `go test -race` before submitting changes to concurrent code paths
