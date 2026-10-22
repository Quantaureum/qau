# Quantaureum Node

Quantaureum is a quantum-resistant, EVM-compatible Proof-of-Stake (PoS) Layer 1 blockchain.

- **Consensus**: QPOS (Proof-of-Stake, validators lock stake; block rewards auto-compound)
- **EVM**: full integration (current `go-ethereum` slice)
- **Post-quantum**: validator identities, consensus signatures, and staking use post-quantum primitives (Dilithium3 / Falcon-512).

## Experimental — not live

Some surfaces exist in the code but are not usable on the network yet. They are
listed here so integrators do not read a registered method as a supported one.

- **Account abstraction (ERC-4337)**: the `eth_*` and `qau_*` user-operation
  methods are registered, and the `Bundler` is implemented and tested, but no
  component consumes built bundles, so nothing can include a user operation in a
  block. `eth_sendUserOperation` / `qau_sendUserOperation` refuse submissions with
  `account abstraction is not live: user operations are not bundled on chain yet`
  rather than returning a hash for work that cannot happen. Do not integrate
  against these methods until this note is removed.

## Requirements

- Go 1.22+ (from `go.mod`)
- Node.js & pnpm (for `qswap/` and web modules)
- Optional: `jq`, `curl` for CLI scripts

## Quick start

1. Build the node:

   ```bash
   go build ./...
   ```

2. Or use the included dev scripts (Windows PowerShell):

   ```powershell
   .\run.ps1
   ```

3. Run tests:

   ```bash
   go test ./node ./consensus ./p2p
   ```

## Repository layout (high level)

- `cmd/`, `node/`, `p2p/`, `consensus/`, `params/`, `state/`, `state-sync/` — Go node and chain logic
- `qswap/`, `staking-ui/`, `wasm/` — Web/JS and Wasm modules
- `docs/` — network and mechanism documentation (historical/draft semantics preserved)

## License / Contribution / Security

- Codebase is proprietary to Quantaureum; see `SECURITY.md`.
- For dependency pins (fail-closed), see `docs/BUILD_LOCK.md` / related lock mechanisms.

_Last updated in-repo: 2026-05-29_
