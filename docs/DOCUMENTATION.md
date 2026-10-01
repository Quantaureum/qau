# Quantaureum Documentation Map

Single index for all public documentation. Public facts (chain IDs, supply,
parameters) are defined in [WHITEPAPER.md](WHITEPAPER.md) and
[TOKEN_ECONOMICS.md](TOKEN_ECONOMICS.md); every other doc must stay consistent
with them. If a number differs, the whitepaper wins — fix the other doc.

## Canonical Facts (single source of truth)

| Fact | Value | Defined in |
|------|-------|-----------|
| Mainnet chain ID | 1668 | WHITEPAPER.md, validator guide |
| Testnet chain ID | 1669 | validator guide, configs |
| Devnet chain ID | 1333 | INSTALL.md, DEVELOPER_GUIDE.md |
| Genesis supply | 20,000,000 QAU | WHITEPAPER.md §8.2, TOKEN_ECONOMICS.md §3.1 |
| Signature scheme | Dilithium3 (ML-DSA-65) | WHITEPAPER.md §2.1 |
| KEM | Kyber-768 (ML-KEM-768) | WHITEPAPER.md §2.2 |
| Consensus | QPOS (Casper FFG + LMD GHOST) | WHITEPAPER.md §3 |
| Block interval | 12 s (mainnet slot) | WHITEPAPER.md §3.1 |
| Min validator stake | 32 QAU | validator guide, TOKEN_ECONOMICS.md |
| Official RPC | https://rpc.quantaureum.com | WHITEPAPER.md §12 |
| Security contact | security@quantaureum.com | SECURITY.md |

## By Audience

### Run a node
- [INSTALL.md](INSTALL.md) — build from source (Windows/Linux), join a network,
  systemd/NSSM services, troubleshooting
- [DOCKER.md](DOCKER.md) — container deployment, compose profiles
- [MULTINODE_SETUP.md](MULTINODE_SETUP.md) — local multi-node test setup
- [DATA_PERSISTENCE.md](DATA_PERSISTENCE.md) — storage layers, backup/restore

### Become a validator
- [validator-onboarding-guide.md](validator-onboarding-guide.md) — hardware,
  staking parameters, slashing, full walkthrough; master/identity/session
  key design (`vkctl` usage in INSTALL.md §9)

### Develop
- [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) — architecture, module map
- [API.md](API.md) — JSON-RPC reference
- [EVM-COMPATIBILITY.md](EVM-COMPATIBILITY.md) — EVM-style tooling support
- [api/](api/) — RPC surface docs (bridge / rollup / shard)
- [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) — repo layout

### Understand the protocol
- [WHITEPAPER.md](WHITEPAPER.md) —
  flagship technical document (EN/zh kept in sync)
- [TOKEN_ECONOMICS.md](TOKEN_ECONOMICS.md) / [TOKEN_ECONOMICS_CN.md](TOKEN_ECONOMICS_CN.md)
- [economic-model.md](economic-model.md) — simulation-backed economics
- [stardust_consensus_paper.md](stardust_consensus_paper.md) — consensus details
- [commit-reveal-v2-design.md](commit-reveal-v2-design.md) — anti-MEV design
- [da-architecture.md](da-architecture.md) / [da-crypto.md](da-crypto.md) —
  data availability layer
- [QSWAP-STQAU-API.md](QSWAP-STQAU-API.md) — QSwap AMM + liquid staking API

### Security
- [SECURITY.md](../SECURITY.md) — reporting policy, bounty table
- [plans/](plans/) — per-release engineering plans (R-series)

### Internal (not in this repo)
Operator runbooks, deployment manifests, audit archives, and incident notes
live in the private operations workspace — never in this repository.

## Website / marketing copy

The public website must not introduce facts absent from the canonical list
above. Team, partnership, and case-study claims must be real and verifiable
before publication. No invented credentials, no "AI autonomous evolution"
features that do not exist in the protocol, no fictional enterprise customers.
