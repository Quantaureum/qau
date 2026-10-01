# Changelog

All notable changes to the Quantaureum project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-testnet-rc1] - 2026-04-27

### Added
- **QVM JIT Compilation**: Just-In-Time compiler for 10-100x contract execution speedup
  - `qvm/jit/compiler.go`: JITCompiler with bytecode→MicroOp compilation pipeline
  - `qvm/jit/cache.go`: LRU compilation cache with hit/miss statistics
  - `qvm/jit_adapter.go`: Type adapters bridging qvm and jit type systems
  - `qvm/executor.go`: JIT integration with automatic interpreter fallback on failure
  - Supports 50+ opcodes: arithmetic, bitwise, memory, storage, context, logging
  - Gas accounting with 3 gas/MicroOp base consumption
  - Jump destination analysis and basic optimization passes
- **MEV Protection (Proposer-Builder Separation)**: Builder auction mechanism to prevent transaction front-running
  - `miner/mev_protection.go`: BuilderBid, MEVAuction, MEVBlockBuilder, MEVProtection
  - Builder RPC API (`qau_builder_submitBid`, `qau_builder_getSlotInfo`, `qau_builder_getWinningBid`)
  - Integration with QPOS block production pipeline
  - MEV reward crediting to proposer
- Testnet genesis configuration (chainId=1669)
- Production-grade Dockerfile with multi-stage build
- Docker Compose orchestration for 3 validator nodes + Prometheus + Grafana
- CI/CD pipeline (Go build/test/lint + Docker + Frontend + Wallet)
- GraphQL handler security hardening (CSP, CORS, rate limiting, query depth/complexity limits)
- Go SDK HKDF-SHA256 key derivation (compatible with TypeScript wallet)
- Wallet CSP configuration with connect-src whitelist
- .gitignore production hardening (sensitive files, .db, keys, dev accounts)
- .golangci.yml lint configuration (20+ rules including gosec)
- Security audit CI workflow (Gitleaks, govulncheck, gosec, Semgrep, Bandit)

### Changed
- Testnet node chainId: 1333 → 1669
- Testnet node devMode: true → false
- Testnet node devAutoUnlockAccounts: true → false
- Testnet node logFormat: text → json
- Testnet RPC binding: 127.0.0.1 → 0.0.0.0 (public RPC)
- Wallet default network: DEVNET → TESTNET
- Frontend .env.production: localhost → testnet-rpc.quantaureum.com
- Frontend EnhancedNavbar: Cloudflare Tunnel URLs → environment variables
- Go SDK key derivation: HMAC-SHA512 → HKDF-SHA256 (wallet compatibility)
- chain_config.go TestnetConfig chainId: 2 → 1669

### Fixed
- node/node.go: Printf format string bugs (lines 814, 847)
- GraphQL wildcard CORS removed (security fix)
- GraphQL introspection disabled by default (security fix)
- GraphQL playground disabled by default (security fix)

### Security
- .gitignore: Added testnet/keys/, dev_key.txt, *.db, *.zip, pkg/mod/, pids.json
- CORS whitelist for testnet domains
- Wallet CSP with connect-src restrictions
- API key authentication for GraphQL endpoints
- HMAC-constant-time key comparison
- AES-256-GCM backup encryption with scrypt key derivation (#125)
- Log sensitive data sanitization — automatic redaction of private keys, passwords, tokens (#127)
- Streaming chunked encryption format for large backup files
- Backup encryption passphrase validation and header integrity check
- RPC error Data field sanitization in production mode (#247)
- Token Sale frontend localhost → testnet domain (page.tsx, purchase/route.ts, hardhat.config.ts)
- Wallet manifest host_permissions: localhost:8545 → testnet-rpc.quantaureum.com (#61)
- Wallet Chrome manifest: added update_url field (#229)
- Security audit logger default archive directory (data/audit) (#189)
- RPC method prefix: eth_ → qau_ automatic mapping confirmed (#57)
