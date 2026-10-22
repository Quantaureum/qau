# Changelog

All notable changes to the Quantaureum project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **BREAKING (state trie hasher):** `trie.SetHasher` and `trie.GetHasher` are
  removed and the node hash function of the state trie is pinned inside the
  package. They read and wrote a package-level variable with no lock behind it,
  while nine production sites read it as blocks were being applied and
  `LeafNode.recomputeHash` never read it at all — a swap would have hashed new
  leaves under the incoming function and updated or decoded existing leaves under
  SHA3-256, so two honest nodes replaying the same transactions would have
  disagreed on the state root. Nothing outside the package ever called them; the
  only callers were two tests asserting properties every hash function satisfies.
  Code that needs a different hasher can no longer switch one in at runtime.
- **BREAKING (RPC state snapshots):** `evm_snapshot` and `evm_revert` no longer
  touch state. `evm_snapshot` recorded `height -> current root` in a StateDB map
  that is never read back for a restore, and `evm_revert` fed the caller's block
  height into `StateDB.RevertToSnapshot`, whose argument is a position in the live
  dirty-state journal, so the call either poisoned the next authoritative commit or
  rewound the journal of an unrelated in-flight execution frame. Both methods stay
  registered and admin-gated and now fail with
  `evm state snapshot/restore is not supported: block-height snapshots cannot be
  restored on this node` (JSON-RPC `-32603`). The `SnapshotManager` injection seam
  that used to wire a reverter into the RPC stack is removed. Fork recovery remains
  available as the admin-gated `debug_rollbackChainToHeight`, which is a
  rewind-and-replay, not a snapshot revert.
- **BREAKING (light-client state proofs):** `qau_light_getStateProof`,
  `qau_light_verifyStateProof`, `qau_light_getMultiStateProof`,
  `qau_light_getSerializedStateProof` and `qau_light_getCompactProof` now build
  account proofs with `StateDB.ProveAccount` (the canonical Verkle path, rooted at
  the live state root) instead of `GetAccountWithProof`, whose proof was the
  literal placeholder `[][]byte{}, // Simplified` and verified against nothing.
  The node verifies the proof it is about to hand out and refuses when it does not
  verify, when the tip header's state root disagrees with the live root, or when
  the backend cannot prove at all; those are errors, never pseudo-proofs, and the
  account that comes back is decoded from the proved leaf rather than read from the
  dirty overlay. Prover failures used to be reported as
  `-32000 state not found`, which a light client reads as "the account does not
  exist"; they are now `-32603 state proof unavailable` with the prover's
  explanation in `data`, while a genuinely absent account returns success with
  `account: null` plus a verified exclusion proof. `AccountProof`, previously
  declared and left empty, carries decodable proof material. In a batch request an
  account that cannot be proved aborts the call instead of shortening the list, and
  a malformed `storageKeys` entry is rejected with `-32602` instead of being dropped
  from the requested set.
- **BREAKING (light-client proof wire format):** serialized Verkle proofs use a
  versioned, full-fidelity encoding (version byte `0x02`) covering `IsExclusion`,
  `ExtensionStems`, `StemHash`, `InclusionLeaf` and `ExclusionEvidence` — every
  field `Verify` reads. The previous encoding carried four fields, so a proof that
  verified in memory did not verify after a round trip. Blobs with no version byte,
  with version `0x01`, with trailing bytes, or with stem or proof lengths beyond the
  declared bounds decode as malformed. Commitments are not encodable while proof
  aggregation is unimplemented, so a proof carrying them is not serialized at all
  rather than silently losing them.
- **BREAKING (light-client storage proofs):** a non-empty `storageKeys` argument to
  any `qau_light_*` state-proof method is refused with
  `proof not supported: ... committed storage is not part of the Verkle state trie
  on this node, so no state-root-bound storage proof exists`. `StateDB.Commit`
  writes slots to the key-value store only, so `ProveStorage` could return an
  *exclusion* proof, which verifies against the state root, alongside the non-zero
  value the node had just read back. The contradiction is removed at the source
  instead of being shipped to a light client.
- **`eth_getProof` storage entries are labelled:** every entry in `storageProof`
  now carries `"unverified": true`, and the result carries a top-level
  `"unverified": true` whenever any storage entry is present. Values are still
  answered from the key-value store, because callers expect them, but they are no
  longer presented as state-root-bound proof material. Account proofs are
  unaffected: when `ProveAccount` yields a root-bound proof the response keeps
  `"unverified": false`.
- **BREAKING (account abstraction):** `eth_sendUserOperation` and
  `qau_sendUserOperation` no longer accept submissions. Account abstraction is not
  live on this network: nothing in the node consumes the bundles the bundler
  builds, so an accepted operation was parked in an in-memory set that no block
  producer ever read, and the caller was handed an operation hash that could
  never resolve to a receipt. Both methods now fail with
  `account abstraction is not live: user operations are not bundled on chain yet`
  (JSON-RPC error code `-32603`), and `txpool.TxPool.AddUserOperation` returns
  `txpool.ErrUserOpsNotLive`. The estimate and read methods are unchanged:
  `*_estimateUserOperationGas` still returns a local gas estimate, and
  `*_getUserOperationByHash` / `*_getUserOperationReceipt` return `null`.
  `Bundler` and its admission logic are kept intact for the release that wires an
  on-chain consumer; integrations must stop submitting user operations to nodes
  until then. This supersedes the `UserOperation.Hash` note below for
  `*_sendUserOperation`, which now never reaches hashing.
  Observability added with it: `qau_aa_bundles_dropped_total` on `/metrics`
  (JSON key `aa_bundles_dropped`) counts bundles discarded because
  `BundleChannel()` was full or unread — expected to stay at zero while AA is
  dark, non-zero once a caller enables the bundler without a consumer.
- **BREAKING (account abstraction):** `UserOperation.Hash` now commits to the full
  user-operation payload (sender, nonce, init code, call data, paymaster fields,
  gas limits, fees) instead of a subset. Any AA client, bundler, or verifier
  contract that computes the user-operation hash off-chain must upgrade in
  lockstep; `qau_sendUserOperation` returns a different hash for identical inputs
  than previous releases. UserOperations signed under the old scheme will not
  validate after this upgrade.
- Economics RPC signature domain now binds `chainID` and the full parameter
  payload (`QAU-<method>|<chainID>|<address>|<nonce>|<params>`), matching the
  DeFi and governance domains. Signers must include the chain ID; signatures
  produced for one chain no longer validate on another.
- Sync committee headers are signed and verified over a single canonical
  message (`sync_committee_v2` domain with chainID, epoch, height, slot, and the
  header signing root). Block producers and light clients now agree byte-for-byte;
  light clients should use `encoding.BlockHeaderSigningRoot` plus
  `consensus.BuildSyncCommitteeMessage`.
- Minimum Go toolchain raised to Go 1.26.10 (fixes GO-2026-6809 in crypto/x509).
- **BREAKING (RPC replay protection):** state-mutating staking, DeFi, and
  economics requests must now carry a nonce of the form
  `<unixDeadline>:<random>`, where `<random>` is at least 16 characters (for
  example `1761050000:9f2c4d6e8a0b1c3d`). The deadline must be no more than
  10 minutes ahead of the node clock, with 30 seconds of past skew tolerated.
  Legacy opaque nonces are rejected with
  `invalid nonce format: expected <unixDeadline>:<random>`; an expired
  deadline returns `signature deadline expired`. Clients must generate a new
  nonce and signature for every request; replaying one returns
  `nonce already used (replay detected)`.
- **BREAKING (governance RPC):** `qau_createProposal`, `qau_castVote`,
  `qau_finalizeProposal`, and `qau_executeProposal` now require an explicit
  `deadline` field (decimal Unix seconds, as a string) in addition to
  `nonce`, `signature`, and `publicKey`. The signed payload is
  `QAU-<method>|<chainID>|<address>|<nonce>|<deadline>|<params>`. Requests
  omitting the field fail with
  `deadline is required for replay protection`; add
  `"deadline": "<unixSeconds>"` to existing request objects and cover it in
  the signature.
- `sign_stake` now emits the canonical stake-authorization inputs alongside
  the signature: `chainId`, `commission`, `recipient`, and `deadline` are
  added to `nonce`, `signature`, `pubkey`, `address`, `amount`, and `method`.
  Tooling that parsed the previous output shape must be updated.
- **Light client sync-committee response:** `qau_light_verifySyncCommitteeSig`
  now returns a three-way result (`valid` / `verified` / `reason`) instead of
  a plain bool: `valid` reflects format checks, `verified` reflects the
  cryptographic verification, and `reason` carries the specific failure
  (unknown, expired, mismatched, etc.).
- **Bridge fail-closed:** mainnet bridge header verification now fails closed
  (rejects the transaction) when the header verifier is unavailable or
  degraded, instead of falling back to a lenient mode. Set
  `QAU_ALLOW_DEGRADED_BRIDGE_HEADER_VERIFICATION=1` to restore the legacy
  behavior explicitly.
- **AA admission validation budget:** the bundler's admission path now enforces
  a per-sender sub-cap
  (`DefaultUserOpValidationsPerSenderPerWindow = 64`, 1/16 of the global
  1024-run window) on the simulation runs it triggers. A single sender can no
  longer monopolize the global validation budget; further submissions from a
  sender over the cap are rejected with a per-sender "validation budget
  exceeded" error, distinct from the global-budget error.
- **Governance deposit reservation:** deposit-lock operations now reserve
  against the voter's free balance rather than transferring coins; the
  actual settlement happens at proposal execution time.
- **Rollup L1 anchor:** memory-only L1 anchor is now opt-in via
  `QAU_ALLOW_MEMORY_L1_ANCHOR=1`. Without the flag the rollup fails closed
  when a persistent L1 anchor is not available.

### Fixed
- **Startup state restoration is now accepted or rejected, not merely attempted.**
  The boot-time replay skipped any height it could not read as long as the misses
  were not ten in a row, then logged "State restored" without ever comparing the
  result to the chain head, and its only caller downgraded every error to a
  warning the rest of the boot path forgot — so a node could run on state built
  from an incomplete replay with nothing in the process knowing it. An isolated
  unreadable height now aborts the replay, and the restoration is recorded as
  verified (at the tip height) only when every height in `[1, tip]` was applied
  and the committed root equals the tip header's `StateRoot`, the comparison the
  rebuild path and the persisted-state anchor already treat as the definition of
  trustworthy state. A refused restoration is logged as an error and leaves the
  state unverified: boot proceeds, `IsStateReady()` keeps the producer from
  building, and the syncer's `rebuildState` owns the repair.
- **A node no longer advertises state pruning it does not perform.** `DefaultConfig`
  and the `--prune` flag both default to enabled, and every node started with a
  banner announcing pruning as switched on with a 1000-block retention window,
  while `qaudb/state.StatePruner` had no construction point anywhere in the node or
  command trees. The operator's actual condition is the opposite of that line:
  state grows with the chain. The startup line now reads
  `State Pruning: configured (retention=1000 blocks, batch=100) but NOT
  IMPLEMENTED IN THIS BUILD - state grows with the chain`, comes from a single
  `PruningStatusLine`, and is logged as a warning as well as printed, so the fact
  is on record where the disk growth is observable. A `PruningImplemented`
  constant ties the wording to the wiring: the `retention enforced` wording is
  unreachable until something constructs a pruner, and a guard test fails if the
  constant and the wiring ever move apart, in either direction.
- **The durable state database is now released on shutdown, and can be released
  safely.** `initState()` opens a persistent BoltDB for the state and hands it to
  the `StateDB`, which is the only object that can close it — but nothing in the
  node lifecycle ever called `StateDB.Close()`, so the file descriptor and BoltDB's
  exclusive file lock outlived `Stop()`. The next `Start()` in the same process then
  stalls in the open retry loop (~150 s) and either fails to boot or, with DevMode,
  falls back to a fresh empty in-memory state on top of a block store that still
  holds the chain. `Close()` could not simply be wired in: its handle is shared by
  construction with every `Copy()`, every build copy and — after `Promote` — the
  instance it replaced, and `Close` took neither the writer gate nor any ownership
  record, so it could land inside another instance's commit or promote replay
  (leaving the base half-applied with the commit-pending marker unreadable) and
  double-close the handle. Release now goes through the per-database control block:
  it waits on the durable-writer gate, closes the base handle at most once, and
  stays retryable if the close itself fails.
- **Durable state writes are now serialized across StateDB instances over one
  database.** `StateDB.Copy()` shares the durable database by design, and each
  instance guarded only its own mutex, so a block-building copy could promote while
  the import path committed a different block: the two writers had no lock in
  common, and the promotion replayed an outdated block — its accounts, its Verkle
  root and its last-committed height/root markers — on top of the state the sync
  path had just made durable. The result is a database belonging to neither branch,
  which crash recovery cannot detect because the interleaving is self-consistent as
  far as the stored anchor is concerned. Every instance over one database now
  inherits a single writer gate, taken by `Commit`, `PruneState`,
  `RollbackToHeight`, `Promote` and the snap-import writers, and a build copy
  additionally remembers the durable anchor of the database it branched from:
  `Promote` refuses with `ErrStaleBuildState` before writing anything once that
  anchor has moved, so the block under construction is discarded and the next slot
  builds on the new tip. The block producer treats a stale build as the normal race
  it is (INFO, discard) and any other promotion failure as a state-trust event
  (ERROR, discard, stop producing), because a replay that dies partway cannot be
  undone.
- **A promotion can no longer advertise an anchor whose data it did not apply.** The
  write-buffer replay ordered keys by byte value, and the durability metadata keys
  are prefixed with `_` (0x5F), which sorts before the account, storage and code
  prefixes. On a database that splits an over-limit batch — the production backend
  does, at 50k operations / 64 MB — the replay therefore published the last-committed
  height and root and cleared the commit-pending marker in the first transaction,
  before the accounts behind them existed: a crash or a rejected write left the node
  claiming a durable height it could not read back, with the marker already gone, so
  recovery saw a clean shutdown. The replay is now two phases: data keys first, where
  a split across transactions is allowed, then the durability metadata in a single
  un-splittable transaction, with the commit-pending marker pre-written before any
  replay so an interrupted promotion is detected at the next start.
- **Snap-sync imports are inside the writer gate.** `ImportAccount`, `ImportStorage`,
  `ImportCode` and `ClearSnapImport` wrote and deleted raw database keys from p2p
  handler goroutines under no lock shared with a promotion, and because they leave
  the last-committed height and root untouched, the staleness fence above cannot see
  them: a promotion could interleave with an import or with the discard that follows
  a failed snap root verification, publishing a root the disk does not hold.
- `StateDB.Copy()` now deep-copies the pruning bookkeeping map (block height ->
  state root). It was carried over by reference, so the live StateDB and every copy
  shared one Go map while each instance guarded it with its own mutex. The block
  producer builds on `stateDB.Copy()` and commits that copy with
  `CommitWithBlock`, which reaches `CreateSnapshot` and `PruneState` — both writers
  — while the import path commits the main StateDB on another goroutine; the
  collision is an unrecoverable `concurrent map writes` runtime fault, and even
  when it did not land, a block-building copy that was discarded still added and
  deleted entries in the live instance's history.
- State-lifecycle entry points that mutate committed state now hold the StateDB
  execution frame for their whole duration, through the single
  `StateDB.WithExecutionFrame` helper: the shutdown state flush, the node's fork
  rollback, the consensus adapter's rollback, and the syncer's state rebuild. Each
  used to call `Commit`/`RollbackToHeight` directly, and the journal and the
  position-based snapshot stack are shared per StateDB instance, so a rollback or
  flush landing while a block transition held the frame restored pre-fork values
  underneath a journal that still recorded post-fork writes, cleared the stack from
  under the live frame, and let a partially applied block become durable state
  behind a commit marker that had advanced past it. A failed shutdown flush is
  logged and still reports success; durability rests on the commit-pending marker
  plus `RecoverConsistency` at next start, not on trapping the operator.
- Replay-protected RPC endpoints now verify the request signature before writing
  to the persistent replay store, so unauthenticated traffic can no longer grow
  the store; nonces remain replayable after a failed signature check.
- Replay-store entries are retained through the full nonce grace window
  (deadline + 30s skew) and are pruned by a periodic background sweep instead of
  accumulating indefinitely.
- RPC replay guards fail closed when the store is unavailable (nil guard) rather
  than accepting the request.
- Rollup initialization failures now fail node startup instead of being logged
  and ignored.
- Airdrop tool re-synchronizes its nonce after commit/reveal failures instead of
  issuing subsequent transactions with a stale nonce.

### Security
- **Inbound message-dedup eviction is bounded.** `MessageValidator.IsDuplicate`
  evicted its `seenMessages` replay cache by scanning the whole map to drop one
  entry at a time, looping from the 100000-entry cap down to 90%. Because the
  dedup key is `sha3(payload)` and `IsDuplicate` runs *before* format validation,
  a single connected peer could fill the map with distinct (even malformed)
  payloads, after which every further message triggered an O(cap*evict) sweep of
  roughly a billion map accesses performed while holding the global
  `seenMessagesMu` — stalling message validation for every peer. Memory was
  already capped; the amplification was worst-case single-call work under the
  lock. The eviction now mirrors the `lastMessages` sweep already proven in the
  same file: one pass drops every entry past the 30s dedup window, and only if
  still at capacity does it sort once and batch-drop the oldest 10%. Behavior
  tests pin that expired entries are fully purged on overflow, the map stays
  capped under an all-fresh flood, the newest entry survives, and dedup within
  the window still fires.
- **Pre-push guards cover two more AGENTS.md classes.** The published-tree guard
  now also fails on embedded Dilithium3 key material (a `dilithium3:` prefix
  abutting 64 or more hex characters) and on `user@<IPv4>` SSH targets whose
  address is publicly routable. Honest placeholders are deliberately not
  reported: code that only names the `dilithium3:"` prefix does not match, and the
  routable classifier excludes RFC-1918, loopback, link-local, TEST-NET, CGNAT,
  benchmark, multicast/reserved, and non-canonical octets, so documentation
  examples using those ranges stay quiet. A unit test pins the classifier's
  boundary cases.
- **Operational narratives no longer ship in the tree.** Fifteen source comments
  and internal documents paired an internal site identifier with a chain height or
  an incident date. Heights are public chain data; the pairing with a specific
  machine is not, and it is exactly the reverse fingerprint that lets an outsider
  map infrastructure. The write-ups now keep the technical conclusion with neutral
  site labels, and a drift guard walks the pushed tree and fails on the shapes that
  were removed, so they cannot return through the next incident note.
- **Shipped text integrity.** The repository root carried a private assistant
  working-notes file that had been committed by a bulk `git add`, written entirely
  in Chinese; elsewhere, English comments and documents had picked up full-width
  CJK punctuation, and one comment had lost characters to a code-page mismatch
  (`??` where letters used to be). The notes file is out of the tracked tree and
  ignored, the damaged text is repaired, and guard tests now fail on tracked hidden
  markdown at the repository root, on shipped text that is not valid UTF-8, and on
  shipped text that carries characters from a CJK, Hangul, or full-width form
  script.
- **Machine identity no longer ships in the tree.** A committed planning document
  pinned the Go toolchain to an absolute path under the developer's own home
  directory (a Windows drive letter plus the OS account name), which is a
  reverse fingerprint AGENTS.md forbids in published files. The path is now stated
  machine-agnostically, and a guard walks the published tree and fails on any
  drive-into-home path, personal `/home/<user>` directory, OS account name, or
  local workspace root.
- **User-facing channels are grounded in what the project declares.** The
  PagerDuty channel hardcoded a "View in Dashboard" link to a host on a
  top-level domain the project never published; a Code-of-Conduct mailbox and the
  testnet bootstrap/cert hostnames used two more undeclared domains. Public
  endpoints and contacts must have a real, declared destination, so the dashboard
  link is now a configuration field omitted entirely from the incident payload
  when unset, the conduct mailbox routes to the declared maintainer address, and
  the testnet hosts use the single canonical domain. A guard fails on any
  `@quantaureum.*` address or `://`/`dns4/` reference on a non-canonical
  top-level domain.
- **Dead build-ignored scaffolds removed from package directories.** Six one-off
  struct-size analysis tools and an empty code-generator shell lived in production
  package directories behind `//go:build ignore`, redeclaring shipped types without
  ever compiling. They are quarantined under `.local-only/`, and a guard fails if
  any build-ignored Go file reappears in the published tree without an
  allowlisted justification.
- `sign_stake` now signs the canonical stake-authorization hash
  (`types.ComputeStakeAuthorizationHash`) instead of the legacy string format.
- `keystore_to_plainkey` zeroizes plaintext passwords and derived key material
  after use.

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
