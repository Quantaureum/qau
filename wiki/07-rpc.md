# 07 - L7 Service Layer — `rpc/` `graphql/`

## 7.1 Positioning

- External JSON-RPC 2.0 endpoints (HTTP/WS) are the only channel for wallet-node interaction.
- Method naming convention (**hard rule**):
  - Standard JSON-RPC → `eth_*` (e.g. `eth_blockNumber`)
  - Quantaureum-specific → `qau_*` (e.g. `qau_qposStatus`, `qau_tss_*`)
  - See the full table in [14-rpc-surface.md](./14-rpc-surface.md).
- Special: HMAC authentication (commit-reveal security), rate limiting, WebSocket subscriptions.

## 7.2 Core Files and Entry Points

| File | Key Exports | Responsibility |
|------|---------|------|
| [rpc/server.go](../rpc/server.go) | `Server`, `NewServer`, `RegisterHandler(method, fn)`, `RegisterAdminMethod(method)`, `Start` | RPC bus + method registry + routing |
| [rpc/api.go](../rpc/api.go) | `API`, `StateReader/BlockReader` interfaces, `RegisterHandlers`, `QPOSStatus`, `GetStake`, `SignQuantumTransaction` | API implementation + method registration (`qau_qposStatus`@`:874`, `qau_getStake`@`:879`, `qau_signQuantumTransaction`@`:899`) |
| [rpc/auth.go](../rpc/auth.go) | HMAC authentication, `verifyCommitAuth`, admin method authorization | commit-reveal front-running-protection authentication |
| [rpc/ratelimit.go](../rpc/ratelimit.go) | `RateLimiter`, per-method QPS caps | Rate limiting (`qau_signQuantumTransaction`=5 etc.) |
| [rpc/websocket.go](../rpc/websocket.go) | WS endpoint + `eth_subscribe` | WebSocket subscriptions |
| [rpc/qtd_api.go](../rpc/qtd_api.go) | `TSSAPI` (`qau_tss_generateKeyShares`, `qau_tss_getPublicKey`, `qau_tss_getShare`, `qau_tss_signMessage`, `qau_tss_verifySignature`, `qau_tss_status`) | QTD threshold-signing API |
| [rpc/quantum_api.go](../rpc/quantum_api.go) | `qau_signQuantumTransaction`, `qau_verifyQuantumTransaction`, key/privacy methods | Quantum signing/privacy |
| [rpc/multisig_api.go](../rpc/multisig_api.go) | `qau_registerMultisigWallet`, `qau_createMultisigProposal`, `qau_approveMultisigProposal`, `qau_executeMultisigProposal` | Multisig |
| [rpc/economics_api.go](../rpc/economics_api.go) | `qau_getStakingPools`, `qau_getStakingStats`, `qau_getUserStakes`, `qau_claimRewards` etc. | Staking/economics |
| [rpc/defi_api.go](../rpc/defi_api.go) | DeFi liquidity queries | Liquidity pools/swap |
| [rpc/bridge_api.go](../rpc/bridge_api.go) | L1↔L2 bridge queries | Bridge deposit/withdrawal status |
| [rpc/rollup_api.go](../rpc/rollup_api.go) | `qau_rollup*` | Rollup L2 |
| [rpc/governance_api.go](../rpc/governance_api.go) | Governance queries | Proposals/voting |
| [rpc/shard_api.go](../rpc/shard_api.go) | `qau_shardGetShardCount` etc. | Sharding |
| [rpc/blob_api.go](../rpc/blob_api.go) | `qau_getBlobBaseFee`, `qau_getBlobSidecar`, `qau_sendBlobTransaction` | DA blobs |
| [rpc/builder_api.go](../rpc/builder_api.go) | `qau_builder_submitBid` etc. | Block auctions |
| [rpc/proof_api.go](../rpc/proof_api.go) | Proof-related | State proofs |
| [rpc/debug_api.go](../rpc/debug_api.go) | `debug_traceTransaction` etc. | Debugging |
| [rpc/fee_api.go](../rpc/fee_api.go) | `eth_feeHistory`, `qau_getFeeHistory` | Fee history |
| [rpc/stardust_api.go](../rpc/stardust_api.go) | `qau_stardust_getDKGStatus` | DKG monitoring |
| [rpc/personal.go](../rpc/personal.go) | `personal_importRawKey`, `personal_unlockAccount`, `personal_listAccounts` | Local account management |
| [rpc/advanced.go](../rpc/advanced.go) | `admin_*`, advanced management | Administration |
| [rpc/access_list_api.go](../rpc/access_list_api.go) | `eth_createAccessList` | ACCESS LIST generation |
| [rpc/api_sign_tx_stub.go](../rpc/api_sign_tx_stub.go) | `qau_signQuantumTransaction` compile-time stub | Client-side signing safety (node-side signing disabled by default) |

## 7.3 Method Registration Mechanism

`rpc/server.go` maintains a registry of method name → handler function (`RegisterHandler`);
`rpc/api.go` and `qtd_api.go` register all methods in `RegisterHandlers`.

```go
// server.go (schematic)
func (s *Server) RegisterHandler(method string, handler Handler) {
    s.handlers[method] = handler
}
func (s *Server) RegisterAdminMethod(method string) {
    s.adminMethods[method] = true
}

// api.go (schematic)
func (api *API) RegisterHandlers(server *Server) {
    server.RegisterHandler("eth_blockNumber", api.BlockNumber)
    server.RegisterHandler("qau_qposStatus", api.QPOSStatus)   // :874
    server.RegisterHandler("qau_getStake", api.GetStake)       // :879
    server.RegisterAdminMethod("qau_signQuantumTransaction")   // :898
    server.RegisterHandler("qau_signQuantumTransaction", api.SignQuantumTransaction) // :899
}
```

- Method-name format validation: only alphanumeric and underscore allowed (see [server.go:1314](../rpc/server.go#L1314)).
- Admin methods (admin_*, some qau_tss_*) require HMAC authentication, otherwise 401.

## 7.4 Signature Separation (Security Design)

- `qau_signQuantumTransaction` is **disabled at compile time** by default (`api_sign_tx_stub.go` returns
  `ErrCodeUnauthorized`), promoting **client-side signing** (wallet-side Dilithium3).
- The node side is enabled only under special configuration/dev mode, and is subject to a high
  rate limit in `ratelimit.go` (QPS=5).

## 7.5 Authentication and Front-Running Protection (commit-reveal)

- `auth.go`: performs HMAC validation (`verifyCommitAuth`) on committed `commit.reveal` transactions.
- Large transfers (≥1 QAU) must use the commit-reveal path; a bare `eth_sendTransaction` is rejected
  by txpool (see [15-lessons.md § R40.T](./15-lessons.md#154-r40t---high-value-transfer-protection)).
- The wallet-side `QUANTAUREUM_COMMIT_AUTH_SECRET` must equal the node's `--commit.auth.secret`.

## 7.6 Rate Limiting

`ratelimit.go` sets a separate QPS cap for methods prone to jamming, for example:

| Method | QPS |
|------|-----|
| `qau_signQuantumTransaction` | 5 |
| (others default) | controlled by the `rpc.rate_limit` config |

## 7.7 GraphQL (`graphql/`)

- `handler.go`, `schema.go`, `resolver.go`, `complexity.go`, `auth.go`.
- Provides a read-only GraphQL endpoint; coexists with JSON-RPC, sharing `StateReader/BlockReader`.

## 7.8 New RPC Method Checklist

1. Determine whether standard or specific: standard → `eth_*`, specific → `qau_*`.
2. Implement `func (api *X) Method(ctx, params) (any, *Error)` in the corresponding `*_api.go`.
3. Register in `RegisterHandlers` with `server.RegisterHandler("method", api.X)`;
   if it is an admin method, additionally `server.RegisterAdminMethod("method")`.
4. Update the full table in [14-rpc-surface.md](./14-rpc-surface.md).
5. **Sync the wallet whitelist**: `QUANTAUREUM_RPC_METHOD_WHITELIST` in
   `quantaureum-wallet/.../network-controller-init.ts` must include the new method
   (new `qau_*` requires dual-side synchronization).

## 7.9 Key Anti-Patterns

```go
// Wrong: a standard method using the qau_ prefix
server.RegisterHandler("qau_blockNumber", api.BlockNumber)

// Wrong: forgetting to add rate limiting/auth to a sensitive method
server.RegisterHandler("qau_signQuantumTransaction", api.SignQuantumTransaction) // no RegisterAdminMethod
```
