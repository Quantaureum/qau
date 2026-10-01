# 10 - Entry Points and Tools — `cmd/`

> All executable binaries are placed in `cmd/`. The node's main entry point is `qaud`;
> the operations entry point is `qauctl`.

## 10.1 Binary Overview

| Binary | Directory | Purpose |
|--------|------|------|
| **qaud** | `cmd/qaud` | **Node daemon main entry point** |
| **qauctl** | `cmd/qauctl` | **Unified management tool** (validator/account-remote/contract/genesis/status/audit/key/perf/tx) |
| qasm | `cmd/qasm` | QASM assembler (compile .qasm → .hex) |
| qau-cli | `cmd/qau-cli` | Full-featured command-line client |
| qau-visor | `cmd/qau-visor` | Daemon process manager |
| qauaudit | `cmd/qauaudit` | Audit tool |
| qaucold / qaucold-gui | `cmd/qaucold*` | Cold-signing CLI / GUI |
| keytool | `cmd/keytool` | Key tool |
| keyderive | `cmd/keyderive` | Key derivation |
| keyinfo | `cmd/keyinfo` | Key information |
| keydebug | `cmd/keydebug` | Key debugging |
| keyverify | `cmd/keyverify` | Key verification |
| derivepub | `cmd/derivepub` | Derive the public key from the private key |
| export_key | `cmd/export_key` | Export keys |
| verifykey | `cmd/verifykey` | Verify keys |
| faucet | `cmd/faucet` | Faucet |
| localnet | `cmd/localnet` | Local multi-node testnet |
| transfer | `cmd/transfer` | Simple transfer |
| stakeall | `cmd/stakeall` | Batch staking |
| sign_call / sign_deploy / sign_stake | `cmd/sign_*` | Transaction signing (call/deploy/stake) |
| tx-sender | `cmd/tx-sender` | Batch transaction sending |
| tss-genkey | `cmd/tss-genkey` | TSS key generation |
| tss_dkg_gen | `cmd/tss_dkg_gen` | TSS DKG generation |
| qsign | `cmd/qsign` | Quantum signing CLI |
| checkconfig | `cmd/checkconfig` | Configuration check |
| checkts | `cmd/checkts` | Timestamp check |
| deploy_vesting_all | `cmd/deploy_vesting_all` | Batch LinearVesting deployment (environment-variable driven) |
| transfer_commit | `cmd/transfer_commit` | commit-reveal front-running-protected transfer (required for large amounts) |

## 10.2 `qaud` — Node Main Entry Point

Startup sequence ([cmd/qaud/main.go](../cmd/qaud/main.go)): 

```
main()
  ├─ flag parsing (rpc/ws/p2p/chain-id/commit.auth.secret/…)
  ├─ loadConfig() (reads configs/config.json)
  ├─ resolveGenesis() (embed genesis/*.json)
  ├─ metrics.StartMetricsServer()
  ├─ node.New(cfg, logger)
  ├─ node.Start(ctx)
  │    ├─ qaudb storage open + genesis initialization
  │    ├─ p2p host start
  │    ├─ qpos.Start() (if validator then DKG/threshold key)
  │    ├─ blockProducer.Run()
  │    ├─ rpc.Server.Start() (8545/8546)
  │    └─ graphql up (optional)
```

Key startup flags (schematic): 

```
--rpc.addr      RPC listen address (default 127.0.0.1:8545)
--ws.addr       WS listen address (default 127.0.0.1:8546)
--p2p.addr      P2P listen (default :9000)
--chain-id      Chain ID (1668/1669/1333)
--commit.auth.secret   front-running-protection HMAC key (must equal the wallet's QUANTAUREUM_COMMIT_AUTH_SECRET)
--dev-accounts  devnet pre-provisioned accounts
```

## 10.3 `qauctl` — Operations Management Tool

`cmd/qauctl` is Cobra-based, command tree (`cmd/qauctl/cmd/`): 

```
qauctl
├── validator
│     deploy <keyfile> <ssh-server> --ssh-key <key>
│     check  <server> --ssh-key <key>
│     info   <keyfile>
├── genesis
│     generate --validator-keys <k1,k2,...> --alloc ./alloc.json --output ./genesis.json --chain-id 1668
│     show-validators --validator-keys <k1,k2,...>
├── account-remote
│     import <keyfile> <rpc-url> --password <pw>
│     unlock <addr> <rpc-url> --password <pw>
│     list   <rpc-url>
├── contract
│     deploy <hexfile> <rpc-url> --from <addr> <constructor-args...>
│     call   <contract> <selector> <rpc-url> --from <addr>
├── status
│     node / block / sync --rpc <url>
├── audit
├── key
├── perf
└── tx
```

> **R40.A note**: the `<rpc-url>` positional argument of `account-remote` takes effect only
> when the `--rpc` flag is not explicitly set (judged by `cmd.Flags().Changed("rpc")`). See
> [15-lessons.md § R40.A](./15-lessons.md#151-r40a---rpc-url-selection).

## 10.4 One-Command Startup Examples

```bash
# local private chain (in-memory)
go run ./cmd/qaud

# build then run
make build
./build/qaud --config configs/config.dev.json

# local multi-node testnet
go run ./cmd/localnet --nodes 3

# compile a QASM contract
go run ./cmd/qasm compile ./contracts/my_contract.qasm
```

## 10.5 New Binary Specification

- Each binary keeps a **minimal entry point**: only flag parsing + calling core libraries,
  no business logic.
- Tools involving remote nodes/private keys must use environment variables
   (`QAU_VALIDATOR_NODES`, `QAU_SSH_KEY`), and hardcoding IPs/key paths is forbidden
   (see [15-lessons.md § R50](./15-lessons.md#157-r50---public-repository-hygiene)).
