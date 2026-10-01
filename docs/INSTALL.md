# Quantaureum Node Installation Guide (Windows & Linux)

This guide covers installing, running, and upgrading a Quantaureum node from
source on Windows and Linux. For Docker deployments see [DOCKER.md](DOCKER.md);
for validator staking/economics see the [Validator Onboarding Guide](validator-onboarding-guide.md).

> **Conventions used in this document**
> - `CHANGE_ME_*` placeholders mark values YOU must replace. Never copy a
>   command containing an unfilled placeholder.
> - This document contains no real addresses, hostnames, IPs, or keys. Example
>   outputs use throwaway devnet data only.

## Contents

1. [Requirements](#1-requirements)
2. [Build from source (Windows)](#2-build-from-source-windows)
3. [Build from source (Linux)](#3-build-from-source-linux)
4. [Directory layout](#4-directory-layout)
5. [First run: local devnet node](#5-first-run-local-devnet-node)
6. [Joining a network (testnet / mainnet)](#6-joining-a-network-testnet--mainnet)
7. [Key management](#7-key-management)
8. [Running a validator](#8-running-a-validator)
9. [Session-key rotation (R131)](#9-session-key-rotation-r131)
10. [Running as a service](#10-running-as-a-service)
11. [Upgrading](#11-upgrading)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Requirements

| Component | Minimum | Notes |
|-----------|---------|-------|
| Go | 1.26+ | `go version` to check |
| Git | any recent | source checkout |
| OS | Windows 10/11, Linux (amd64/arm64) | static binaries, CGO disabled |
| RAM | 4 GB (full node), 8 GB (validator) | |
| Disk | 100 GB+ SSD | chain data grows over time |

The binaries are fully static (`CGO_ENABLED=0`): you can cross-compile on one
platform and copy the binary to another.

## 2. Build from source (Windows)

```powershell
git clone https://github.com/Quantaureum/qau.git
cd qau

# Build the node daemon and the CLI
go build -o build\qaud.exe .\cmd\qaud
go build -o build\qauctl.exe .\cmd\qauctl

# Optional tooling
go build -o build\vkctl.exe .\cmd\vkctl          # session-key rotation (R131)
go build -o build\qau-faucet.exe .\cmd\faucet    # testnet faucet service

.\build\qaud.exe -version
```

> The repo is a **multi-module Go workspace** (main module + `crypto/`,
> `encoding/`, `types/`, `tools/tests/integration/testutil` wired through
> `go.work` and `replace` directives). Build from the repository root so the
> workspace resolves; do not build a single subdirectory in isolation.

## 3. Build from source (Linux)

```bash
sudo apt update && sudo apt install -y git build-essential   # Debian/Ubuntu
# or: sudo dnf install -y git gcc     (Fedora), apk add git gcc musl-dev (Alpine)

git clone https://github.com/Quantaureum/qau.git
cd qau

go build -o build/qaud ./cmd/qaud
go build -o build/qauctl ./cmd/qauctl
go build -o build/vkctl ./cmd/vkctl
./build/qaud -version
```

### Install to PATH and create a service user (recommended)

```bash
sudo install -m 0755 build/qaud build/qauctl build/vkctl /usr/local/bin/

sudo useradd --system --home-dir /var/lib/quantaureum --shell /usr/sbin/nologin quantaureum
sudo mkdir -p /var/lib/quantaureum /etc/quantaureum
sudo chown -R quantaureum:quantaureum /var/lib/quantaureum
```

## 4. Directory layout

| Path | Purpose |
|------|---------|
| `<datadir>/` | chain data, node key, keystore |
| `<datadir>/keystore/` | encrypted key files (one JSON per address) |
| `<datadir>/genesis.json` | genesis used by this datadir (copied on first run) |
| `/etc/quantaureum/` (Linux) | config files, password files (root-owned, mode 600) |
| `~/qau` (Windows, typical) | `config.json`, `keystore/`, `genesis.json` |

**Security rule**: nothing in `<datadir>` or `/etc/quantaureum` should ever be
committed to git. Keep the repo and the datadir strictly separated.

## 5. First run: local devnet node

The fastest smoke test — a single-node devnet (chain ID 1333) with built-in
deterministic dev genesis (public dev seeds, DEVNET ONLY):

```bash
# Linux
./build/qaud -dev -networkid 1333 -blockinterval 2 \
  -datadir ./dev-data \
  -rpc -rpcaddr 127.0.0.1:8545 \
  -health -healthaddr 127.0.0.1:8080
```

```powershell
# Windows
.\build\qaud.exe -dev -networkid 1333 -blockinterval 2 `
  -datadir .\dev-data `
  -rpc -rpcaddr 127.0.0.1:8545 `
  -health -healthaddr 127.0.0.1:8080
```

Expected: `Block #N produced (...)` log lines every ~2 seconds. Verify:

```bash
curl -s -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
# {"jsonrpc":"2.0","id":1,"result":"0x1e"}   <- a growing hex number
```

> **Dev-mode disclaimers shown at startup are expected**: signature
> verification bypass, auto-unlocked dev accounts. Dev mode is refused on
> mainnet (`networkId=1668`) by design.

## 6. Joining a network (testnet / mainnet)

### 6.1 Get the genesis file

Every node on a network must use the identical genesis file. Obtain it from
the network's official channel (release assets / community docs), place it at
`/etc/quantaureum/genesis.json` (Linux) or a folder outside the repo (Windows).

> A fixed `timestamp` in the genesis ensures all nodes compute the same
> genesis hash. Nodes with mismatched genesis files can never sync.

### 6.2 Create a config file

Create `/etc/quantaureum/config.json` (Linux) or `qau-mainnet.json` (Windows).
Minimal sync-node config:

```json
{
  "name": "CHANGE_ME_NODE_NAME",
  "networkId": 1668,
  "genesisFile": "/etc/quantaureum/genesis.json",
  "dataDir": "/var/lib/quantaureum",
  "listenAddr": "CHANGE_ME_PUBLIC_IP:9000",
  "externalIP": "CHANGE_ME_PUBLIC_IP",
  "bootstrapPeers": ["CHANGE_ME_BOOTSTRAP_ENODE"],
  "maxPeers": 50,
  "rpcEnabled": true,
  "rpcAddr": "127.0.0.1:8545",
  "wsEnabled": true,
  "wsAddr": "127.0.0.1:8546",
  "healthEnabled": true,
  "healthAddr": "127.0.0.1:8080",
  "validatorEnabled": false,
  "cacheSize": 512,
  "logLevel": "info",
  "logFormat": "json"
}
```

Field notes (each of these is enforced by startup validation):

- `networkId`: **1668 mainnet / 1669 testnet / 1333 devnet.** The default when
  the field is missing is 1668 (mainnet), and `devMode` is rejected on
  mainnet — a dev config without `networkId` fails with
  `devMode must not be enabled on mainnet`.
- `listenAddr` / `externalIP`: the P2P layer **refuses** `0.0.0.0` or empty
  host listen addresses without `externalIP` (fail-closed: an unreachable
  advertisement is worse than no advertisement). Set both to your node's
  publicly reachable IP.
- `rpcAddr`: keep on `127.0.0.1` unless you deliberately expose RPC through a
  reverse proxy with TLS and rate limiting.
- `bootstrapPeers`: enode URLs of existing nodes, obtained from the network's
  official channel.

### 6.3 Start and verify

```bash
qaud --config /etc/quantaureum/config.json
```

Verify sync progress:

```bash
curl -s -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
curl -s -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"net_peerCount","params":[],"id":1}'
```

`eth_blockNumber` climbing = syncing. `net_peerCount` >= 1 = connected.

## 7. Key management

Keys are **Dilithium3** (post-quantum) keypairs stored as encrypted keystore
JSON files. Private key material is never printed to stdout by the tooling.

### 7.1 Generate a key

```bash
# Interactive password prompt
qauctl key generate --datadir /var/lib/quantaureum

# Non-interactive (password via env var, e.g. for scripts/systemd)
QAU_KEYSTORE_PASSWORD=CHANGE_ME_STRONG_PASSWORD \
  qauctl key generate --datadir /var/lib/quantaureum
```

Output (address will differ):

```
Key generated successfully!
  Address: QAU44FO3YVZ6UOP5JTV5RWIV5RSZQTG74KI
  Keystore: /var/lib/quantaureum/keystore
```

The keystore file is `<datadir>/keystore/<address-lowercase>.json`.

### 7.2 List / inspect keys

```bash
qauctl key list --datadir /var/lib/quantaureum
qauctl key inspect QAU44FO3YVZ6UOP5JTV5RWIV5RSZQTG74KI --datadir /var/lib/quantaureum
```

`inspect` shows keystore metadata **without decrypting** — no password needed.

### 7.3 Password resolution (EIP-2335-style priority)

When starting a validator, the keystore password is resolved in this order:

1. `--validator-password-file <file>` CLI flag (recommended for production)
2. `QAU_VALIDATOR_KEY_PASSWORD` environment variable
3. `validatorKeyPassword` in the config file — **ignored on load**: plaintext
   passwords never round-trip through config JSON (SV-09 fix). Do not use.

Create the password file root-only:

```bash
sudo install -m 600 /dev/null /etc/quantaureum/validator-password
sudo sh -c 'cat > /etc/quantaureum/validator-password'   # type password, Ctrl-D
```

## 8. Running a validator

### 8.1 Hardware & prerequisites

See the [Validator Onboarding Guide](validator-onboarding-guide.md) for
staking parameters (min stake, commission), slashing conditions, and hardware
sizing. Summary: 8 GB RAM, 500 GB+ SSD NVMe, 100 Mbit symmetric, static public
IP, and a Dilithium3 validator key registered on-chain.

### 8.2 Generate the validator key (offline, recommended)

On an **air-gapped machine** (the key should never touch an internet-connected
disk before it is needed):

```bash
qauctl key generate --datadir ./cold-keystore
```

Transfer only the keystore JSON to the validator host
(e.g. USB stick, `scp`) into `/etc/quantaureum/keys/`:

```bash
sudo install -m 600 keystore-JSON /etc/quantaureum/keys/validator.json
```

### 8.3 Validator config

Extend the sync-node config from §6.2 with:

```json
{
  "name": "CHANGE_ME_NODE_NAME",
  "networkId": 1668,
  "genesisFile": "/etc/quantaureum/genesis.json",
  "dataDir": "/var/lib/quantaureum",
  "listenAddr": "CHANGE_ME_PUBLIC_IP:9000",
  "externalIP": "CHANGE_ME_PUBLIC_IP",
  "bootstrapPeers": ["CHANGE_ME_BOOTSTRAP_ENODE"],
  "rpcEnabled": false,
  "healthEnabled": true,
  "healthAddr": "127.0.0.1:8080",
  "validatorEnabled": true,
  "validatorKey": "/etc/quantaureum/keys/validator.json",
  "validatorPasswordFile": "/etc/quantaureum/validator-password",
  "cacheSize": 512,
  "logLevel": "info",
  "logFormat": "json"
}
```

Notes:

- RPC disabled on validators by default. Manage the node via health endpoint
  and logs; enable RPC only on `127.0.0.1` if a local monitoring agent needs it.
- `validatorPasswordFile` is the config-file equivalent of
  `--validator-password-file` (priority 1 and 2 above still win).

### 8.4 Start and confirm

```bash
qaud --config /etc/quantaureum/config.json
```

Startup confirms:

```
Validator Mode: ENABLED
```

and block production logs show `proposer=<your-address-prefix>...` when you
are the slot proposer. Verify the node's view of your validator:

```bash
curl -s -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"qau_validatorKeyStatus","params":["CHANGE_ME_VALIDATOR_ADDRESS"],"id":1}'
```

## 9. Session-key rotation (R131)

R131 (validator key sovereignty) separates the **base/identity key** (cold,
signs on-chain rotation events only) from the **session key** (hot, signs
blocks per-epoch). If the hot key leaks, rotation revokes it at an epoch
boundary without touching the identity.

### 9.1 Provision a session key

On the ceremony/offline host:

```bash
qauctl key generate --datadir ./session-keystore
```

Copy the session keystore JSON to the validator host at
`/etc/quantaureum/keys/session.json` (root-only). Point the node at it:

```bash
# environment variable (systemd Environment=, container env, etc.)
QAU_SESSION_KEY_FILE=/etc/quantaureum/keys/session.json
QAU_SESSION_KEY_PASSWORD_FILE=/etc/quantaureum/session-password
```

> **Fail-closed signing**: if a session key is active on-chain but the local
> session-key file is missing or mismatched, the node refuses to sign rather
> than falling back to the base key. This is by design — do not "fix" it by
> deleting the on-chain session state; rotate instead.

### 9.2 Rotate with vkctl

`vkctl` builds and signs a `TxTypeValidatorKey` transaction. **By default it
does NOT broadcast** — it prints the signed raw transaction for transport
through an air-gapped workflow. Broadcasting requires `--rpc` explicitly:

```bash
# 1. Prepare (on the offline host): show the signed rotation tx hex
vkctl rotate \
  -chain-id 1668 \
  -validator CHANGE_ME_VALIDATOR_ADDRESS \
  -identity-key /etc/quantaureum/keys/validator.json \
  -master-key /etc/quantaureum/keys/master.json \
  -password-file /etc/quantaureum/validator-password \
  -session-pubkey-hex CHANGE_ME_SESSION_PUBKEY_HEX \
  -activation-epoch CHANGE_ME_FUTURE_EPOCH

# 2. Broadcast (from an online host, when you are ready)
vkctl rotate ... -rpc http://CHANGE_ME_RPC_ENDPOINT
```

`-activation-epoch` must be a future epoch (`current epoch < activation`), so
every validator sees the same deterministic activation point. Other subcommands:
`bind-master` (bind a cold master address to your validator identity) and
`revoke` (nuclear option — irreversible).

> Air-gap by default: `vkctl` printing instead of broadcasting lets you sign
> on a cold machine and carry the hex out via removable media.

## 10. Running as a service

### 10.1 Linux: systemd

`/etc/systemd/system/quantaureum.service`:

```ini
[Unit]
Description=Quantaureum Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=quantaureum
Group=quantaureum
ExecStart=/usr/local/bin/qaud --config /etc/quantaureum/config.json
Restart=on-failure
RestartSec=5
# Journald contains no key material, but keep the unit tight anyway:
NoNewPrivileges=true
ProtectSystem=full
ReadWritePaths=/var/lib/quantaureum

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now quantaureum
sudo systemctl status quantaureum
journalctl -u quantaureum -f
```

If the node runs as a validator, prefer passing the password via a
`EnvironmentFile` (mode 600) instead of the unit file itself:

```ini
[Service]
EnvironmentFile=/etc/quantaureum/quantaureum.env
# /etc/quantaureum/quantaureum.env contains:
#   QAU_VALIDATOR_KEY_PASSWORD=CHANGE_ME_STRONG_PASSWORD
```

### 10.2 Windows: NSSM or Task Scheduler

There is no first-party Windows service integration; use [NSSM](https://nssm.cc/):

```powershell
nssm install Quantaureum C:\qau\qaud.exe --config C:\qau\config.json
nssm set Quantaureum AppDirectory C:\qau
nssm set Quantaureum AppStdout C:\qau\logs\node.log
nssm set Quantaureum AppStderr C:\qau\logs\node-error.log
nssm start Quantaureum
```

Or a scheduled task at boot (`schtasks /create /sc onstart /tn Quantaureum
/tr "C:\qau\qaud.exe --config C:\qau\config.json"`).

## 11. Upgrading

```bash
cd qau
git pull
go build -o build/qaud ./cmd/qaud

# Linux: restart under systemd (state persists in the datadir)
sudo systemctl restart quantaureum

# Verify after restart
curl -s -X POST http://127.0.0.1:8545 -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

Genesis compatibility is checked at startup: nodes refuse to run when the
datadir's genesis hash mismatches (error tagged `R3-NODE-02`). If a network
performs a coordinated chain reset, operators receive a new genesis file and
start with a **fresh datadir** — never mix old chain data with a new genesis.

## 12. Troubleshooting

| Symptom | Cause / fix |
|---------|------------|
| `devMode must not be enabled on mainnet (networkId=1668)` | dev config missing `"networkId": 1333`; the default network is mainnet |
| `ListenAddr ... but ExternalIP is not set` | `listenAddr` is `0.0.0.0`/empty-host without `externalIP`; set both to the public IP |
| `failed to load genesis from ...` | genesis path wrong; devnet needs none (built-in dev genesis) |
| Genesis hash mismatch (`R3-NODE-02`) | datadir holds a different chain; use a fresh datadir or the correct genesis file |
| Sync stalls, `net_peerCount` 0 | check firewall for port 9000; check `bootstrapPeers` enodes; check genesis identical to peers' |
| 5-min `no peers` warning on a single dev node | expected on isolated devnets; solo production is gated by consensus rules |
| Keystore `Failed to unlock` | password wrong, or password file path/mode; check §7.3 resolution order |
| Node refuses to sign after session-key rotation | fail-closed by design: the local session key is missing/mismatched; provision it or rotate again (§9) |

---

## Appendix: quick command reference

```text
qaud      --config <file>            run node with config
          -dev -networkid 1333        local devnet
          -validator -validatorkey <file> -validator-password-file <file>   validator mode
qauctl    key generate|list|inspect   keystore management
          genesis generate            build genesis.json from validator keys
          status                      node status
          backup|restore              datadir backup/restore
vkctl     rotate|bind-master|revoke   R131 validator-key ops (no broadcast by default)
```
