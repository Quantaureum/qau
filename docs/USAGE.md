# Usage Guide

This guide covers the main node daemon and the two primary command-line tools.

## Binaries

| Binary | Purpose |
| --- | --- |
| `qaud` | Node daemon. |
| `qauctl` | Node management and status tool. |
| `qau-cli` | Client-facing interface for accounts, transactions, contracts, and chain queries. |
| `qau-visor` | Optional process supervisor for the node daemon. |

Every command supports `--help`. Use it to inspect the exact flags available in
the binary you built.

## Start And Stop The Node

Start with an explicit configuration:

```sh
qaud --config /etc/quantaureum/config.json
```

Or start with a built-in public network preset:

```sh
qaud --network mainnet --datadir /var/lib/quantaureum \
  --bootnodes enode://65b6dcc0aeb5e0458996d3c6934a36c5213caf8074e4153c3f9e0f5f225789f7@163.192.142.82:9000
```

For mainnet, omit `--bootnodes` to use the canonical records built into the
client. Supplying `--bootnodes` replaces that built-in list.
Mainnet and testnet do not require an external genesis JSON file. See
[NETWORK.md](NETWORK.md) for genesis verification and connection checks.

Use an `enode://` record from a trusted Quantaureum channel when connecting to
a public network. The record pins the remote node identity; a plain
`host:port` value does not.

Show version information for the installed binaries:

```sh
qaud --version
qauctl --version
qau-cli --version
qau-visor --version
```

All of these commands read the shared version metadata from
`internal/version/version.go`. Release builds can override the version, Git
commit, and build timestamp with the `ldflags` example in the README.

Stop a foreground process with `Ctrl+C`, or send `SIGTERM` to its process ID.
For a systemd deployment:

```sh
sudo systemctl stop quantaureum
```

## Node Status With qauctl

The examples assume the default local RPC endpoint. Use `--rpc` to select
another endpoint:

```sh
qauctl --rpc http://127.0.0.1:8545 status node
qauctl --rpc http://127.0.0.1:8545 status sync
qauctl --rpc http://127.0.0.1:8545 status peers
qauctl --rpc http://127.0.0.1:8545 status block --height -1
qauctl --rpc http://127.0.0.1:8545 status metrics
```

For a non-loopback or remote endpoint, use HTTPS and avoid bypassing certificate
validation.

## Configuration With qauctl

Initialize, validate, and display a JSON configuration:

```sh
qauctl --config /etc/quantaureum/config.json config init
qauctl --config /etc/quantaureum/config.json config validate
qauctl --config /etc/quantaureum/config.json config show
```

Read or update one value with dot notation:

```sh
qauctl --config /etc/quantaureum/config.json config get rpcAddr
qauctl --config /etc/quantaureum/config.json config set maxPeers 100
```

After editing the file, validate it again before restarting the node.

## Chain Queries With qau-cli

```sh
qau-cli blockchain info --rpc http://127.0.0.1:8545
qau-cli blockchain block number <block-number> --rpc http://127.0.0.1:8545
qau-cli blockchain block latest --rpc http://127.0.0.1:8545
qau-cli network peers list --rpc http://127.0.0.1:8545
```

`--rpc` is defined on individual `qau-cli` subcommands, not on the root
command. Check the exact flags with:

```sh
qau-cli --help
qau-cli blockchain --help
```

## JSON-RPC

The node exposes Ethereum-compatible JSON-RPC methods. The examples use a
local node; replace the URL with `https://rpc.quantaureum.com` to use the
verified public mainnet endpoint. Verify any remote endpoint with
`eth_chainId` before submitting transactions. Mainnet must return `0x684`.

For example:

```sh
curl -sS http://127.0.0.1:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

Keep the endpoint private unless it is protected by authentication and TLS.

## Accounts And Transactions

Use the account and transaction command groups for common client operations:

```sh
qau-cli account --help
qau-cli tx --help
```

For example, list accounts and query a balance:

```sh
qau-cli account list
qau-cli account balance <address> --rpc http://127.0.0.1:8545
```

In the current implementation, `account list` prints keystore locations and the
RPC method used for a full listing; it does not query the node by itself.

Never paste private keys, mnemonics, or passwords into shell history. Prefer
files with restrictive permissions or an interactive prompt when a command
supports one.

## Smart Contracts

Inspect the contract command group:

```sh
qau-cli contract --help
```

It provides command wrappers for deployment and calls. Use explicit sender,
contract, and bytecode values supplied by your application. Do not store
deployment keys or production bytecode in this source repository.

## Logs And Troubleshooting

For a systemd service:

```sh
journalctl -u quantaureum -f
```

Common checks:

- Confirm the service is running.
- Confirm the RPC endpoint used by the CLI matches the node listener.
- Confirm the selected network preset and bootnode records.
- Confirm the service account can read the configuration and write to the data directory.
- Check peer count and synchronization status.
- Check disk space in the data directory.
