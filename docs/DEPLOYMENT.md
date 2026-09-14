# Deployment Guide

This guide describes a generic Linux deployment from a source-only build. Adapt
paths, service settings, and network controls to your environment. Do not store
secrets or production network artifacts in the source tree.

## 1. Build

Build the binaries on a trusted machine:

```sh
go build ./...
go build -trimpath -o bin/qaud ./cmd/qaud
go build -trimpath -o bin/qau-cli ./cmd/qau-cli
go build -trimpath -o bin/qauctl ./cmd/qauctl
```

Copy the resulting binaries to the target host with a secure transfer method.

## 2. Prepare The Host

Create a dedicated service user and directories:

```sh
sudo useradd --system --home /var/lib/quantaureum --shell /usr/sbin/nologin quantaureum
sudo mkdir -p /etc/quantaureum /var/lib/quantaureum
sudo chown quantaureum:quantaureum /var/lib/quantaureum
sudo chmod 0750 /var/lib/quantaureum
```

Install binaries:

```sh
sudo install -m 0755 bin/qaud /usr/local/bin/qaud
sudo install -m 0755 bin/qau-cli /usr/local/bin/qau-cli
sudo install -m 0755 bin/qauctl /usr/local/bin/qauctl
```

## 3. Provide Runtime Files

This source release does not include a runtime configuration, validator key,
certificate, or password. Mainnet and testnet genesis configurations are built
into the client. Before deployment, provide at least:

- `/etc/quantaureum/config.json`

If the node is a validator, also provide its encrypted key material and a way
to supply the key password securely. Use file permissions that restrict access
to the service account:

```sh
sudo chown root:quantaureum /etc/quantaureum/config.json
sudo chmod 0640 /etc/quantaureum/config.json
```

Set `network` to `mainnet` or `testnet`. Both presets use the canonical
bootstrap records built into the client unless an operator explicitly supplies
authorized peers.
An external genesis file is optional and must match the selected preset. Never
place private keys, passwords, certificates, or production peer lists in the
source repository.

For a node that should keep the same P2P identity, set:

```json
{
  "nodeKeyPath": "/var/lib/quantaureum/nodekey"
}
```

The service account must be able to create and read this file. Restrict it to
the service account:

```sh
sudo chown quantaureum:quantaureum /var/lib/quantaureum/nodekey
sudo chmod 0600 /var/lib/quantaureum/nodekey
```

## 4. Validate Configuration

Generate and edit a JSON configuration:

```sh
sudo qauctl \
  --config /etc/quantaureum/config.json \
  --datadir /var/lib/quantaureum \
  config init
sudo chown root:quantaureum /etc/quantaureum/config.json
sudo chmod 0640 /etc/quantaureum/config.json
```

Edit the file, then validate it:

```sh
sudo -u quantaureum qauctl \
  --config /etc/quantaureum/config.json \
  config validate
```

Configuration details are documented in [CONFIGURATION.md](CONFIGURATION.md).
Network identity, genesis verification, and bootnode configuration are
documented in [NETWORK.md](NETWORK.md).

## 5. Run As A Service

Create `/etc/systemd/system/quantaureum.service`:

```ini
[Unit]
Description=Quantaureum node
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=quantaureum
Group=quantaureum
WorkingDirectory=/var/lib/quantaureum
ExecStart=/usr/local/bin/qaud --config /etc/quantaureum/config.json
Restart=on-failure
RestartSec=10
TimeoutStopSec=60
KillSignal=SIGTERM
LimitNOFILE=65536

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/quantaureum

[Install]
WantedBy=multi-user.target
```

Enable and start the node:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now quantaureum
sudo systemctl status quantaureum
```

To stop it gracefully:

```sh
sudo systemctl stop quantaureum
```

The node handles `SIGINT` and `SIGTERM` and attempts a clean shutdown.

## 6. Network Exposure

The default configuration binds RPC, WebSocket, health, frontend, and metrics
listeners to loopback addresses. Keep them loopback unless you have a specific
reason to expose them.

For public access:

- Put HTTP, WebSocket, and GraphQL traffic behind a TLS-terminating reverse proxy.
- Restrict CORS to explicit origins.
- Do not expose validator keys or administrative RPC methods publicly.
- Keep metrics and health endpoints on a private network or behind an authenticated proxy.
- Configure the host firewall so only required ports are reachable.

For a public bootnode, also require:

- A persistent `nodeKeyPath` so the authenticated PeerID survives restarts.
- A stable advertised address; a DNS name is preferred, while a direct IP is acceptable when it is canonical.
- Reachable TCP and UDP ports on the advertised P2P port.
- A correct `externalIP`.
- Monitoring for service failures, clock health, disk usage, and peer count.
- Recovery procedures that do not delete the nodekey.

Publish a bootnode only as an `enode://<node-id>@address:port` record. Do not
publish a plain `host:port` address without identity pinning.

## 7. Operational Checks

Use the status commands documented in [USAGE.md](USAGE.md). Monitor:

- Service status and restart count
- Peer count and sync progress
- Disk usage under `/var/lib/quantaureum`
- RPC availability
- Certificate expiry, if TLS is enabled
- Backup integrity for the data directory

Back up the complete data directory while the node is stopped, or use a
filesystem snapshot mechanism that provides a consistent view.
