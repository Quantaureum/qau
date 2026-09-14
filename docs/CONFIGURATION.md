# Configuration Guide

The node reads a JSON configuration file. The source release intentionally does
not include a runtime configuration; operators create and manage it outside the
source tree.

## File Locations

The node uses:

```sh
qaud --config /path/to/config.json
```

If `--config` is omitted, `qaud` uses `config.json` in its current working
directory when that file exists. For a service deployment, always pass an
absolute path.

The management tool can generate and validate a JSON file:

```sh
qauctl \
  --config /etc/quantaureum/config.json \
  --datadir /var/lib/quantaureum \
  config init

qauctl --config /etc/quantaureum/config.json config validate
qauctl --config /etc/quantaureum/config.json config show
```

## Configuration Precedence

1. Built-in defaults
2. Values from the JSON configuration file
3. Command-line flags

Some boolean command-line flags replace the corresponding value from the file.
When in doubt, use one source of truth for a setting.

## Minimal Example

The following example is a starting point for a reverse-proxied node. Replace
the placeholders with values that match your network:

```json
{
  "name": "example-node",
  "dataDir": "/var/lib/quantaureum",
  "network": "mainnet",
  "networkId": 1668,
  "nodeKeyPath": "/var/lib/quantaureum/nodekey",
  "listenAddr": "0.0.0.0:9000",
  "externalIP": "REPLACE_WITH_PUBLIC_IP",
  "bootstrapPeers": [],
  "maxPeers": 50,
  "enableDHT": true,
  "rpcEnabled": true,
  "rpcAuthEnabled": true,
  "rpcAddr": "127.0.0.1:8545",
  "wsEnabled": true,
  "wsAddr": "127.0.0.1:8546",
  "allowedOrigins": ["https://console.example.invalid"],
  "healthEnabled": true,
  "healthAddr": "127.0.0.1:8080",
  "metricsEnabled": true,
  "metricsAddr": "127.0.0.1:9090",
  "metricsPath": "/metrics",
  "logLevel": "info",
  "logFormat": "json",
  "syncMode": "snap",
  "pruningConfig": {
    "enabled": true,
    "retentionBlocks": 1000
  },
  "upgrade": {
    "enabled": true,
    "runMigrations": true
  }
}
```

This example intentionally contains no private key, password, certificate, or
production topology.

## Common Fields

| Field | Purpose |
| --- | --- |
| `name` | Human-readable node name used in logs and status output. |
| `dataDir` | Root directory for chain data and derived databases. |
| `network` | Network preset: `dev`, `testnet`, or `mainnet`. Use a custom setup when this field is empty. |
| `networkId` | Network identifier. Mainnet is `1668`, testnet is `1669`, and devnet is `1333`. |
| `listenAddr` | P2P listener address. |
| `externalIP` | Advertised external address when the node is reachable through NAT. |
| `nodeKeyPath` | Persistent P2P identity key. The node creates it automatically when missing. |
| `bootstrapPeers` | Initial peer records used for discovery. Prefer `enode://` records so the remote identity is pinned. |
| `genesisFile` | Path to the externally supplied genesis file. |
| `expectedGenesisHash` | Optional explicit startup check. Named presets use the client's built-in hash automatically. |
| `rpcEnabled`, `rpcAddr` | HTTP JSON-RPC listener. |
| `wsEnabled`, `wsAddr` | WebSocket JSON-RPC listener. |
| `allowedOrigins` | Explicit browser origins permitted for cross-origin access. |
| `healthEnabled`, `healthAddr` | Health listener. |
| `metricsEnabled`, `metricsAddr`, `metricsPath` | Prometheus metrics listener. |
| `logLevel`, `logFormat` | Logging level and output format. |
| `syncMode` | `snap` for the default synchronization path or `full` to re-execute blocks. |
| `pruningConfig` | State pruning controls. |

## Network Selection

Network presets select the network identifier and use the genesis embedded in
the client. Mainnet uses network ID and chain ID `1668`; testnet uses `1669`.
The client verifies the canonical genesis configuration hash automatically.

`genesisFile` and `QAU_GENESIS_FILE` are optional external overrides. For
mainnet and testnet, the external file must match the built-in chain identity
and genesis hash. Use an empty `network` value for a custom network with its
own genesis file.

Mainnet and testnet use the canonical bootstrap records built into the client.
Custom networks require `bootstrapPeers` or `--bootnodes`; see
[NETWORK.md](NETWORK.md).

Do not enable development mode on mainnet. The node rejects that combination.

## P2P Node Identity

If `nodeKeyPath` is empty, `qaud` generates an in-memory node key and the
PeerID changes whenever the process restarts. That is acceptable for a local
node, but not for a public bootstrap node.

For a stable identity, use an absolute path outside the source tree:

```json
{
  "nodeKeyPath": "/var/lib/quantaureum/nodekey"
}
```

The nodekey is private key material. It must be readable only by the service
account, must never be committed, and must be included in protected backups.
For a public bootnode, keep the same path and key across upgrades and restarts.

Bootstrap records should use the authenticated form:

```json
{
  "bootstrapPeers": [
    "enode://65b6dcc0aeb5e0458996d3c6934a36c5213caf8074e4153c3f9e0f5f225789f7@163.192.142.82:9000",
    "enode://3ef6a7c05e64d2218ce250ae345c05bee2836b3dd24843f6840b1c26773875a1@217.142.189.163:9000",
    "enode://d552745f67d0dfebe9b407a2fad4ff5340ce6273e4d7920ff7080115be9186f1@149.118.59.251:9000",
    "enode://57879ea427537fd3690ed35353a32d1e87035f696995cd4da5126cb2fee05d3d@149.118.61.186:9000",
    "enode://ebf49fb21426f10430e48bf513f07750dc88dfa15c1d65d322b9f922ff1d61da@149.118.62.16:9000",
    "enode://949dcd8f80c032022d2bb7836afc1de9628c49d2f3325131d45d73d5908451e5@149.118.55.2:9000"
  ]
}
```

These are the built-in mainnet records; an explicit `bootstrapPeers` setting or
`--bootnodes` flag replaces them. A plain `host:port` entry is an
unauthenticated legacy address. It does not verify which node answers and
should not be used for a public canonical list.

## Validator Settings

Validator configuration may include:

```json
{
  "validatorEnabled": true,
  "validatorKey": "/etc/quantaureum/validator.key",
  "validatorPasswordFile": "/etc/quantaureum/validator-password"
}
```

Use a dedicated service account and restrictive file permissions:

```sh
sudo chown quantaureum:quantaureum /etc/quantaureum/validator.key
sudo chmod 0600 /etc/quantaureum/validator.key
sudo chown quantaureum:quantaureum /etc/quantaureum/validator-password
sudo chmod 0600 /etc/quantaureum/validator-password
```

Password resolution order is:

1. `--validator-password-file`
2. `QAU_VALIDATOR_KEY_PASSWORD`
3. `validatorPasswordFile` in the JSON configuration

Prefer the password file or an environment variable supplied by your service
manager. Do not paste passwords or private keys into documentation, comments,
or source files.

## TLS

For direct TLS on the RPC listener, set:

```json
{
  "rpcTLSCertFile": "/etc/quantaureum/tls.crt",
  "rpcTLSKeyFile": "/etc/quantaureum/tls.key"
}
```

Equivalent fields exist for WebSocket TLS:

```json
{
  "wsTLSCertFile": "/etc/quantaureum/tls.crt",
  "wsTLSKeyFile": "/etc/quantaureum/tls.key"
}
```

Alternatively, keep listeners on loopback and terminate TLS in a reverse proxy.
Protect certificate and key files with restrictive permissions.

## Runtime Paths

Relative paths can depend on the process working directory. In service
deployments, prefer absolute paths for:

- `dataDir`
- `genesisFile`
- `nodeKeyPath`
- validator key and password files
- TLS certificate and key files
- alerting configuration

The following environment variables can override selected runtime paths:

- `QAU_GENESIS_FILE` (optional external genesis override)
- `QAU_ALERTING_CONFIG_FILE`
- `QAU_VALIDATOR_KEY`
- `QAU_VALIDATOR_KEY_PASSWORD`

## Validation Checklist

Before starting a node, confirm that:

- The configuration is valid JSON.
- `qauctl config validate` succeeds.
- `network` and `networkId` agree.
- Any external `genesisFile` matches the selected preset.
- Authorized bootstrap peers are configured.
- RPC and WebSocket listeners are not unintentionally exposed.
- CORS contains explicit origins and no wildcard.
- Validator material is stored outside the repository with restrictive permissions.
- The data directory has enough free disk space and is writable by the service account.
