# Quantaureum Docker Deployment Guide

The image is a multi-stage build: `qaud` (node), `qauctl` (management CLI) and
`qau-faucet` (testnet faucet service) are static binaries in an Alpine runtime,
running as the non-root `qau` user. No secrets are baked into the image —
keys and passwords are injected at runtime via environment variables or
read-only mounts.

## Quick Start

### 1. Build the Image

```bash
docker build -t quantaureum/qau-node:latest .
```

### 2. Start the Local Dev Node

The default `docker-compose.yml` service (`qau-node`) runs a local devnet node
(chain ID 1333, 2-second blocks) from `deploy/config.example.json`.

```bash
docker compose up -d
docker compose logs -f qau-node
```

Verify:

```bash
# Health check
curl http://127.0.0.1:8080/health

# Block height
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  http://127.0.0.1:8545
```

> **Port conflict?** If something else on the host already listens on 8545,
> remap the published ports, e.g.
> `docker compose up -d && docker run ... -p 127.0.0.1:28545:8545`, or edit the
> `ports:` section of `docker-compose.yml`.

### 3. Customize the Configuration

Copy the template and mount it over the default:

```bash
cp deploy/config.example.json deploy/config.json
# edit deploy/config.json (networkId, bootstrapPeers, externalIP, ...)
docker compose up -d
```

The compose file mounts `./deploy/config.json` into the container. Keys and
passwords are NEVER placed in config files — see "Validator Deployment".

## Networks

| Network | Chain ID | Genesis | Notes |
|---------|----------|---------|-------|
| devnet  | 1333     | built-in `DevGenesis()` (no file needed) | local dev, 2-3s blocks |
| testnet | 1669     | `genesis/testnet.json` (operator-provided) | faucet enabled |
| mainnet | 1668     | `genesis/mainnet.json` (operator-provided) | production |

Configuration notes learned from running the image:

- **`networkId` must match the intended network.** The default config falls
  back to mainnet (1668), and `devMode` is refused on mainnet — a dev config
  without `"networkId": 1333` fails with
  `devMode must not be enabled on mainnet`.
- **`listenAddr: "0.0.0.0:9000"` requires `externalIP`.** The P2P layer
  refuses to bind all interfaces without a configured external IP (fail-closed
  against unreachable advertisements and direct attacks). Inside a container,
  set `externalIP` to the container IP (e.g. `172.17.0.2` for the default
  bridge) or pass the host's reachable IP for production.
- **Dev genesis needs no file**: if `genesisFile` is empty, devnet uses the
  built-in deterministic dev genesis (public dev seeds, DEVNET ONLY).

## Testnet with Faucet

```bash
# Provide the faucet key (operator-managed, gitignored)
cp /path/to/faucet.key deploy/keys/faucet.key

docker compose --profile testnet up -d
```

The faucet runs as a sidecar sharing the testnet node's network namespace
(the faucet binary targets `http://localhost:8545`), listening on
`127.0.0.1:18088` from the host:

```bash
curl http://127.0.0.1:18088/health
```

Faucet behavior: 100 QAU per claim, 24h rate limit per address,
1000 QAU global daily cap (Sybil defense). Set `QUANTAUREUM_FAUCET_API_KEY`
in `.env` to require an API key on the fund endpoint.

## Validator Deployment (Production)

Keys are NEVER baked into the image, compose file, or config. The validator
profile expects:

1. A keystore file at `deploy/keys/validator.key` (mounted read-only).
2. The keystore password in `.env` (gitignored):

```bash
cat > .env <<EOF
QAU_VALIDATOR_KEY_PASSWORD=change-me
EOF

docker compose --profile validator up -d
```

Recommended (R131 session-key sovereignty design): per-block signing uses an
epoch-bound session key injected via `QAU_SESSION_KEY_FILE`, while the base
validator key only signs on-chain identity/rotation events. Rotate session
keys at epoch boundaries with `vkctl rotate`.

Key generation on the host:

```bash
docker run --rm -v $(pwd)/deploy/keys:/keys --entrypoint qauctl \
  quantaureum/qau-node:latest keygen --output /keys/validator.key
```

## Monitoring (Local Only)

```bash
docker compose --profile monitoring up -d
```

- Prometheus: http://127.0.0.1:9092
- Grafana: http://127.0.0.1:3030 (admin — set `GF_SECURITY_ADMIN_PASSWORD` in
  `.env` before any non-local use; the default is for local testing only)

## Ports

| Port | Service | Description |
|------|---------|-------------|
| 9000 | P2P | Inter-node communication |
| 8545 | JSON-RPC | API endpoint |
| 8546 | WebSocket | Real-time subscriptions |
| 8080 | Health | Health check endpoint |
| 18088 | Faucet | Testnet faucet (testnet profile) |

All compose ports are published on `127.0.0.1` only — nothing is exposed to
the public internet by default.

## Data Persistence

Data is stored in Docker volumes: `qau-data` (chain data), `qau-testnet-data`,
`qau-validator-data`, `faucet-ratelimit`, `prometheus-data`, `grafana-data`.

### Back Up Data

```bash
docker run --rm -v qau-data:/data -v $(pwd)/backup:/backup alpine \
  tar czf /backup/qau-data-$(date +%Y%m%d).tar.gz -C /data .
```

### Restore Data

```bash
docker run --rm -v qau-data:/data -v $(pwd)/backup:/backup alpine \
  tar xzf /backup/qau-data-YYYYMMDD.tar.gz -C /data .
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| QAU_LOG_LEVEL | info | Log level (debug/info/warn/error) |
| QAU_LOG_FORMAT | json | Log format (json/text) |
| QAU_GENESIS_FILE | genesis/dev.json | Genesis file path (per-network default) |
| QAU_VALIDATOR_KEY_PASSWORD | (none) | Validator keystore password (validator profile) |
| QAU_SESSION_KEY_FILE | (none) | R131 session signing key file (recommended) |
| QUANTAUREUM_FAUCET_KEY_FILE | (none) | Faucet private key file (faucet) |
| QUANTAUREUM_FAUCET_LISTEN | 127.0.0.1:3001 | Faucet listen address |
| QUANTAUREUM_FAUCET_API_KEY | (none) | Optional API key for the faucet endpoint |

## Production Recommendations

### Resource Allocation

```yaml
deploy:
  resources:
    limits:
      cpus: '4'
      memory: 8G
    reservations:
      cpus: '2'
      memory: 4G
```

### Security

1. Do not expose the RPC port to the public internet (compose already binds
   127.0.0.1)
2. Use a reverse proxy (nginx/traefik) with TLS for any public endpoint
3. Back up data and keys regularly
4. Never commit `.env`, `deploy/keys/`, or any key material — the repo's
   `.gitignore`/`.dockerignore` quarantine them

### Log Management

The compose file ships with a sane default:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "100m"
    max-file: "5"
```

## Troubleshooting

### Node Fails to Start

```bash
docker compose logs qau-node
```

Common failures:

- `devMode must not be enabled on mainnet (networkId=1668)` — the config lacks
  `"networkId": 1333` for a devnet
- `ListenAddr ... but ExternalIP is not set` — set `externalIP` (container IP
  or host IP) whenever `listenAddr` is `0.0.0.0`
- `failed to load genesis from genesis/...` — the genesis file path does not
  exist; devnet works without one (built-in dev genesis)

### Cannot Connect to Other Nodes

1. Check that port 9000 is open in the firewall
2. Check the `bootstrapPeers` configuration
3. Confirm network connectivity

### Upgrading

```bash
docker compose build      # rebuild from source
# or: docker compose pull # if published on a registry
docker compose up -d
```
