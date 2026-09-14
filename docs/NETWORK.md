# Network Guide

The `qaud` client contains the public identity and genesis configuration for
the named Quantaureum networks. No runtime genesis JSON file is required for
mainnet or testnet.

## Built-In Presets

| Network | Chain ID / Network ID | Genesis configuration hash | Validators |
| --- | ---: | --- | ---: |
| Mainnet | 1668 | `94e178e6faec5ed2c51e109b9d465c613620df245fee665fa77a28158b33e506` | 6 |
| Testnet | 1669 | `7a3993d596afe2fe2d818299a69adff9ad838455c46958fc7c6b66c8c409f20b` | 4 |

The hexadecimal JSON-RPC form of the chain ID is `0x684` for mainnet and
`0x685` for testnet.

## Public RPC

The verified public mainnet JSON-RPC endpoint is:

```text
https://rpc.quantaureum.com
```

Verify the endpoint before use:

```sh
curl -sS https://rpc.quantaureum.com \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
```

The mainnet endpoint must return `"result":"0x684"`. A public RPC endpoint is
convenient for read-only queries and transaction submission, but operators and
applications that require independent verification should run their own node
and verify its genesis hash and peer connectivity as described below.

Start a mainnet node:

```sh
qaud \
  --network mainnet \
  --datadir /var/lib/quantaureum
```

Start a testnet node:

```sh
qaud \
  --network testnet \
  --datadir /var/lib/quantaureum-testnet \
  --bootnodes enode://<node-id>@testnet-bootnode.example.invalid:9000
```

The client verifies the built-in genesis configuration hash at startup. The
startup log must show the expected hash above and the correct chain ID:

```text
Using built-in mainnet genesis
Genesis configuration hash verified: matches expected hash
Chain ID: 1668
```

## External Genesis Override

An operator may still supply a genesis file explicitly:

```sh
qaud --network mainnet --genesis /etc/quantaureum/mainnet-genesis.json
```

`QAU_GENESIS_FILE` has the same effect when no `--genesis` flag or
`genesisFile` configuration field is present.

For a named preset, the external file is an override for file placement only.
It must have the preset chain ID, network ID, `minSignatures`, and genesis
configuration hash. A modified or non-canonical file is rejected before the
node starts. Custom networks with an empty `network` field continue to use an
external genesis without the preset hash requirement.

To independently calculate the configuration hash of a genesis JSON file, run:

```sh
go run ./cmd/genesis_hash /path/to/genesis.json
```

Compare the output byte-for-byte with the hash in the table above. Uppercase,
lowercase, and `0x` prefixes are not used by the expected value.

## Bootnodes

The mainnet preset contains the following authenticated canonical bootstrap
records. When `--network mainnet` is selected and no bootstrap peers are
configured, `qaud` uses these records automatically:

```json
{
  "network": "mainnet",
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

An explicit `bootstrapPeers` setting or `--bootnodes` flag replaces the
built-in list. Use only peer records obtained through a trusted Quantaureum
channel, and do not add unverified endpoints to the client source.

### Authenticated Records

The preferred bootstrap record is an Ethereum-style enode URL:

```text
enode://65b6dcc0aeb5e0458996d3c6934a36c5213caf8074e4153c3f9e0f5f225789f7@163.192.142.82:9000
```

`<node-id>` is the public, authenticated node identity. When `qaud` dials an
enode record, the encrypted transport handshake requires the server's
authenticated PeerID to match that node ID. If a different server answers at
the address, or the endpoint's identity changes after a restart, the bootstrap
connection is rejected.

Raw `host:port` values remain supported for local development and existing
deployments, but they do not pin the remote identity. Do not use raw addresses
for a public canonical bootstrap list.

The current canonical records use direct IP addresses. A stable DNS name is
preferred when one is available because it lets an operator migrate or repair a
bootnode without republishing its node ID. Whether the advertised endpoint is
a DNS name or an IP address, it must resolve to the address and port that the
bootnode advertises.

### Persistent Node Identity

A canonical bootnode must keep the same authenticated identity across
restarts. Configure a persistent node key:

```json
{
  "nodeKeyPath": "/var/lib/quantaureum/nodekey"
}
```

The node creates the file automatically when it does not exist. The file is
private key material: store it outside the source repository, include it in a
protected backup, and restrict its permissions:

```sh
chown quantaureum:quantaureum /var/lib/quantaureum/nodekey
chmod 0600 /var/lib/quantaureum/nodekey
```

Do not publish a node as canonical until its `nodeKeyPath` is persistent, its
PeerID has survived a controlled restart, and its advertised endpoint is
reachable and resolves to that bootnode.

## Confirm Connection

At startup, confirm the network identity before checking connectivity:

```text
Using built-in mainnet genesis
Genesis configuration hash verified: matches expected hash
Chain ID: 1668
```

The exact log wording can change between releases. The required properties are
the selected preset, the expected genesis hash, and the expected chain ID.

After startup, confirm the local endpoint and peer state:

```sh
qauctl --rpc http://127.0.0.1:8545 status node
qauctl --rpc http://127.0.0.1:8545 status sync
qauctl --rpc http://127.0.0.1:8545 status peers
```

Check the chain ID directly:

```sh
curl -sS http://127.0.0.1:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
```

Mainnet must return `0x684` and testnet must return `0x685`. A successful
connection also requires a non-zero peer count and increasing sync progress. If
the chain ID is correct but the peer count remains zero, verify the bootnode
records, the P2P listener, firewall rules, and NAT configuration.

For an authenticated bootstrap record, a connection failure containing
`server identity mismatch` means the endpoint did not present the node ID in
the enode record. Stop using the record, verify its source, and obtain the
current record from a trusted Quantaureum channel.
