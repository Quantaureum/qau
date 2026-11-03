# Per-Epoch Verifiable Randomness API

Quantaureum exposes the chain's per-epoch randomness through two read-only,
public JSON-RPC methods and one WebSocket push feed:

- `qau_randomnessLatest` — randomness of the highest **finalized** epoch
- `qau_randomnessGet` — randomness of a specific epoch
- `newRandomness` WebSocket subscription — push notification for each newly
  finalized epoch (see [WebSocket subscription](#websocket-subscription))

## What this randomness is (and is not)

The served value is the **per-epoch VRF accumulator** recorded on epoch
boundary block headers (`VRFAccumulator`), produced by
`consensus.ComputeNextVRFAccumulator` and validated by every node on import.
Its guarantees are:

- **Unbiasable**: every block folds a post-quantum (Dilithium-based) VRF
  output into the accumulator, and the accumulator's self-consistency
  (`ComputeNextVRFAccumulator` over the parent) is re-verified on every block
  import. Honest caveat (audit QR-40): enforcing that each proposer's
  contribution carries a valid VRF proof (`vrfEnforced` in
  `core/block_validator.go`) is **not yet enabled network-wide** — it is an
  epoch-gated activation planned as a coordinated upgrade. Until then,
  grind-resistance of the accumulator rests on the honest-majority assumption
  rather than on cryptographic proposer-proof enforcement.
- **Finality-bound**: once the epoch is finalized, its accumulator is
  irreversible.
- **Publicly verifiable**: the accumulator is plain block-header data. Any
  client can cross-check the served value against the boundary block (see
  [Verification](#verification)) — no trust in the serving node is required.

It is **not** a hardware quantum random number generator (QRNG) and no such
claim is made. The randomness is cryptographically verifiable and
post-quantum; it is not sourced from a physical quantum process.

Note: the separate commit-reveal random beacon mechanism (consensus
`RandomBeacon`) is not served by these methods and is not active in
production.

## Methods

### qau_randomnessLatest

Returns the randomness of the highest finalized epoch. No parameters.

Until the first epoch finalization the call returns error `-32000`.

```bash
curl -s http://127.0.0.1:8645 -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"qau_randomnessLatest","params":[]}'
```

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "epoch": 18420,
    "randomness": "0xa3f9c1...",
    "boundaryBlock": "0x8f8bf",
    "blockHash": "0x77e5...",
    "finalized": true,
    "source": "vrf-accumulator"
  }
}
```

### qau_randomnessGet

Returns the randomness of a specific epoch.

Params: `{"epoch": <uint64>}` — a decimal number or a numeric string.

```bash
curl -s http://127.0.0.1:8645 -X POST \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"qau_randomnessGet","params":{"epoch":18420}}'
```

Response fields:

| Field           | Format                  | Meaning                                                        |
|-----------------|-------------------------|----------------------------------------------------------------|
| `epoch`         | decimal JSON number     | Epoch the randomness belongs to                                 |
| `randomness`    | `0x` hex (32 bytes)     | The VRF accumulator — the canonical randomness value            |
| `boundaryBlock` | `0x` hex height         | Height of the epoch's boundary (last) block — the last block whose header carries this epoch (`Header.Epoch == epoch`). Note: epochs advance per slot while heights advance per produced block, so this height is NOT `epoch*32 + 31` on chains with skipped slots. |
| `blockHash`     | `0x` hex                | Hash of the boundary block                                      |
| `finalized`     | boolean                 | `true` only when the epoch is finalized (irreversible)          |
| `source`        | string                  | Always `vrf-accumulator`                                        |

Semantics:

- A **sealed but not-yet-finalized** epoch is served with `finalized: false`.
  Its randomness can still change on a reorg until finality — wait for
  `finalized: true` before using it for anything irreversible.
- An epoch whose boundary block does not exist yet on this node returns
  error `-32000`.
- `qau_randomnessLatest` serves only finalized epochs (the "epoch 0 is not
  treated as finalized" policy matches the `eth_getBlockByNumber`
  `"finalized"` tag).

## WebSocket subscription

Nodes push newly finalized epoch randomness to `newRandomness` WebSocket
subscribers. Subscribe with `eth_subscribe`:

```json
{"jsonrpc":"2.0","id":1,"method":"eth_subscribe","params":["newRandomness"]}
```

Each finalized epoch is delivered as an `eth_subscription` notification whose
`params.result` payload carries the same fields as the `qau_randomness*`
responses:

| Field           | Format              | Meaning                                          |
|-----------------|---------------------|--------------------------------------------------|
| `epoch`         | decimal JSON number | Finalized epoch the randomness belongs to        |
| `randomness`    | `0x` hex (32 bytes) | The VRF accumulator of the epoch's boundary block |
| `boundaryBlock` | `0x` hex height     | Height of the epoch's boundary (last) block       |
| `blockHash`     | `0x` hex            | Hash of the boundary block                        |
| `finalized`     | boolean             | Always `true` — only finalized epochs are pushed  |
| `source`        | string              | Always `vrf-accumulator`                          |

Delivery semantics are **at-most-once**, not guaranteed delivery:

- Each subscriber has a bounded event queue. Under backpressure (a slow
  consumer) events are **dropped and not replayed** — the node does not
  buffer missed epochs.
- A reconnect (or a dropped socket) does not replay past epochs.

Consumers that must not miss an epoch should track the last seen `epoch` and
backfill gaps by polling `qau_randomnessGet` — on reconnect, and optionally on
a timer as a fallback alongside the subscription. Because finalized epochs are
immutable, backfill via `qau_randomnessGet` yields exactly the same values the
pushed events would have carried.

## Verification

The response is cross-checkable against public block data, so consumers do
not need to trust the serving node:

1. Take `boundaryBlock` from the response and call
   `eth_getBlockByNumber(boundaryBlock, false)`.
2. Confirm `blockHash` matches the block's `hash` field.
3. Confirm `randomness` equals the block's `vrfAccumulator` field — the same
   header value every node validated at import time.

Because a `finalized: true` epoch's boundary block is immutable, this
comparison pins the randomness to an irreversible on-chain value.

Consumers needing more than 32 bytes should derive them from `randomness`
(e.g., a KDF/counter construction) rather than requesting multiple epochs,
or derive per-consumer values as
`SHA-256(randomness || consumerSalt)` so that different applications reading
the same epoch do not collide.

## Access control and rate limits

Both methods are in the public allowlist (`PublicMethods` in `rpc/auth.go`):
no API key is required, and they are not admin-gated.

Unauthenticated requests are subject to the node's default rate limiter
(100 requests/second per IP, 1000 requests/second globally by default — see
`DefaultRateLimitConfig` in `rpc/ratelimit.go`). Operators serving
high-volume consumers can issue an API key with a higher `RateLimit` and a
`Permissions` whitelist restricted to these methods (`GenerateAPIKey` in
`rpc/auth.go`).

The methods expose only data that is already public on chain — unlike
`qau_qrngGetRandom` (admin-gated per audit API-02), serving them neither
drains node-local entropy nor correlates with it.
