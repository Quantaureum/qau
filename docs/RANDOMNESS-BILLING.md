# Randomness API Billing

This document describes the on-chain billing loop for the verifiable
randomness API (see [RANDOMNESS-API.md](RANDOMNESS-API.md)): consumers pay
QAU into the `vrf_deposit` contract and the billing worker converts deposits
into API-key service time.

## Billing model — honest scope

- **Time subscription**: a deposit of `N × weiPerDay` raw wei extends the
  named API key's expiry by `N` days (integer floor; deposits below one day
  are recorded on-chain but grant no time).
- **No per-request metering.** The node counts usage per key (`UsageCount`)
  and enforces per-key rate limits, but payment buys *time*, not requests.
  Per-request billing would require quota-decrement enforcement in the auth
  path and is deliberately out of scope.
- Deposits are service fees: `deposit()` payments are NOT withdrawable by
  depositors. `withdraw()` is the operator sweep (owner-only).
- The served randomness remains publicly verifiable and free at the base
  tier; paid keys buy higher rate limits, not exclusive data.

## Components

| Component | Location | Role |
|---|---|---|
| `vrf_deposit` contract | `contracts/qasm/vrf_deposit.qasm` (+`.hex`) | Holds deposits, emits `Deposit(address,uint256,bytes32)` events |
| Billing worker | `cmd/vrf-billing` | Watches events, calls `admin_extendAPIKey` |
| Key management RPC | `rpc/admin_key_api.go` | `admin_generateAPIKey` / `admin_listAPIKeys` / `admin_revokeAPIKey` / `admin_extendAPIKey` (admin-gated) |
| Key persistence | `<dataDir>/apikeys.json` | Hashed key registry, survives restarts |

## Event format (worker ↔ contract contract)

- `topic0` = `keccak256("Deposit(address,uint256,bytes32)")` (the worker
  computes this constant from the signature; override with `-topic0`).
- `data` (96 bytes): `pad32(payer) ++ pad32(amountWei) ++ pad32(keyHash)`.
  The caller passes their API key's SHA-256 hash (`keyHash`) in the deposit
  call, so the worker can address the key without any off-chain registry.
  Standard ABI tooling can decode both topics and data.

## Deployment

1. Assemble: `go run ./cmd/qasm assemble contracts/qasm/vrf_deposit.qasm contracts/qasm/vrf_deposit.hex`
2. Deploy via a contract-creation transaction (`TxTypeCreate`) carrying the
   hex bytecode as `data`, signed like any transaction. The receipt's
   `contractAddress` is the deployed address (`qvm.CreateAddress(sender, nonce)`).
3. Record the address — it is the worker's `-contract` argument.

## Key issuance and the worker

```bash
# 1. Issue a consumer key (admin RPC; plaintext shown once):
#    "rateLimit" is the paid tier in requests/minute (QR-41): omit or 0 for
#    the unthrottled default, e.g. 240 to sell a 240 req/min tier.
curl -s http://127.0.0.1:8545 -X POST -H 'Content-Type: application/json' \
  -H 'X-API-Key: <ADMIN_KEY>' \
  -d '{"jsonrpc":"2.0","id":1,"method":"admin_generateAPIKey",
       "params":{"name":"consumer-a","permissions":["qau_randomnessGet","qau_randomnessLatest"],"days":0,"rateLimit":240}}'
# -> {"result":{"apiKey":"<PLAINTTEXT>","keyHash":"0x<64 hex>","rateLimit":240,...}}

# 2. Run the worker against the deployed contract:
go build ./cmd/vrf-billing/
./vrf-billing -rpc http://127.0.0.1:8545 \
  -contract 0x<contractAddress> \
  -admin-key <ADMIN_KEY> \
  -wei-per-day 1000000000000000000 \
  -state ./vrf-billing-state.json
```

Worker behavior:

- Anchors at the current **finalized** height on first boot (no historical
  replay); processes only at/below finalized height each pass — receipts are
  proposer-authority data outside the consensus root, so finality is the
  reorg-safety boundary.
- Idempotent: the state file records the last processed height; writes are
  atomic (temp + rename) after every processed log. `-dry-run` prints actions
  without state changes.
- Processing latency: a deposit is converted once its block is **finalized**
  plus at most one poll interval — `-interval` defaults to **30 s**, so the
  end-to-end delay is finality latency + up to ~30 s (QR-45).
- A failed `admin_extendAPIKey` is logged loudly (with the on-chain tx hash)
  but does not stall the pass; the deposit remains reconcilable manually
  from chain data. Deposits worth more than 3650 days are split into several
  `admin_extendAPIKey` calls (the RPC caps a single call at 3650 days).
- Deposits below `weiPerDay` grant zero days and are skipped (visible in
  logs).

## Consumer flow

1. Call `admin_generateAPIKey` (or ask the operator) → receive plaintext key
   `K` and its `keyHash = SHA-256(K)`. Pass `rateLimit` (requests/minute) to
   buy a paid tier; omit or 0 keeps the key unthrottled (QR-41).
2. Send `K` as `X-API-Key` on `qau_randomness*` calls; the key's `RateLimit`
   throttles it per minute (see `auth.go` `APIKeyInfo`).
3. To extend service: call `deposit(bytes32 keyHash)` on `vrf_deposit` with
   `value = days × weiPerDay` and `keyHash` in calldata. The worker extends
   the key within one poll interval after the epoch finalizes (~13 min worst
   case on this chain's finality cadence).

**The key must exist before the deposit lands (QR-45).** The worker addresses
keys only by the `keyHash` carried in the deposit event. A deposit whose
`keyHash` matches no registered API key cannot be converted: the worker logs
the event and moves on, and deposits are non-withdrawable service fees (the
contract has no depositor refund), so **the funds are permanently stuck**.
Always generate the key first, then deposit against its `keyHash`.

**Zero-block epochs have no randomness (QR-45).** The randomness service
serves per-epoch VRF accumulators, and an epoch's accumulator is carried by
that epoch's boundary block. If an epoch produced no block, its randomness
is permanently "not available yet" — there is no block to carry it, so the
error for such an epoch is a permanent state, not a delay; the next epoch
with blocks resumes the sequence.

## Security notes

- `apikeys.json` contains hashes only; it must still be treated as
  sensitive (rate-limit metadata and expiry are operationally useful to an
  attacker). The file is written with 0600 on POSIX.
- `admin_*` methods require admin authentication (API key with admin
  permissions, HMAC, or admin address per the node's auth policy) — never
  expose them on a public listener without that gate.
- The worker's `-admin-key` is a plaintext credential; provision it via a
  secret manager, not shell history.
