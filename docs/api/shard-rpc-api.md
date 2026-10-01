# Shard RPC API Documentation

> P4-2 - 2026-07-15 - Quantaureum Sharding JSON-RPC Interface

## Overview

Shard RPC methods use the `qau_shard*` prefix and are exposed via the JSON-RPC 2.0 protocol. All methods return `-32601 "sharding not available (disabled)"` when sharding is not enabled (`QAU_ENABLE_SHARDING != "1"`).

**Endpoint:** `http://127.0.0.1:8545` (shares the port with the L1 RPC)

**Method classification:**
- 7 read-only methods (query shard status, blocks, commitments, receipts)
- 1 admin-gated write method (submit cross-shard messages)

**Return format notes:**
- Numeric values are returned as decimal integers (not hex)
- Addresses are hex strings with a `0x` prefix
- Hashes are hex strings with a `0x` prefix

---

## qau_shardGetShardCount

Returns the total number of all shards (active + inactive).

### Parameters

No parameters.

### Return value

| Field | Type | Description |
|------|------|------|
| (result) | int | Total number of shards |

### Example

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_shardGetShardCount","params":[],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": 4
}
```

---

## qau_shardGetActiveShardCount

Returns the number of active (`Active` status) shards.

### Parameters

No parameters.

### Return value

| Field | Type | Description |
|------|------|------|
| (result) | int | Number of active shards |

### Example

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_shardGetActiveShardCount","params":[],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": 3
}
```

---

## qau_shardGetShard

Returns information about a specified shard.

### Parameters

| Parameter | Type | Required | Description |
|------|------|------|------|
| shardId | uint64 | Yes | Shard ID |

### Return value

| Field | Type | Description |
|------|------|------|
| shardId | uint64 | Shard ID |
| status | string | Shard status: `Initializing` / `Active` / `Inactive` / `Migrating` |
| validators | string[] | List of validator addresses (`0x` hex) |
| latestHeight | uint64 | Latest block height |
| epoch | uint64 | Current epoch |
| assignmentEpoch | uint64 | Assignment table epoch (if present) |

### Example

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_shardGetShard",
       "params":[{"shardId":1}],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "shardId": 1,
    "status": "Active",
    "validators": [
      "0x9528fec867f70e4307f8032cec7cfac6bf42f17c",
      "0x464fa238475a22a6b7d024d9c29e0cf8200e638c",
      "0x3333333333333333333333333333333333333333"
    ],
    "latestHeight": 15234,
    "epoch": 42,
    "assignmentEpoch": 42
  }
}
```

### Errors

| Code | Description |
|------|------|
| -32601 | Sharding not enabled / shard does not exist |

---

## qau_shardGetBlock

Returns the block at a specified height on a specified shard.

### Parameters

| Parameter | Type | Required | Description |
|------|------|------|------|
| shardId | uint64 | Yes | Shard ID |
| height | uint64 | Yes | Block height |

### Return value

| Field | Type | Description |
|------|------|------|
| shardId | uint64 | Shard ID |
| height | uint64 | Block height |
| parentHash | string | Parent block hash (`0x` hex) |
| stateRoot | string | State root (`0x` hex) |
| txRoot | string | Transaction root (`0x` hex) |
| crossMsgRoot | string | Cross-shard message root (`0x` hex) |
| timestamp | uint64 | Block timestamp (Unix seconds) |
| proposer | string | Proposer address (`0x` hex) |
| signature | string | Proposer signature (`0x` hex) |
| finalized | bool | Whether it is finalized |
| txCount | int | Number of transactions |
| crossMsgCount | int | Number of cross-shard messages |
| vrfProof | string | VRF proof (`0x` hex, returned only when present) |
| vrfOutput | string | VRF output (`0x` hex) |

### Example

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_shardGetBlock",
       "params":[{"shardId":1,"height":15234}],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "shardId": 1,
    "height": 15234,
    "parentHash": "0xabc123...",
    "stateRoot": "0xdef456...",
    "txRoot": "0x789abc...",
    "crossMsgRoot": "0x000000...",
    "timestamp": 1721049600,
    "proposer": "0x9528fec867f70e4307f8032cec7cfac6bf42f17c",
    "signature": "0x...",
    "finalized": true,
    "txCount": 12,
    "crossMsgCount": 0,
    "vrfOutput": "0x..."
  }
}
```

### Errors

| Code | Description |
|------|------|
| -32601 | Sharding not enabled / shard does not exist / block does not exist |

---

## qau_shardGetCommitment

Returns the commitment (the commitment anchored to the main chain) at a specified height on a specified shard.

### Parameters

| Parameter | Type | Required | Description |
|------|------|------|------|
| shardId | uint64 | Yes | Shard ID |
| height | uint64 | Yes | Block height |

### Return value

| Field | Type | Description |
|------|------|------|
| shardId | uint64 | Shard ID |
| height | uint64 | Block height |
| commitment | string | Commitment hash (`0x` hex, 32 bytes) |

### Example

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_shardGetCommitment",
       "params":[{"shardId":1,"height":15000}],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "shardId": 1,
    "height": 15000,
    "commitment": "0xa1b2c3d4e5f6..."
  }
}
```

### Errors

| Code | Description |
|------|------|
| -32601 | Sharding not enabled / shard does not exist / no commitment submitted for this height |

---

## qau_shardSubmitCrossShardMessage

Submits a cross-shard message to the source shard. **This method is admin-gated** and requires administrator permissions.

### Parameters

| Parameter | Type | Required | Description |
|------|------|------|------|
| sourceShard | uint64 | Yes | Source shard ID |
| destShard | uint64 | Yes | Destination shard ID |
| sender | string | Yes | Sender address (`0x` hex) |
| recipient | string | Yes | Recipient address (`0x` hex) |
| payload | string | Yes | Message payload (`0x` hex, <= 64KB) |
| nonce | uint64 | Yes | Sender nonce (must be strictly increasing) |
| timestamp | uint64 | Yes | Timestamp (Unix seconds) |
| signature | string | Yes | Sender's Dilithium3 signature (`0x` hex) |

### Return value

| Field | Type | Description |
|------|------|------|
| messageId | string | Message ID (`0x` hex, derived from source/dest/sender/nonce) |
| accepted | bool | Whether it was accepted (always `true`) |

### Example

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "qau_shardSubmitCrossShardMessage",
    "params": [{
      "sourceShard": 1,
      "destShard": 2,
      "sender": "0x9528fec867f70e4307f8032cec7cfac6bf42f17c",
      "recipient": "0x464fa238475a22a6b7d024d9c29e0cf8200e638c",
      "payload": "0x48656c6c6f",
      "nonce": 42,
      "timestamp": 1721049600,
      "signature": "0x..."
    }],
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "messageId": "0x9f8a2b...",
    "accepted": true
  }
}
```

### Errors

| Code | Description |
|------|------|
| -32601 | Sharding not enabled / source shard does not exist |
| -32602 | Malformed parameters (address/payload/signature parse failure) |
| -32603 | Submission failed (shard inactive / payload too large / invalid signature / non-monotonic nonce) |

### Security Notes

- **Signature verification**: The message must be signed by the sender's Dilithium3 private key
- **Nonce monotonicity** (HIGH-17): The nonce of the same sender must be strictly increasing to prevent replay
- **Canonical ID** (GOV-R2-01): messageId is derived from (source, dest, sender, nonce) and cannot be tampered with
- **Payload size limit**: <= 65536 bytes (`ShardCrossMsgMaxSize`)

---

## qau_shardGetReceipt

Returns the cross-shard message receipt for a specified shard.

### Parameters

| Parameter | Type | Required | Description |
|------|------|------|------|
| shardId | uint64 | Yes | Shard ID |
| messageId | string | Yes | Message ID (`0x` hex) |

### Return value

| Field | Type | Description |
|------|------|------|
| messageId | string | Message ID (`0x` hex) |
| sourceShard | uint64 | Source shard ID |
| destShard | uint64 | Destination shard ID |
| txHash | string | Associated transaction hash (`0x` hex) |
| blockHeight | uint64 | Associated block height |
| relayed | bool | Whether it has been relayed |
| relayedAt | uint64 | Slot at relay time |
| spent | bool | Whether the receipt has been spent |
| spentAt | uint64 | Slot at spend time |

### Example

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_shardGetReceipt",
       "params":[{"shardId":1,"messageId":"0x9f8a2b..."}],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "messageId": "0x9f8a2b...",
    "sourceShard": 1,
    "destShard": 2,
    "txHash": "0xabc123...",
    "blockHeight": 15234,
    "relayed": true,
    "relayedAt": 15235,
    "spent": false,
    "spentAt": 0
  }
}
```

### Errors

| Code | Description |
|------|------|
| -32601 | Sharding not enabled / shard does not exist / receipt does not exist |

---

## qau_shardIsReceiptSpent

Checks whether the cross-shard message receipt for a specified shard has been spent.

### Parameters

| Parameter | Type | Required | Description |
|------|------|------|------|
| shardId | uint64 | Yes | Shard ID |
| messageId | string | Yes | Message ID (`0x` hex) |

### Return value

| Field | Type | Description |
|------|------|------|
| shardId | uint64 | Shard ID |
| messageId | string | Message ID (`0x` hex) |
| spent | bool | Whether it has been spent |

### Example

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_shardIsReceiptSpent",
       "params":[{"shardId":2,"messageId":"0x9f8a2b..."}],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "shardId": 2,
    "messageId": "0x9f8a2b...",
    "spent": false
  }
}
```

### Errors

| Code | Description |
|------|------|
| -32601 | Sharding not enabled / shard does not exist |

---

## Error Code Summary

| Code | Meaning | Trigger Scenario |
|------|------|---------|
| -32601 | Method unavailable / resource does not exist | Sharding not enabled / shard does not exist / block does not exist / receipt does not exist / commitment does not exist |
| -32602 | Parameter error | JSON parse failure / malformed address format / malformed payload format / malformed signature format |
| -32603 | Internal error | Cross-shard message submission failed (shard inactive / payload too large / invalid signature / non-monotonic nonce) |

## Related Documents

- Shard operations runbooks are maintained in the operator's internal documentation (not part of the public repo).
- [ShardManager Architecture Document](../architecture/shard-manager.md) - seven-layer architecture, component interactions, sequence diagrams
- [JSON-RPC API Overview](JSON_RPC_API.md) - standard `eth_*` methods