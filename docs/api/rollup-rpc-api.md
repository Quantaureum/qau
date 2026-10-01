# Rollup RPC API Documentation

> W-P4-3 - 2026-07-15 - Quantaureum L2 Rollup JSON-RPC Interface

## Overview

Rollup RPC methods use the `qau_rollup*` prefix and are exposed via the JSON-RPC 2.0 protocol. All methods return a `-32601` error when the Rollup is not enabled.

**Endpoint:** `http://127.0.0.1:8545` (shares the port with the L1 RPC)

**Note:** All numeric values are returned as decimal integers (not hex); addresses and hashes are hex strings with a `0x` prefix.

---

## qau_rollupGetStatus

Retrieves the Rollup engine status, statistics, and configuration.

### Parameters

No parameters.

### Return value

| Field | Type | Description |
|------|------|------|
| status | string | Engine status: `stopped` / `running` / `paused` / `stopping` |
| totalBatches | uint64 | Total number of successfully submitted batches |
| totalTxs | uint64 | Total number of processed L2 transactions |
| uptime | string | Uptime (Go duration format) |
| pendingTxs | int | Number of pending transactions |
| chainId | uint64 | L2 chain ID (1670) |
| l1ChainId | uint64 | L1 chain ID (1668) |
| blockTime | string | L2 block interval |

### Example

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_rollupGetStatus","params":[],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "status": "running",
    "totalBatches": 15234,
    "totalTxs": 89721,
    "uptime": "8h30m15s",
    "pendingTxs": 3,
    "chainId": 1670,
    "l1ChainId": 1668,
    "blockTime": "2s"
  }
}
```

---

## qau_rollupGetBatch

Retrieves information about a specified batch.

### Parameters

| Parameter | Type | Required | Description |
|------|------|------|------|
| index | uint64 | Yes | Batch index (starting from 0) |

### Return value

| Field | Type | Description |
|------|------|------|
| index | uint64 | Batch index |
| prevStateRoot | string | Pre-batch state root (0x hex) |
| postStateRoot | string | Post-batch state root (0x hex) |
| txCount | int | Number of transactions in the batch |
| totalGasUsed | uint64 | Total Gas consumed by the batch |
| timestamp | int64 | Batch creation timestamp (Unix) |
| status | string | Batch status: `pending` / `submitted` / `finalized` / `challenged` / `rejected` |
| batchHash | string | Batch hash (0x hex) |
| submittedAt | int64 | Submission timestamp |
| finalizedAt | int64 | Finalization timestamp |
| challengeDeadline | int64 | Challenge deadline timestamp |

### Example

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_rollupGetBatch","params":[{"index":42}],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "index": 42,
    "prevStateRoot": "0xabc123...",
    "postStateRoot": "0xdef456...",
    "txCount": 15,
    "totalGasUsed": 315000,
    "timestamp": 1721000000,
    "status": "finalized",
    "batchHash": "0x789abc...",
    "submittedAt": 1721000005,
    "finalizedAt": 1721604805,
    "challengeDeadline": 1721604800
  }
}
```

---

## qau_rollupGetStateRoot

Retrieves the L2 state root. Can query the state root of a specific batch or the latest state root.

### Parameters

| Parameter | Type | Required | Description |
|------|------|------|------|
| batchIndex | uint64 | No | Batch index. If omitted, returns the latest state root |

### Return value

**Specific batch:**
| Field | Type | Description |
|------|------|------|
| batchIndex | uint64 | Batch index |
| stateRoot | string | State root (0x hex) |

**Latest state root:**
| Field | Type | Description |
|------|------|------|
| stateRoot | string | Latest state root (0x hex) |
| latest | bool | Always true |

### Example

**Query a specific batch:**
```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_rollupGetStateRoot","params":[{"batchIndex":5}],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "batchIndex": 5,
    "stateRoot": "0xabcdef1234567890..."
  }
}
```

**Query the latest:**
```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"qau_rollupGetStateRoot","params":[],"id":1}'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "stateRoot": "0xabcdef1234567890...",
    "latest": true
  }
}
```

---

## qau_rollupSendRawTransaction

Submits a pre-signed L2 transaction to the sequencer. **This method is admin-only** and requires authentication.

### Parameters

| Parameter | Type | Required | Description |
|------|------|------|------|
| nonce | uint64 | Yes | Sender nonce |
| gasPrice | uint64 | Yes | Gas price (wei) |
| gasLimit | uint64 | Yes | Gas limit |
| to | string | No | Recipient address (0x hex, omitted for contract creation) |
| value | string | No | Transfer amount (0x hex, in wei) |
| data | string | No | Call data (0x hex, used for contract calls) |
| from | string | Yes | Sender address (0x hex) |
| chainId | uint64 | Yes | L2 chain ID (must be 1670) |
| publicKey | string | Yes | Sender's Dilithium3 public key (0x hex, 1952 bytes) |
| signature | string | Yes | Dilithium3 signature (0x hex, 3293 bytes) |

### Return value

| Field | Type | Description |
|------|------|------|
| txHash | string | Transaction hash (0x hex) |
| status | string | Always `submitted` |

### L2 Transaction Signature Format

L2 transactions use the Dilithium3 post-quantum signature algorithm. The signature covers the following fields:

```
SigningHash = SHA256(
    From      ||  // 20 bytes - sender address
    Nonce     ||  // 8 bytes  - transaction nonce
    GasPrice  ||  // 8 bytes  - gas price
    GasLimit  ||  // 8 bytes  - gas limit
    To        ||  // 20 bytes - recipient address (optional)
    Value     ||  // variable  - transfer amount (length-prefixed)
    Data      ||  // variable  - call data (length-prefixed)
    ChainID       // 8 bytes  - L2 chain ID (prevents cross-chain replay)
)
```

**Signature verification flow:**
1. Derive the address from `publicKey` and verify it matches `from`
2. Compute `SigningHash`
3. Verify the Dilithium3 signature (`signature` over `SigningHash`)

**Notes:**
- `publicKey` and `signature` are not included in `SigningHash` (they are verification metadata)
- `ChainID` must be 1670 (L2), distinguishing it from the L1's 1668, to prevent cross-chain replay
- L2 account public keys are not stored on L1, so transactions must carry the public key inline

### Example

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{
    "jsonrpc": "2.0",
    "method": "qau_rollupSendRawTransaction",
    "params": [{
      "nonce": 0,
      "gasPrice": 1000000000,
      "gasLimit": 21000,
      "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
      "value": "0x64",
      "from": "0x4444444444444444444444444444444444444444",
      "chainId": 1670,
      "publicKey": "0x<1952 bytes Dilithium3 public key hex>",
      "signature": "0x<3293 bytes Dilithium3 signature hex>"
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
    "txHash": "0xabcdef1234567890...",
    "status": "submitted"
  }
}
```

### Error Codes

| Error Code | Description |
|--------|------|
| -32601 | Rollup not enabled |
| -32602 | Invalid parameters (missing required fields, malformed address, etc.) |
| -32000 | Transaction submission failed (signature verification failure, ChainID mismatch, insufficient balance, etc.) |

---

## qau_rollupGetAnchor

Retrieves the L1 anchoring record of a batch. Used by challengers to verify batch integrity.

### Parameters

Supports two parameter formats:

**Object format:**
| Parameter | Type | Required | Description |
|------|------|------|------|
| batchHash | string | Yes | Batch hash (0x hex, 32 bytes) |

**String format:** Pass the batch hash string directly.

### Return value

**Anchored:**
| Field | Type | Description |
|------|------|------|
| found | bool | Always true |
| batchHash | string | Batch hash (0x hex) |
| postStateRoot | string | Post-batch state root (0x hex) |
| txDataHash | string | Transaction data hash (0x hex, sha256) |
| submitHeight | uint64 | L1 submission height |
| challengeBlocks | uint64 | Challenge period in blocks |
| challengeDeadlineHeight | uint64 | Challenge deadline height (submitHeight + challengeBlocks) |
| currentHeight | uint64 | Current L1 height |

**Not found:**
| Field | Type | Description |
|------|------|------|
| found | bool | Always false |

**L1 anchoring not configured:**
| Field | Type | Description |
|------|------|------|
| enabled | bool | Always false |
| message | string | "L1 anchor not configured" |

### Example

```bash
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "qau_rollupGetAnchor",
    "params": [{"batchHash": "0x789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456"}],
    "id": 1
  }'
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "found": true,
    "batchHash": "0x789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456",
    "postStateRoot": "0xdef456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef01",
    "txDataHash": "0xabc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "submitHeight": 1000500,
    "challengeBlocks": 100,
    "challengeDeadlineHeight": 1000600,
    "currentHeight": 1000525
  }
}
```

---

## Error Code Table

| Error Code | Meaning | Trigger Scenario |
|--------|------|---------|
| -32601 | Method not found | Rollup not enabled (`QAU_ENABLE_ROLLUP` not set) |
| -32602 | Invalid params | Missing parameters, malformed formats, invalid address/hash format |
| -32000 | Server error | Transaction submission failure, batch does not exist, state root not found, and other internal errors |

### Common Error Messages

| Error Message | Cause | Solution |
|---------|------|---------|
| `rollup not available (disabled)` | Rollup not enabled | Set `QAU_ENABLE_ROLLUP=1` |
| `invalid 'from' address` | Malformed address format | Use a 20-byte hex address with a 0x prefix |
| `missing 'publicKey'` | Public key missing | L2 transactions must carry the Dilithium3 public key |
| `missing 'signature'` | Signature missing | L2 transactions must carry the Dilithium3 signature |
| `invalid 'value' (expected hex string)` | Malformed value format | Use a hex string with a 0x prefix |
| `transaction chainID X does not match rollup chainID Y` | ChainID mismatch | L2 transactions must use ChainID=1670 |
| `transaction signature is required` | Signature verification failure | Check public key derivation and signature correctness |
| `batch not found` | Batch does not exist | Check whether the batch index is valid |
| `state root not found for batch index` | State root does not exist | The batch may not be submitted or the index is invalid |
| `invalid batchHash (expected 32-byte hex)` | Malformed hash format | Use a 32-byte hex value with a 0x prefix |

---

## L1-L2 Bridge RPC Methods

The following methods are used to query bridge status (all read-only):

| Method | Description |
|------|------|
| `qau_l1BridgeGetStatus` | Bridge status (address, L1 liquidity, number of pending withdrawals) |
| `qau_l1BridgeGetLiquidity` | Total QAU locked on L1 (hex) |
| `qau_l1BridgeGetDeposit` | Query a deposit record (by deposit hash) |
| `qau_l1BridgeGetFinalizedStateRoot` | Query a finalized L2 state root (by batch index) |
| `qau_l1BridgeGetContractBytecode` | Get the L1Bridge QASM contract bytecode (for deployment) |
| `qau_l1BridgeEncodeRecordFinalizedBatch` | Encode the recordFinalizedBatch call data |