# Bridge Arbitration RPC API Documentation

> P4-2 - 2026-07-15 - Quantaureum Cross-Chain Bridge API

## 1. Overview

The bridge arbitration subsystem provides two types of API interfaces:

| Interface Type | Protocol | Prefix | Authentication | Use Case |
|---------|------|------|------|---------|
| JSON-RPC | JSON-RPC 2.0 | `qau_bridge*` | Standard RPC authentication (admin methods require authentication) | Wallets / block explorers / integrators |
| HTTP API | RESTful | `/api/v1/bridge/*` | `X-API-Key` request header | Operations management / relayer operations |

## 2. JSON-RPC Methods (3)

All JSON-RPC methods follow the standard JSON-RPC 2.0 specification. When the bridge feature is disabled, a `-32601` error is returned.

### 2.1 qau_bridgeGetStatus

Returns an overview of the overall bridge status.

**Permissions:** Public (no authentication required)

**Parameters:** None

```json
{
  "jsonrpc": "2.0",
  "method": "qau_bridgeGetStatus",
  "params": [],
  "id": 1
}
```

**Return value:**

| Field | Type | Description |
|------|------|------|
| `enabled` | bool | Whether the bridge is enabled |
| `pendingMessages` | int | Number of messages currently in PENDING status |
| `supportedChains` | int | Number of configured chains |

**Example response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "enabled": true,
    "pendingMessages": 3,
    "supportedChains": 2
  }
}
```

### 2.2 qau_bridgeGetPendingTransfers

Returns all pending cross-chain transfer messages. **This method is admin-only** and requires authentication.

**Permissions:** Admin (requires RPC authentication)

**Parameters:** None

```json
{
  "jsonrpc": "2.0",
  "method": "qau_bridgeGetPendingTransfers",
  "params": [],
  "id": 1
}
```

**Return value:** Array of message objects

| Field | Type | Description |
|------|------|------|
| `id` | string | Unique message identifier |
| `sourceChain` | string | Source chain ID |
| `targetChain` | string | Target chain ID |
| `sourceAddress` | string | Sending address on the source chain |
| `targetAddress` | string | Receiving address on the target chain |
| `assetType` | string | Asset type (NATIVE/QRC20/QRC721/QRC1155/QAU/WRAPPED) |
| `amount` | string | Transfer amount (smallest unit, decimal string) |
| `nonce` | uint64 | Replay-prevention nonce |
| `timestamp` | int64 | Message creation timestamp (Unix) |
| `status` | string | Message status (PENDING) |
| `messageType` | string | Message type (ASSET_TRANSFER/CONTRACT_CALL/DATA_TRANSFER) |

**Example response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": [
    {
      "id": "msg-001",
      "sourceChain": "quantaureum",
      "targetChain": "ethereum",
      "sourceAddress": "0x1111111111111111111111111111111111111111",
      "targetAddress": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1",
      "assetType": "QAU",
      "amount": "1000000000000000000",
      "nonce": 42,
      "timestamp": 1721000000,
      "status": "PENDING",
      "messageType": "ASSET_TRANSFER"
    }
  ]
}
```

### 2.3 qau_bridgeGetSupportedChains

Returns the list of chain IDs supported by the bridge.

**Permissions:** Public (no authentication required)

**Parameters:** None

```json
{
  "jsonrpc": "2.0",
  "method": "qau_bridgeGetSupportedChains",
  "params": [],
  "id": 1
}
```

**Return value:**

| Field | Type | Description |
|------|------|------|
| `chains` | string[] | List of supported chain IDs |
| `count` | int | Number of chains |

**Example response:**

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "chains": ["quantaureum", "ethereum"],
    "count": 2
  }
}
```

## 3. HTTP API Endpoints (7)

All HTTP API endpoints require `X-API-Key` request header authentication. The API Key is set in the node configuration, hashed with SHA256, and compared in constant time.

### 3.1 Authentication

```
X-API-Key: <your-api-key>
```

Authentication failure returns `401 Unauthorized`:
```json
{"error": "unauthorized: invalid or missing API key"}
```

### 3.2 GET /api/v1/bridge/status

Returns a bridge status overview (same as `qau_bridgeGetStatus`).

**Response:**
```json
{
  "enabled": true,
  "pendingMessages": 3,
  "supportedChains": 2
}
```

### 3.3 GET|POST /api/v1/bridge/message

- **GET**: Retrieve a single message by the `id` query parameter
- **POST**: Submit a new cross-chain message

**GET parameters:** `?id=<messageID>`

**GET response:**
```json
{
  "id": "msg-001",
  "sourceChain": "quantaureum",
  "targetChain": "ethereum",
  "status": "EXECUTED",
  "amount": "1000000000000000000"
}
```

**POST request body:**
```json
{
  "id": "msg-002",
  "source_chain": "quantaureum",
  "target_chain": "ethereum",
  "source_address": "0xB74A...",
  "target_address": "0x742d...",
  "asset_type": "QAU",
  "amount": "500000000000000000",
  "nonce": 43,
  "message_type": "ASSET_TRANSFER",
  "quantum_signature": "<3293 bytes hex>",
  "quantum_public_key": "<1952 bytes hex>"
}
```

**POST response:**
```json
{
  "success": true,
  "message_id": "msg-002"
}
```

### 3.4 GET /api/v1/bridge/messages

Query a list of messages by status.

**Parameters:** `?status=<PENDING|VERIFIED|EXECUTED|FAILED|EXPIRED>`

**Response:**
```json
{
  "messages": [
    {"id": "msg-001", "status": "PENDING", ...}
  ],
  "count": 1
}
```

### 3.5 POST|GET /api/v1/bridge/lock

- **POST**: Create an asset lock
- **GET**: Query lock status by `id`

**POST request body:**
```json
{
  "asset_id": "0xTokenAddr...",
  "amount": "1000000000000000000",
  "source_chain": "quantaureum",
  "target_chain": "ethereum",
  "locker": "0xB74A..."
}
```

**POST response:**
```json
{
  "lock_id": "lock-001",
  "status": "Pending"
}
```

### 3.6 GET /api/v1/bridge/locks

Query the asset lock list.

**Parameters:** `?status=<Pending|Locked|Minted|Burned|Unlocked>`

**Response:**
```json
{
  "locks": [
    {"lock_id": "lock-001", "status": "Locked", ...}
  ],
  "count": 1
}
```

### 3.7 POST /api/v1/bridge/relay

Submit a relay task.

**Request body:**
```json
{
  "message_id": "msg-001"
}
```

**Response:**
```json
{
  "task_id": "task-001",
  "status": "submitted"
}
```

### 3.8 GET /api/v1/bridge/validators

Returns the current bridge validator set.

**Response:**
```json
{
  "validators": [
    {
      "address": "0x1111111111111111111111111111111111111111",
      "active": true,
      "stake": "1000000000000000000000000",
      "signed_count": 42,
      "missed_count": 0
    }
  ],
  "threshold": 2,
  "total_stake": "3000000000000000000000000"
}
```

## 4. Error Codes

| Error Code | Meaning | Trigger Scenario |
|--------|------|---------|
| `-32601` | Method not found | Bridge not enabled (`api.bridge == nil`) |
| `-32000` | Server error | Internal error (e.g., storage read failure) |
| `-32602` | Invalid params | Missing or malformed parameters |
| `401` | Unauthorized | API Key invalid or missing |
| `400` | Bad Request | Request body parse failure |
| `404` | Not Found | Message/lock does not exist |
| `500` | Internal Server Error | Authentication not configured or internal exception |

## 5. Security Notes

- `qau_bridgeGetPendingTransfers` is an **admin-only** method, marked via `RegisterAdminMethod`; the RPC server's authentication middleware enforces authentication
- The HTTP API's `X-API-Key` is hashed with SHA256 and compared in **constant time** (`subtle.ConstantTimeCompare`) to prevent timing attacks
- The API server is configured with Slowloris protection (`ReadHeaderTimeout: 10s`) and header size limits (`MaxHeaderBytes: 1MiB`)
- On message submission, `QuantumPublicKey` is forcibly validated to be in the `trustedValidatorKeys` set (BRDG-01 FIX)