# Quantaureum RPC API Documentation

## Overview

Quantaureum provides a JSON-RPC 2.0 compatible API for interacting with the blockchain.
All native methods use the `qau_` prefix. For backward compatibility with Ethereum tools
(e.g., MetaMask), `eth_` prefixed calls are automatically mapped to `qau_` equivalents.

**Testnet Endpoints:**
- HTTP RPC: `https://testnet-rpc.quantaureum.com`
- WebSocket: `wss://testnet-rpc.quantaureum.com/ws`
- Health Check: `https://testnet-rpc.quantaureum.com/health`

**Local Development Endpoints:**
- HTTP RPC: `http://localhost:8645`
- WebSocket: `ws://localhost:8646`
- Health Check: `http://localhost:8080/health`

---

## RPC Methods (QAU Native)

### Chain Information

| Method | Description |
|--------|-------------|
| `eth_chainId` | Returns the chain ID (testnet: 0x685 = 1669) |
| `net_version` | Returns the network ID |
| `eth_protocolVersion` | Returns the protocol version |
| `eth_blockNumber` | Returns the latest block number |
| `eth_gasPrice` | Returns the current gas price |
| `eth_syncing` | Returns sync status or false if synced |

#### `eth_chainId`
Returns the chain ID.

**Request:**
```json
{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}
```

**Response:**
```json
{"jsonrpc":"2.0","result":"0x685","id":1}
```

#### `net_version`
Returns the network ID as decimal string.

**Request:**
```json
{"jsonrpc":"2.0","method":"net_version","params":[],"id":1}
```

**Response:**
```json
{"jsonrpc":"2.0","result":"1669","id":1}
```

#### `eth_protocolVersion`
Returns the protocol version.

#### `eth_blockNumber`
Returns the latest block number.

**Request:**
```json
{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}
```

**Response:**
```json
{"jsonrpc":"2.0","result":"0x10","id":1}
```

#### `eth_gasPrice`
Returns the current gas price (default: 1 Gwei = 0x3b9aca00).

#### `eth_syncing`
Returns an object with sync progress, or `false` if synced.

**Response (syncing):**
```json
{
  "startingBlock": "0x0",
  "currentBlock": "0x100",
  "highestBlock": "0x200"
}
```

### Account Methods

| Method | Description |
|--------|-------------|
| `eth_getBalance` | Returns the balance of an account |
| `eth_getTransactionCount` | Returns the nonce of an account |
| `eth_getCode` | Returns the contract code at an address |
| `eth_getStorageAt` | Returns the storage value at a position |

#### `eth_getBalance`
Returns the balance of an account.

**Parameters:**
1. `address` - Account address (0x-hex or QAU-Base32)
2. `block` - Block number or "latest" (optional, default: "latest")

**Request:**
```json
{"jsonrpc":"2.0","method":"eth_getBalance","params":["0xa38b3b8679a3b20c7d23226bb60ca13c670e994e","latest"],"id":1}
```

**Response:**
```json
{"jsonrpc":"2.0","result":"0xde0b6b3a7640000","id":1}
```

#### `eth_getTransactionCount`
Returns the nonce of an account.

**Parameters:**
1. `address` - Account address
2. `block` - Block number or "latest"

#### `eth_getCode`
Returns the code at an address (empty string for non-contract accounts).

**Parameters:**
1. `address` - Contract address
2. `block` - Block number or "latest"

#### `eth_getStorageAt`
Returns the storage value at a given position.

**Parameters:**
1. `address` - Contract address
2. `position` - Storage key (hex)
3. `block` - Block number or "latest" (optional)

### Block Methods

| Method | Description |
|--------|-------------|
| `eth_getBlockByHash` | Returns a block by its hash |
| `eth_getBlockByNumber` | Returns a block by its number |
| `eth_getBlockTransactionCountByHash` | Returns transaction count in a block by hash |
| `eth_getBlockTransactionCountByNumber` | Returns transaction count in a block by number |
| `eth_getTransactionByBlockHashAndIndex` | Returns a transaction by block hash and index |
| `eth_getTransactionByBlockNumberAndIndex` | Returns a transaction by block number and index |

#### `eth_getBlockByHash`
Returns a block by its hash.

**Parameters:**
1. `hash` - Block hash
2. `fullTx` - If true, returns full transaction objects; if false, returns only hashes

#### `eth_getBlockByNumber`
Returns a block by its number.

**Parameters:**
1. `number` - Block number (hex), "latest", "earliest", "pending", "safe", or "finalized"
2. `fullTx` - If true, returns full transaction objects

> **Note:** "safe" and "finalized" use QPOS finality data. "finalized" returns the highest block in the finalized epoch; "safe" returns the highest block in the justified epoch. Falls back to "latest" when QPOS status is unavailable.

### Transaction Methods

| Method | Description |
|--------|-------------|
| `eth_sendTransaction` | Sends a transaction (requires unlocked account) |
| `eth_sendRawTransaction` | Sends a signed raw transaction |
| `eth_getTransactionByHash` | Returns a transaction by its hash |
| `eth_getTransactionReceipt` | Returns a transaction receipt |
| `eth_estimateGas` | Estimates gas for a transaction |
| `eth_call` | Executes a contract call (no state change) |
| `qau_submitCommitment` | Submits a commit-reveal commitment |

#### `eth_sendRawTransaction`
Sends a signed raw transaction (recommended for production).

**Parameters:**
1. `data` - Signed transaction data (hex, protobuf-encoded with Dilithium3 signature)

**Request:**
```json
{"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x..."],"id":1}
```

**Response:**
```json
{"jsonrpc":"2.0","result":"0x...txhash...","id":1}
```

#### `eth_sendTransaction`
Sends a transaction using an unlocked account (requires personal_unlockAccount first).

**Parameters:**
1. `transaction` - Transaction object: `{from, to, value, data, gasLimit, gasPrice}`

> **Note:** For production, prefer `eth_sendRawTransaction` with client-side signing.

#### `eth_estimateGas`
Estimates the gas needed for a transaction.

**Parameters:**
1. `transaction` - Transaction object (same as eth_sendTransaction)

**Response:**
```json
{"jsonrpc":"2.0","result":"0x5208","id":1}
```

#### `eth_call`
Executes a contract call without changing state.

**Parameters:**
1. `transaction` - Transaction object
2. `block` - Block number or "latest" (optional)

### Filter Methods

| Method | Description |
|--------|-------------|
| `eth_newFilter` | Creates a new log filter |
| `eth_newBlockFilter` | Creates a filter for new blocks |
| `eth_newPendingTransactionFilter` | Creates a filter for pending transactions |
| `eth_uninstallFilter` | Removes a filter |
| `eth_getFilterChanges` | Returns new events since last poll |
| `eth_getFilterLogs` | Returns all events matching a filter |
| `eth_getLogs` | Returns logs matching a filter object |

### Network Methods

| Method | Description |
|--------|-------------|
| `net_version` | Returns the network ID (decimal string) |
| `net_peerCount` | Returns the number of connected peers |
| `net_listening` | Returns true if the node is listening |

### Transaction Pool Methods

| Method | Description |
|--------|-------------|
| `txpool_status` | Returns pending/queued transaction counts |
| `txpool_content` | Returns pending/queued transaction details |
| `eth_pendingTransactions` | Returns all pending transactions |

### Web3 Methods

| Method | Description |
|--------|-------------|
| `web3_clientVersion` | Returns the client version ("Quantaureum/v1.0.0/go") |
| `web3_sha3` | Returns Keccak-256 hash of input |

### Admin Methods (Require Authentication)

| Method | Description |
|--------|-------------|
| `admin_peers` | Returns connected peer information |
| `admin_nodeInfo` | Returns local node information |
| `admin_mint` | Mints new tokens (admin only, IP-whitelisted) |
| `qau_admin_peers` | Same as admin_peers (qau_ prefix) |
| `qau_admin_nodeInfo` | Same as admin_nodeInfo (qau_ prefix) |
| `qau_admin_mint` | Same as admin_mint (qau_ prefix) |

> **Security:** Admin methods require API key authentication and IP whitelist validation.

### Personal Account Methods (Require Authentication)

| Method | Description |
|--------|-------------|
| `personal_newAccount` | Creates a new Dilithium3 account |
| `personal_unlockAccount` | Unlocks an account for signing |
| `personal_importRawKey` | Imports a Dilithium3 private key |
| `personal_sendTransaction` | Sends a transaction from an unlocked account |
| `personal_sign` | Signs data with an account's key |

### QPOS Consensus Methods

| Method | Description |
|--------|-------------|
| `qau_qposStatus` | Returns QPOS consensus status |

### Staking Methods

| Method | Description | Auth Required |
|--------|-------------|---------------|
| `qau_stake` | Stake QAU tokens as a validator | Yes (Dilithium3 sig) |
| `qau_unstake` | Request unstake of staked tokens | Yes (Dilithium3 sig) |
| `qau_getStake` | Get stake info for an address | No |
| `qau_getStakingPools` | Get available staking pools | No |
| `qau_getStakingStats` | Get global staking statistics | No |
| `qau_getUserStakes` | Get all stakes for a user | No |
| `qau_claimRewards` | Claim pending staking rewards | Yes (Dilithium3 sig) |
| `qau_compoundRewards` | Re-stake pending rewards | Yes (Dilithium3 sig) |
| `qau_getStakingContracts` | Get staking contract addresses | No |
| `qau_getPendingRewards` | Get pending rewards for an address | No |
| `qau_getUnstakeStatus` | Get unstake request status | No |
| `qau_getContractBalance` | Get staking contract balance | No |

#### `qau_stake`
Stake QAU tokens to become a validator.

**Parameters:**
1. `address` - Staker address (hex)
2. `amount` - Amount to stake (hex wei)
3. `commission` - Commission rate (optional, default 0)
4. `nonce` - Unique nonce for replay protection
5. `signature` - Dilithium3 signature
6. `publicKey` - Dilithium3 public key (hex)

### Quantum Transaction Methods

| Method | Description |
|--------|-------------|
| `qau_signQuantumTransaction` | Sign a transaction with Dilithium3 key (dev mode only) |
| `qau_verifyQuantumTransaction` | Verify a Dilithium3 transaction signature |

> **Security:** `qau_signQuantumTransaction` is disabled in production. Use client-side signing instead.

---

## Health Check

### `GET /health`
Returns node health status.

**Response:**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": 3600,
  "block_height": 100,
  "peer_count": 5
}
```

---

## Error Codes

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON |
| -32600 | Invalid request | Missing or invalid jsonrpc/method |
| -32601 | Method not found | Unknown RPC method |
| -32602 | Invalid params | Missing or invalid parameters |
| -32603 | Internal error | Server-side error |
| -32000 | Not found | Resource not found |
| -32001 | Invalid transaction | Transaction validation failed |
| -32002 | Insufficient funds | Account balance too low |
| -32003 | Unauthorized | Authentication/authorization failed |

---

## Ethereum Compatibility

Quantaureum automatically maps `eth_` prefixed methods to `qau_` equivalents:

| Ethereum Method | Quantaureum Method |
|-----------------|-------------------|
| `eth_chainId` | `eth_chainId` |
| `eth_getBalance` | `eth_getBalance` |
| `eth_sendRawTransaction` | `eth_sendRawTransaction` |
| `eth_blockNumber` | `eth_blockNumber` |
| `eth_getBlockByNumber` | `eth_getBlockByNumber` |
| `eth_call` | `eth_call` |
| `eth_estimateGas` | `eth_estimateGas` |
| `net_version` | `net_version` |

> This mapping ensures compatibility with MetaMask and other Ethereum wallet extensions.

---

## Examples

### PowerShell (Testnet)

```powershell
# Get block number
$body = '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
Invoke-RestMethod -Uri "https://testnet-rpc.quantaureum.com" -Method POST -Body $body -ContentType "application/json"

# Get balance
$body = '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0xa38b3b8679a3b20c7d23226bb60ca13c670e994e","latest"],"id":1}'
Invoke-RestMethod -Uri "https://testnet-rpc.quantaureum.com" -Method POST -Body $body -ContentType "application/json"
```

### curl (Testnet)

```bash
# Get block number
curl -X POST https://testnet-rpc.quantaureum.com \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'

# Get balance
curl -X POST https://testnet-rpc.quantaureum.com \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getBalance","params":["0xa38b3b8679a3b20c7d23226bb60ca13c670e994e","latest"],"id":1}'
```

### JavaScript

```javascript
// Using fetch
const response = await fetch('https://testnet-rpc.quantaureum.com', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    jsonrpc: '2.0',
    method: 'eth_blockNumber',
    params: [],
    id: 1
  })
});
const result = await response.json();
console.log(parseInt(result.result, 16));
```

---

## Configuration

See `config.json` for node configuration options:

```json
{
  "rpcEnabled": true,
  "rpcAddr": "0.0.0.0:8645",
  "wsEnabled": true,
  "wsAddr": "0.0.0.0:8646"
}
```

### Security Configuration

- **Rate Limiting:** Enabled by default (1000 req/s)
- **CORS:** Configure `rpcCorsAllowedOrigins` for production
- **TLS:** Use `StartTLS()` with valid certificates for production
- **Admin Methods:** Require API key + IP whitelist
