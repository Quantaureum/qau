# @quantaureum/sdk

Version 1.0.0

TypeScript SDK for interacting with the Quantaureum quantum-safe blockchain.

## Features

- 🔐 **Wallet Management** - Create, import, and manage wallets with BIP-39 mnemonic support
- 📡 **Provider Connection** - Connect to Quantaureum nodes via JSON-RPC
- 📝 **Transaction Signing** - Sign and send transactions with EIP-155 support
- 📜 **Smart Contract Interaction** - Deploy and interact with smart contracts
- 🛠️ **Utility Functions** - Format, hash, and encode blockchain data
- 📦 **TypeScript First** - Full type definitions for all APIs
- 🌳 **Tree-shakeable** - Import only what you need

## Installation

```bash
npm install @quantaureum/sdk
```

```bash
yarn add @quantaureum/sdk
```

```bash
pnpm add @quantaureum/sdk
```

## Quick Start

### Connect to a Node

```typescript
import { JsonRpcProvider } from '@quantaureum/sdk';

const provider = new JsonRpcProvider('http://localhost:8545');

// Get current block number
const blockNumber = await provider.getBlockNumber();
console.log('Current block:', blockNumber);

// Get account balance
const balance = await provider.getBalance('0x742d35Cc6634C0532925a3b844Bc9e7595f...');
console.log('Balance:', balance);
```

### Create and Use a Wallet

```typescript
import { Wallet, JsonRpcProvider, parseEther } from '@quantaureum/sdk';

// Create a random wallet
const wallet = Wallet.createRandom();
console.log('Address:', wallet.address);
console.log('Mnemonic:', wallet.mnemonic);

// Or import from mnemonic
const importedWallet = Wallet.fromMnemonic(
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
);

// Or import from private key
const walletFromKey = new Wallet('0x...');

// Connect wallet to provider
const provider = new JsonRpcProvider('http://localhost:8545');
const connectedWallet = wallet.connect(provider);

// Send a transaction
const tx = await connectedWallet.sendTransaction({
  to: '0x742d35Cc6634C0532925a3b844Bc9e7595f...',
  value: parseEther('1.0'),
});

// Wait for confirmation
const receipt = await tx.wait();
console.log('Transaction confirmed in block:', receipt.blockNumber);
```

### Sign Messages

```typescript
import { Wallet, verifyMessage } from '@quantaureum/sdk';

const wallet = Wallet.createRandom();

// Sign a message
const message = 'Hello, Quantaureum!';
const signature = await wallet.signMessage(message);

// Verify the signature
const isValid = verifyMessage(message, signature, wallet.address);
console.log('Signature valid:', isValid);
```

### Interact with Smart Contracts

```typescript
import { Contract, JsonRpcProvider, Wallet } from '@quantaureum/sdk';

const abi = [
  'function balanceOf(address owner) view returns (uint256)',
  'function transfer(address to, uint256 amount) returns (bool)',
  'event Transfer(address indexed from, address indexed to, uint256 value)',
];

const provider = new JsonRpcProvider('http://localhost:8545');
const wallet = new Wallet('0x...', provider);

// Create contract instance
const contract = new Contract('0x...contractAddress...', abi, wallet);

// Read contract state (no transaction)
const balance = await contract.balanceOf(wallet.address);
console.log('Token balance:', balance);

// Write to contract (sends transaction)
const tx = await contract.transfer('0x...recipient...', 1000n);
const receipt = await tx.wait();
console.log('Transfer confirmed:', receipt.transactionHash);

// Query historical events
const events = await contract.queryFilter('Transfer', 0, 'latest');
console.log('Transfer events:', events.length);
```


## API Reference

### Providers

#### JsonRpcProvider

Connect to a Quantaureum node via JSON-RPC.

```typescript
import { JsonRpcProvider } from '@quantaureum/sdk';

const provider = new JsonRpcProvider(url, options?);
```

**Methods:**

| Method | Description | Returns |
|--------|-------------|---------|
| `getNetwork()` | Get network info | `Promise<Network>` |
| `getBlockNumber()` | Get current block number | `Promise<number>` |
| `getGasPrice()` | Get current gas price | `Promise<bigint>` |
| `getBlock(blockHashOrNumber)` | Get block by hash or number | `Promise<Block \| null>` |
| `getTransaction(hash)` | Get transaction by hash | `Promise<TransactionResponse \| null>` |
| `getTransactionReceipt(hash)` | Get transaction receipt | `Promise<TransactionReceipt \| null>` |
| `getBalance(address, blockTag?)` | Get account balance | `Promise<bigint>` |
| `getCode(address, blockTag?)` | Get contract code | `Promise<string>` |
| `getTransactionCount(address, blockTag?)` | Get nonce | `Promise<number>` |
| `sendTransaction(signedTx)` | Broadcast signed transaction | `Promise<TransactionResponse>` |
| `call(tx, blockTag?)` | Execute read-only call | `Promise<string>` |
| `estimateGas(tx)` | Estimate gas for transaction | `Promise<bigint>` |
| `getLogs(filter)` | Query event logs | `Promise<Log[]>` |

### Signers

#### Wallet

Manage private keys and sign transactions.

```typescript
import { Wallet } from '@quantaureum/sdk';

// Create random wallet
const wallet = Wallet.createRandom();

// From mnemonic
const wallet = Wallet.fromMnemonic(mnemonic, path?);

// From private key
const wallet = new Wallet(privateKey, provider?);
```

**Properties:**

| Property | Type | Description |
|----------|------|-------------|
| `address` | `string` | Checksummed address |
| `publicKey` | `string` | Public key (uncompressed) |
| `mnemonic` | `string \| null` | Mnemonic phrase (if available) |
| `path` | `string \| null` | HD derivation path |
| `provider` | `Provider \| null` | Connected provider |

**Methods:**

| Method | Description | Returns |
|--------|-------------|---------|
| `connect(provider)` | Connect to provider | `Wallet` |
| `signMessage(message)` | Sign message (EIP-191) | `Promise<string>` |
| `signTransaction(tx)` | Sign transaction | `Promise<string>` |
| `sendTransaction(tx)` | Sign and send transaction | `Promise<TransactionResponse>` |
| `exportPrivateKey()` | Export private key | `string` |

### Contracts

#### Contract

Interact with smart contracts.

```typescript
import { Contract } from '@quantaureum/sdk';

const contract = new Contract(address, abi, signerOrProvider);
```

**Methods:**

| Method | Description | Returns |
|--------|-------------|---------|
| `connect(signerOrProvider)` | Connect to new signer/provider | `Contract` |
| `attach(address)` | Attach to new address | `Contract` |
| `queryFilter(event, fromBlock?, toBlock?)` | Query historical events | `Promise<ContractEvent[]>` |
| `on(event, listener)` | Subscribe to events | `void` |
| `off(event, listener)` | Unsubscribe from events | `void` |
| `[functionName](...args)` | Call contract function | `Promise<any>` |

#### Interface

Parse and encode ABI data.

```typescript
import { Interface } from '@quantaureum/sdk';

const iface = new Interface(abi);
```

**Methods:**

| Method | Description | Returns |
|--------|-------------|---------|
| `getFunction(nameOrSelector)` | Get function fragment | `FunctionFragment` |
| `getEvent(nameOrTopic)` | Get event fragment | `EventFragment` |
| `encodeFunctionData(name, args)` | Encode function call | `string` |
| `decodeFunctionResult(name, data)` | Decode function result | `unknown[]` |
| `encodeFilterTopics(name, args)` | Encode event filter topics | `(string \| null)[]` |
| `decodeEventLog(name, data, topics)` | Decode event log | `Record<string, unknown>` |


### Utilities

#### Formatting

```typescript
import { formatEther, parseEther, formatUnits, parseUnits } from '@quantaureum/sdk';

// Convert wei to ether string
formatEther(1000000000000000000n); // "1.0"

// Convert ether string to wei
parseEther('1.0'); // 1000000000000000000n

// Custom decimals
formatUnits(1000000n, 6); // "1.0"
parseUnits('1.0', 6); // 1000000n
```

#### Address

```typescript
import { isAddress, getAddress, computeAddress } from '@quantaureum/sdk';

// Validate address
isAddress('0x742d35Cc6634C0532925a3b844Bc9e7595f...'); // true

// Get checksummed address
getAddress('0x742d35cc6634c0532925a3b844bc9e7595f...'); // "0x742d35Cc6634C0532925a3b844Bc9e7595f..."

// Compute address from public key
computeAddress(publicKey);
```

#### Hashing

```typescript
import { keccak256, sha256, id } from '@quantaureum/sdk';

// Keccak256 hash
keccak256('0x1234'); // "0x..."
keccak256(new Uint8Array([1, 2, 3, 4])); // "0x..."

// SHA256 hash
sha256('0x1234'); // "0x..."

// Hash UTF-8 string (keccak256)
id('transfer(address,uint256)'); // "0xa9059cbb..."
```

#### Hex Conversion

```typescript
import { toHex, fromHex, hexlify, arrayify } from '@quantaureum/sdk';

// Number/BigInt to hex
toHex(255); // "0xff"
toHex(1000n); // "0x3e8"

// Hex to Uint8Array
fromHex('0x1234'); // Uint8Array([0x12, 0x34])

// Uint8Array to hex
hexlify(new Uint8Array([0x12, 0x34])); // "0x1234"

// Alias for fromHex
arrayify('0x1234'); // Uint8Array([0x12, 0x34])
```

#### ABI Encoding

```typescript
import { encodeAbi, decodeAbi, encodeFunctionData, decodeFunctionResult } from '@quantaureum/sdk';

// Encode values
encodeAbi(['address', 'uint256'], ['0x...', 1000n]); // "0x..."

// Decode values
decodeAbi(['address', 'uint256'], '0x...'); // ['0x...', 1000n]

// Encode function call
encodeFunctionData(abi, 'transfer', ['0x...', 1000n]); // "0x..."

// Decode function result
decodeFunctionResult(abi, 'balanceOf', '0x...'); // [1000n]
```

### Error Handling

The SDK provides typed error classes for different error scenarios:

```typescript
import {
  QuantaureumError,
  RpcError,
  TransactionError,
  ValidationError,
  NetworkError,
  ContractError,
  ErrorCode,
  isRpcError,
  isTransactionError,
} from '@quantaureum/sdk';

try {
  await wallet.sendTransaction(tx);
} catch (error) {
  if (isTransactionError(error)) {
    console.log('Transaction failed:', error.reason);
    console.log('Error code:', error.code);
  } else if (isRpcError(error)) {
    console.log('RPC error:', error.rpcCode, error.rpcMessage);
  }
}
```

**Error Codes:**

| Code | Description |
|------|-------------|
| `NETWORK_ERROR` | Network connection failed |
| `TIMEOUT` | Request timed out |
| `RPC_ERROR` | RPC server error |
| `TRANSACTION_FAILED` | Transaction failed |
| `TRANSACTION_REVERTED` | Transaction reverted |
| `INSUFFICIENT_FUNDS` | Insufficient balance |
| `INVALID_ARGUMENT` | Invalid parameter |
| `INVALID_ADDRESS` | Invalid address format |
| `CALL_EXCEPTION` | Contract call failed |
| `NO_PROVIDER` | No provider connected |

## Types

All types are exported for TypeScript users:

```typescript
import type {
  // Block types
  Block,
  BlockWithTransactions,
  BlockTag,

  // Transaction types
  TransactionRequest,
  TransactionResponse,
  TransactionReceipt,
  Log,

  // Network types
  Network,
  EventFilter,

  // Provider types
  Provider,
  JsonRpcProviderOptions,

  // Signer types
  Signer,

  // ABI types
  ABI,
  ABIFunction,
  ABIEvent,
} from '@quantaureum/sdk';
```

## Browser Support

The SDK works in modern browsers that support ES2020+. For older browsers, you may need to polyfill:

- `BigInt`
- `TextEncoder` / `TextDecoder`
- `crypto.getRandomValues`

## Node.js Support

Requires Node.js 18.0.0 or higher.

## License

Apache License 2.0. See the repository [LICENSE](../../LICENSE).
