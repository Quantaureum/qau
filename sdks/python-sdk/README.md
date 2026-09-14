# Quantaureum Python SDK

Version 1.0.0

A Pythonic, type-safe SDK for interacting with the Quantaureum quantum-safe blockchain.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Type Checked](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](http://mypy-lang.org/)

## Features

- **Type-Safe**: Full type hints with mypy strict mode compatibility
- **Async Support**: Native asyncio support with sync API fallback
- **Wallet Management**: BIP-39 mnemonic support, message signing, transaction signing
- **Smart Contracts**: ABI encoding/decoding, contract interaction, event querying
- **Utilities**: Ether formatting, address validation, hashing functions

## Installation

```bash
pip install quantaureum
```

For development with testing tools:

```bash
pip install quantaureum[dev]
```

## Requirements

- Python 3.10 or higher

## Quick Start

### Connecting to a Node

```python
from quantaureum import JsonRpcProvider

# Connect to a Quantaureum node
provider = JsonRpcProvider("http://localhost:8545")

# Get network information
network = provider.get_network()
print(f"Connected to: {network.name} (Chain ID: {network.chain_id})")

# Get current block number
block_number = provider.get_block_number()
print(f"Current block: {block_number}")

# Get gas price
gas_price = provider.get_gas_price()
print(f"Gas price: {gas_price} wei")
```

### Creating and Managing Wallets

```python
from quantaureum import Wallet, format_ether

# Create a new random wallet
wallet = Wallet.create_random()
print(f"Address: {wallet.address}")
print(f"Mnemonic: {wallet.mnemonic}")

# Import from mnemonic
wallet = Wallet.from_mnemonic("your twelve word mnemonic phrase here ...")

# Import from private key
wallet = Wallet.from_private_key("0x...")

# Connect wallet to provider for sending transactions
wallet = wallet.connect(provider)

# Check balance
balance = provider.get_balance(wallet.address)
print(f"Balance: {format_ether(balance)} QAU")
```

### Signing Messages

```python
from quantaureum import Wallet, recover_message_signer

wallet = Wallet.create_random()

# Sign a message
message = "Hello, Quantaureum!"
signature = wallet.sign_message(message)
print(f"Signature: {signature}")

# Recover signer address
recovered = recover_message_signer(message, signature)
assert recovered == wallet.address
```

### Sending Transactions

```python
from quantaureum import Wallet, JsonRpcProvider, parse_ether

provider = JsonRpcProvider("http://localhost:8545")
wallet = Wallet.from_private_key("0x...").connect(provider)

# Send a transaction
tx_response = wallet.send_transaction({
    "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f5bB0e",
    "value": parse_ether("1.0"),  # 1 QAU
})

print(f"Transaction hash: {tx_response.hash}")

# Wait for confirmation
receipt = tx_response.wait()
print(f"Confirmed in block: {receipt.block_number}")
print(f"Gas used: {receipt.gas_used}")
```


### Interacting with Smart Contracts

```python
from quantaureum import Contract, JsonRpcProvider, Wallet

provider = JsonRpcProvider("http://localhost:8545")
wallet = Wallet.from_private_key("0x...").connect(provider)

# ERC-20 ABI (simplified)
erc20_abi = [
    {
        "name": "balanceOf",
        "type": "function",
        "stateMutability": "view",
        "inputs": [{"name": "account", "type": "address"}],
        "outputs": [{"name": "", "type": "uint256"}]
    },
    {
        "name": "transfer",
        "type": "function",
        "stateMutability": "nonpayable",
        "inputs": [
            {"name": "to", "type": "address"},
            {"name": "amount", "type": "uint256"}
        ],
        "outputs": [{"name": "", "type": "bool"}]
    },
    {
        "name": "Transfer",
        "type": "event",
        "inputs": [
            {"name": "from", "type": "address", "indexed": True},
            {"name": "to", "type": "address", "indexed": True},
            {"name": "value", "type": "uint256", "indexed": False}
        ]
    }
]

# Create contract instance
contract = Contract("0x...", erc20_abi, wallet)

# Read-only call (no transaction)
balance = contract.balanceOf(wallet.address).call()
print(f"Token balance: {balance}")

# State-changing call (sends transaction)
tx = contract.transfer("0x...", 1000).send()
receipt = tx.wait()
print(f"Transfer confirmed: {receipt.transaction_hash}")

# Query historical events
events = contract.query_filter("Transfer", from_block=0, to_block="latest")
for event in events:
    print(f"Transfer: {event.args['from']} -> {event.args['to']}: {event.args['value']}")
```

### Async API

```python
import asyncio
from quantaureum import AsyncJsonRpcProvider

async def main():
    async with AsyncJsonRpcProvider("http://localhost:8545") as provider:
        # All methods are async
        block_number = await provider.get_block_number()
        print(f"Block: {block_number}")

        # Concurrent requests
        balance1, balance2 = await asyncio.gather(
            provider.get_balance("0x..."),
            provider.get_balance("0x...")
        )

asyncio.run(main())
```

## API Reference

### Providers

| Class | Description |
|-------|-------------|
| `JsonRpcProvider` | Synchronous JSON-RPC provider |
| `AsyncJsonRpcProvider` | Asynchronous JSON-RPC provider |

**Provider Methods:**
- `get_network()` - Get network information
- `get_block_number()` - Get current block height
- `get_block(block_hash_or_number)` - Get block by hash or number
- `get_transaction(tx_hash)` - Get transaction by hash
- `get_transaction_receipt(tx_hash)` - Get transaction receipt
- `get_balance(address)` - Get account balance in wei
- `get_code(address)` - Get contract bytecode
- `get_transaction_count(address)` - Get account nonce
- `get_gas_price()` - Get current gas price
- `estimate_gas(tx)` - Estimate gas for transaction
- `call(tx)` - Execute read-only call
- `send_raw_transaction(signed_tx)` - Broadcast signed transaction

### Wallet

| Method | Description |
|--------|-------------|
| `Wallet.create_random()` | Create new wallet with random key |
| `Wallet.from_private_key(key)` | Import from private key |
| `Wallet.from_mnemonic(phrase)` | Import from BIP-39 mnemonic |
| `wallet.connect(provider)` | Connect to a provider |
| `wallet.sign_message(message)` | Sign a message (EIP-191) |
| `wallet.sign_transaction(tx)` | Sign a transaction |
| `wallet.send_transaction(tx)` | Sign and send transaction |
| `wallet.address` | Get wallet address |
| `wallet.mnemonic` | Get mnemonic (if available) |
| `wallet.export_private_key()` | Export private key |

### Contract

| Method | Description |
|--------|-------------|
| `Contract(address, abi, signer)` | Create contract instance |
| `contract.connect(signer)` | Connect to new signer |
| `contract.<method>(...).call()` | Read-only call |
| `contract.<method>(...).send()` | State-changing call |
| `contract.query_filter(event, ...)` | Query historical events |

### Utility Functions

**Formatting:**
- `format_ether(wei)` - Convert wei to ether string
- `parse_ether(ether)` - Convert ether string to wei
- `format_units(value, decimals)` - Format with custom decimals
- `parse_units(value, decimals)` - Parse with custom decimals
- `format_gwei(wei)` - Convert wei to gwei string
- `parse_gwei(gwei)` - Convert gwei string to wei

**Address:**
- `is_address(value)` - Check if valid address
- `get_address(address)` - Get checksummed address (EIP-55)
- `compute_address(public_key)` - Compute address from public key

**Hashing:**
- `keccak256(data)` - Compute Keccak-256 hash
- `sha256(data)` - Compute SHA-256 hash
- `id(text)` - Keccak-256 of UTF-8 string
- `function_selector(signature)` - Get 4-byte function selector
- `event_topic(signature)` - Get event topic hash

**Hex:**
- `to_hex(value)` - Convert to hex string
- `from_hex(hex_str)` - Convert hex to bytes
- `is_hex_string(value)` - Check if valid hex string

**ABI:**
- `encode_abi(types, values)` - ABI encode values
- `decode_abi(types, data)` - ABI decode data
- `encode_function_data(abi, name, args)` - Encode function call
- `decode_function_result(abi, name, data)` - Decode function result

### Exceptions

| Exception | Description |
|-----------|-------------|
| `QuantaureumError` | Base exception for all SDK errors |
| `RpcError` | RPC-related errors with error code |
| `TransactionError` | Transaction failures with revert reason |
| `ValidationError` | Input validation errors |
| `NetworkError` | Network connection errors |
| `SignerError` | Signing-related errors |
| `ContractError` | Contract interaction errors |

### Types

| Type | Description |
|------|-------------|
| `Block` | Block data with transaction hashes |
| `BlockWithTransactions` | Block with full transaction objects |
| `TransactionRequest` | Transaction parameters for sending |
| `TransactionResponse` | Transaction response from node |
| `TransactionReceipt` | Receipt after confirmation |
| `Log` | Event log entry |
| `Network` | Network information |
| `FeeData` | Gas fee information |

## Development

### Dependency Management

This SDK uses **pinned dependencies** for reproducible builds. All dependencies are locked to exact versions in:
- `pyproject.toml` - Exact versions for production dependencies
- `requirements.lock` - Complete dependency tree with transitive dependencies

**Installing Dependencies:**

```bash
# Clone the repository
git clone https://github.com/quantaureum/qau.git
cd qau/sdks/python-sdk

# Install with exact versions (recommended)
pip install -r requirements.lock

# Or install from pyproject.toml
pip install -e ".[dev]"
```

**Updating Dependencies:**

When updating dependencies, follow this process:

1. Update version in `pyproject.toml`
2. Install in clean environment: `pip install -e .`
3. Test thoroughly with new version
4. Update `requirements.lock`: `pip freeze > requirements.lock`
5. Run full test suite: `pytest --cov=quantaureum`
6. Commit both files together

**Why Pinned Versions?**

- Ensures reproducible builds across environments
- Prevents breaking changes from dependency updates
- Improves security by controlling exactly what versions are used
- Makes vulnerability tracking easier

### Testing

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=quantaureum

# Run property-based tests
pytest tests/test_*_property.py

# Type checking
mypy quantaureum --strict

# Linting
ruff check quantaureum
ruff format quantaureum
```

## License

Apache License 2.0. See the repository [LICENSE](../../LICENSE).

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting pull requests.

## Links

- [Documentation](https://docs.quantaureum.io/sdk/python)
- [GitHub Repository](https://github.com/quantaureum/qau/tree/main/sdks/python-sdk)
- [Issue Tracker](https://github.com/quantaureum/qau/issues)
- [Quantaureum Website](https://quantaureum.io)
