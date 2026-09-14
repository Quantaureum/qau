# Quantaureum Rust SDK

Version 1.0.0

A type-safe, memory-safe Rust SDK for interacting with the Quantaureum quantum-safe blockchain.

## Features

- **Type Safety**: Idiomatic Rust types with compile-time guarantees
- **Async/Await**: Full async support using Tokio runtime
- **Account Management**: Create, import, and manage blockchain accounts
- **Transaction Signing**: Sign transactions with EIP-155 replay protection
- **Smart Contracts**: Deploy and interact with smart contracts via ABI
- **Utility Functions**: Common blockchain operations (hashing, unit conversion, etc.)
- **Error Handling**: Comprehensive error types with pattern matching support

## Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
quantaureum-sdk = "1.0.0"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

```rust
use quantaureum_sdk::{Client, Account, Provider};

#[tokio::main]
async fn main() -> quantaureum_sdk::Result<()> {
    // Connect to a Quantaureum node
    let client = Client::new("http://localhost:8545").await?;

    // Create a new account
    let account = Account::new()?;
    println!("Address: {}", account.address());

    // Get current block number
    let block_number = client.block_number().await?;
    println!("Current block: {}", block_number);

    // Get account balance
    let balance = client.balance_at(account.address(), None).await?;
    println!("Balance: {} wei", balance);

    Ok(())
}
```

## Account Management

### Create a Random Account

```rust
use quantaureum_sdk::Account;

let account = Account::new()?;
println!("Address: {}", account.address());
println!("Private Key: {}", account.private_key_hex());
```

### Import from Private Key

```rust
use quantaureum_sdk::Account;

// From bytes
let key = [1u8; 32];
let account = Account::from_private_key(&key)?;

// From hex string
let hex_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
let account = Account::from_private_key_hex(hex_key)?;
```

### Import from Mnemonic (BIP-39)

```rust
use quantaureum_sdk::Account;

let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let account = Account::from_mnemonic(phrase, "m/44'/60'/0'/0/0")?;

// Generate a new mnemonic
let new_mnemonic = Account::generate_mnemonic(12)?;
println!("Mnemonic: {}", new_mnemonic);
```

### Sign Messages

```rust
use quantaureum_sdk::Account;

let account = Account::new()?;
let message = b"Hello, Quantaureum!";

let signature = account.sign_message(message)?;
println!("Signature: {}", signature.to_hex());

// Recover signer address
let message_hash = quantaureum_sdk::accounts::hash_message(message);
let recovered = signature.recover(&message_hash)?;
assert_eq!(recovered, account.address());
```

## Transactions

### Build and Sign a Transaction

```rust
use quantaureum_sdk::{Account, Client, Provider, types::{TransactionRequest, U256, Address}};

#[tokio::main]
async fn main() -> quantaureum_sdk::Result<()> {
    let client = Client::new("http://localhost:8545").await?;
    let account = Account::new()?;

    let to = Address::from_hex("0x1234567890123456789012345678901234567890")?;

    // Build transaction
    let tx = TransactionRequest::new()
        .to(to)
        .value(U256::from(1_000_000_000_000_000_000u64)) // 1 ETH
        .gas(21000)
        .gas_price(client.suggest_gas_price().await?)
        .nonce(client.pending_nonce_at(account.address()).await?);

    // Sign with chain ID for EIP-155 replay protection
    let chain_id = client.chain_id().await?;
    let signed_tx = account.sign_transaction(&tx, chain_id)?;

    // Send transaction
    let tx_hash = client.send_raw_transaction(&signed_tx.rlp_encode()).await?;
    println!("Transaction hash: {}", tx_hash);

    Ok(())
}
```

### Get Transaction Receipt

```rust
use quantaureum_sdk::{Client, Provider, H256};

#[tokio::main]
async fn main() -> quantaureum_sdk::Result<()> {
    let client = Client::new("http://localhost:8545").await?;

    let tx_hash = H256::from_hex("0x...")?;

    if let Some(receipt) = client.transaction_receipt(tx_hash).await? {
        println!("Status: {}", if receipt.status == 1 { "Success" } else { "Failed" });
        println!("Gas used: {}", receipt.gas_used);
        println!("Block: {}", receipt.block_number);
    }

    Ok(())
}
```


## Smart Contracts

### Interact with a Contract

```rust
use quantaureum_sdk::{Client, Contract, Address, U256, Provider};
use std::sync::Arc;

#[tokio::main]
async fn main() -> quantaureum_sdk::Result<()> {
    let client = Arc::new(Client::new("http://localhost:8545").await?);

    let contract_address = Address::from_hex("0x...")?;
    let abi_json = r#"[
        {
            "type": "function",
            "name": "balanceOf",
            "inputs": [{"name": "account", "type": "address"}],
            "outputs": [{"name": "", "type": "uint256"}],
            "stateMutability": "view"
        },
        {
            "type": "function",
            "name": "transfer",
            "inputs": [
                {"name": "to", "type": "address"},
                {"name": "amount", "type": "uint256"}
            ],
            "outputs": [{"name": "", "type": "bool"}],
            "stateMutability": "nonpayable"
        }
    ]"#;

    let contract = Contract::from_json(contract_address, abi_json, client)?;

    // Call a read-only function
    let owner = Address::from_hex("0x...")?;
    let balance: U256 = contract.call("balanceOf", (owner,)).await?;
    println!("Balance: {}", balance);

    Ok(())
}
```

### Encode/Decode Function Calls

```rust
use quantaureum_sdk::{Contract, Address, U256};

// Encode a function call
let data = contract.encode("transfer", (recipient, amount))?;

// Decode return data
let result: bool = contract.decode("transfer", &return_data)?;
```

## Utility Functions

### Unit Conversion

```rust
use quantaureum_sdk::utils::{to_wei, from_wei};
use primitive_types::U256;

// Convert Ether to Wei
let wei = to_wei("1.5", 18)?;
assert_eq!(wei, U256::from(1_500_000_000_000_000_000u64));

// Convert Wei to Ether
let ether = from_wei(U256::from(1_000_000_000_000_000_000u64), 18);
assert_eq!(ether, "1.0");

// Different decimals (e.g., USDC with 6 decimals)
let usdc_wei = to_wei("100.50", 6)?;
```

### Hashing

```rust
use quantaureum_sdk::utils::{keccak256, keccak256_hash};

// Get hash as bytes
let hash = keccak256(b"hello");

// Get hash as H256
let hash = keccak256_hash(b"hello");
println!("Hash: {}", hash);
```

### Hex Conversion

```rust
use quantaureum_sdk::utils::{bytes_to_hex, hex_to_bytes, has_0x_prefix, add_0x_prefix};

// Bytes to hex
let hex = bytes_to_hex(&[0xde, 0xad, 0xbe, 0xef]);
assert_eq!(hex, "0xdeadbeef");

// Hex to bytes
let bytes = hex_to_bytes("0xdeadbeef")?;
assert_eq!(bytes, vec![0xde, 0xad, 0xbe, 0xef]);

// Check/add prefix
assert!(has_0x_prefix("0x1234"));
assert_eq!(add_0x_prefix("1234"), "0x1234");
```

### Address Validation

```rust
use quantaureum_sdk::utils::{is_valid_address, to_checksum_address};

// Validate address
assert!(is_valid_address("0x1234567890123456789012345678901234567890"));
assert!(!is_valid_address("0x1234")); // too short

// Convert to checksum format (EIP-55)
let checksum = to_checksum_address("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
assert_eq!(checksum, Some("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".to_string()));
```

## Error Handling

The SDK uses a custom `Error` type with pattern matching support:

```rust
use quantaureum_sdk::{Client, Error, Provider};

async fn example() -> quantaureum_sdk::Result<()> {
    let client = Client::new("http://localhost:8545").await?;

    match client.block_number().await {
        Ok(block) => println!("Block: {}", block),
        Err(Error::Rpc { code, message, .. }) => {
            eprintln!("RPC error {}: {}", code, message);
        }
        Err(Error::Connection(msg)) => {
            eprintln!("Connection failed: {}", msg);
        }
        Err(Error::InvalidAddress(msg)) => {
            eprintln!("Invalid address: {}", msg);
        }
        Err(e) => return Err(e),
    }

    Ok(())
}
```

### Error Types

| Error Variant | Description |
|---------------|-------------|
| `Rpc` | RPC error from the blockchain node |
| `Transaction` | Transaction-related error |
| `Validation` | Invalid parameter validation error |
| `Signing` | Signing operation error |
| `Abi` | ABI encoding/decoding error |
| `Connection` | Network connection error |
| `InvalidAddress` | Invalid address format |
| `InvalidPrivateKey` | Invalid private key |
| `InvalidMnemonic` | Invalid mnemonic phrase |
| `InvalidHex` | Invalid hexadecimal string |
| `Http` | HTTP request error |
| `Json` | JSON serialization error |

## API Reference

### Core Types

| Type | Description |
|------|-------------|
| `Address` | 20-byte Ethereum-style address |
| `H256` | 32-byte hash value |
| `U256` | 256-bit unsigned integer |
| `Account` | Account with private key and address |
| `Client` | JSON-RPC client for node communication |
| `Contract` | Smart contract interaction interface |

### Transaction Types

| Type | Description |
|------|-------------|
| `TransactionRequest` | Unsigned transaction builder |
| `SignedTransaction` | Signed transaction ready for broadcast |
| `TransactionReceipt` | Transaction receipt after mining |
| `CallRequest` | Read-only call request |
| `Filter` | Log filter for querying events |

### Provider Methods

| Method | Description |
|--------|-------------|
| `block_number()` | Get current block number |
| `block_by_number(n)` | Get block by number |
| `block_by_hash(h)` | Get block by hash |
| `transaction_by_hash(h)` | Get transaction by hash |
| `transaction_receipt(h)` | Get transaction receipt |
| `balance_at(addr, block)` | Get account balance |
| `nonce_at(addr, block)` | Get account nonce |
| `pending_nonce_at(addr)` | Get pending nonce |
| `code_at(addr, block)` | Get contract code |
| `suggest_gas_price()` | Get suggested gas price |
| `estimate_gas(msg)` | Estimate gas for call |
| `send_raw_transaction(tx)` | Send signed transaction |
| `call(msg, block)` | Execute read-only call |
| `get_logs(filter)` | Get logs matching filter |
| `chain_id()` | Get chain ID |

## Dependencies

- `tokio` - Async runtime
- `reqwest` - HTTP client
- `k256` - Elliptic curve cryptography (secp256k1)
- `sha3` / `tiny-keccak` - Keccak256 hashing
- `bip39` - Mnemonic phrase support
- `rlp` - RLP encoding
- `primitive-types` - U256 type
- `thiserror` - Error handling
- `serde` / `serde_json` - Serialization

## License

Apache License 2.0. See the repository [LICENSE](../LICENSE).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
