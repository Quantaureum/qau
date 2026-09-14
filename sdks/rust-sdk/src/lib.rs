// Quantaureum Rust SDK source, version 1.0.0.
//! # Quantaureum Rust SDK
//!
//! A type-safe, memory-safe Rust SDK for interacting with the Quantaureum
//! quantum-safe blockchain.
//!
//! ## Features
//!
//! - **Type Safety**: Idiomatic Rust types with compile-time guarantees
//! - **Async/Await**: Full async support using Tokio runtime
//! - **Account Management**: Create, import, and manage blockchain accounts
//! - **Transaction Signing**: Sign transactions with EIP-155 replay protection
//! - **Smart Contracts**: Deploy and interact with smart contracts via ABI
//! - **Utility Functions**: Common blockchain operations (hashing, unit conversion, etc.)
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use quantaureum_sdk::{Client, Account, Provider};
//!
//! #[tokio::main]
//! async fn main() -> quantaureum_sdk::Result<()> {
//!     // Connect to a Quantaureum node
//!     let client = Client::new("http://localhost:8545").await?;
//!
//!     // Create a new account
//!     let account = Account::new()?;
//!     println!("Address: {}", account.address());
//!
//!     // Get current block number
//!     let block_number = client.block_number().await?;
//!     println!("Current block: {}", block_number);
//!
//!     // Get account balance
//!     let balance = client.balance_at(account.address(), None).await?;
//!     println!("Balance: {} wei", balance);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Account Management
//!
//! Create accounts from random keys, private keys, or mnemonic phrases:
//!
//! ```rust
//! use quantaureum_sdk::Account;
//!
//! // Create a random account
//! let account = Account::new().unwrap();
//!
//! // Create from private key
//! let key = [1u8; 32];
//! let account = Account::from_private_key(&key).unwrap();
//!
//! // Create from mnemonic
//! let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
//! let account = Account::from_mnemonic(phrase, "m/44'/60'/0'/0/0").unwrap();
//! ```
//!
//! ## Transaction Signing
//!
//! Sign and send transactions:
//!
//! ```rust,ignore
//! use quantaureum_sdk::{Account, Client, Provider, types::{TransactionRequest, U256, Address}};
//!
//! #[tokio::main]
//! async fn main() -> quantaureum_sdk::Result<()> {
//!     let client = Client::new("http://localhost:8545").await?;
//!     let account = Account::new()?;
//!
//!     let to = Address::from_hex("0x1234567890123456789012345678901234567890")?;
//!     let tx = TransactionRequest::new()
//!         .to(to)
//!         .value(U256::from(1_000_000_000_000_000_000u64)) // 1 ETH
//!         .gas(21000)
//!         .gas_price(U256::from(20_000_000_000u64))
//!         .nonce(0);
//!
//!     let chain_id = client.chain_id().await?;
//!     let signed_tx = account.sign_transaction(&tx, chain_id)?;
//!
//!     let tx_hash = client.send_raw_transaction(&signed_tx.rlp_encode()).await?;
//!     println!("Transaction hash: {}", tx_hash);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Smart Contract Interaction
//!
//! Interact with deployed smart contracts:
//!
//! ```rust,ignore
//! use quantaureum_sdk::{Client, Contract, Address, U256};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> quantaureum_sdk::Result<()> {
//!     let client = Arc::new(Client::new("http://localhost:8545").await?);
//!
//!     let contract_address = Address::from_hex("0x...")?;
//!     let abi_json = r#"[{"type":"function","name":"balanceOf",...}]"#;
//!
//!     let contract = Contract::from_json(contract_address, abi_json, client)?;
//!
//!     // Call a read-only function
//!     let balance: U256 = contract.call("balanceOf", (contract_address,)).await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Utility Functions
//!
//! Common blockchain utilities:
//!
//! ```rust
//! use quantaureum_sdk::utils::{keccak256, to_wei, from_wei, is_valid_address};
//! use primitive_types::U256;
//!
//! // Hash data
//! let hash = keccak256(b"hello");
//!
//! // Convert units
//! let wei = to_wei("1.5", 18).unwrap();
//! let ether = from_wei(U256::from(1_500_000_000_000_000_000u64), 18);
//!
//! // Validate addresses
//! assert!(is_valid_address("0x1234567890123456789012345678901234567890"));
//! ```
//!
//! ## Error Handling
//!
//! The SDK uses a custom `Error` type with pattern matching support:
//!
//! ```rust,ignore
//! use quantaureum_sdk::{Client, Error, Provider};
//!
//! async fn example() -> quantaureum_sdk::Result<()> {
//!     let client = Client::new("http://localhost:8545").await?;
//!
//!     match client.block_number().await {
//!         Ok(block) => println!("Block: {}", block),
//!         Err(Error::Rpc { code, message, .. }) => {
//!             eprintln!("RPC error {}: {}", code, message);
//!         }
//!         Err(Error::Connection(msg)) => {
//!             eprintln!("Connection failed: {}", msg);
//!         }
//!         Err(e) => return Err(e),
//!     }
//!
//!     Ok(())
//! }
//! ```

// ============================================================================
// Module Declarations
// ============================================================================

/// Account management module.
///
/// Provides account creation, key management, and signing functionality.
///
/// # Examples
///
/// ```rust
/// use quantaureum_sdk::accounts::{Account, Signature};
///
/// // Create a new random account
/// let account = Account::new().unwrap();
///
/// // Sign a message
/// let signature = account.sign_message(b"Hello, Quantaureum!").unwrap();
/// ```
pub mod accounts;

/// Client module for blockchain node communication.
///
/// Provides the `Client` struct and `Provider` trait for interacting with
/// Quantaureum blockchain nodes via JSON-RPC.
///
/// # Examples
///
/// ```rust,ignore
/// use quantaureum_sdk::client::{Client, Provider};
///
/// #[tokio::main]
/// async fn main() -> quantaureum_sdk::Result<()> {
///     let client = Client::new("http://localhost:8545").await?;
///     let block = client.block_number().await?;
///     Ok(())
/// }
/// ```
pub mod client;

/// Smart contract interaction module.
///
/// Provides contract deployment, method calls, and event handling.
///
/// # Examples
///
/// ```rust,ignore
/// use quantaureum_sdk::contracts::{Contract, Abi};
/// use std::sync::Arc;
///
/// let client = Arc::new(Client::new("http://localhost:8545").await?);
/// let contract = Contract::from_json(address, abi_json, client)?;
/// ```
pub mod contracts;

/// Error types for the SDK.
///
/// Defines custom error types using `thiserror` for different error categories,
/// supporting pattern matching for error handling.
pub mod error;

/// Core type definitions.
///
/// Provides fundamental types used throughout the SDK:
/// - `Address`: 20-byte Ethereum-style address
/// - `H256`: 32-byte hash value
/// - `U256`: 256-bit unsigned integer
/// - Transaction types, block types, and more
pub mod types;

/// Utility functions module.
///
/// Provides common utility functions for blockchain operations:
/// - Hex encoding/decoding
/// - Keccak256 hashing
/// - Address validation
/// - Unit conversion (Wei/Ether)
pub mod utils;

// ============================================================================
// Re-exports - Core Types
// ============================================================================

/// Re-export of the Account struct for account management.
///
/// # Examples
///
/// ```rust
/// use quantaureum_sdk::Account;
///
/// let account = Account::new().unwrap();
/// println!("Address: {}", account.address());
/// ```
pub use accounts::Account;

/// Re-export of the Signature struct for message signatures.
pub use accounts::Signature;

/// Re-export of the Client struct for node communication.
///
/// # Examples
///
/// ```rust,ignore
/// use quantaureum_sdk::Client;
///
/// let client = Client::new("http://localhost:8545").await?;
/// ```
pub use client::Client;

/// Re-export of the ClientConfig struct for client configuration.
pub use client::ClientConfig;

/// Re-export of the Provider trait for blockchain interaction.
///
/// This trait defines the interface for all blockchain operations.
pub use client::Provider;

/// Re-export of the Error enum for error handling.
///
/// # Examples
///
/// ```rust
/// use quantaureum_sdk::Error;
///
/// fn handle_error(err: Error) {
///     match err {
///         Error::InvalidAddress(msg) => println!("Invalid address: {}", msg),
///         Error::InvalidPrivateKey => println!("Invalid private key"),
///         _ => println!("Other error: {}", err),
///     }
/// }
/// ```
pub use error::Error;

/// Re-export of the Result type alias.
///
/// This is a convenience alias for `std::result::Result<T, Error>`.
pub use error::Result;

/// Re-export of the Address type (20 bytes).
///
/// # Examples
///
/// ```rust
/// use quantaureum_sdk::Address;
///
/// let addr = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();
/// println!("Checksum: {}", addr.to_checksum());
/// ```
pub use types::Address;

/// Re-export of the H256 type (32-byte hash).
///
/// # Examples
///
/// ```rust
/// use quantaureum_sdk::H256;
///
/// let hash = H256::from_hex("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap();
/// ```
pub use types::H256;

/// Re-export of the U256 type (256-bit unsigned integer).
///
/// This is re-exported from the `primitive-types` crate.
pub use types::U256;

// ============================================================================
// Re-exports - Contract Types
// ============================================================================

/// Re-export of the Contract struct for smart contract interaction.
pub use contracts::Contract;

/// Re-export of the Abi struct for ABI parsing.
pub use contracts::Abi;

/// Re-export of the ContractCall struct for prepared contract calls.
pub use contracts::ContractCall;

/// Re-export of the PendingTransaction struct for awaiting confirmations.
pub use contracts::PendingTransaction;

/// Re-export of ABI-related types.
pub use contracts::{
    AbiConstructor, AbiEvent, AbiEventParam, AbiFallback, AbiFunction, AbiParam, AbiReceive,
    Detokenize, StateMutability, Token, Tokenize,
};

/// Re-export of event-related types.
pub use contracts::{ContractEvents, DecodedLog, EventFilter};

// ============================================================================
// Re-exports - Transaction Types
// ============================================================================

/// Re-export of transaction-related types.
pub use types::{
    Block, BlockWithTransactions, CallRequest, Filter, Log, SignedTransaction, Transaction,
    TransactionReceipt, TransactionRequest,
};

// ============================================================================
// Re-exports - Account Utilities
// ============================================================================

/// Re-export of mnemonic-related functions and constants.
pub use accounts::mnemonic::{from_mnemonic, generate_mnemonic, DEFAULT_DERIVATION_PATH};

/// Re-export of signing-related functions.
pub use accounts::{hash_message, sign_hash, sign_message, sign_transaction};

// ============================================================================
// Prelude Module
// ============================================================================

/// Prelude module for convenient imports.
///
/// Import everything commonly needed with a single use statement:
///
/// ```rust
/// use quantaureum_sdk::prelude::*;
/// ```
pub mod prelude {
    pub use crate::accounts::{Account, Signature};
    pub use crate::client::{Client, ClientConfig, Provider};
    pub use crate::contracts::{
        Abi, Contract, ContractCall, Detokenize, PendingTransaction, Token, Tokenize,
    };
    pub use crate::error::{Error, Result};
    pub use crate::types::{
        Address, Block, CallRequest, Filter, Log, SignedTransaction, Transaction,
        TransactionReceipt, TransactionRequest, H256, U256,
    };
    pub use crate::utils::{
        bytes_to_hex, from_wei, hex_to_bytes, is_valid_address, keccak256, to_checksum_address,
        to_wei,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_reexport() {
        let account = Account::new().unwrap();
        assert_eq!(account.address().as_bytes().len(), 20);
    }

    #[test]
    fn test_address_reexport() {
        let addr = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();
        assert_eq!(addr.to_hex(), "0x1234567890123456789012345678901234567890");
    }

    #[test]
    fn test_h256_reexport() {
        let hash = H256::ZERO;
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_u256_reexport() {
        let value = U256::from(1000u64);
        assert_eq!(value.as_u64(), 1000);
    }

    #[test]
    fn test_error_reexport() {
        let err = Error::InvalidAddress("test".to_string());
        assert!(err.to_string().contains("test"));
    }

    #[test]
    fn test_prelude_imports() {
        use crate::prelude::*;

        let account = Account::new().unwrap();
        let _addr: Address = account.address();
        let _hash: H256 = H256::ZERO;
        let _value: U256 = U256::from(100u64);
    }
}
