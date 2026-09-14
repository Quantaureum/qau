// Quantaureum Rust SDK source, version 1.0.0.
//! Client module for blockchain node communication.
//!
//! This module provides the `Client` struct and `Provider` trait for
//! interacting with Quantaureum blockchain nodes via JSON-RPC.
//!
//! # Examples
//!
//! ```rust,ignore
//! use quantaureum_sdk::{Client, Provider};
//!
//! #[tokio::main]
//! async fn main() -> quantaureum_sdk::Result<()> {
//!     // Connect to a node
//!     let client = Client::new("http://localhost:8545").await?;
//!
//!     // Get current block number
//!     let block_number = client.block_number().await?;
//!     println!("Current block: {}", block_number);
//!
//!     // Get balance
//!     let address = "0x1234567890123456789012345678901234567890".parse()?;
//!     let balance = client.balance_at(address, None).await?;
//!     println!("Balance: {}", balance);
//!
//!     Ok(())
//! }
//! ```

#[allow(clippy::module_inception)]
mod client;
mod rpc;

pub use client::{Client, ClientConfig, Provider};
pub use rpc::{parse, RpcError, RpcRequest, RpcResponse, RpcTransport};
