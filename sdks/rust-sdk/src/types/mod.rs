// Quantaureum Rust SDK source, version 1.0.0.
//! Core type definitions.
//!
//! This module provides the fundamental types used throughout the SDK:
//!
//! - [`Address`]: A 20-byte Ethereum-style address
//! - [`H256`]: A 32-byte hash value
//! - [`U256`]: A 256-bit unsigned integer (re-exported from `primitive-types`)
//! - [`Block`]: A block in the blockchain
//! - [`Transaction`]: A transaction as returned from the node
//! - [`TransactionRequest`]: A transaction request for building unsigned transactions
//! - [`SignedTransaction`]: A signed transaction ready for broadcast
//! - [`TransactionReceipt`]: Transaction receipt returned after mining
//! - [`Log`]: A log entry emitted by a transaction
//! - [`CallRequest`]: A call request for read-only calls
//! - [`Filter`]: A log filter for querying logs

mod address;
mod block;
mod hash;
mod transaction;

pub use address::Address;
pub use block::{Block, BlockWithTransactions, Transaction};
pub use hash::H256;
pub use primitive_types::U256;
pub use transaction::{
    CallRequest, Filter, Log, SignedTransaction, TransactionReceipt, TransactionRequest,
};
