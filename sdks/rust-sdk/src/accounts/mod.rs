// Quantaureum Rust SDK source, version 1.0.0.
//! Account management module.
//!
//! This module provides account creation, key management, and signing functionality.

mod account;
pub mod mnemonic;
mod signing;

pub use account::Account;
pub use mnemonic::{from_mnemonic, generate_mnemonic, DEFAULT_DERIVATION_PATH};
pub use signing::{hash_message, sign_hash, sign_message, sign_transaction, Signature};
