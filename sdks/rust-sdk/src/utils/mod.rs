// Quantaureum Rust SDK source, version 1.0.0.
//! Utility functions module.
//!
//! This module provides common utility functions for blockchain operations.

mod address;
mod hash;
mod hex_utils;
mod units;
pub mod validation;

// Re-export hex utilities
pub use hex_utils::{add_0x_prefix, bytes_to_hex, has_0x_prefix, hex_to_bytes};

// Re-export hash utilities
pub use hash::{keccak256, keccak256_hash};

// Re-export address utilities
pub use address::{is_valid_address, to_checksum_address};

// Re-export unit conversion utilities
pub use units::{format_units, from_wei, parse_units, to_wei, ETHER_DECIMALS};

// Re-export validation utilities
pub use validation::{
    validate_abi_json, validate_address, validate_byte_length, validate_decimal_string,
    validate_derivation_path, validate_hex_length, validate_hex_string, validate_mnemonic_phrase,
    validate_mnemonic_word_count, validate_not_blank, validate_not_empty, validate_private_key,
    validate_private_key_hex, validate_url,
};
