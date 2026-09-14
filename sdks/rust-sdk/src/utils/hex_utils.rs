// Quantaureum Rust SDK source, version 1.0.0.
//! Hex encoding/decoding utilities.
//!
//! This module provides functions for converting between bytes and hexadecimal strings.

use crate::error::{Error, Result};

/// Checks if a string has the "0x" prefix.
///
/// # Arguments
///
/// * `s` - The string to check
///
/// # Returns
///
/// `true` if the string starts with "0x" or "0X", `false` otherwise.
pub fn has_0x_prefix(s: &str) -> bool {
    s.starts_with("0x") || s.starts_with("0X")
}

/// Adds the "0x" prefix to a hex string if not already present.
///
/// # Arguments
///
/// * `s` - The hex string
///
/// # Returns
///
/// A string with the "0x" prefix.
pub fn add_0x_prefix(s: &str) -> String {
    if has_0x_prefix(s) {
        s.to_string()
    } else {
        format!("0x{}", s)
    }
}

/// Converts a byte slice to a hexadecimal string with "0x" prefix.
///
/// # Arguments
///
/// * `bytes` - The byte slice to convert
///
/// # Returns
///
/// A hexadecimal string representation with "0x" prefix.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Converts a hexadecimal string to bytes.
///
/// The input string may optionally have a "0x" or "0X" prefix.
///
/// # Arguments
///
/// * `hex_str` - The hexadecimal string to convert
///
/// # Returns
///
/// A `Result` containing the decoded bytes, or an error if the input is invalid.
///
/// # Errors
///
/// Returns `Error::InvalidHex` if:
/// - The string contains non-hexadecimal characters
/// - The string has an odd number of characters (after removing prefix)
pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>> {
    let s = if has_0x_prefix(hex_str) {
        &hex_str[2..]
    } else {
        hex_str
    };

    hex::decode(s).map_err(|e| Error::InvalidHex(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_has_0x_prefix() {
        assert!(has_0x_prefix("0x1234"));
        assert!(has_0x_prefix("0X1234"));
        assert!(has_0x_prefix("0x"));
        assert!(!has_0x_prefix("1234"));
        assert!(!has_0x_prefix(""));
        assert!(!has_0x_prefix("x1234"));
    }

    #[test]
    fn test_add_0x_prefix() {
        assert_eq!(add_0x_prefix("1234"), "0x1234");
        assert_eq!(add_0x_prefix("0x1234"), "0x1234");
        assert_eq!(add_0x_prefix("0X1234"), "0X1234");
        assert_eq!(add_0x_prefix(""), "0x");
    }

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(bytes_to_hex(&[0xde, 0xad, 0xbe, 0xef]), "0xdeadbeef");
        assert_eq!(bytes_to_hex(&[0x00, 0x01, 0x02]), "0x000102");
        assert_eq!(bytes_to_hex(&[]), "0x");
        assert_eq!(bytes_to_hex(&[0xff]), "0xff");
    }

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(
            hex_to_bytes("0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            hex_to_bytes("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(hex_to_bytes("0x").unwrap(), Vec::<u8>::new());
        assert_eq!(hex_to_bytes("").unwrap(), Vec::<u8>::new());
        assert_eq!(hex_to_bytes("0x00").unwrap(), vec![0x00]);
    }

    #[test]
    fn test_hex_to_bytes_invalid() {
        assert!(hex_to_bytes("0xgg").is_err());
        assert!(hex_to_bytes("0x123").is_err()); // odd length
        assert!(hex_to_bytes("xyz").is_err());
    }

    #[test]
    fn test_roundtrip() {
        let original = vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0xff];
        let hex_str = bytes_to_hex(&original);
        let decoded = hex_to_bytes(&hex_str).unwrap();
        assert_eq!(original, decoded);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: quantaureum-rust-sdk, Property 6: Hex Conversion Round-Trip
        // For any byte slice, calling bytes_to_hex() then hex_to_bytes() SHALL return the original byte slice.
        // Validates: Requirements 5.5
        #[test]
        fn prop_hex_roundtrip(bytes: Vec<u8>) {
            let hex_str = bytes_to_hex(&bytes);
            let decoded = hex_to_bytes(&hex_str).unwrap();
            prop_assert_eq!(bytes, decoded);
        }
    }
}
