// Quantaureum Rust SDK source, version 1.0.0.
//! Input validation utilities.
//!
//! This module provides validation functions for all public API inputs,
//! ensuring that invalid inputs are rejected with descriptive errors
//! rather than causing panics.

use crate::error::{Error, Result};

/// Validates that a string is not empty.
///
/// # Arguments
///
/// * `value` - The string to validate
/// * `field` - The field name for error messages
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::Validation)` if empty.
pub fn validate_not_empty(value: &str, field: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::Validation {
            field: field.to_string(),
            message: "cannot be empty".to_string(),
        });
    }
    Ok(())
}

/// Validates that a string is not empty or whitespace-only.
///
/// # Arguments
///
/// * `value` - The string to validate
/// * `field` - The field name for error messages
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::Validation)` if empty or whitespace-only.
pub fn validate_not_blank(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::Validation {
            field: field.to_string(),
            message: "cannot be empty or whitespace-only".to_string(),
        });
    }
    Ok(())
}

/// Validates that a byte slice has the expected length.
///
/// # Arguments
///
/// * `bytes` - The byte slice to validate
/// * `expected_len` - The expected length
/// * `field` - The field name for error messages
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::Validation)` if length doesn't match.
pub fn validate_byte_length(bytes: &[u8], expected_len: usize, field: &str) -> Result<()> {
    if bytes.len() != expected_len {
        return Err(Error::Validation {
            field: field.to_string(),
            message: format!("expected {} bytes, got {}", expected_len, bytes.len()),
        });
    }
    Ok(())
}

/// Validates that a hex string has valid format.
///
/// # Arguments
///
/// * `hex` - The hex string to validate (with or without 0x prefix)
/// * `field` - The field name for error messages
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::Validation)` if invalid.
pub fn validate_hex_string(hex: &str, field: &str) -> Result<()> {
    let hex = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);

    if hex.is_empty() {
        return Ok(()); // Empty hex is valid (represents empty bytes)
    }

    // Check for odd length
    if !hex.len().is_multiple_of(2) {
        return Err(Error::Validation {
            field: field.to_string(),
            message: "hex string must have even length".to_string(),
        });
    }

    // Check for invalid characters
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Validation {
            field: field.to_string(),
            message: "hex string contains invalid characters".to_string(),
        });
    }

    Ok(())
}

/// Validates that a hex string has the expected byte length when decoded.
///
/// # Arguments
///
/// * `hex` - The hex string to validate (with or without 0x prefix)
/// * `expected_bytes` - The expected number of bytes when decoded
/// * `field` - The field name for error messages
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::Validation)` if invalid.
pub fn validate_hex_length(hex: &str, expected_bytes: usize, field: &str) -> Result<()> {
    validate_hex_string(hex, field)?;

    let hex = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);
    let actual_bytes = hex.len() / 2;

    if actual_bytes != expected_bytes {
        return Err(Error::Validation {
            field: field.to_string(),
            message: format!("expected {} bytes, got {}", expected_bytes, actual_bytes),
        });
    }

    Ok(())
}

/// Validates an address string.
///
/// # Arguments
///
/// * `address` - The address string to validate
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::InvalidAddress)` if invalid.
pub fn validate_address(address: &str) -> Result<()> {
    let hex = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .unwrap_or(address);

    if hex.len() != 40 {
        return Err(Error::InvalidAddress(format!(
            "expected 40 hex characters, got {}",
            hex.len()
        )));
    }

    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::InvalidAddress(
            "contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a private key byte slice.
///
/// # Arguments
///
/// * `key` - The private key bytes to validate
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::InvalidPrivateKey)` if invalid.
pub fn validate_private_key(key: &[u8]) -> Result<()> {
    if key.len() != 32 {
        return Err(Error::InvalidPrivateKey);
    }

    // Check if key is all zeros (invalid for secp256k1)
    if key.iter().all(|&b| b == 0) {
        return Err(Error::InvalidPrivateKey);
    }

    Ok(())
}

/// Validates a private key hex string.
///
/// # Arguments
///
/// * `hex` - The private key hex string to validate
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::InvalidPrivateKey)` if invalid.
pub fn validate_private_key_hex(hex: &str) -> Result<()> {
    let hex = hex
        .strip_prefix("0x")
        .or_else(|| hex.strip_prefix("0X"))
        .unwrap_or(hex);

    if hex.len() != 64 {
        return Err(Error::InvalidPrivateKey);
    }

    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::InvalidHex(
            "private key contains invalid characters".to_string(),
        ));
    }

    Ok(())
}

/// Validates a mnemonic phrase.
///
/// # Arguments
///
/// * `phrase` - The mnemonic phrase to validate
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::InvalidMnemonic)` if invalid.
pub fn validate_mnemonic_phrase(phrase: &str) -> Result<()> {
    let phrase = phrase.trim();

    if phrase.is_empty() {
        return Err(Error::InvalidMnemonic(
            "mnemonic phrase cannot be empty".to_string(),
        ));
    }

    let words: Vec<&str> = phrase.split_whitespace().collect();
    let word_count = words.len();

    // Valid word counts for BIP-39: 12, 15, 18, 21, 24
    if ![12, 15, 18, 21, 24].contains(&word_count) {
        return Err(Error::InvalidMnemonic(format!(
            "invalid word count: {}. Must be 12, 15, 18, 21, or 24",
            word_count
        )));
    }

    Ok(())
}

/// Validates a derivation path.
///
/// # Arguments
///
/// * `path` - The derivation path to validate
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::InvalidMnemonic)` if invalid.
pub fn validate_derivation_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::InvalidMnemonic(
            "derivation path cannot be empty".to_string(),
        ));
    }

    if !path.starts_with("m/") && path != "m" {
        return Err(Error::InvalidMnemonic(format!(
            "derivation path must start with 'm/' or be 'm', got: {}",
            path
        )));
    }

    // Validate each component
    let components: Vec<&str> = path.split('/').collect();
    for (i, component) in components.iter().enumerate() {
        if i == 0 {
            if *component != "m" {
                return Err(Error::InvalidMnemonic(format!(
                    "derivation path must start with 'm', got: {}",
                    component
                )));
            }
            continue;
        }

        let component = component.trim_end_matches('\'').trim_end_matches('h');
        if component.parse::<u32>().is_err() {
            return Err(Error::InvalidMnemonic(format!(
                "invalid path component: {}",
                components[i]
            )));
        }
    }

    Ok(())
}

/// Validates a URL string.
///
/// # Arguments
///
/// * `url` - The URL to validate
/// * `field` - The field name for error messages
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::Validation)` if invalid.
pub fn validate_url(url: &str, field: &str) -> Result<()> {
    if url.is_empty() {
        return Err(Error::Validation {
            field: field.to_string(),
            message: "URL cannot be empty".to_string(),
        });
    }

    // Basic URL validation - must start with http:// or https:// or ws:// or wss://
    if !url.starts_with("http://")
        && !url.starts_with("https://")
        && !url.starts_with("ws://")
        && !url.starts_with("wss://")
    {
        return Err(Error::Validation {
            field: field.to_string(),
            message: "URL must start with http://, https://, ws://, or wss://".to_string(),
        });
    }

    Ok(())
}

/// Validates a word count for mnemonic generation.
///
/// # Arguments
///
/// * `word_count` - The word count to validate
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::InvalidMnemonic)` if invalid.
pub fn validate_mnemonic_word_count(word_count: usize) -> Result<()> {
    if ![12, 15, 18, 21, 24].contains(&word_count) {
        return Err(Error::InvalidMnemonic(format!(
            "invalid word count: {}. Must be 12, 15, 18, 21, or 24",
            word_count
        )));
    }
    Ok(())
}

/// Validates a decimal string for unit conversion.
///
/// # Arguments
///
/// * `value` - The decimal string to validate
/// * `field` - The field name for error messages
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::Validation)` if invalid.
pub fn validate_decimal_string(value: &str, field: &str) -> Result<()> {
    let value = value.trim();

    if value.is_empty() {
        return Err(Error::Validation {
            field: field.to_string(),
            message: "cannot be empty".to_string(),
        });
    }

    // Check for multiple decimal points
    let dot_count = value.chars().filter(|&c| c == '.').count();
    if dot_count > 1 {
        return Err(Error::Validation {
            field: field.to_string(),
            message: "invalid decimal format: multiple decimal points".to_string(),
        });
    }

    // Check for valid characters (digits, optional leading minus, optional decimal point)
    let chars: Vec<char> = value.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c == '-' && i == 0 {
            continue; // Leading minus is allowed
        }
        if c == '.' {
            continue; // Decimal point is allowed
        }
        if !c.is_ascii_digit() {
            return Err(Error::Validation {
                field: field.to_string(),
                message: format!("invalid character '{}' in decimal string", c),
            });
        }
    }

    Ok(())
}

/// Validates ABI JSON string.
///
/// # Arguments
///
/// * `json` - The ABI JSON string to validate
///
/// # Returns
///
/// `Ok(())` if valid, or `Err(Error::Abi)` if invalid.
pub fn validate_abi_json(json: &str) -> Result<()> {
    if json.trim().is_empty() {
        return Err(Error::Abi("ABI JSON cannot be empty".to_string()));
    }

    // Basic JSON array validation
    let trimmed = json.trim();
    if !trimmed.starts_with('[') || !trimmed.ends_with(']') {
        return Err(Error::Abi("ABI JSON must be an array".to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_not_empty() {
        assert!(validate_not_empty("hello", "field").is_ok());
        assert!(validate_not_empty("", "field").is_err());
    }

    #[test]
    fn test_validate_not_blank() {
        assert!(validate_not_blank("hello", "field").is_ok());
        assert!(validate_not_blank("  hello  ", "field").is_ok());
        assert!(validate_not_blank("", "field").is_err());
        assert!(validate_not_blank("   ", "field").is_err());
        assert!(validate_not_blank("\t\n", "field").is_err());
    }

    #[test]
    fn test_validate_byte_length() {
        assert!(validate_byte_length(&[1, 2, 3], 3, "field").is_ok());
        assert!(validate_byte_length(&[1, 2, 3], 4, "field").is_err());
        assert!(validate_byte_length(&[], 0, "field").is_ok());
    }

    #[test]
    fn test_validate_hex_string() {
        assert!(validate_hex_string("0x1234", "field").is_ok());
        assert!(validate_hex_string("1234", "field").is_ok());
        assert!(validate_hex_string("0x", "field").is_ok());
        assert!(validate_hex_string("", "field").is_ok());
        assert!(validate_hex_string("0xabcdef", "field").is_ok());
        assert!(validate_hex_string("0xABCDEF", "field").is_ok());

        // Invalid cases
        assert!(validate_hex_string("0x123", "field").is_err()); // Odd length
        assert!(validate_hex_string("0xgg", "field").is_err()); // Invalid chars
        assert!(validate_hex_string("xyz", "field").is_err()); // Invalid chars
    }

    #[test]
    fn test_validate_hex_length() {
        assert!(validate_hex_length("0x1234", 2, "field").is_ok());
        assert!(validate_hex_length("1234", 2, "field").is_ok());
        assert!(validate_hex_length("0x", 0, "field").is_ok());

        // Invalid cases
        assert!(validate_hex_length("0x1234", 3, "field").is_err());
        assert!(validate_hex_length("0x123", 2, "field").is_err()); // Odd length
    }

    #[test]
    fn test_validate_address() {
        assert!(validate_address("0x1234567890123456789012345678901234567890").is_ok());
        assert!(validate_address("1234567890123456789012345678901234567890").is_ok());
        assert!(validate_address("0xABCDEF1234567890abcdef1234567890ABCDEF12").is_ok());

        // Invalid cases
        assert!(validate_address("0x1234").is_err()); // Too short
        assert!(validate_address("0xGGGG567890123456789012345678901234567890").is_err()); // Invalid chars
        assert!(validate_address("").is_err()); // Empty
    }

    #[test]
    fn test_validate_private_key() {
        assert!(validate_private_key(&[1u8; 32]).is_ok());
        assert!(validate_private_key(&[0xab; 32]).is_ok());

        // Invalid cases
        assert!(validate_private_key(&[1u8; 16]).is_err()); // Too short
        assert!(validate_private_key(&[1u8; 64]).is_err()); // Too long
        assert!(validate_private_key(&[0u8; 32]).is_err()); // All zeros
    }

    #[test]
    fn test_validate_private_key_hex() {
        let valid_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(validate_private_key_hex(valid_key).is_ok());
        assert!(validate_private_key_hex(&format!("0x{}", valid_key)).is_ok());

        // Invalid cases
        assert!(validate_private_key_hex("0x1234").is_err()); // Too short
        assert!(validate_private_key_hex(
            "gg23456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
        .is_err()); // Invalid chars
    }

    #[test]
    fn test_validate_mnemonic_phrase() {
        let valid_12 = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(validate_mnemonic_phrase(valid_12).is_ok());

        // Invalid cases
        assert!(validate_mnemonic_phrase("").is_err()); // Empty
        assert!(validate_mnemonic_phrase("   ").is_err()); // Whitespace only
        assert!(validate_mnemonic_phrase("one two three").is_err()); // Wrong word count
    }

    #[test]
    fn test_validate_derivation_path() {
        assert!(validate_derivation_path("m/44'/60'/0'/0/0").is_ok());
        assert!(validate_derivation_path("m/44h/60h/0h/0/0").is_ok());
        assert!(validate_derivation_path("m").is_ok());

        // Invalid cases
        assert!(validate_derivation_path("").is_err()); // Empty
        assert!(validate_derivation_path("44'/60'/0'/0/0").is_err()); // Missing m/
        assert!(validate_derivation_path("m/abc").is_err()); // Invalid component
    }

    #[test]
    fn test_validate_url() {
        assert!(validate_url("http://localhost:8545", "url").is_ok());
        assert!(validate_url("https://mainnet.infura.io", "url").is_ok());
        assert!(validate_url("ws://localhost:8546", "url").is_ok());
        assert!(validate_url("wss://mainnet.infura.io/ws", "url").is_ok());

        // Invalid cases
        assert!(validate_url("", "url").is_err()); // Empty
        assert!(validate_url("localhost:8545", "url").is_err()); // Missing protocol
        assert!(validate_url("ftp://localhost", "url").is_err()); // Invalid protocol
    }

    #[test]
    fn test_validate_mnemonic_word_count() {
        assert!(validate_mnemonic_word_count(12).is_ok());
        assert!(validate_mnemonic_word_count(15).is_ok());
        assert!(validate_mnemonic_word_count(18).is_ok());
        assert!(validate_mnemonic_word_count(21).is_ok());
        assert!(validate_mnemonic_word_count(24).is_ok());

        // Invalid cases
        assert!(validate_mnemonic_word_count(0).is_err());
        assert!(validate_mnemonic_word_count(11).is_err());
        assert!(validate_mnemonic_word_count(13).is_err());
    }

    #[test]
    fn test_validate_decimal_string() {
        assert!(validate_decimal_string("123", "value").is_ok());
        assert!(validate_decimal_string("123.456", "value").is_ok());
        assert!(validate_decimal_string("-123.456", "value").is_ok());
        assert!(validate_decimal_string("0.001", "value").is_ok());
        assert!(validate_decimal_string("  123  ", "value").is_ok());

        // Invalid cases
        assert!(validate_decimal_string("", "value").is_err()); // Empty
        assert!(validate_decimal_string("1.2.3", "value").is_err()); // Multiple dots
        assert!(validate_decimal_string("abc", "value").is_err()); // Invalid chars
        assert!(validate_decimal_string("12a34", "value").is_err()); // Invalid chars
    }

    #[test]
    fn test_validate_abi_json() {
        assert!(validate_abi_json("[]").is_ok());
        assert!(validate_abi_json("[{}]").is_ok());
        assert!(validate_abi_json("  []  ").is_ok());

        // Invalid cases
        assert!(validate_abi_json("").is_err()); // Empty
        assert!(validate_abi_json("   ").is_err()); // Whitespace only
        assert!(validate_abi_json("{}").is_err()); // Not an array
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    // Feature: quantaureum-rust-sdk, Property 10: Invalid Input Validation
    // For any invalid input (empty strings where not allowed, malformed addresses, invalid hex),
    // the SDK SHALL return an Err with a descriptive error rather than panicking.
    // Validates: Requirements 7.3

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Property 10: Empty strings should be rejected where not allowed
        #[test]
        fn prop_empty_string_rejected(field in "[a-z]+") {
            let result = validate_not_empty("", &field);
            prop_assert!(result.is_err(), "Empty string should be rejected");

            if let Err(Error::Validation { field: f, message: m }) = result {
                prop_assert!(!f.is_empty(), "Field name should not be empty");
                prop_assert!(!m.is_empty(), "Error message should not be empty");
            } else {
                prop_assert!(false, "Expected Validation error");
            }
        }

        // Property 10: Whitespace-only strings should be rejected where not allowed
        #[test]
        fn prop_whitespace_string_rejected(
            whitespace in "[ \t\n\r]+",
            field in "[a-z]+"
        ) {
            let result = validate_not_blank(&whitespace, &field);
            prop_assert!(result.is_err(), "Whitespace-only string should be rejected");
        }

        // Property 10: Invalid hex strings should be rejected
        #[test]
        fn prop_invalid_hex_rejected(
            invalid_chars in "[g-zG-Z!@#$%^&*()]+",
            field in "[a-z]+"
        ) {
            let result = validate_hex_string(&invalid_chars, &field);
            prop_assert!(result.is_err(), "Invalid hex characters should be rejected");
        }

        // Property 10: Odd-length hex strings should be rejected
        #[test]
        fn prop_odd_hex_length_rejected(
            hex_chars in "[0-9a-fA-F]{1,99}",
            field in "[a-z]+"
        ) {
            // Only test odd-length strings
            prop_assume!(hex_chars.len() % 2 == 1);

            let result = validate_hex_string(&hex_chars, &field);
            prop_assert!(result.is_err(), "Odd-length hex string should be rejected");
        }

        // Property 10: Valid hex strings should be accepted
        #[test]
        fn prop_valid_hex_accepted(
            bytes in prop::collection::vec(any::<u8>(), 0..50),
            field in "[a-z]+"
        ) {
            let hex_str = hex::encode(&bytes);
            let result = validate_hex_string(&hex_str, &field);
            prop_assert!(result.is_ok(), "Valid hex string should be accepted");

            // Also test with 0x prefix
            let hex_with_prefix = format!("0x{}", hex_str);
            let result_with_prefix = validate_hex_string(&hex_with_prefix, &field);
            prop_assert!(result_with_prefix.is_ok(), "Valid hex string with 0x prefix should be accepted");
        }

        // Property 10: Invalid address length should be rejected
        #[test]
        fn prop_invalid_address_length_rejected(
            hex_chars in "[0-9a-fA-F]{0,39}|[0-9a-fA-F]{41,80}"
        ) {
            let result = validate_address(&hex_chars);
            prop_assert!(result.is_err(), "Invalid address length should be rejected");

            // Also test with 0x prefix
            let with_prefix = format!("0x{}", hex_chars);
            let result_with_prefix = validate_address(&with_prefix);
            prop_assert!(result_with_prefix.is_err(), "Invalid address length with prefix should be rejected");
        }

        // Property 10: Valid addresses should be accepted
        #[test]
        fn prop_valid_address_accepted(bytes in prop::array::uniform20(any::<u8>())) {
            let hex_str = hex::encode(bytes);
            let result = validate_address(&hex_str);
            prop_assert!(result.is_ok(), "Valid address should be accepted");

            // Also test with 0x prefix
            let with_prefix = format!("0x{}", hex_str);
            let result_with_prefix = validate_address(&with_prefix);
            prop_assert!(result_with_prefix.is_ok(), "Valid address with prefix should be accepted");
        }

        // Property 10: Invalid private key length should be rejected
        #[test]
        fn prop_invalid_private_key_length_rejected(
            bytes in prop::collection::vec(any::<u8>(), 0..32).prop_union(
                prop::collection::vec(any::<u8>(), 33..64)
            )
        ) {
            let result = validate_private_key(&bytes);
            prop_assert!(result.is_err(), "Invalid private key length should be rejected");
        }

        // Property 10: All-zero private key should be rejected
        #[test]
        fn prop_zero_private_key_rejected(_dummy in 0..1u8) {
            let zero_key = [0u8; 32];
            let result = validate_private_key(&zero_key);
            prop_assert!(result.is_err(), "All-zero private key should be rejected");
        }

        // Property 10: Valid private keys should be accepted
        #[test]
        fn prop_valid_private_key_accepted(bytes in prop::array::uniform32(any::<u8>())) {
            // Skip all-zero keys
            prop_assume!(bytes.iter().any(|&b| b != 0));

            let result = validate_private_key(&bytes);
            prop_assert!(result.is_ok(), "Valid private key should be accepted");
        }

        // Property 10: Invalid mnemonic word counts should be rejected
        #[test]
        fn prop_invalid_mnemonic_word_count_rejected(
            word_count in (0usize..100).prop_filter("not valid word count", |&n| {
                ![12, 15, 18, 21, 24].contains(&n)
            })
        ) {
            let result = validate_mnemonic_word_count(word_count);
            prop_assert!(result.is_err(), "Invalid word count {} should be rejected", word_count);
        }

        // Property 10: Valid mnemonic word counts should be accepted
        #[test]
        fn prop_valid_mnemonic_word_count_accepted(
            word_count in prop::sample::select(vec![12usize, 15, 18, 21, 24])
        ) {
            let result = validate_mnemonic_word_count(word_count);
            prop_assert!(result.is_ok(), "Valid word count {} should be accepted", word_count);
        }

        // Property 10: Invalid URLs should be rejected
        #[test]
        fn prop_invalid_url_rejected(
            invalid_url in "[a-z]+://[a-z]+".prop_filter("not valid protocol", |s| {
                !s.starts_with("http://") && !s.starts_with("https://")
                && !s.starts_with("ws://") && !s.starts_with("wss://")
            }),
            field in "[a-z]+"
        ) {
            let result = validate_url(&invalid_url, &field);
            prop_assert!(result.is_err(), "Invalid URL should be rejected: {}", invalid_url);
        }

        // Property 10: Valid URLs should be accepted
        #[test]
        fn prop_valid_url_accepted(
            protocol in prop::sample::select(vec!["http://", "https://", "ws://", "wss://"]),
            host in "[a-z]{3,10}",
            port in 1000u16..65535u16,
            field in "[a-z]+"
        ) {
            let url = format!("{}{}:{}", protocol, host, port);
            let result = validate_url(&url, &field);
            prop_assert!(result.is_ok(), "Valid URL should be accepted: {}", url);
        }

        // Property 10: Invalid decimal strings should be rejected
        #[test]
        fn prop_invalid_decimal_rejected(
            invalid_decimal in "[a-zA-Z!@#$%^&*()]+",
            field in "[a-z]+"
        ) {
            let result = validate_decimal_string(&invalid_decimal, &field);
            prop_assert!(result.is_err(), "Invalid decimal string should be rejected: {}", invalid_decimal);
        }

        // Property 10: Multiple decimal points should be rejected
        #[test]
        fn prop_multiple_decimal_points_rejected(
            num1 in 0u32..1000,
            num2 in 0u32..1000,
            num3 in 0u32..1000,
            field in "[a-z]+"
        ) {
            let invalid = format!("{}.{}.{}", num1, num2, num3);
            let result = validate_decimal_string(&invalid, &field);
            prop_assert!(result.is_err(), "Multiple decimal points should be rejected: {}", invalid);
        }

        // Property 10: Valid decimal strings should be accepted
        #[test]
        fn prop_valid_decimal_accepted(
            integer in 0u64..1000000,
            fractional in 0u32..1000000,
            field in "[a-z]+"
        ) {
            let decimal = format!("{}.{}", integer, fractional);
            let result = validate_decimal_string(&decimal, &field);
            prop_assert!(result.is_ok(), "Valid decimal string should be accepted: {}", decimal);
        }

        // Property 10: Invalid derivation paths should be rejected
        #[test]
        fn prop_invalid_derivation_path_rejected(
            invalid_path in "[0-9'/]+".prop_filter("doesn't start with m", |s| !s.starts_with("m"))
        ) {
            let result = validate_derivation_path(&invalid_path);
            prop_assert!(result.is_err(), "Invalid derivation path should be rejected: {}", invalid_path);
        }

        // Property 10: Valid derivation paths should be accepted
        #[test]
        fn prop_valid_derivation_path_accepted(
            purpose in 0u32..100,
            coin_type in 0u32..100,
            account in 0u32..10,
            change in 0u32..2,
            index in 0u32..100
        ) {
            let path = format!("m/{}'/{}'/{}'/{}/{}", purpose, coin_type, account, change, index);
            let result = validate_derivation_path(&path);
            prop_assert!(result.is_ok(), "Valid derivation path should be accepted: {}", path);
        }

        // Property 10: Empty ABI JSON should be rejected
        #[test]
        fn prop_empty_abi_rejected(whitespace in "[ \t\n\r]*") {
            let result = validate_abi_json(&whitespace);
            prop_assert!(result.is_err(), "Empty ABI JSON should be rejected");
        }

        // Property 10: Non-array ABI JSON should be rejected
        #[test]
        fn prop_non_array_abi_rejected(_dummy in 0..1u8) {
            let result = validate_abi_json("{}");
            prop_assert!(result.is_err(), "Non-array ABI JSON should be rejected");

            let result2 = validate_abi_json("\"string\"");
            prop_assert!(result2.is_err(), "String ABI JSON should be rejected");
        }

        // Property 10: Valid ABI JSON arrays should be accepted
        #[test]
        fn prop_valid_abi_array_accepted(_dummy in 0..1u8) {
            let result = validate_abi_json("[]");
            prop_assert!(result.is_ok(), "Empty array ABI JSON should be accepted");

            let result2 = validate_abi_json("[{}]");
            prop_assert!(result2.is_ok(), "Array with object ABI JSON should be accepted");
        }
    }
}
