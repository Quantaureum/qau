// Quantaureum Rust SDK source, version 1.0.0.
//! Wei/Ether unit conversion utilities.
//!
//! This module provides functions for converting between different units of cryptocurrency.
//! The base unit is Wei (1 Ether = 10^18 Wei).

use crate::error::{Error, Result};
use primitive_types::U256;

/// Number of decimal places for Ether (18 decimals).
pub const ETHER_DECIMALS: u32 = 18;

/// Converts an ether value string to Wei.
///
/// # Arguments
///
/// * `ether` - The ether value as a string (e.g., "1.5")
/// * `decimals` - The number of decimal places (typically 18 for Ether)
///
/// # Returns
///
/// A `Result` containing the Wei value as U256.
///
/// # Errors
///
/// Returns an error if the input string is invalid or the value overflows.
///
/// # Examples
///
/// ```
/// use quantaureum_sdk::utils::to_wei;
///
/// let wei = to_wei("1.0", 18).unwrap();
/// assert_eq!(wei.to_string(), "1000000000000000000");
///
/// let wei = to_wei("0.5", 18).unwrap();
/// assert_eq!(wei.to_string(), "500000000000000000");
/// ```
pub fn to_wei(ether: &str, decimals: u32) -> Result<U256> {
    parse_units(ether, decimals)
}

/// Converts a Wei value to an ether string.
///
/// # Arguments
///
/// * `wei` - The Wei value as U256
/// * `decimals` - The number of decimal places (typically 18 for Ether)
///
/// # Returns
///
/// The ether value as a string.
///
/// # Examples
///
/// ```
/// use quantaureum_sdk::utils::from_wei;
/// use primitive_types::U256;
///
/// let ether = from_wei(U256::from(1_000_000_000_000_000_000u64), 18);
/// assert_eq!(ether, "1.0");
///
/// let ether = from_wei(U256::from(500_000_000_000_000_000u64), 18);
/// assert_eq!(ether, "0.5");
/// ```
pub fn from_wei(wei: U256, decimals: u32) -> String {
    format_units(wei, decimals)
}

/// Parses a decimal string value into the smallest unit.
///
/// # Arguments
///
/// * `value` - The decimal value as a string (e.g., "1.5")
/// * `decimals` - The number of decimal places
///
/// # Returns
///
/// A `Result` containing the value in the smallest unit as U256.
///
/// # Errors
///
/// Returns an error if:
/// - The input string is empty or invalid
/// - The value has more decimal places than allowed
/// - The value overflows U256
pub fn parse_units(value: &str, decimals: u32) -> Result<U256> {
    // Validate decimal string format
    crate::utils::validation::validate_decimal_string(value, "value")?;

    let value = value.trim();

    // Split into integer and fractional parts
    let parts: Vec<&str> = value.split('.').collect();

    // Already validated that there's at most one decimal point

    let integer_part = parts[0];
    let fractional_part = if parts.len() == 2 { parts[1] } else { "" };

    // Check if fractional part is too long
    if fractional_part.len() > decimals as usize {
        return Err(Error::Validation {
            field: "value".to_string(),
            message: format!(
                "too many decimal places: {} (max {})",
                fractional_part.len(),
                decimals
            ),
        });
    }

    // Calculate the multiplier
    let multiplier = U256::from(10).pow(U256::from(decimals));

    // Parse integer part
    let integer_value = if integer_part.is_empty() || integer_part == "-" {
        U256::zero()
    } else {
        U256::from_dec_str(integer_part.trim_start_matches('-')).map_err(|_| Error::Validation {
            field: "value".to_string(),
            message: "integer part overflow".to_string(),
        })?
    };

    // Calculate integer contribution
    let integer_wei = integer_value
        .checked_mul(multiplier)
        .ok_or_else(|| Error::Validation {
            field: "value".to_string(),
            message: "overflow".to_string(),
        })?;

    // Parse fractional part
    let fractional_wei = if fractional_part.is_empty() {
        U256::zero()
    } else {
        // Pad fractional part to full decimals
        let padded = format!("{:0<width$}", fractional_part, width = decimals as usize);
        U256::from_dec_str(&padded).map_err(|_| Error::Validation {
            field: "value".to_string(),
            message: "fractional part overflow".to_string(),
        })?
    };

    // Combine
    let result = integer_wei
        .checked_add(fractional_wei)
        .ok_or_else(|| Error::Validation {
            field: "value".to_string(),
            message: "overflow".to_string(),
        })?;

    Ok(result)
}

/// Formats a value from the smallest unit to a decimal string.
///
/// # Arguments
///
/// * `value` - The value in the smallest unit as U256
/// * `decimals` - The number of decimal places
///
/// # Returns
///
/// The formatted decimal string.
pub fn format_units(value: U256, decimals: u32) -> String {
    if decimals == 0 {
        return value.to_string();
    }

    let divisor = U256::from(10).pow(U256::from(decimals));
    let integer_part = value / divisor;
    let fractional_part = value % divisor;

    if fractional_part.is_zero() {
        format!("{}.0", integer_part)
    } else {
        // Format fractional part with leading zeros
        let frac_str = format!("{:0>width$}", fractional_part, width = decimals as usize);
        // Trim trailing zeros
        let frac_str = frac_str.trim_end_matches('0');
        format!("{}.{}", integer_part, frac_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_to_wei_whole_number() {
        let wei = to_wei("1", 18).unwrap();
        assert_eq!(wei, U256::from(10u64).pow(U256::from(18)));
    }

    #[test]
    fn test_to_wei_decimal() {
        let wei = to_wei("1.5", 18).unwrap();
        let expected = U256::from(15u64) * U256::from(10u64).pow(U256::from(17));
        assert_eq!(wei, expected);
    }

    #[test]
    fn test_to_wei_small_decimal() {
        let wei = to_wei("0.000000000000000001", 18).unwrap();
        assert_eq!(wei, U256::from(1));
    }

    #[test]
    fn test_to_wei_zero() {
        let wei = to_wei("0", 18).unwrap();
        assert_eq!(wei, U256::zero());
    }

    #[test]
    fn test_from_wei_whole_number() {
        let ether = from_wei(U256::from(10u64).pow(U256::from(18)), 18);
        assert_eq!(ether, "1.0");
    }

    #[test]
    fn test_from_wei_decimal() {
        let wei = U256::from(15u64) * U256::from(10u64).pow(U256::from(17));
        let ether = from_wei(wei, 18);
        assert_eq!(ether, "1.5");
    }

    #[test]
    fn test_from_wei_small() {
        let ether = from_wei(U256::from(1), 18);
        assert_eq!(ether, "0.000000000000000001");
    }

    #[test]
    fn test_from_wei_zero() {
        let ether = from_wei(U256::zero(), 18);
        assert_eq!(ether, "0.0");
    }

    #[test]
    fn test_parse_units_different_decimals() {
        // 6 decimals (like USDC)
        let value = parse_units("1.5", 6).unwrap();
        assert_eq!(value, U256::from(1_500_000u64));
    }

    #[test]
    fn test_format_units_different_decimals() {
        // 6 decimals (like USDC)
        let value = format_units(U256::from(1_500_000u64), 6);
        assert_eq!(value, "1.5");
    }

    #[test]
    fn test_to_wei_invalid_empty() {
        assert!(to_wei("", 18).is_err());
    }

    #[test]
    fn test_to_wei_invalid_format() {
        assert!(to_wei("1.2.3", 18).is_err());
        assert!(to_wei("abc", 18).is_err());
    }

    #[test]
    fn test_to_wei_too_many_decimals() {
        assert!(to_wei("1.0000000000000000001", 18).is_err());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: quantaureum-rust-sdk, Property 5: Wei/Ether Conversion Round-Trip
        // For any valid Wei value, calling from_wei() then to_wei() SHALL return the original value.
        // Validates: Requirements 5.1, 5.2
        #[test]
        fn prop_wei_ether_roundtrip(wei_value in 0u64..1_000_000_000_000_000_000u64) {
            let wei = U256::from(wei_value);
            let ether_str = from_wei(wei, 18);
            let recovered_wei = to_wei(&ether_str, 18).unwrap();
            prop_assert_eq!(wei, recovered_wei);
        }

        // Feature: quantaureum-rust-sdk, Property 5: Wei/Ether Conversion Round-Trip
        // For different decimal values (6, 8, 18), round-trip conversion should preserve value.
        // Validates: Requirements 5.1, 5.2
        #[test]
        fn prop_units_roundtrip_various_decimals(
            value in 0u64..1_000_000_000u64,
            decimals in 1u32..18u32
        ) {
            let wei = U256::from(value);
            let formatted = format_units(wei, decimals);
            let recovered = parse_units(&formatted, decimals).unwrap();
            prop_assert_eq!(wei, recovered);
        }
    }
}
