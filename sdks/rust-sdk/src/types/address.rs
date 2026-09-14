// Quantaureum Rust SDK source, version 1.0.0.
//! Address type definition.
//!
//! Provides a 20-byte address type for Quantaureum accounts and contracts.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// A 20-byte Ethereum-style address.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Address([u8; 20]);

impl Address {
    /// The zero address (0x0000...0000).
    pub const ZERO: Address = Address([0u8; 20]);

    /// Creates an Address from a 20-byte array.
    ///
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::Address;
    ///
    /// let bytes = [0u8; 20];
    /// let addr = Address::from_bytes(bytes);
    /// assert_eq!(addr, Address::ZERO);
    /// ```
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }

    /// Creates an Address from a byte slice.
    ///
    /// Returns an error if the slice is not exactly 20 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 20 {
            return Err(Error::InvalidAddress(format!(
                "expected 20 bytes, got {}",
                slice.len()
            )));
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(slice);
        Ok(Address(bytes))
    }

    /// Creates an Address from a hexadecimal string.
    ///
    /// The string may optionally start with "0x".
    ///
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::Address;
    ///
    /// let addr = Address::from_hex("0x0000000000000000000000000000000000000000").unwrap();
    /// assert_eq!(addr, Address::ZERO);
    /// ```
    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);

        if hex.len() != 40 {
            return Err(Error::InvalidAddress(format!(
                "expected 40 hex characters, got {}",
                hex.len()
            )));
        }

        let bytes = hex::decode(hex).map_err(|e| Error::InvalidHex(e.to_string()))?;
        Self::from_slice(&bytes)
    }

    /// Returns the address as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Returns the address as a hexadecimal string with "0x" prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::Address;
    ///
    /// let addr = Address::ZERO;
    /// assert_eq!(addr.to_hex(), "0x0000000000000000000000000000000000000000");
    /// ```
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Returns the address in EIP-55 checksum format.
    ///
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::Address;
    ///
    /// let addr = Address::from_hex("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
    /// assert_eq!(addr.to_checksum(), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    /// ```
    pub fn to_checksum(&self) -> String {
        use tiny_keccak::{Hasher, Keccak};

        let hex_addr = hex::encode(self.0);
        let mut hasher = Keccak::v256();
        hasher.update(hex_addr.as_bytes());
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);

        let mut checksum = String::with_capacity(42);
        checksum.push_str("0x");

        for (i, c) in hex_addr.chars().enumerate() {
            let hash_byte = hash[i / 2];
            let hash_nibble = if i % 2 == 0 {
                hash_byte >> 4
            } else {
                hash_byte & 0x0f
            };

            if c.is_ascii_alphabetic() && hash_nibble >= 8 {
                checksum.push(c.to_ascii_uppercase());
            } else {
                checksum.push(c);
            }
        }

        checksum
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_hex())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_checksum())
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Address::from_hex(s)
    }
}

impl From<[u8; 20]> for Address {
    fn from(bytes: [u8; 20]) -> Self {
        Address::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Address::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_zero() {
        let addr = Address::ZERO;
        assert_eq!(addr.to_hex(), "0x0000000000000000000000000000000000000000");
    }

    #[test]
    fn test_address_from_hex() {
        let addr = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();
        assert_eq!(addr.to_hex(), "0x1234567890123456789012345678901234567890");
    }

    #[test]
    fn test_address_from_hex_no_prefix() {
        let addr = Address::from_hex("1234567890123456789012345678901234567890").unwrap();
        assert_eq!(addr.to_hex(), "0x1234567890123456789012345678901234567890");
    }

    #[test]
    fn test_address_checksum() {
        // Test vector from EIP-55
        let addr = Address::from_hex("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
        assert_eq!(
            addr.to_checksum(),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
    }

    #[test]
    fn test_address_invalid_length() {
        let result = Address::from_hex("0x1234");
        assert!(result.is_err());
    }
}
