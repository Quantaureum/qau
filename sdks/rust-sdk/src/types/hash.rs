// Quantaureum Rust SDK source, version 1.0.0.
//! H256 hash type definition.
//!
//! Provides a 32-byte hash type for transaction hashes, block hashes, etc.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};

/// A 32-byte hash value.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct H256([u8; 32]);

impl H256 {
    /// The zero hash (0x0000...0000).
    pub const ZERO: H256 = H256([0u8; 32]);

    /// Creates an H256 from a 32-byte array.
    ///
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::H256;
    ///
    /// let bytes = [0u8; 32];
    /// let hash = H256::from_bytes(bytes);
    /// assert_eq!(hash, H256::ZERO);
    /// ```
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        H256(bytes)
    }

    /// Creates an H256 from a byte slice.
    ///
    /// Returns an error if the slice is not exactly 32 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != 32 {
            return Err(Error::Validation {
                field: "hash".to_string(),
                message: format!("expected 32 bytes, got {}", slice.len()),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(H256(bytes))
    }

    /// Creates an H256 from a hexadecimal string.
    ///
    /// The string may optionally start with "0x".
    ///
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::H256;
    ///
    /// let hash = H256::from_hex("0x0000000000000000000000000000000000000000000000000000000000000000").unwrap();
    /// assert_eq!(hash, H256::ZERO);
    /// ```
    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);

        if hex.len() != 64 {
            return Err(Error::InvalidHex(format!(
                "expected 64 hex characters, got {}",
                hex.len()
            )));
        }

        let bytes = hex::decode(hex).map_err(|e| Error::InvalidHex(e.to_string()))?;
        Self::from_slice(&bytes)
    }

    /// Returns the hash as a byte slice.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the hash as a hexadecimal string with "0x" prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::H256;
    ///
    /// let hash = H256::ZERO;
    /// assert_eq!(hash.to_hex(), "0x0000000000000000000000000000000000000000000000000000000000000000");
    /// ```
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }
}

impl fmt::Debug for H256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H256({})", self.to_hex())
    }
}

impl fmt::Display for H256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for H256 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        H256::from_hex(s)
    }
}

impl From<[u8; 32]> for H256 {
    fn from(bytes: [u8; 32]) -> Self {
        H256::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for H256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for H256 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for H256 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        H256::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_h256_zero() {
        let hash = H256::ZERO;
        assert_eq!(
            hash.to_hex(),
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_h256_from_hex() {
        let hash =
            H256::from_hex("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
                .unwrap();
        assert_eq!(
            hash.to_hex(),
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    }

    #[test]
    fn test_h256_from_hex_no_prefix() {
        let hash =
            H256::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
                .unwrap();
        assert_eq!(
            hash.to_hex(),
            "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
        );
    }

    #[test]
    fn test_h256_invalid_length() {
        let result = H256::from_hex("0x1234");
        assert!(result.is_err());
    }

    #[test]
    fn test_h256_from_bytes() {
        let bytes = [0xab; 32];
        let hash = H256::from_bytes(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }
}
