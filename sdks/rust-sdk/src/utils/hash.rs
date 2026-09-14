// Quantaureum Rust SDK source, version 1.0.0.
//! Hash functions (keccak256).
//!
//! This module provides cryptographic hash functions used in blockchain operations.

use crate::types::H256;
use tiny_keccak::{Hasher, Keccak};

/// Computes the Keccak-256 hash of the input data.
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// A 32-byte array containing the hash.
///
/// # Examples
///
/// ```
/// use quantaureum_sdk::utils::keccak256;
///
/// let hash = keccak256(b"hello");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

/// Computes the Keccak-256 hash and returns it as an H256.
///
/// # Arguments
///
/// * `data` - The data to hash
///
/// # Returns
///
/// An H256 containing the hash.
///
/// # Examples
///
/// ```
/// use quantaureum_sdk::utils::keccak256_hash;
///
/// let hash = keccak256_hash(b"hello");
/// // The keccak256 hash of "hello" is well-known
/// ```
pub fn keccak256_hash(data: &[u8]) -> H256 {
    H256::from_bytes(keccak256(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_keccak256_empty() {
        let hash = keccak256(b"");
        // Known keccak256 hash of empty string
        let expected =
            hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_keccak256_hello() {
        let hash = keccak256(b"hello");
        // Known keccak256 hash of "hello"
        let expected =
            hex::decode("1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
                .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_keccak256_hash_returns_h256() {
        let hash = keccak256_hash(b"test");
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_keccak256_consistency() {
        let data = b"some test data";
        let hash1 = keccak256(data);
        let hash2 = keccak256(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_keccak256_different_inputs() {
        let hash1 = keccak256(b"input1");
        let hash2 = keccak256(b"input2");
        assert_ne!(hash1, hash2);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: quantaureum-rust-sdk, Property 8: Keccak256 Hash Consistency
        // For any input data, calling keccak256() multiple times SHALL always return the same hash.
        // Validates: Requirements 5.4
        #[test]
        fn prop_keccak256_consistency(data: Vec<u8>) {
            let hash1 = keccak256(&data);
            let hash2 = keccak256(&data);
            prop_assert_eq!(hash1, hash2);
        }

        // Feature: quantaureum-rust-sdk, Property 8: Keccak256 Hash Consistency (collision resistance)
        // For any two different inputs, keccak256() SHALL return different hashes.
        // Validates: Requirements 5.4
        #[test]
        fn prop_keccak256_collision_resistance(data1: Vec<u8>, data2: Vec<u8>) {
            prop_assume!(data1 != data2);
            let hash1 = keccak256(&data1);
            let hash2 = keccak256(&data2);
            prop_assert_ne!(hash1, hash2);
        }
    }
}
