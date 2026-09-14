// Quantaureum Rust SDK source, version 1.0.0.
//! Mnemonic phrase support (BIP-39).
//!
//! This module provides functionality for creating accounts from mnemonic phrases
//! and generating new mnemonic phrases.

use bip39::{Language, Mnemonic};
use k256::ecdsa::SigningKey;

use crate::error::{Error, Result};
use crate::types::Address;
use crate::utils::keccak256;

use super::account::Account;

/// Default derivation path for Ethereum-compatible accounts (BIP-44).
pub const DEFAULT_DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";

/// Generates a new random mnemonic phrase.
///
/// # Arguments
///
/// * `word_count` - The number of words in the mnemonic (12, 15, 18, 21, or 24)
///
/// # Returns
///
/// A `Result` containing the mnemonic phrase as a string.
///
/// # Errors
///
/// Returns `Error::InvalidMnemonic` if the word count is not valid.
///
/// # Examples
///
/// ```
/// use quantaureum_sdk::accounts::mnemonic::generate_mnemonic;
///
/// let mnemonic = generate_mnemonic(12).unwrap();
/// println!("Mnemonic: {}", mnemonic);
/// ```
pub fn generate_mnemonic(word_count: usize) -> Result<String> {
    // Validate word count
    crate::utils::validation::validate_mnemonic_word_count(word_count)?;

    // Calculate entropy bytes needed for word count
    // 12 words = 128 bits = 16 bytes
    // 15 words = 160 bits = 20 bytes
    // 18 words = 192 bits = 24 bytes
    // 21 words = 224 bits = 28 bytes
    // 24 words = 256 bits = 32 bytes
    let entropy_bytes = match word_count {
        12 => 16,
        15 => 20,
        18 => 24,
        21 => 28,
        24 => 32,
        _ => unreachable!(), // Already validated above
    };

    // Generate random entropy
    use k256::elliptic_curve::rand_core::{OsRng, RngCore};
    let mut entropy = vec![0u8; entropy_bytes];
    OsRng.fill_bytes(&mut entropy);

    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| Error::InvalidMnemonic(e.to_string()))?;

    Ok(mnemonic.to_string())
}

/// Creates an Account from a mnemonic phrase.
///
/// # Arguments
///
/// * `phrase` - The BIP-39 mnemonic phrase
/// * `path` - The derivation path (e.g., "m/44'/60'/0'/0/0")
///
/// # Returns
///
/// A `Result` containing the Account derived from the mnemonic.
///
/// # Errors
///
/// Returns `Error::InvalidMnemonic` if:
/// - The phrase is empty
/// - The phrase has an invalid word count
/// - The derivation path is invalid
///
/// # Examples
///
/// ```
/// use quantaureum_sdk::accounts::mnemonic::{from_mnemonic, DEFAULT_DERIVATION_PATH};
///
/// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// let account = from_mnemonic(phrase, DEFAULT_DERIVATION_PATH).unwrap();
/// ```
pub fn from_mnemonic(phrase: &str, path: &str) -> Result<Account> {
    // Validate inputs
    crate::utils::validation::validate_mnemonic_phrase(phrase)?;
    crate::utils::validation::validate_derivation_path(path)?;

    // Parse the mnemonic phrase
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
        .map_err(|e| Error::InvalidMnemonic(e.to_string()))?;

    // Generate seed from mnemonic (with empty passphrase)
    let seed = mnemonic.to_seed("");

    // Derive the private key using the path
    let private_key = derive_key_from_path(&seed, path)?;

    // Create the account
    let mut account = Account::from_private_key(&private_key)?;
    account.set_mnemonic(phrase.to_string());

    Ok(account)
}

/// Derives a private key from a seed using a BIP-32/BIP-44 derivation path.
///
/// This is a simplified implementation that handles the standard Ethereum path.
fn derive_key_from_path(seed: &[u8], path: &str) -> Result<[u8; 32]> {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    // Parse the derivation path
    let components: Vec<&str> = path.split('/').collect();
    if components.is_empty() || components[0] != "m" {
        return Err(Error::InvalidMnemonic(format!(
            "invalid derivation path: {}",
            path
        )));
    }

    // Generate master key from seed
    let mut mac = HmacSha512::new_from_slice(b"Bitcoin seed")
        .map_err(|e| Error::InvalidMnemonic(e.to_string()))?;
    mac.update(seed);
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    let mut chain_code = [0u8; 32];
    key.copy_from_slice(&result[..32]);
    chain_code.copy_from_slice(&result[32..]);

    // Derive child keys for each path component
    for component in components.iter().skip(1) {
        let (index, hardened) = parse_path_component(component)?;

        let child_index = if hardened { index | 0x80000000 } else { index };

        // Derive child key
        let mut mac = HmacSha512::new_from_slice(&chain_code)
            .map_err(|e| Error::InvalidMnemonic(e.to_string()))?;

        if hardened {
            // Hardened derivation: use 0x00 || private_key || index
            mac.update(&[0x00]);
            mac.update(&key);
        } else {
            // Normal derivation: use public_key || index
            let signing_key = SigningKey::from_slice(&key).map_err(|_| Error::InvalidPrivateKey)?;
            let verifying_key = signing_key.verifying_key();
            let public_key = verifying_key.to_encoded_point(true);
            mac.update(public_key.as_bytes());
        }
        mac.update(&child_index.to_be_bytes());

        let result = mac.finalize().into_bytes();

        // Add the derived key to the parent key (mod curve order)
        let derived_key = &result[..32];
        key = add_private_keys(&key, derived_key)?;
        chain_code.copy_from_slice(&result[32..]);
    }

    Ok(key)
}

/// Parses a path component like "44'" or "0" into (index, is_hardened).
fn parse_path_component(component: &str) -> Result<(u32, bool)> {
    let hardened = component.ends_with('\'') || component.ends_with('h');
    let index_str = if hardened {
        &component[..component.len() - 1]
    } else {
        component
    };

    let index: u32 = index_str
        .parse()
        .map_err(|_| Error::InvalidMnemonic(format!("invalid path component: {}", component)))?;

    Ok((index, hardened))
}

/// Adds two private keys modulo the secp256k1 curve order.
fn add_private_keys(key1: &[u8; 32], key2: &[u8]) -> Result<[u8; 32]> {
    use k256::elliptic_curve::ops::Reduce;
    use k256::{NonZeroScalar, Scalar, U256};

    let scalar1 = <Scalar as Reduce<U256>>::reduce_bytes(key1.into());

    let mut key2_arr = [0u8; 32];
    key2_arr.copy_from_slice(&key2[..32]);
    let scalar2 = <Scalar as Reduce<U256>>::reduce_bytes((&key2_arr).into());

    let sum = scalar1 + scalar2;

    // Check if result is zero (invalid)
    let non_zero = NonZeroScalar::new(sum);
    if non_zero.is_none().into() {
        return Err(Error::InvalidPrivateKey);
    }

    Ok(sum.to_bytes().into())
}

/// Derives the address from a signing key.
#[allow(dead_code)]
fn derive_address(signing_key: &SigningKey) -> Result<Address> {
    use k256::ecdsa::VerifyingKey;

    let verifying_key = VerifyingKey::from(signing_key);
    let public_key = verifying_key.to_encoded_point(false);
    let public_key_bytes = public_key.as_bytes();

    let hash = keccak256(&public_key_bytes[1..]);

    let mut address_bytes = [0u8; 20];
    address_bytes.copy_from_slice(&hash[12..]);

    Ok(Address::from_bytes(address_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic_12_words() {
        let mnemonic = generate_mnemonic(12).unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    #[test]
    fn test_generate_mnemonic_24_words() {
        let mnemonic = generate_mnemonic(24).unwrap();
        let words: Vec<&str> = mnemonic.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn test_generate_mnemonic_invalid_count() {
        let result = generate_mnemonic(13);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_mnemonic_known_vector() {
        // Test vector: well-known mnemonic and expected address
        // This is the standard "abandon" test mnemonic
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let account = from_mnemonic(phrase, DEFAULT_DERIVATION_PATH).unwrap();

        // The expected address for this mnemonic at m/44'/60'/0'/0/0
        let expected_address = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
        assert_eq!(
            account.address().to_checksum().to_lowercase(),
            expected_address.to_lowercase()
        );
    }

    #[test]
    fn test_from_mnemonic_stores_phrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let account = from_mnemonic(phrase, DEFAULT_DERIVATION_PATH).unwrap();

        assert_eq!(account.mnemonic(), Some(phrase));
    }

    #[test]
    fn test_from_mnemonic_invalid_phrase() {
        let result = from_mnemonic("invalid mnemonic phrase", DEFAULT_DERIVATION_PATH);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_mnemonic_different_paths() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let account1 = from_mnemonic(phrase, "m/44'/60'/0'/0/0").unwrap();
        let account2 = from_mnemonic(phrase, "m/44'/60'/0'/0/1").unwrap();

        // Different paths should produce different addresses
        assert_ne!(account1.address(), account2.address());
    }

    #[test]
    fn test_mnemonic_roundtrip() {
        // Generate a mnemonic
        let phrase = generate_mnemonic(12).unwrap();

        // Create account from mnemonic
        let account1 = from_mnemonic(&phrase, DEFAULT_DERIVATION_PATH).unwrap();

        // Create another account from the same mnemonic
        let account2 = from_mnemonic(&phrase, DEFAULT_DERIVATION_PATH).unwrap();

        // Both should have the same address
        assert_eq!(account1.address(), account2.address());

        // Both should have the same private key
        assert_eq!(account1.private_key_bytes(), account2.private_key_bytes());
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: quantaureum-rust-sdk, Property 3: Mnemonic Import/Export Round-Trip
        // For any Account created from a mnemonic phrase, exporting the mnemonic and
        // creating a new Account from it SHALL produce an Account with the identical
        // address and private key.
        // Validates: Requirements 2.5, 2.6
        #[test]
        fn prop_mnemonic_roundtrip(word_count in prop::sample::select(vec![12usize, 15, 18, 21, 24])) {
            // Generate a random mnemonic
            let phrase = generate_mnemonic(word_count).unwrap();

            // Create account from mnemonic
            let account1 = from_mnemonic(&phrase, DEFAULT_DERIVATION_PATH).unwrap();

            // Verify mnemonic is stored
            prop_assert_eq!(account1.mnemonic(), Some(phrase.as_str()));

            // Create another account from the same mnemonic
            let account2 = from_mnemonic(&phrase, DEFAULT_DERIVATION_PATH).unwrap();

            // Both should have the same address
            prop_assert_eq!(
                account1.address(),
                account2.address(),
                "Same mnemonic should derive same address"
            );

            // Both should have the same private key
            prop_assert_eq!(
                account1.private_key_bytes(),
                account2.private_key_bytes(),
                "Same mnemonic should derive same private key"
            );
        }

        // Feature: quantaureum-rust-sdk, Property 3: Mnemonic consistency across paths
        // For any mnemonic, different derivation paths should produce different addresses.
        // Validates: Requirements 2.5, 2.6
        #[test]
        fn prop_mnemonic_different_paths_different_addresses(
            word_count in prop::sample::select(vec![12usize, 24]),
            index1 in 0u32..10,
            index2 in 0u32..10
        ) {
            prop_assume!(index1 != index2);

            let phrase = generate_mnemonic(word_count).unwrap();
            let path1 = format!("m/44'/60'/0'/0/{}", index1);
            let path2 = format!("m/44'/60'/0'/0/{}", index2);

            let account1 = from_mnemonic(&phrase, &path1).unwrap();
            let account2 = from_mnemonic(&phrase, &path2).unwrap();

            prop_assert_ne!(
                account1.address(),
                account2.address(),
                "Different paths should derive different addresses"
            );
        }

        // Feature: quantaureum-rust-sdk, Property 3: Generated mnemonics are valid
        // For any generated mnemonic, it should be parseable and usable.
        // Validates: Requirements 2.5, 2.6
        #[test]
        fn prop_generated_mnemonic_is_valid(word_count in prop::sample::select(vec![12usize, 15, 18, 21, 24])) {
            let phrase = generate_mnemonic(word_count).unwrap();

            // Verify word count
            let words: Vec<&str> = phrase.split_whitespace().collect();
            prop_assert_eq!(words.len(), word_count);

            // Verify it can be used to create an account
            let result = from_mnemonic(&phrase, DEFAULT_DERIVATION_PATH);
            prop_assert!(result.is_ok(), "Generated mnemonic should be valid");
        }
    }
}
