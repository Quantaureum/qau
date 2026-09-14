// Quantaureum Rust SDK source, version 1.0.0.
//! Account structure and methods.
//!
//! This module provides the core Account structure for managing private keys
//! and deriving addresses.

use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;

use crate::error::{Error, Result};
use crate::types::Address;
use crate::utils::keccak256;

/// An account representing a blockchain identity with a private key.
///
/// The Account struct manages a private key and derives the corresponding
/// public address. It supports creating accounts from random keys, existing
/// private keys, or mnemonic phrases.
pub struct Account {
    /// The ECDSA signing key (private key)
    signing_key: SigningKey,
    /// The derived address
    address: Address,
    /// Optional mnemonic phrase (if account was created from mnemonic)
    mnemonic: Option<String>,
}

impl Account {
    /// Creates a new account with a randomly generated private key.
    ///
    /// # Returns
    ///
    /// A `Result` containing the new Account, or an error if key generation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::Account;
    ///
    /// let account = Account::new().unwrap();
    /// println!("Address: {}", account.address());
    /// ```
    pub fn new() -> Result<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        let address = Self::derive_address(&signing_key)?;

        Ok(Account {
            signing_key,
            address,
            mnemonic: None,
        })
    }

    /// Creates an account from a 32-byte private key.
    ///
    /// # Arguments
    ///
    /// * `key` - A 32-byte slice containing the private key
    ///
    /// # Returns
    ///
    /// A `Result` containing the Account, or an error if the key is invalid.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPrivateKey` if:
    /// - The key is not exactly 32 bytes
    /// - The key is all zeros
    /// - The key is not a valid secp256k1 private key
    ///
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::Account;
    ///
    /// let key = [1u8; 32]; // Example key (don't use in production!)
    /// let account = Account::from_private_key(&key).unwrap();
    /// ```
    pub fn from_private_key(key: &[u8]) -> Result<Self> {
        // Validate private key
        crate::utils::validation::validate_private_key(key)?;

        let signing_key = SigningKey::from_slice(key).map_err(|_| Error::InvalidPrivateKey)?;
        let address = Self::derive_address(&signing_key)?;

        Ok(Account {
            signing_key,
            address,
            mnemonic: None,
        })
    }

    /// Creates an account from a hexadecimal private key string.
    ///
    /// # Arguments
    ///
    /// * `hex` - A hexadecimal string (with or without "0x" prefix) containing the private key
    ///
    /// # Returns
    ///
    /// A `Result` containing the Account, or an error if the key is invalid.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidPrivateKey` if the hex string is not 64 characters.
    /// Returns `Error::InvalidHex` if the string contains invalid hex characters.
    ///
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::Account;
    ///
    /// let hex_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    /// let account = Account::from_private_key_hex(hex_key).unwrap();
    /// ```
    pub fn from_private_key_hex(hex: &str) -> Result<Self> {
        // Validate hex format
        crate::utils::validation::validate_private_key_hex(hex)?;

        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let key_bytes = hex::decode(hex).map_err(|e| Error::InvalidHex(e.to_string()))?;
        Self::from_private_key(&key_bytes)
    }

    /// Creates an account from a BIP-39 mnemonic phrase.
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
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::Account;
    ///
    /// let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    /// let account = Account::from_mnemonic(phrase, "m/44'/60'/0'/0/0").unwrap();
    /// ```
    pub fn from_mnemonic(phrase: &str, path: &str) -> Result<Self> {
        super::mnemonic::from_mnemonic(phrase, path)
    }

    /// Generates a new random mnemonic phrase.
    ///
    /// # Arguments
    ///
    /// * `word_count` - The number of words (12, 15, 18, 21, or 24)
    ///
    /// # Returns
    ///
    /// A `Result` containing the mnemonic phrase as a string.
    ///
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::Account;
    ///
    /// let mnemonic = Account::generate_mnemonic(12).unwrap();
    /// println!("Mnemonic: {}", mnemonic);
    /// ```
    pub fn generate_mnemonic(word_count: usize) -> Result<String> {
        super::mnemonic::generate_mnemonic(word_count)
    }

    /// Returns the account's address.
    ///
    /// # Returns
    ///
    /// The derived Address for this account.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns the private key as a 32-byte array.
    ///
    /// # Returns
    ///
    /// A 32-byte array containing the private key.
    ///
    /// # Security
    ///
    /// Handle the returned bytes with care. Never log or expose private keys.
    pub fn private_key(&self) -> [u8; 32] {
        self.private_key_bytes()
    }

    /// Returns the private key as a 32-byte array.
    ///
    /// # Returns
    ///
    /// A 32-byte array containing the private key.
    pub fn private_key_bytes(&self) -> [u8; 32] {
        let bytes = self.signing_key.to_bytes();
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes[..]);
        result
    }

    /// Returns the private key as a hexadecimal string with "0x" prefix.
    ///
    /// # Returns
    ///
    /// A hexadecimal string representation of the private key.
    ///
    /// # Security
    ///
    /// Handle the returned string with care. Never log or expose private keys.
    pub fn private_key_hex(&self) -> String {
        format!("0x{}", hex::encode(self.signing_key.to_bytes()))
    }

    /// Returns the mnemonic phrase if the account was created from one.
    ///
    /// # Returns
    ///
    /// An `Option` containing the mnemonic phrase, or `None` if the account
    /// was not created from a mnemonic.
    pub fn mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    /// Returns a reference to the internal signing key.
    ///
    /// This is used internally for signing operations.
    #[allow(dead_code)]
    pub(crate) fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Signs a transaction with EIP-155 replay protection.
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction request to sign
    /// * `chain_id` - The chain ID for EIP-155 replay protection
    ///
    /// # Returns
    ///
    /// A `Result` containing the SignedTransaction, or an error if signing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::{Account, types::{TransactionRequest, U256, Address}};
    ///
    /// let account = Account::new().unwrap();
    /// let to = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();
    /// let tx = TransactionRequest::new()
    ///     .to(to)
    ///     .value(U256::from(1000))
    ///     .gas(21000)
    ///     .gas_price(U256::from(20_000_000_000u64))
    ///     .nonce(0);
    ///
    /// let signed_tx = account.sign_transaction(&tx, 1).unwrap();
    /// ```
    pub fn sign_transaction(
        &self,
        tx: &crate::types::TransactionRequest,
        chain_id: u64,
    ) -> Result<crate::types::SignedTransaction> {
        super::signing::sign_transaction(&self.signing_key, tx, chain_id)
    }

    /// Sets the mnemonic phrase for this account.
    ///
    /// This is used internally when creating accounts from mnemonics.
    pub(crate) fn set_mnemonic(&mut self, mnemonic: String) {
        self.mnemonic = Some(mnemonic);
    }

    /// Signs a message using the Ethereum signed message format.
    ///
    /// The message is prefixed with "\x19Ethereum Signed Message:\n{length}"
    /// before hashing and signing.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// A `Result` containing the Signature, or an error if signing fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use quantaureum_sdk::Account;
    ///
    /// let account = Account::new().unwrap();
    /// let signature = account.sign_message(b"Hello, World!").unwrap();
    /// ```
    pub fn sign_message(&self, message: &[u8]) -> Result<super::signing::Signature> {
        super::signing::sign_message(&self.signing_key, message)
    }

    /// Derives the address from a signing key.
    ///
    /// The address is derived by:
    /// 1. Getting the uncompressed public key (65 bytes, starting with 0x04)
    /// 2. Taking the last 64 bytes (removing the 0x04 prefix)
    /// 3. Computing keccak256 hash
    /// 4. Taking the last 20 bytes
    fn derive_address(signing_key: &SigningKey) -> Result<Address> {
        use k256::ecdsa::VerifyingKey;

        let verifying_key = VerifyingKey::from(signing_key);
        let public_key = verifying_key.to_encoded_point(false);
        let public_key_bytes = public_key.as_bytes();

        // Skip the 0x04 prefix (uncompressed point indicator)
        // and hash the remaining 64 bytes (x and y coordinates)
        let hash = keccak256(&public_key_bytes[1..]);

        // Take the last 20 bytes of the hash
        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..]);

        Ok(Address::from_bytes(address_bytes))
    }
}

impl std::fmt::Debug for Account {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Account")
            .field("address", &self.address)
            .field("has_mnemonic", &self.mnemonic.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_new() {
        let account = Account::new().unwrap();
        // Address should be valid (20 bytes)
        assert_eq!(account.address().as_bytes().len(), 20);
        // Private key should be 32 bytes
        assert_eq!(account.private_key_bytes().len(), 32);
    }

    #[test]
    fn test_account_from_private_key() {
        let key = [1u8; 32];
        let account = Account::from_private_key(&key).unwrap();
        assert_eq!(account.private_key_bytes(), key);
    }

    #[test]
    fn test_account_from_private_key_hex() {
        let hex_key = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let account = Account::from_private_key_hex(hex_key).unwrap();

        // Verify the private key matches
        let expected_key =
            hex::decode("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
                .unwrap();
        assert_eq!(
            account.private_key_bytes().as_slice(),
            expected_key.as_slice()
        );
    }

    #[test]
    fn test_account_from_private_key_hex_no_prefix() {
        let hex_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let account = Account::from_private_key_hex(hex_key).unwrap();

        let expected_key = hex::decode(hex_key).unwrap();
        assert_eq!(
            account.private_key_bytes().as_slice(),
            expected_key.as_slice()
        );
    }

    #[test]
    fn test_account_address_derivation_consistency() {
        let key = [42u8; 32];
        let account1 = Account::from_private_key(&key).unwrap();
        let account2 = Account::from_private_key(&key).unwrap();

        // Same private key should derive same address
        assert_eq!(account1.address(), account2.address());

        // Multiple calls to address() should return same value
        assert_eq!(account1.address(), account1.address());
    }

    #[test]
    fn test_account_private_key_hex() {
        let key = [0xab; 32];
        let account = Account::from_private_key(&key).unwrap();

        let hex = account.private_key_hex();
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn test_account_invalid_private_key_length() {
        let short_key = [1u8; 16];
        let result = Account::from_private_key(&short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_account_invalid_hex() {
        let result = Account::from_private_key_hex("0xgg");
        assert!(result.is_err());
    }

    #[test]
    fn test_account_no_mnemonic_by_default() {
        let account = Account::new().unwrap();
        assert!(account.mnemonic().is_none());
    }

    #[test]
    fn test_known_address_derivation() {
        // Synthetic, non-funded secp256k1 test key. It exists only to make the
        // address derivation assertion deterministic.
        let hex_key = "0000000000000000000000000000000000000000000000000000000000000001";
        let account = Account::from_private_key_hex(hex_key).unwrap();

        let expected_address = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf";
        assert_eq!(
            account.address().to_checksum().to_lowercase(),
            expected_address.to_lowercase()
        );
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: quantaureum-rust-sdk, Property 1: Account Address Derivation Consistency
        // For any valid private key, creating an Account and calling address() multiple times
        // SHALL always return the same address, and creating a new Account from the same
        // private key SHALL derive the identical address.
        // Validates: Requirements 2.2, 2.7
        #[test]
        fn prop_address_derivation_consistency(seed: [u8; 32]) {
            // Skip invalid keys (all zeros or very small values can be invalid for secp256k1)
            prop_assume!(seed.iter().any(|&b| b != 0));

            // Try to create account, skip if key is invalid for the curve
            if let Ok(account1) = Account::from_private_key(&seed) {
                // Multiple calls to address() should return the same value
                let addr1 = account1.address();
                let addr2 = account1.address();
                prop_assert_eq!(addr1, addr2, "Multiple address() calls should return same value");

                // Creating another account from the same key should derive the same address
                let account2 = Account::from_private_key(&seed).unwrap();
                prop_assert_eq!(
                    account1.address(),
                    account2.address(),
                    "Same private key should derive same address"
                );

                // Private keys should also match
                prop_assert_eq!(
                    account1.private_key_bytes(),
                    account2.private_key_bytes(),
                    "Same private key should be preserved"
                );
            }
        }

        // Feature: quantaureum-rust-sdk, Property 1: Account Address Derivation Consistency (hex variant)
        // For any valid private key hex string, creating an Account should derive the same address
        // as creating from raw bytes.
        // Validates: Requirements 2.2, 2.7
        #[test]
        fn prop_address_derivation_from_hex_consistency(seed: [u8; 32]) {
            prop_assume!(seed.iter().any(|&b| b != 0));

            if let Ok(account_bytes) = Account::from_private_key(&seed) {
                let hex_key = account_bytes.private_key_hex();
                let account_hex = Account::from_private_key_hex(&hex_key).unwrap();

                prop_assert_eq!(
                    account_bytes.address(),
                    account_hex.address(),
                    "Address from bytes and hex should match"
                );
            }
        }
    }
}
