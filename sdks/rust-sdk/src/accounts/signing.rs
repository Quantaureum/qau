// Quantaureum Rust SDK source, version 1.0.0.
//! Message and transaction signing.
//!
//! This module provides signature creation and verification functionality.

use k256::ecdsa::{RecoveryId, SigningKey, VerifyingKey};

use crate::error::{Error, Result};
use crate::types::Address;
use crate::utils::keccak256;

/// An ECDSA signature with recovery ID.
///
/// The signature consists of:
/// - `r`: The R component (32 bytes)
/// - `s`: The S component (32 bytes)
/// - `v`: The recovery ID (0 or 1, often encoded as 27 or 28)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    /// The R component of the signature
    pub r: [u8; 32],
    /// The S component of the signature
    pub s: [u8; 32],
    /// The recovery ID (v value)
    pub v: u8,
}

impl Signature {
    /// Creates a new Signature from components.
    pub fn new(r: [u8; 32], s: [u8; 32], v: u8) -> Self {
        Signature { r, s, v }
    }

    /// Converts the signature to a 65-byte array.
    ///
    /// The format is: r (32 bytes) || s (32 bytes) || v (1 byte)
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);
        bytes[64] = self.v;
        bytes
    }

    /// Creates a Signature from a 65-byte array.
    ///
    /// The format is: r (32 bytes) || s (32 bytes) || v (1 byte)
    pub fn from_bytes(bytes: &[u8; 65]) -> Result<Self> {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..64]);
        let v = bytes[64];

        Ok(Signature { r, s, v })
    }

    /// Converts the signature to a hexadecimal string with "0x" prefix.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }

    /// Creates a Signature from a hexadecimal string.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str).map_err(|e| Error::InvalidHex(e.to_string()))?;

        if bytes.len() != 65 {
            return Err(Error::Signing(format!(
                "expected 65 bytes, got {}",
                bytes.len()
            )));
        }

        let mut arr = [0u8; 65];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr)
    }

    /// Recovers the signer's address from the signature and message hash.
    ///
    /// # Arguments
    ///
    /// * `message_hash` - The 32-byte hash of the message that was signed
    ///
    /// # Returns
    ///
    /// The address of the signer, or an error if recovery fails.
    pub fn recover(&self, message_hash: &[u8; 32]) -> Result<Address> {
        // Reconstruct the k256 signature
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&self.r);
        sig_bytes[32..].copy_from_slice(&self.s);

        let signature = k256::ecdsa::Signature::from_slice(&sig_bytes)
            .map_err(|e| Error::Signing(format!("invalid signature: {}", e)))?;

        // Convert v to recovery ID (0 or 1)
        let recovery_id = if self.v >= 27 {
            RecoveryId::try_from(self.v - 27)
        } else {
            RecoveryId::try_from(self.v)
        }
        .map_err(|e| Error::Signing(format!("invalid recovery id: {}", e)))?;

        // Recover the verifying key
        let verifying_key =
            VerifyingKey::recover_from_prehash(message_hash, &signature, recovery_id)
                .map_err(|e| Error::Signing(format!("recovery failed: {}", e)))?;

        // Derive address from verifying key
        let public_key = verifying_key.to_encoded_point(false);
        let public_key_bytes = public_key.as_bytes();
        let hash = keccak256(&public_key_bytes[1..]);

        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..]);

        Ok(Address::from_bytes(address_bytes))
    }
}

/// Signs a message using the Ethereum signed message format.
///
/// The message is prefixed with "\x19Ethereum Signed Message:\n{length}"
/// before hashing and signing.
///
/// # Arguments
///
/// * `signing_key` - The private key to sign with
/// * `message` - The message to sign
///
/// # Returns
///
/// A Signature containing r, s, and v components.
pub fn sign_message(signing_key: &SigningKey, message: &[u8]) -> Result<Signature> {
    let message_hash = hash_message(message);
    sign_hash(signing_key, &message_hash)
}

/// Hashes a message using the Ethereum signed message format.
///
/// The message is prefixed with "\x19Ethereum Signed Message:\n{length}"
/// before hashing.
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut data = prefix.into_bytes();
    data.extend_from_slice(message);
    keccak256(&data)
}

/// Signs a pre-computed hash.
///
/// # Arguments
///
/// * `signing_key` - The private key to sign with
/// * `hash` - The 32-byte hash to sign
///
/// # Returns
///
/// A Signature containing r, s, and v components.
pub fn sign_hash(signing_key: &SigningKey, hash: &[u8; 32]) -> Result<Signature> {
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(hash)
        .map_err(|e| Error::Signing(format!("signing failed: {}", e)))?;

    let sig_bytes = signature.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[..32]);
    s.copy_from_slice(&sig_bytes[32..]);

    // Use recovery ID directly (0 or 1), add 27 for Ethereum compatibility
    let v = recovery_id.to_byte() + 27;

    Ok(Signature { r, s, v })
}

/// Signs a transaction with EIP-155 replay protection.
///
/// # Arguments
///
/// * `signing_key` - The private key to sign with
/// * `tx` - The transaction request to sign
/// * `chain_id` - The chain ID for EIP-155 replay protection
///
/// # Returns
///
/// A SignedTransaction ready for broadcast.
pub fn sign_transaction(
    signing_key: &SigningKey,
    tx: &crate::types::TransactionRequest,
    chain_id: u64,
) -> Result<crate::types::SignedTransaction> {
    use crate::types::{SignedTransaction, U256};

    // Get transaction fields with defaults
    let nonce = tx.nonce.ok_or_else(|| Error::Validation {
        field: "nonce".to_string(),
        message: "nonce is required".to_string(),
    })?;
    let gas_price = tx.gas_price.unwrap_or(U256::zero());
    let gas = tx.gas.ok_or_else(|| Error::Validation {
        field: "gas".to_string(),
        message: "gas limit is required".to_string(),
    })?;
    let value = tx.value.unwrap_or(U256::zero());
    let data = tx.data.clone().unwrap_or_default();

    // RLP encode the unsigned transaction with chain_id for EIP-155
    let unsigned_hash = {
        let mut stream = rlp::RlpStream::new_list(9);
        stream.append(&nonce);
        stream.append(&u256_to_bytes(&gas_price));
        stream.append(&gas);

        if let Some(to) = &tx.to {
            stream.append(&to.as_bytes().as_slice());
        } else {
            stream.append_empty_data();
        }

        stream.append(&u256_to_bytes(&value));
        stream.append(&data.as_slice());
        stream.append(&chain_id);
        stream.append(&0u8);
        stream.append(&0u8);

        keccak256(&stream.out())
    };

    // Sign the hash
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&unsigned_hash)
        .map_err(|e| Error::Signing(format!("signing failed: {}", e)))?;

    let sig_bytes = signature.to_bytes();
    let mut r_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&sig_bytes[..32]);
    s_bytes.copy_from_slice(&sig_bytes[32..]);

    // Calculate v for EIP-155: v = chain_id * 2 + 35 + recovery_id
    let v = chain_id * 2 + 35 + recovery_id.to_byte() as u64;

    Ok(SignedTransaction {
        nonce,
        gas_price,
        gas,
        to: tx.to,
        value,
        data,
        v,
        r: U256::from_big_endian(&r_bytes),
        s: U256::from_big_endian(&s_bytes),
    })
}

/// Converts U256 to bytes, removing leading zeros.
fn u256_to_bytes(value: &crate::types::U256) -> Vec<u8> {
    if value.is_zero() {
        return vec![];
    }

    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);

    // Find first non-zero byte
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(32);
    bytes[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accounts::Account;

    #[test]
    fn test_signature_to_bytes_roundtrip() {
        let sig = Signature {
            r: [1u8; 32],
            s: [2u8; 32],
            v: 27,
        };

        let bytes = sig.to_bytes();
        let recovered = Signature::from_bytes(&bytes).unwrap();

        assert_eq!(sig, recovered);
    }

    #[test]
    fn test_signature_to_hex_roundtrip() {
        let sig = Signature {
            r: [0xab; 32],
            s: [0xcd; 32],
            v: 28,
        };

        let hex = sig.to_hex();
        let recovered = Signature::from_hex(&hex).unwrap();

        assert_eq!(sig, recovered);
    }

    #[test]
    fn test_sign_message_and_recover() {
        let account = Account::new().unwrap();
        let message = b"Hello, Quantaureum!";

        let signature = sign_message(account.signing_key(), message).unwrap();
        let message_hash = hash_message(message);
        let recovered_address = signature.recover(&message_hash).unwrap();

        assert_eq!(recovered_address, account.address());
    }

    #[test]
    fn test_sign_hash_and_recover() {
        let account = Account::new().unwrap();
        let hash = keccak256(b"test data");

        let signature = sign_hash(account.signing_key(), &hash).unwrap();
        let recovered_address = signature.recover(&hash).unwrap();

        assert_eq!(recovered_address, account.address());
    }

    #[test]
    fn test_hash_message_format() {
        // Test that hash_message produces expected format
        let message = b"test";
        let hash = hash_message(message);

        // The hash should be 32 bytes
        assert_eq!(hash.len(), 32);

        // Same message should produce same hash
        let hash2 = hash_message(message);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_different_messages_different_signatures() {
        let account = Account::new().unwrap();

        let sig1 = sign_message(account.signing_key(), b"message1").unwrap();
        let sig2 = sign_message(account.signing_key(), b"message2").unwrap();

        // Different messages should produce different signatures
        assert_ne!(sig1.r, sig2.r);
    }

    #[test]
    fn test_signature_v_value() {
        let account = Account::new().unwrap();
        let signature = sign_message(account.signing_key(), b"test").unwrap();

        // v should be 27 or 28 for Ethereum compatibility
        assert!(signature.v == 27 || signature.v == 28);
    }

    #[test]
    fn test_sign_transaction_and_recover() {
        use crate::types::{Address, TransactionRequest, U256};

        let account = Account::new().unwrap();
        let to = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();

        let tx = TransactionRequest::new()
            .to(to)
            .value(U256::from(1000))
            .gas(21000)
            .gas_price(U256::from(20_000_000_000u64))
            .nonce(0);

        let chain_id = 1u64;
        let signed_tx = sign_transaction(account.signing_key(), &tx, chain_id).unwrap();

        // Verify the signed transaction fields
        assert_eq!(signed_tx.nonce, 0);
        assert_eq!(signed_tx.gas, 21000);
        assert_eq!(signed_tx.to, Some(to));

        // Verify we can recover the signer
        let recovered_address = signed_tx.recover_signer().unwrap();
        assert_eq!(recovered_address, account.address());
    }

    #[test]
    fn test_sign_transaction_eip155_v_value() {
        use crate::types::{Address, TransactionRequest, U256};

        let account = Account::new().unwrap();
        let to = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();

        let tx = TransactionRequest::new()
            .to(to)
            .value(U256::from(1000))
            .gas(21000)
            .gas_price(U256::from(20_000_000_000u64))
            .nonce(0);

        let chain_id = 1u64;
        let signed_tx = sign_transaction(account.signing_key(), &tx, chain_id).unwrap();

        // For EIP-155: v = chain_id * 2 + 35 + recovery_id
        // So v should be 37 or 38 for chain_id = 1
        assert!(signed_tx.v == 37 || signed_tx.v == 38);
    }

    #[test]
    fn test_sign_transaction_contract_creation() {
        use crate::types::{TransactionRequest, U256};

        let account = Account::new().unwrap();

        // Contract creation has no 'to' address
        let tx = TransactionRequest::new()
            .data(vec![0x60, 0x80, 0x60, 0x40]) // Some bytecode
            .gas(100000)
            .gas_price(U256::from(20_000_000_000u64))
            .nonce(0);

        let chain_id = 1u64;
        let signed_tx = sign_transaction(account.signing_key(), &tx, chain_id).unwrap();

        assert!(signed_tx.to.is_none());

        // Verify we can recover the signer
        let recovered_address = signed_tx.recover_signer().unwrap();
        assert_eq!(recovered_address, account.address());
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use crate::accounts::Account;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Feature: quantaureum-rust-sdk, Property 2: Message Signature Round-Trip
        // For any Account and any message bytes, signing the message with sign_message()
        // and then recovering the signer address from the signature SHALL return the
        // account's address.
        // Validates: Requirements 2.4
        #[test]
        fn prop_message_signature_roundtrip(seed: [u8; 32], message: Vec<u8>) {
            // Skip invalid keys
            prop_assume!(seed.iter().any(|&b| b != 0));

            if let Ok(account) = Account::from_private_key(&seed) {
                let signature = sign_message(account.signing_key(), &message).unwrap();
                let message_hash = hash_message(&message);
                let recovered_address = signature.recover(&message_hash).unwrap();

                prop_assert_eq!(
                    recovered_address,
                    account.address(),
                    "Recovered address should match signer's address"
                );
            }
        }

        // Feature: quantaureum-rust-sdk, Property 2: Message Signature Round-Trip (hash variant)
        // For any Account and any hash, signing the hash with sign_hash()
        // and then recovering the signer address SHALL return the account's address.
        // Validates: Requirements 2.4
        #[test]
        fn prop_hash_signature_roundtrip(seed: [u8; 32], hash_input: [u8; 32]) {
            prop_assume!(seed.iter().any(|&b| b != 0));

            if let Ok(account) = Account::from_private_key(&seed) {
                let signature = sign_hash(account.signing_key(), &hash_input).unwrap();
                let recovered_address = signature.recover(&hash_input).unwrap();

                prop_assert_eq!(
                    recovered_address,
                    account.address(),
                    "Recovered address should match signer's address"
                );
            }
        }

        // Feature: quantaureum-rust-sdk, Property 2: Signature bytes round-trip
        // For any valid signature, converting to bytes and back should preserve the signature.
        // Validates: Requirements 2.4
        #[test]
        fn prop_signature_bytes_roundtrip(r: [u8; 32], s: [u8; 32], v in 27u8..=28u8) {
            let sig = Signature::new(r, s, v);
            let bytes = sig.to_bytes();
            let recovered = Signature::from_bytes(&bytes).unwrap();

            prop_assert_eq!(sig, recovered, "Signature should survive bytes roundtrip");
        }

        // Feature: quantaureum-rust-sdk, Property 2: Signature hex round-trip
        // For any valid signature, converting to hex and back should preserve the signature.
        // Validates: Requirements 2.4
        #[test]
        fn prop_signature_hex_roundtrip(r: [u8; 32], s: [u8; 32], v in 27u8..=28u8) {
            let sig = Signature::new(r, s, v);
            let hex = sig.to_hex();
            let recovered = Signature::from_hex(&hex).unwrap();

            prop_assert_eq!(sig, recovered, "Signature should survive hex roundtrip");
        }

        // Feature: quantaureum-rust-sdk, Property 4: Transaction Signing Validity
        // For any valid TransactionRequest and Account, signing the transaction with
        // sign_transaction() SHALL produce a SignedTransaction where the recovered
        // signer address matches the account's address.
        // Validates: Requirements 2.3
        #[test]
        fn prop_transaction_signing_validity(
            seed: [u8; 32],
            nonce: u64,
            gas in 21000u64..1000000u64,
            gas_price_gwei in 1u64..1000u64,
            value_wei in 0u64..1000000u64,
            chain_id in 1u64..100u64,
            to_bytes: [u8; 20]
        ) {
            use crate::types::{Address, TransactionRequest, U256};

            prop_assume!(seed.iter().any(|&b| b != 0));

            if let Ok(account) = Account::from_private_key(&seed) {
                let to = Address::from_bytes(to_bytes);
                let gas_price = U256::from(gas_price_gwei) * U256::from(1_000_000_000u64);

                let tx = TransactionRequest::new()
                    .to(to)
                    .value(U256::from(value_wei))
                    .gas(gas)
                    .gas_price(gas_price)
                    .nonce(nonce);

                let signed_tx = sign_transaction(account.signing_key(), &tx, chain_id).unwrap();

                // Verify transaction fields are preserved
                prop_assert_eq!(signed_tx.nonce, nonce);
                prop_assert_eq!(signed_tx.gas, gas);
                prop_assert_eq!(signed_tx.to, Some(to));
                prop_assert_eq!(signed_tx.value, U256::from(value_wei));

                // Verify we can recover the signer
                let recovered_address = signed_tx.recover_signer().unwrap();
                prop_assert_eq!(
                    recovered_address,
                    account.address(),
                    "Recovered address should match signer's address"
                );
            }
        }

        // Feature: quantaureum-rust-sdk, Property 4: Transaction Signing EIP-155 v value
        // For any signed transaction, the v value should follow EIP-155 format.
        // Validates: Requirements 2.3
        #[test]
        fn prop_transaction_signing_eip155_v(
            seed: [u8; 32],
            chain_id in 1u64..1000u64,
            to_bytes: [u8; 20]
        ) {
            use crate::types::{Address, TransactionRequest, U256};

            prop_assume!(seed.iter().any(|&b| b != 0));

            if let Ok(account) = Account::from_private_key(&seed) {
                let to = Address::from_bytes(to_bytes);

                let tx = TransactionRequest::new()
                    .to(to)
                    .value(U256::from(1000))
                    .gas(21000)
                    .gas_price(U256::from(20_000_000_000u64))
                    .nonce(0);

                let signed_tx = sign_transaction(account.signing_key(), &tx, chain_id).unwrap();

                // For EIP-155: v = chain_id * 2 + 35 + recovery_id (0 or 1)
                // So v should be chain_id * 2 + 35 or chain_id * 2 + 36
                let expected_v_low = chain_id * 2 + 35;
                let expected_v_high = chain_id * 2 + 36;

                prop_assert!(
                    signed_tx.v == expected_v_low || signed_tx.v == expected_v_high,
                    "v value {} should be {} or {} for chain_id {}",
                    signed_tx.v, expected_v_low, expected_v_high, chain_id
                );
            }
        }
    }
}
