// Quantaureum Rust SDK source, version 1.0.0.
//! Transaction type definitions.
//!
//! This module provides transaction-related types for creating, signing,
//! and sending transactions.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::{Address, H256, U256};
use crate::utils::keccak256;

/// A transaction request for building unsigned transactions.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TransactionRequest {
    /// The sender address (optional, derived from signer)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,
    /// The recipient address (None for contract creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    /// Gas limit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<u64>,
    /// Gas price in wei
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<U256>,
    /// Value to transfer in wei
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<U256>,
    /// Transaction data (contract call data or contract bytecode)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
    /// Transaction nonce
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
}

impl TransactionRequest {
    /// Creates a new empty transaction request.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the recipient address.
    pub fn to(mut self, to: Address) -> Self {
        self.to = Some(to);
        self
    }

    /// Sets the value to transfer.
    pub fn value(mut self, value: U256) -> Self {
        self.value = Some(value);
        self
    }

    /// Sets the gas limit.
    pub fn gas(mut self, gas: u64) -> Self {
        self.gas = Some(gas);
        self
    }

    /// Sets the gas price.
    pub fn gas_price(mut self, gas_price: U256) -> Self {
        self.gas_price = Some(gas_price);
        self
    }

    /// Sets the transaction data.
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }

    /// Sets the nonce.
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Sets the sender address.
    pub fn from(mut self, from: Address) -> Self {
        self.from = Some(from);
        self
    }
}

/// A signed transaction ready for broadcast.
#[derive(Clone, Debug)]
pub struct SignedTransaction {
    /// Transaction nonce
    pub nonce: u64,
    /// Gas price in wei
    pub gas_price: U256,
    /// Gas limit
    pub gas: u64,
    /// Recipient address (None for contract creation)
    pub to: Option<Address>,
    /// Value to transfer in wei
    pub value: U256,
    /// Transaction data
    pub data: Vec<u8>,
    /// Signature v value (includes chain_id for EIP-155)
    pub v: u64,
    /// Signature r value
    pub r: U256,
    /// Signature s value
    pub s: U256,
}

impl SignedTransaction {
    /// RLP encodes the signed transaction for broadcast.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new_list(9);

        stream.append(&self.nonce);
        stream.append(&u256_to_bytes(&self.gas_price));
        stream.append(&self.gas);

        // Encode 'to' field - empty for contract creation
        if let Some(to) = &self.to {
            stream.append(&to.as_bytes().as_slice());
        } else {
            stream.append_empty_data();
        }

        stream.append(&u256_to_bytes(&self.value));
        stream.append(&self.data.as_slice());
        stream.append(&self.v);
        stream.append(&u256_to_bytes(&self.r));
        stream.append(&u256_to_bytes(&self.s));

        stream.out().to_vec()
    }

    /// Computes the transaction hash.
    pub fn hash(&self) -> H256 {
        let encoded = self.rlp_encode();
        H256::from_bytes(keccak256(&encoded))
    }

    /// Recovers the signer's address from the signed transaction.
    pub fn recover_signer(&self) -> Result<Address> {
        use k256::ecdsa::{RecoveryId, VerifyingKey};

        // Reconstruct the unsigned transaction hash
        let unsigned_hash = self.unsigned_hash()?;

        // Extract signature components
        let mut r_bytes = [0u8; 32];
        let mut s_bytes = [0u8; 32];

        let r_arr = u256_to_bytes(&self.r);
        let s_arr = u256_to_bytes(&self.s);

        // Pad to 32 bytes
        let r_start = 32 - r_arr.len();
        let s_start = 32 - s_arr.len();
        r_bytes[r_start..].copy_from_slice(&r_arr);
        s_bytes[s_start..].copy_from_slice(&s_arr);

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&r_bytes);
        sig_bytes[32..].copy_from_slice(&s_bytes);

        let signature = k256::ecdsa::Signature::from_slice(&sig_bytes)
            .map_err(|e| Error::Signing(format!("invalid signature: {}", e)))?;

        // Calculate recovery ID from v
        // For EIP-155: v = chain_id * 2 + 35 + recovery_id
        // For legacy: v = 27 + recovery_id
        let recovery_id = if self.v >= 35 {
            // EIP-155 transaction
            let chain_id = (self.v - 35) / 2;
            let recovery_byte = (self.v - 35 - chain_id * 2) as u8;
            RecoveryId::try_from(recovery_byte)
        } else {
            // Legacy transaction
            RecoveryId::try_from((self.v - 27) as u8)
        }
        .map_err(|e| Error::Signing(format!("invalid recovery id: {}", e)))?;

        // Recover the verifying key
        let verifying_key =
            VerifyingKey::recover_from_prehash(unsigned_hash.as_bytes(), &signature, recovery_id)
                .map_err(|e| Error::Signing(format!("recovery failed: {}", e)))?;

        // Derive address from verifying key
        let public_key = verifying_key.to_encoded_point(false);
        let public_key_bytes = public_key.as_bytes();
        let hash = keccak256(&public_key_bytes[1..]);

        let mut address_bytes = [0u8; 20];
        address_bytes.copy_from_slice(&hash[12..]);

        Ok(Address::from_bytes(address_bytes))
    }

    /// Computes the hash of the unsigned transaction (for signing).
    fn unsigned_hash(&self) -> Result<H256> {
        // For EIP-155, we need to include chain_id in the unsigned hash
        let chain_id = if self.v >= 35 {
            Some((self.v - 35) / 2)
        } else {
            None
        };

        let encoded = if let Some(chain_id) = chain_id {
            // EIP-155 encoding: [nonce, gasPrice, gas, to, value, data, chainId, 0, 0]
            let mut stream = rlp::RlpStream::new_list(9);
            stream.append(&self.nonce);
            stream.append(&u256_to_bytes(&self.gas_price));
            stream.append(&self.gas);

            if let Some(to) = &self.to {
                stream.append(&to.as_bytes().as_slice());
            } else {
                stream.append_empty_data();
            }

            stream.append(&u256_to_bytes(&self.value));
            stream.append(&self.data.as_slice());
            stream.append(&chain_id);
            stream.append(&0u8);
            stream.append(&0u8);
            stream.out().to_vec()
        } else {
            // Legacy encoding: [nonce, gasPrice, gas, to, value, data]
            let mut stream = rlp::RlpStream::new_list(6);
            stream.append(&self.nonce);
            stream.append(&u256_to_bytes(&self.gas_price));
            stream.append(&self.gas);

            if let Some(to) = &self.to {
                stream.append(&to.as_bytes().as_slice());
            } else {
                stream.append_empty_data();
            }

            stream.append(&u256_to_bytes(&self.value));
            stream.append(&self.data.as_slice());
            stream.out().to_vec()
        };

        Ok(H256::from_bytes(keccak256(&encoded)))
    }
}

/// Converts U256 to bytes, removing leading zeros.
fn u256_to_bytes(value: &U256) -> Vec<u8> {
    if value.is_zero() {
        return vec![];
    }

    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes);

    // Find first non-zero byte
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(32);
    bytes[start..].to_vec()
}

/// Transaction receipt returned after a transaction is mined.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Transaction hash
    pub transaction_hash: H256,
    /// Block hash
    pub block_hash: H256,
    /// Block number
    pub block_number: u64,
    /// Transaction index in the block
    pub transaction_index: u64,
    /// Sender address
    pub from: Address,
    /// Recipient address (None for contract creation)
    pub to: Option<Address>,
    /// Gas used by this transaction
    pub gas_used: u64,
    /// Cumulative gas used in the block up to this transaction
    pub cumulative_gas_used: u64,
    /// Contract address created (if contract creation)
    pub contract_address: Option<Address>,
    /// Logs emitted by this transaction
    pub logs: Vec<Log>,
    /// Transaction status (1 = success, 0 = failure)
    pub status: u64,
}

/// A log entry emitted by a transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Log {
    /// Contract address that emitted the log
    pub address: Address,
    /// Log topics (indexed parameters)
    pub topics: Vec<H256>,
    /// Log data (non-indexed parameters)
    pub data: Vec<u8>,
    /// Block number
    pub block_number: u64,
    /// Transaction hash
    pub transaction_hash: H256,
    /// Transaction index in the block
    pub transaction_index: u64,
    /// Block hash
    pub block_hash: H256,
    /// Log index in the block
    pub log_index: u64,
}

/// A call request for executing read-only calls.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CallRequest {
    /// The sender address (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,
    /// The recipient address
    pub to: Address,
    /// Gas limit (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<u64>,
    /// Gas price in wei (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<U256>,
    /// Value to transfer in wei (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<U256>,
    /// Call data (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Vec<u8>>,
}

impl CallRequest {
    /// Creates a new call request to the specified address.
    pub fn new(to: Address) -> Self {
        Self {
            to,
            ..Default::default()
        }
    }

    /// Sets the sender address.
    pub fn from(mut self, from: Address) -> Self {
        self.from = Some(from);
        self
    }

    /// Sets the gas limit.
    pub fn gas(mut self, gas: u64) -> Self {
        self.gas = Some(gas);
        self
    }

    /// Sets the gas price.
    pub fn gas_price(mut self, gas_price: U256) -> Self {
        self.gas_price = Some(gas_price);
        self
    }

    /// Sets the value to transfer.
    pub fn value(mut self, value: U256) -> Self {
        self.value = Some(value);
        self
    }

    /// Sets the call data.
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = Some(data);
        self
    }
}

/// A log filter for querying logs.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Filter {
    /// Start block number (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_block: Option<u64>,
    /// End block number (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_block: Option<u64>,
    /// Contract addresses to filter (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<Vec<Address>>,
    /// Topics to filter (optional)
    #[serde(default)]
    pub topics: Vec<Option<Vec<H256>>>,
}

impl Filter {
    /// Creates a new empty filter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the start block number.
    pub fn from_block(mut self, block: u64) -> Self {
        self.from_block = Some(block);
        self
    }

    /// Sets the end block number.
    pub fn to_block(mut self, block: u64) -> Self {
        self.to_block = Some(block);
        self
    }

    /// Sets a single address to filter.
    pub fn address(mut self, address: Address) -> Self {
        self.address = Some(vec![address]);
        self
    }

    /// Sets multiple addresses to filter.
    pub fn addresses(mut self, addresses: Vec<Address>) -> Self {
        self.address = Some(addresses);
        self
    }

    /// Adds a topic filter at the specified index.
    pub fn topic(mut self, index: usize, topic: H256) -> Self {
        while self.topics.len() <= index {
            self.topics.push(None);
        }
        self.topics[index] = Some(vec![topic]);
        self
    }

    /// Adds multiple topic filters at the specified index.
    pub fn topics_at(mut self, index: usize, topics: Vec<H256>) -> Self {
        while self.topics.len() <= index {
            self.topics.push(None);
        }
        self.topics[index] = Some(topics);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_request_builder() {
        let to = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();
        let tx = TransactionRequest::new()
            .to(to)
            .value(U256::from(1000))
            .gas(21000)
            .gas_price(U256::from(20_000_000_000u64))
            .nonce(0);

        assert_eq!(tx.to, Some(to));
        assert_eq!(tx.value, Some(U256::from(1000)));
        assert_eq!(tx.gas, Some(21000));
        assert_eq!(tx.nonce, Some(0));
    }

    #[test]
    fn test_signed_transaction_hash() {
        let tx = SignedTransaction {
            nonce: 0,
            gas_price: U256::from(20_000_000_000u64),
            gas: 21000,
            to: Some(Address::from_hex("0x1234567890123456789012345678901234567890").unwrap()),
            value: U256::from(1000),
            data: vec![],
            v: 27,
            r: U256::from(1),
            s: U256::from(2),
        };

        let hash = tx.hash();
        assert_eq!(hash.as_bytes().len(), 32);
    }

    #[test]
    fn test_signed_transaction_rlp_encode() {
        let tx = SignedTransaction {
            nonce: 0,
            gas_price: U256::from(20_000_000_000u64),
            gas: 21000,
            to: Some(Address::from_hex("0x1234567890123456789012345678901234567890").unwrap()),
            value: U256::from(1000),
            data: vec![],
            v: 27,
            r: U256::from(1),
            s: U256::from(2),
        };

        let encoded = tx.rlp_encode();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_u256_to_bytes() {
        let empty: Vec<u8> = vec![];
        assert_eq!(u256_to_bytes(&U256::zero()), empty);
        assert_eq!(u256_to_bytes(&U256::from(1)), vec![1u8]);
        assert_eq!(u256_to_bytes(&U256::from(256)), vec![1u8, 0u8]);
        assert_eq!(u256_to_bytes(&U256::from(0xff)), vec![0xffu8]);
    }
}
