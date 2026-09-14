// Quantaureum Rust SDK source, version 1.0.0.
//! Block type definitions.
//!
//! This module provides block-related types for querying blockchain data.

use serde::{Deserialize, Serialize};

use crate::types::{Address, H256};

/// A block in the blockchain.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    /// Block number (height)
    pub number: u64,
    /// Block hash
    pub hash: H256,
    /// Parent block hash
    pub parent_hash: H256,
    /// Block timestamp (Unix timestamp)
    pub timestamp: u64,
    /// Transaction hashes in this block
    pub transactions: Vec<H256>,
    /// Gas limit for this block
    pub gas_limit: u64,
    /// Total gas used by all transactions in this block
    pub gas_used: u64,
    /// Address of the block producer/miner
    pub miner: Address,
    /// State root hash (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_root: Option<H256>,
    /// Transactions root hash (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transactions_root: Option<H256>,
    /// Receipts root hash (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipts_root: Option<H256>,
    /// Block nonce (optional, for PoW chains)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    /// Block difficulty (optional, for PoW chains)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub difficulty: Option<u64>,
    /// Extra data (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_data: Option<Vec<u8>>,
}

impl Block {
    /// Returns true if this is the genesis block (block 0).
    pub fn is_genesis(&self) -> bool {
        self.number == 0
    }

    /// Returns the number of transactions in this block.
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
}

/// A block with full transaction details.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockWithTransactions {
    /// Block number (height)
    pub number: u64,
    /// Block hash
    pub hash: H256,
    /// Parent block hash
    pub parent_hash: H256,
    /// Block timestamp (Unix timestamp)
    pub timestamp: u64,
    /// Full transaction details
    pub transactions: Vec<Transaction>,
    /// Gas limit for this block
    pub gas_limit: u64,
    /// Total gas used by all transactions in this block
    pub gas_used: u64,
    /// Address of the block producer/miner
    pub miner: Address,
}

/// A transaction as returned from the node.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction hash
    pub hash: H256,
    /// Sender address
    pub from: Address,
    /// Recipient address (None for contract creation)
    pub to: Option<Address>,
    /// Value transferred in wei
    pub value: crate::types::U256,
    /// Gas limit
    pub gas: u64,
    /// Gas price in wei
    pub gas_price: crate::types::U256,
    /// Transaction data
    pub input: Vec<u8>,
    /// Transaction nonce
    pub nonce: u64,
    /// Block hash (None if pending)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<H256>,
    /// Block number (None if pending)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    /// Transaction index in block (None if pending)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_index: Option<u64>,
    /// Signature v value
    pub v: u64,
    /// Signature r value
    pub r: crate::types::U256,
    /// Signature s value
    pub s: crate::types::U256,
}

impl Transaction {
    /// Returns true if this transaction is pending (not yet mined).
    pub fn is_pending(&self) -> bool {
        self.block_hash.is_none()
    }

    /// Returns true if this is a contract creation transaction.
    pub fn is_contract_creation(&self) -> bool {
        self.to.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_is_genesis() {
        let block = Block {
            number: 0,
            hash: H256::ZERO,
            parent_hash: H256::ZERO,
            timestamp: 0,
            transactions: vec![],
            gas_limit: 0,
            gas_used: 0,
            miner: Address::ZERO,
            state_root: None,
            transactions_root: None,
            receipts_root: None,
            nonce: None,
            difficulty: None,
            extra_data: None,
        };
        assert!(block.is_genesis());

        let block2 = Block { number: 1, ..block };
        assert!(!block2.is_genesis());
    }

    #[test]
    fn test_block_transaction_count() {
        let block = Block {
            number: 100,
            hash: H256::ZERO,
            parent_hash: H256::ZERO,
            timestamp: 1234567890,
            transactions: vec![H256::ZERO, H256::ZERO, H256::ZERO],
            gas_limit: 8_000_000,
            gas_used: 21000,
            miner: Address::ZERO,
            state_root: None,
            transactions_root: None,
            receipts_root: None,
            nonce: None,
            difficulty: None,
            extra_data: None,
        };
        assert_eq!(block.transaction_count(), 3);
    }

    #[test]
    fn test_transaction_is_pending() {
        let tx = Transaction {
            hash: H256::ZERO,
            from: Address::ZERO,
            to: Some(Address::ZERO),
            value: crate::types::U256::zero(),
            gas: 21000,
            gas_price: crate::types::U256::from(20_000_000_000u64),
            input: vec![],
            nonce: 0,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            v: 27,
            r: crate::types::U256::zero(),
            s: crate::types::U256::zero(),
        };
        assert!(tx.is_pending());

        let mined_tx = Transaction {
            block_hash: Some(H256::ZERO),
            block_number: Some(100),
            transaction_index: Some(0),
            ..tx
        };
        assert!(!mined_tx.is_pending());
    }

    #[test]
    fn test_transaction_is_contract_creation() {
        let tx = Transaction {
            hash: H256::ZERO,
            from: Address::ZERO,
            to: None,
            value: crate::types::U256::zero(),
            gas: 100000,
            gas_price: crate::types::U256::from(20_000_000_000u64),
            input: vec![0x60, 0x80, 0x60, 0x40], // Sample bytecode
            nonce: 0,
            block_hash: None,
            block_number: None,
            transaction_index: None,
            v: 27,
            r: crate::types::U256::zero(),
            s: crate::types::U256::zero(),
        };
        assert!(tx.is_contract_creation());

        let transfer_tx = Transaction {
            to: Some(Address::ZERO),
            ..tx
        };
        assert!(!transfer_tx.is_contract_creation());
    }
}
