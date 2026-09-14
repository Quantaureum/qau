// Quantaureum Rust SDK source, version 1.0.0.
//! Contract event handling.
//!
//! This module provides functionality for filtering and subscribing to
//! contract events (logs) on the Quantaureum blockchain.

use std::sync::Arc;

use crate::client::Provider;
use crate::contracts::abi::{AbiEvent, AbiEventParam, Detokenize, Token};
use crate::error::{Error, Result};
use crate::types::{Address, Filter, Log, H256};
use crate::utils::keccak256;

/// An event filter for querying contract events.
///
/// This struct provides a builder pattern for constructing event filters
/// and querying logs from the blockchain.
pub struct EventFilter<P: Provider> {
    /// The provider for blockchain interaction
    provider: Arc<P>,
    /// The base filter
    filter: Filter,
    /// The event ABI (optional, for decoding)
    event_abi: Option<AbiEvent>,
}

impl<P: Provider> EventFilter<P> {
    /// Creates a new event filter.
    pub fn new(provider: Arc<P>) -> Self {
        Self {
            provider,
            filter: Filter::new(),
            event_abi: None,
        }
    }

    /// Creates a new event filter with an event ABI for decoding.
    pub fn with_event(provider: Arc<P>, event: AbiEvent) -> Self {
        let topic = event.topic();
        let mut filter = Filter::new();
        if topic != H256::ZERO {
            filter = filter.topic(0, topic);
        }
        Self {
            provider,
            filter,
            event_abi: Some(event),
        }
    }

    /// Sets the contract address to filter.
    pub fn address(mut self, address: Address) -> Self {
        self.filter = self.filter.address(address);
        self
    }

    /// Sets multiple contract addresses to filter.
    pub fn addresses(mut self, addresses: Vec<Address>) -> Self {
        self.filter = self.filter.addresses(addresses);
        self
    }

    /// Sets the start block for the filter.
    pub fn from_block(mut self, block: u64) -> Self {
        self.filter = self.filter.from_block(block);
        self
    }

    /// Sets the end block for the filter.
    pub fn to_block(mut self, block: u64) -> Self {
        self.filter = self.filter.to_block(block);
        self
    }

    /// Adds a topic filter at the specified index.
    ///
    /// Index 0 is typically the event signature hash.
    /// Indices 1-3 are for indexed parameters.
    pub fn topic(mut self, index: usize, topic: H256) -> Self {
        self.filter = self.filter.topic(index, topic);
        self
    }

    /// Adds multiple topic filters at the specified index.
    pub fn topics_at(mut self, index: usize, topics: Vec<H256>) -> Self {
        self.filter = self.filter.topics_at(index, topics);
        self
    }

    /// Returns the underlying filter.
    pub fn filter(&self) -> &Filter {
        &self.filter
    }

    /// Queries logs matching this filter.
    ///
    /// Returns raw logs without decoding.
    pub async fn get_logs(&self) -> Result<Vec<Log>> {
        self.provider.get_logs(&self.filter).await
    }

    /// Queries and decodes logs matching this filter.
    ///
    /// Returns decoded event data if an event ABI was provided.
    pub async fn get_decoded_logs<T: Detokenize>(&self) -> Result<Vec<DecodedLog<T>>> {
        let logs = self.provider.get_logs(&self.filter).await?;
        let event = self
            .event_abi
            .as_ref()
            .ok_or_else(|| Error::Abi("no event ABI provided".to_string()))?;

        logs.into_iter()
            .map(|log| decode_log(&log, event))
            .collect()
    }
}

/// A decoded log entry.
#[derive(Debug, Clone)]
pub struct DecodedLog<T> {
    /// The raw log
    pub log: Log,
    /// The decoded event data
    pub data: T,
}

/// Decodes a log entry using the provided event ABI.
fn decode_log<T: Detokenize>(log: &Log, event: &AbiEvent) -> Result<DecodedLog<T>> {
    let mut tokens = Vec::new();
    let mut topic_index = 1; // Skip topic[0] which is the event signature
    let mut data_offset = 0;

    for input in &event.inputs {
        if input.indexed {
            // Indexed parameters are in topics
            if topic_index >= log.topics.len() {
                return Err(Error::Abi(
                    "not enough topics for indexed parameters".to_string(),
                ));
            }
            let token = decode_indexed_param(&log.topics[topic_index], input)?;
            tokens.push(token);
            topic_index += 1;
        } else {
            // Non-indexed parameters are in data
            let (token, consumed) = decode_data_param(&log.data, data_offset, input)?;
            tokens.push(token);
            data_offset += consumed;
        }
    }

    let data = T::from_tokens(tokens)?;
    Ok(DecodedLog {
        log: log.clone(),
        data,
    })
}

/// Decodes an indexed parameter from a topic.
fn decode_indexed_param(topic: &H256, param: &AbiEventParam) -> Result<Token> {
    let type_str = &param.param_type;

    if type_str == "address" {
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&topic.as_bytes()[12..]);
        Ok(Token::Address(Address::from_bytes(bytes)))
    } else if type_str.starts_with("uint") || type_str.starts_with("int") {
        let value = primitive_types::U256::from_big_endian(topic.as_bytes());
        if type_str.starts_with("uint") {
            Ok(Token::Uint(value))
        } else {
            Ok(Token::Int(value))
        }
    } else if type_str == "bool" {
        let b = topic.as_bytes()[31] != 0;
        Ok(Token::Bool(b))
    } else if type_str.starts_with("bytes") && type_str.len() <= 7 {
        // Fixed bytes (bytes1 to bytes32)
        let size: usize = type_str[5..].parse().unwrap_or(32);
        Ok(Token::FixedBytes(topic.as_bytes()[..size].to_vec()))
    } else {
        // For dynamic types (string, bytes, arrays), the topic contains the hash
        // We can't decode the actual value, so return the hash as bytes
        Ok(Token::FixedBytes(topic.as_bytes().to_vec()))
    }
}

/// Decodes a non-indexed parameter from the data field.
fn decode_data_param(data: &[u8], offset: usize, param: &AbiEventParam) -> Result<(Token, usize)> {
    let type_str = &param.param_type;

    if type_str == "address" {
        if offset + 32 > data.len() {
            return Err(Error::Abi("insufficient data for address".to_string()));
        }
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&data[offset + 12..offset + 32]);
        Ok((Token::Address(Address::from_bytes(bytes)), 32))
    } else if type_str.starts_with("uint") {
        if offset + 32 > data.len() {
            return Err(Error::Abi("insufficient data for uint".to_string()));
        }
        let value = primitive_types::U256::from_big_endian(&data[offset..offset + 32]);
        Ok((Token::Uint(value), 32))
    } else if type_str.starts_with("int") {
        if offset + 32 > data.len() {
            return Err(Error::Abi("insufficient data for int".to_string()));
        }
        let value = primitive_types::U256::from_big_endian(&data[offset..offset + 32]);
        Ok((Token::Int(value), 32))
    } else if type_str == "bool" {
        if offset + 32 > data.len() {
            return Err(Error::Abi("insufficient data for bool".to_string()));
        }
        let b = data[offset + 31] != 0;
        Ok((Token::Bool(b), 32))
    } else if type_str.starts_with("bytes") && type_str.len() > 5 && !type_str.ends_with("[]") {
        // Fixed bytes (bytes1 to bytes32)
        let size: usize = type_str[5..]
            .parse()
            .map_err(|_| Error::Abi(format!("invalid fixed bytes type: {}", type_str)))?;
        if offset + 32 > data.len() {
            return Err(Error::Abi("insufficient data for fixed bytes".to_string()));
        }
        Ok((Token::FixedBytes(data[offset..offset + size].to_vec()), 32))
    } else if type_str == "bytes" {
        // Dynamic bytes
        if offset + 32 > data.len() {
            return Err(Error::Abi("insufficient data for bytes offset".to_string()));
        }
        let data_offset =
            primitive_types::U256::from_big_endian(&data[offset..offset + 32]).as_usize();
        if data_offset + 32 > data.len() {
            return Err(Error::Abi("insufficient data for bytes length".to_string()));
        }
        let length =
            primitive_types::U256::from_big_endian(&data[data_offset..data_offset + 32]).as_usize();
        if data_offset + 32 + length > data.len() {
            return Err(Error::Abi(
                "insufficient data for bytes content".to_string(),
            ));
        }
        let bytes = data[data_offset + 32..data_offset + 32 + length].to_vec();
        Ok((Token::Bytes(bytes), 32))
    } else if type_str == "string" {
        // Dynamic string
        if offset + 32 > data.len() {
            return Err(Error::Abi(
                "insufficient data for string offset".to_string(),
            ));
        }
        let data_offset =
            primitive_types::U256::from_big_endian(&data[offset..offset + 32]).as_usize();
        if data_offset + 32 > data.len() {
            return Err(Error::Abi(
                "insufficient data for string length".to_string(),
            ));
        }
        let length =
            primitive_types::U256::from_big_endian(&data[data_offset..data_offset + 32]).as_usize();
        if data_offset + 32 + length > data.len() {
            return Err(Error::Abi(
                "insufficient data for string content".to_string(),
            ));
        }
        let bytes = data[data_offset + 32..data_offset + 32 + length].to_vec();
        let s =
            String::from_utf8(bytes).map_err(|e| Error::Abi(format!("invalid UTF-8: {}", e)))?;
        Ok((Token::String(s), 32))
    } else {
        Err(Error::Abi(format!("unsupported type: {}", type_str)))
    }
}

/// Computes the event topic hash from an event signature.
///
/// # Arguments
///
/// * `signature` - The event signature (e.g., "Transfer(address,address,uint256)")
pub fn event_topic(signature: &str) -> H256 {
    H256::from_bytes(keccak256(signature.as_bytes()))
}

/// Helper function to create a filter for a specific event.
///
/// # Arguments
///
/// * `provider` - The provider for blockchain interaction
/// * `address` - The contract address
/// * `event_signature` - The event signature (e.g., "Transfer(address,address,uint256)")
pub fn filter_for_event<P: Provider>(
    provider: Arc<P>,
    address: Address,
    event_signature: &str,
) -> EventFilter<P> {
    let topic = event_topic(event_signature);
    EventFilter::new(provider).address(address).topic(0, topic)
}

/// Extension trait for Contract to add event filtering capabilities.
pub trait ContractEvents<P: Provider> {
    /// Creates an event filter for the specified event.
    fn event_filter(&self, event_name: &str) -> Result<EventFilter<P>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_topic() {
        // Transfer(address,address,uint256) topic
        let topic = event_topic("Transfer(address,address,uint256)");
        // Known keccak256 hash of "Transfer(address,address,uint256)"
        assert_eq!(
            topic.to_hex(),
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        );
    }

    #[test]
    fn test_approval_event_topic() {
        // Approval(address,address,uint256) topic
        let topic = event_topic("Approval(address,address,uint256)");
        // Known keccak256 hash
        assert_eq!(
            topic.to_hex(),
            "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
        );
    }

    #[test]
    fn test_decode_indexed_address() {
        let topic =
            H256::from_hex("0x0000000000000000000000001234567890123456789012345678901234567890")
                .unwrap();
        let param = AbiEventParam {
            name: "from".to_string(),
            param_type: "address".to_string(),
            indexed: true,
            components: vec![],
        };

        let token = decode_indexed_param(&topic, &param).unwrap();
        if let Token::Address(addr) = token {
            assert_eq!(addr.to_hex(), "0x1234567890123456789012345678901234567890");
        } else {
            panic!("expected Address token");
        }
    }

    #[test]
    fn test_decode_indexed_uint() {
        let topic =
            H256::from_hex("0x00000000000000000000000000000000000000000000000000000000000003e8")
                .unwrap();
        let param = AbiEventParam {
            name: "value".to_string(),
            param_type: "uint256".to_string(),
            indexed: true,
            components: vec![],
        };

        let token = decode_indexed_param(&topic, &param).unwrap();
        if let Token::Uint(v) = token {
            assert_eq!(v, primitive_types::U256::from(1000));
        } else {
            panic!("expected Uint token");
        }
    }

    #[test]
    fn test_decode_indexed_bool() {
        let topic =
            H256::from_hex("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        let param = AbiEventParam {
            name: "approved".to_string(),
            param_type: "bool".to_string(),
            indexed: true,
            components: vec![],
        };

        let token = decode_indexed_param(&topic, &param).unwrap();
        if let Token::Bool(b) = token {
            assert!(b);
        } else {
            panic!("expected Bool token");
        }
    }
}
