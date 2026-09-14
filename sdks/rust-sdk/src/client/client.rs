// Quantaureum Rust SDK source, version 1.0.0.
//! Client implementation for Quantaureum node communication.
//!
//! This module provides the `Client` struct for interacting with
//! Quantaureum blockchain nodes via JSON-RPC.

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{json, Value};

use super::rpc::{parse, RpcTransport};
use crate::error::{Error, Result};
use crate::types::{
    Address, Block, CallRequest, Filter, Log, Transaction, TransactionReceipt, H256, U256,
};

/// Client configuration options.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Request timeout duration
    pub timeout: Duration,
    /// Maximum number of retries for failed requests
    pub max_retries: u32,
    /// Whether to automatically fetch chain ID on connection
    pub auto_chain_id: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_retries: 3,
            auto_chain_id: true,
        }
    }
}

/// Provider trait defining the interface for blockchain node interaction.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Gets the current block number.
    async fn block_number(&self) -> Result<u64>;

    /// Gets a block by number.
    async fn block_by_number(&self, number: Option<u64>) -> Result<Option<Block>>;

    /// Gets a block by hash.
    async fn block_by_hash(&self, hash: H256) -> Result<Option<Block>>;

    /// Gets a transaction by hash.
    async fn transaction_by_hash(&self, hash: H256) -> Result<Option<Transaction>>;

    /// Gets a transaction receipt.
    async fn transaction_receipt(&self, hash: H256) -> Result<Option<TransactionReceipt>>;

    /// Gets the balance of an address at a specific block.
    async fn balance_at(&self, address: Address, block: Option<u64>) -> Result<U256>;

    /// Gets the nonce of an address at a specific block.
    async fn nonce_at(&self, address: Address, block: Option<u64>) -> Result<u64>;

    /// Gets the pending nonce of an address.
    async fn pending_nonce_at(&self, address: Address) -> Result<u64>;

    /// Gets the code at an address.
    async fn code_at(&self, address: Address, block: Option<u64>) -> Result<Vec<u8>>;

    /// Gets the suggested gas price.
    async fn suggest_gas_price(&self) -> Result<U256>;

    /// Estimates gas for a call.
    async fn estimate_gas(&self, msg: &CallRequest) -> Result<u64>;

    /// Sends a raw signed transaction.
    async fn send_raw_transaction(&self, tx: &[u8]) -> Result<H256>;

    /// Executes a call without sending a transaction.
    async fn call(&self, msg: &CallRequest, block: Option<u64>) -> Result<Vec<u8>>;

    /// Gets logs matching a filter.
    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>>;

    /// Gets the chain ID.
    async fn chain_id(&self) -> Result<u64>;
}

/// HTTP/WebSocket client for Quantaureum node communication.
#[derive(Debug, Clone)]
pub struct Client {
    /// RPC transport
    transport: RpcTransport,
    /// Cached chain ID
    chain_id_cache: Option<u64>,
}

impl Client {
    /// Creates a new client connected to the specified URL.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL of the Quantaureum node (e.g., "http://localhost:8545")
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use quantaureum_sdk::Client;
    ///
    /// #[tokio::main]
    /// async fn main() -> quantaureum_sdk::Result<()> {
    ///     let client = Client::new("http://localhost:8545").await?;
    ///     let block_number = client.block_number().await?;
    ///     println!("Current block: {}", block_number);
    ///     Ok(())
    /// }
    /// ```
    pub async fn new(url: &str) -> Result<Self> {
        Self::with_config(url, ClientConfig::default()).await
    }

    /// Creates a new client with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `url` - The URL of the Quantaureum node
    /// * `config` - Client configuration options
    ///
    /// # Errors
    ///
    /// Returns `Error::Validation` if the URL is empty or has an invalid format.
    /// Returns `Error::Connection` if the HTTP client cannot be created.
    pub async fn with_config(url: &str, config: ClientConfig) -> Result<Self> {
        // Validate URL
        crate::utils::validation::validate_url(url, "url")?;

        let http_client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| Error::Connection(format!("Failed to create HTTP client: {}", e)))?;

        let transport = RpcTransport::with_client(url, http_client);

        let mut client = Self {
            transport,
            chain_id_cache: None,
        };

        // Optionally fetch and cache chain ID
        if config.auto_chain_id {
            match client.fetch_chain_id().await {
                Ok(chain_id) => client.chain_id_cache = Some(chain_id),
                Err(_) => {
                    // Ignore error - chain ID will be fetched on demand
                }
            }
        }

        Ok(client)
    }

    /// Returns the URL of the connected node.
    pub fn url(&self) -> &str {
        self.transport.url()
    }

    /// Fetches the chain ID from the node.
    async fn fetch_chain_id(&self) -> Result<u64> {
        let result: String = self.transport.call("eth_chainId", json!([])).await?;
        parse::hex_to_u64(&result)
    }

    /// Converts a block number to the appropriate RPC parameter.
    fn block_param(block: Option<u64>) -> Value {
        match block {
            Some(n) => json!(parse::u64_to_hex(n)),
            None => json!("latest"),
        }
    }
}

#[async_trait]
impl Provider for Client {
    async fn block_number(&self) -> Result<u64> {
        let result: String = self.transport.call("eth_blockNumber", json!([])).await?;
        parse::hex_to_u64(&result)
    }

    async fn block_by_number(&self, number: Option<u64>) -> Result<Option<Block>> {
        let block_param = Self::block_param(number);
        let result: Option<RpcBlock> = self
            .transport
            .call_optional("eth_getBlockByNumber", json!([block_param, false]))
            .await?;
        Ok(result.map(|b| b.into()))
    }

    async fn block_by_hash(&self, hash: H256) -> Result<Option<Block>> {
        let result: Option<RpcBlock> = self
            .transport
            .call_optional("eth_getBlockByHash", json!([hash.to_hex(), false]))
            .await?;
        Ok(result.map(|b| b.into()))
    }

    async fn transaction_by_hash(&self, hash: H256) -> Result<Option<Transaction>> {
        let result: Option<RpcTransaction> = self
            .transport
            .call_optional("eth_getTransactionByHash", json!([hash.to_hex()]))
            .await?;
        result.map(|t| t.try_into()).transpose()
    }

    async fn transaction_receipt(&self, hash: H256) -> Result<Option<TransactionReceipt>> {
        let result: Option<RpcTransactionReceipt> = self
            .transport
            .call_optional("eth_getTransactionReceipt", json!([hash.to_hex()]))
            .await?;
        result.map(|r| r.try_into()).transpose()
    }

    async fn balance_at(&self, address: Address, block: Option<u64>) -> Result<U256> {
        let block_param = Self::block_param(block);
        let result: String = self
            .transport
            .call("eth_getBalance", json!([address.to_hex(), block_param]))
            .await?;
        parse::hex_to_u256(&result)
    }

    async fn nonce_at(&self, address: Address, block: Option<u64>) -> Result<u64> {
        let block_param = Self::block_param(block);
        let result: String = self
            .transport
            .call(
                "eth_getTransactionCount",
                json!([address.to_hex(), block_param]),
            )
            .await?;
        parse::hex_to_u64(&result)
    }

    async fn pending_nonce_at(&self, address: Address) -> Result<u64> {
        let result: String = self
            .transport
            .call(
                "eth_getTransactionCount",
                json!([address.to_hex(), "pending"]),
            )
            .await?;
        parse::hex_to_u64(&result)
    }

    async fn code_at(&self, address: Address, block: Option<u64>) -> Result<Vec<u8>> {
        let block_param = Self::block_param(block);
        let result: String = self
            .transport
            .call("eth_getCode", json!([address.to_hex(), block_param]))
            .await?;
        parse::hex_to_bytes(&result)
    }

    async fn suggest_gas_price(&self) -> Result<U256> {
        let result: String = self.transport.call("eth_gasPrice", json!([])).await?;
        parse::hex_to_u256(&result)
    }

    async fn estimate_gas(&self, msg: &CallRequest) -> Result<u64> {
        let call_obj = build_call_object(msg);
        let result: String = self
            .transport
            .call("eth_estimateGas", json!([call_obj]))
            .await?;
        parse::hex_to_u64(&result)
    }

    async fn send_raw_transaction(&self, tx: &[u8]) -> Result<H256> {
        let tx_hex = parse::bytes_to_hex(tx);
        let result: String = self
            .transport
            .call("eth_sendRawTransaction", json!([tx_hex]))
            .await?;
        H256::from_hex(&result)
    }

    async fn call(&self, msg: &CallRequest, block: Option<u64>) -> Result<Vec<u8>> {
        let block_param = Self::block_param(block);
        let call_obj = build_call_object(msg);
        let result: String = self
            .transport
            .call("eth_call", json!([call_obj, block_param]))
            .await?;
        parse::hex_to_bytes(&result)
    }

    async fn get_logs(&self, filter: &Filter) -> Result<Vec<Log>> {
        let filter_obj = build_filter_object(filter);
        let result: Vec<RpcLog> = self
            .transport
            .call("eth_getLogs", json!([filter_obj]))
            .await?;
        result.into_iter().map(|l| l.try_into()).collect()
    }

    async fn chain_id(&self) -> Result<u64> {
        if let Some(chain_id) = self.chain_id_cache {
            return Ok(chain_id);
        }
        self.fetch_chain_id().await
    }
}

/// Builds a JSON object for eth_call/eth_estimateGas.
fn build_call_object(msg: &CallRequest) -> Value {
    let mut obj = serde_json::Map::new();

    if let Some(from) = &msg.from {
        obj.insert("from".to_string(), json!(from.to_hex()));
    }
    obj.insert("to".to_string(), json!(msg.to.to_hex()));

    if let Some(gas) = msg.gas {
        obj.insert("gas".to_string(), json!(parse::u64_to_hex(gas)));
    }
    if let Some(gas_price) = &msg.gas_price {
        obj.insert("gasPrice".to_string(), json!(parse::u256_to_hex(gas_price)));
    }
    if let Some(value) = &msg.value {
        obj.insert("value".to_string(), json!(parse::u256_to_hex(value)));
    }
    if let Some(data) = &msg.data {
        obj.insert("data".to_string(), json!(parse::bytes_to_hex(data)));
    }

    Value::Object(obj)
}

/// Builds a JSON object for eth_getLogs.
fn build_filter_object(filter: &Filter) -> Value {
    let mut obj = serde_json::Map::new();

    if let Some(from_block) = filter.from_block {
        obj.insert(
            "fromBlock".to_string(),
            json!(parse::u64_to_hex(from_block)),
        );
    }
    if let Some(to_block) = filter.to_block {
        obj.insert("toBlock".to_string(), json!(parse::u64_to_hex(to_block)));
    }
    if let Some(addresses) = &filter.address {
        let addrs: Vec<String> = addresses.iter().map(|a| a.to_hex()).collect();
        if addrs.len() == 1 {
            obj.insert("address".to_string(), json!(addrs[0]));
        } else {
            obj.insert("address".to_string(), json!(addrs));
        }
    }
    if !filter.topics.is_empty() {
        let topics: Vec<Value> = filter
            .topics
            .iter()
            .map(|t| match t {
                Some(hashes) => {
                    let h: Vec<String> = hashes.iter().map(|h| h.to_hex()).collect();
                    if h.len() == 1 {
                        json!(h[0])
                    } else {
                        json!(h)
                    }
                }
                None => Value::Null,
            })
            .collect();
        obj.insert("topics".to_string(), json!(topics));
    }

    Value::Object(obj)
}

// RPC response types for deserialization

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcBlock {
    number: String,
    hash: String,
    parent_hash: String,
    timestamp: String,
    transactions: Vec<String>,
    gas_limit: String,
    gas_used: String,
    miner: String,
    #[serde(default)]
    state_root: Option<String>,
    #[serde(default)]
    transactions_root: Option<String>,
    #[serde(default)]
    receipts_root: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    difficulty: Option<String>,
    #[serde(default)]
    extra_data: Option<String>,
}

impl From<RpcBlock> for Block {
    fn from(rpc: RpcBlock) -> Self {
        Block {
            number: parse::hex_to_u64(&rpc.number).unwrap_or(0),
            hash: H256::from_hex(&rpc.hash).unwrap_or(H256::ZERO),
            parent_hash: H256::from_hex(&rpc.parent_hash).unwrap_or(H256::ZERO),
            timestamp: parse::hex_to_u64(&rpc.timestamp).unwrap_or(0),
            transactions: rpc
                .transactions
                .iter()
                .filter_map(|h| H256::from_hex(h).ok())
                .collect(),
            gas_limit: parse::hex_to_u64(&rpc.gas_limit).unwrap_or(0),
            gas_used: parse::hex_to_u64(&rpc.gas_used).unwrap_or(0),
            miner: Address::from_hex(&rpc.miner).unwrap_or(Address::ZERO),
            state_root: rpc.state_root.and_then(|s| H256::from_hex(&s).ok()),
            transactions_root: rpc.transactions_root.and_then(|s| H256::from_hex(&s).ok()),
            receipts_root: rpc.receipts_root.and_then(|s| H256::from_hex(&s).ok()),
            nonce: rpc.nonce.and_then(|s| parse::hex_to_u64(&s).ok()),
            difficulty: rpc.difficulty.and_then(|s| parse::hex_to_u64(&s).ok()),
            extra_data: rpc.extra_data.and_then(|s| parse::hex_to_bytes(&s).ok()),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcTransaction {
    hash: String,
    from: String,
    to: Option<String>,
    value: String,
    gas: String,
    gas_price: String,
    input: String,
    nonce: String,
    #[serde(default)]
    block_hash: Option<String>,
    #[serde(default)]
    block_number: Option<String>,
    #[serde(default)]
    transaction_index: Option<String>,
    v: String,
    r: String,
    s: String,
}

impl TryFrom<RpcTransaction> for Transaction {
    type Error = Error;

    fn try_from(rpc: RpcTransaction) -> Result<Self> {
        Ok(Transaction {
            hash: H256::from_hex(&rpc.hash)?,
            from: Address::from_hex(&rpc.from)?,
            to: rpc.to.as_ref().map(|s| Address::from_hex(s)).transpose()?,
            value: parse::hex_to_u256(&rpc.value)?,
            gas: parse::hex_to_u64(&rpc.gas)?,
            gas_price: parse::hex_to_u256(&rpc.gas_price)?,
            input: parse::hex_to_bytes(&rpc.input)?,
            nonce: parse::hex_to_u64(&rpc.nonce)?,
            block_hash: rpc
                .block_hash
                .as_ref()
                .map(|s| H256::from_hex(s))
                .transpose()?,
            block_number: rpc
                .block_number
                .as_ref()
                .map(|s| parse::hex_to_u64(s))
                .transpose()?,
            transaction_index: rpc
                .transaction_index
                .as_ref()
                .map(|s| parse::hex_to_u64(s))
                .transpose()?,
            v: parse::hex_to_u64(&rpc.v)?,
            r: parse::hex_to_u256(&rpc.r)?,
            s: parse::hex_to_u256(&rpc.s)?,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcTransactionReceipt {
    transaction_hash: String,
    block_hash: String,
    block_number: String,
    transaction_index: String,
    from: String,
    to: Option<String>,
    gas_used: String,
    cumulative_gas_used: String,
    #[serde(default)]
    contract_address: Option<String>,
    logs: Vec<RpcLog>,
    status: String,
}

impl TryFrom<RpcTransactionReceipt> for TransactionReceipt {
    type Error = Error;

    fn try_from(rpc: RpcTransactionReceipt) -> Result<Self> {
        let logs: Result<Vec<Log>> = rpc.logs.into_iter().map(|l| l.try_into()).collect();
        Ok(TransactionReceipt {
            transaction_hash: H256::from_hex(&rpc.transaction_hash)?,
            block_hash: H256::from_hex(&rpc.block_hash)?,
            block_number: parse::hex_to_u64(&rpc.block_number)?,
            transaction_index: parse::hex_to_u64(&rpc.transaction_index)?,
            from: Address::from_hex(&rpc.from)?,
            to: rpc.to.as_ref().map(|s| Address::from_hex(s)).transpose()?,
            gas_used: parse::hex_to_u64(&rpc.gas_used)?,
            cumulative_gas_used: parse::hex_to_u64(&rpc.cumulative_gas_used)?,
            contract_address: rpc
                .contract_address
                .as_ref()
                .map(|s| Address::from_hex(s))
                .transpose()?,
            logs: logs?,
            status: parse::hex_to_u64(&rpc.status)?,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RpcLog {
    address: String,
    topics: Vec<String>,
    data: String,
    block_number: String,
    transaction_hash: String,
    transaction_index: String,
    block_hash: String,
    log_index: String,
}

impl TryFrom<RpcLog> for Log {
    type Error = Error;

    fn try_from(rpc: RpcLog) -> Result<Self> {
        let topics: Result<Vec<H256>> = rpc.topics.iter().map(|t| H256::from_hex(t)).collect();
        Ok(Log {
            address: Address::from_hex(&rpc.address)?,
            topics: topics?,
            data: parse::hex_to_bytes(&rpc.data)?,
            block_number: parse::hex_to_u64(&rpc.block_number)?,
            transaction_hash: H256::from_hex(&rpc.transaction_hash)?,
            transaction_index: parse::hex_to_u64(&rpc.transaction_index)?,
            block_hash: H256::from_hex(&rpc.block_hash)?,
            log_index: parse::hex_to_u64(&rpc.log_index)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_param() {
        assert_eq!(Client::block_param(None), json!("latest"));
        assert_eq!(Client::block_param(Some(0)), json!("0x0"));
        assert_eq!(Client::block_param(Some(100)), json!("0x64"));
    }

    #[test]
    fn test_build_call_object() {
        let to = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();
        let msg = CallRequest::new(to).gas(21000).value(U256::from(1000));

        let obj = build_call_object(&msg);
        assert!(obj.is_object());

        let map = obj.as_object().unwrap();
        assert_eq!(
            map.get("to").unwrap(),
            "0x1234567890123456789012345678901234567890"
        );
        assert_eq!(map.get("gas").unwrap(), "0x5208");
        assert_eq!(map.get("value").unwrap(), "0x3e8");
    }

    #[test]
    fn test_build_filter_object() {
        let addr = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();
        let filter = Filter::new().from_block(100).to_block(200).address(addr);

        let obj = build_filter_object(&filter);
        assert!(obj.is_object());

        let map = obj.as_object().unwrap();
        assert_eq!(map.get("fromBlock").unwrap(), "0x64");
        assert_eq!(map.get("toBlock").unwrap(), "0xc8");
        assert_eq!(
            map.get("address").unwrap(),
            "0x1234567890123456789012345678901234567890"
        );
    }

    #[test]
    fn test_client_config_default() {
        let config = ClientConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.max_retries, 3);
        assert!(config.auto_chain_id);
    }
}
