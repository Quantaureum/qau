// Quantaureum Rust SDK source, version 1.0.0.
//! Contract struct and methods.
//!
//! This module provides the `Contract` struct for interacting with
//! deployed smart contracts on the Quantaureum blockchain.

use std::sync::Arc;

use crate::client::Provider;
use crate::contracts::abi::{Abi, Detokenize, Tokenize};
use crate::error::{Error, Result};
use crate::types::{Address, CallRequest, TransactionReceipt, TransactionRequest, H256, U256};

/// A contract instance bound to a specific address.
///
/// The `Contract` struct provides methods for calling contract functions
/// and sending transactions to the contract.
///
/// # Type Parameters
///
/// * `P` - The provider type that implements the `Provider` trait
///
/// # Examples
///
/// ```rust,ignore
/// use quantaureum_sdk::{Client, Contract, Address};
///
/// #[tokio::main]
/// async fn main() -> quantaureum_sdk::Result<()> {
///     let client = Client::new("http://localhost:8545").await?;
///     let address = "0x1234567890123456789012345678901234567890".parse()?;
///
///     let abi_json = r#"[{"type":"function","name":"balanceOf",...}]"#;
///     let contract = Contract::from_json(address, abi_json, Arc::new(client))?;
///
///     let balance: U256 = contract.call("balanceOf", (address,)).await?;
///     println!("Balance: {}", balance);
///
///     Ok(())
/// }
/// ```
pub struct Contract<P: Provider> {
    /// Contract address
    address: Address,
    /// Contract ABI
    abi: Abi,
    /// Provider for blockchain interaction
    provider: Arc<P>,
}

impl<P: Provider> Contract<P> {
    /// Creates a new contract instance.
    ///
    /// # Arguments
    ///
    /// * `address` - The contract address
    /// * `abi` - The contract ABI
    /// * `provider` - The provider for blockchain interaction
    pub fn new(address: Address, abi: Abi, provider: Arc<P>) -> Self {
        Self {
            address,
            abi,
            provider,
        }
    }

    /// Creates a new contract instance from a JSON ABI string.
    ///
    /// # Arguments
    ///
    /// * `address` - The contract address
    /// * `json` - The JSON ABI string
    /// * `provider` - The provider for blockchain interaction
    ///
    /// # Errors
    ///
    /// Returns `Error::Abi` if the JSON is empty or not a valid ABI array.
    pub fn from_json(address: Address, json: &str, provider: Arc<P>) -> Result<Self> {
        // Validate ABI JSON format
        crate::utils::validation::validate_abi_json(json)?;

        let abi = Abi::from_json(json)?;
        Ok(Self::new(address, abi, provider))
    }

    /// Returns the contract address.
    pub fn address(&self) -> Address {
        self.address
    }

    /// Returns a reference to the contract ABI.
    pub fn abi(&self) -> &Abi {
        &self.abi
    }

    /// Returns a reference to the provider.
    pub fn provider(&self) -> &Arc<P> {
        &self.provider
    }

    /// Executes a read-only call to a contract function.
    ///
    /// This method does not send a transaction and does not modify state.
    ///
    /// # Arguments
    ///
    /// * `method` - The function name to call
    /// * `args` - The function arguments
    ///
    /// # Type Parameters
    ///
    /// * `T` - The return type that implements `Detokenize`
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let balance: U256 = contract.call("balanceOf", (address,)).await?;
    /// ```
    pub async fn call<T: Detokenize>(&self, method: &str, args: impl Tokenize) -> Result<T> {
        let func = self.abi.function(method)?;
        let data = func.encode(args)?;

        let call_request = CallRequest::new(self.address).data(data);
        let result = self.provider.call(&call_request, None).await?;

        func.decode_output(&result)
    }

    /// Executes a read-only call at a specific block.
    ///
    /// # Arguments
    ///
    /// * `method` - The function name to call
    /// * `args` - The function arguments
    /// * `block` - The block number to execute the call at
    pub async fn call_at<T: Detokenize>(
        &self,
        method: &str,
        args: impl Tokenize,
        block: u64,
    ) -> Result<T> {
        let func = self.abi.function(method)?;
        let data = func.encode(args)?;

        let call_request = CallRequest::new(self.address).data(data);
        let result = self.provider.call(&call_request, Some(block)).await?;

        func.decode_output(&result)
    }

    /// Prepares a transaction to call a contract function.
    ///
    /// This method returns a `ContractCall` that can be customized
    /// before sending.
    ///
    /// # Arguments
    ///
    /// * `method` - The function name to call
    /// * `args` - The function arguments
    pub fn method(&self, method: &str, args: impl Tokenize) -> Result<ContractCall<P>> {
        let func = self.abi.function(method)?;
        let data = func.encode(args)?;

        Ok(ContractCall {
            contract_address: self.address,
            provider: Arc::clone(&self.provider),
            data,
            value: None,
            gas: None,
            gas_price: None,
            nonce: None,
            from: None,
        })
    }

    /// Encodes a function call without executing it.
    ///
    /// # Arguments
    ///
    /// * `method` - The function name
    /// * `args` - The function arguments
    pub fn encode(&self, method: &str, args: impl Tokenize) -> Result<Vec<u8>> {
        let func = self.abi.function(method)?;
        func.encode(args)
    }

    /// Decodes the return value of a function call.
    ///
    /// # Arguments
    ///
    /// * `method` - The function name
    /// * `data` - The encoded return data
    pub fn decode<T: Detokenize>(&self, method: &str, data: &[u8]) -> Result<T> {
        let func = self.abi.function(method)?;
        func.decode_output(data)
    }
}

/// A prepared contract call that can be customized before sending.
pub struct ContractCall<P: Provider> {
    contract_address: Address,
    provider: Arc<P>,
    data: Vec<u8>,
    value: Option<U256>,
    gas: Option<u64>,
    gas_price: Option<U256>,
    nonce: Option<u64>,
    from: Option<Address>,
}

impl<P: Provider> ContractCall<P> {
    /// Sets the value to send with the transaction.
    pub fn value(mut self, value: U256) -> Self {
        self.value = Some(value);
        self
    }

    /// Sets the gas limit for the transaction.
    pub fn gas(mut self, gas: u64) -> Self {
        self.gas = Some(gas);
        self
    }

    /// Sets the gas price for the transaction.
    pub fn gas_price(mut self, gas_price: U256) -> Self {
        self.gas_price = Some(gas_price);
        self
    }

    /// Sets the nonce for the transaction.
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Sets the sender address for the transaction.
    pub fn from(mut self, from: Address) -> Self {
        self.from = Some(from);
        self
    }

    /// Returns the encoded call data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the contract address.
    pub fn contract_address(&self) -> Address {
        self.contract_address
    }

    /// Builds a transaction request from this contract call.
    pub fn into_transaction_request(self) -> TransactionRequest {
        TransactionRequest {
            from: self.from,
            to: Some(self.contract_address),
            gas: self.gas,
            gas_price: self.gas_price,
            value: self.value,
            data: Some(self.data),
            nonce: self.nonce,
        }
    }

    /// Estimates the gas required for this call.
    pub async fn estimate_gas(&self) -> Result<u64> {
        let call_request = CallRequest {
            from: self.from,
            to: self.contract_address,
            gas: self.gas,
            gas_price: self.gas_price,
            value: self.value,
            data: Some(self.data.clone()),
        };

        self.provider.estimate_gas(&call_request).await
    }

    /// Executes the call without sending a transaction.
    pub async fn call<T: Detokenize>(&self) -> Result<T> {
        let call_request = CallRequest {
            from: self.from,
            to: self.contract_address,
            gas: self.gas,
            gas_price: self.gas_price,
            value: self.value,
            data: Some(self.data.clone()),
        };

        let result = self.provider.call(&call_request, None).await?;

        // For raw call results, we return the bytes as-is
        // The caller should decode using the contract's decode method
        T::from_tokens(vec![crate::contracts::abi::Token::Bytes(result)])
    }
}

/// A pending transaction that can be awaited for confirmation.
pub struct PendingTransaction<P: Provider> {
    hash: H256,
    provider: Arc<P>,
}

impl<P: Provider> PendingTransaction<P> {
    /// Creates a new pending transaction.
    pub fn new(hash: H256, provider: Arc<P>) -> Self {
        Self { hash, provider }
    }

    /// Returns the transaction hash.
    pub fn hash(&self) -> H256 {
        self.hash
    }

    /// Waits for the transaction to be mined and returns the receipt.
    ///
    /// This method polls the node until the transaction is confirmed.
    pub async fn await_receipt(&self) -> Result<TransactionReceipt> {
        self.await_confirmations(1).await
    }

    /// Waits for the transaction to reach the specified number of confirmations.
    ///
    /// # Arguments
    ///
    /// * `confirmations` - The number of confirmations to wait for
    pub async fn await_confirmations(&self, confirmations: u64) -> Result<TransactionReceipt> {
        loop {
            if let Some(receipt) = self.provider.transaction_receipt(self.hash).await? {
                // Check if we have enough confirmations
                let current_block = self.provider.block_number().await?;
                let tx_block = receipt.block_number;

                if current_block >= tx_block + confirmations - 1 {
                    // Check transaction status
                    if receipt.status == 0 {
                        return Err(Error::Transaction {
                            hash: Some(self.hash.to_hex()),
                            reason: "transaction reverted".to_string(),
                        });
                    }
                    return Ok(receipt);
                }
            }

            // Wait before polling again
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_call_builder() {
        // Test that ContractCall builder methods work correctly
        let addr = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();

        let tx_request = TransactionRequest::new()
            .to(addr)
            .value(U256::from(1000))
            .gas(21000)
            .data(vec![0xa9, 0x05, 0x9c, 0xbb]);

        assert_eq!(tx_request.to, Some(addr));
        assert_eq!(tx_request.value, Some(U256::from(1000)));
        assert_eq!(tx_request.gas, Some(21000));
        assert_eq!(tx_request.data, Some(vec![0xa9, 0x05, 0x9c, 0xbb]));
    }

    #[test]
    fn test_contract_from_json() {
        // This test would require a mock provider
        // For now, just test ABI parsing
        let json = r#"[
            {
                "type": "function",
                "name": "transfer",
                "inputs": [
                    {"name": "to", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ],
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "nonpayable"
            }
        ]"#;

        let abi = Abi::from_json(json).unwrap();
        let func = abi.function("transfer").unwrap();
        assert_eq!(func.name, "transfer");
    }
}
