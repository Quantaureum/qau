// Quantaureum Rust SDK source, version 1.0.0.
//! JSON-RPC request/response handling.
//!
//! This module provides the low-level JSON-RPC communication infrastructure
//! for interacting with Quantaureum blockchain nodes.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

/// JSON-RPC version string.
const JSONRPC_VERSION: &str = "2.0";

/// A JSON-RPC request.
#[derive(Debug, Serialize)]
pub struct RpcRequest<'a> {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: &'static str,
    /// Request method name
    pub method: &'a str,
    /// Request parameters
    pub params: Value,
    /// Request ID
    pub id: u64,
}

impl<'a> RpcRequest<'a> {
    /// Creates a new RPC request.
    pub fn new(method: &'a str, params: Value, id: u64) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION,
            method,
            params,
            id,
        }
    }
}

/// A JSON-RPC response.
#[derive(Debug, Deserialize)]
pub struct RpcResponse<T> {
    /// JSON-RPC version
    #[allow(dead_code)]
    pub jsonrpc: String,
    /// Response result (if successful)
    pub result: Option<T>,
    /// Response error (if failed)
    pub error: Option<RpcError>,
    /// Response ID
    #[allow(dead_code)]
    pub id: u64,
}

impl<T> RpcResponse<T> {
    /// Converts the response into a Result.
    pub fn into_result(self) -> Result<T> {
        if let Some(error) = self.error {
            Err(error.into())
        } else if let Some(result) = self.result {
            Ok(result)
        } else {
            Err(Error::Rpc {
                code: -1,
                message: "Empty response".to_string(),
                data: None,
            })
        }
    }
}

/// A JSON-RPC error.
#[derive(Debug, Deserialize)]
pub struct RpcError {
    /// Error code
    pub code: i64,
    /// Error message
    pub message: String,
    /// Optional additional data
    pub data: Option<Value>,
}

impl RpcError {
    /// Extracts the revert reason from the error data if present.
    ///
    /// This handles common formats for revert reasons:
    /// - Direct string in data field
    /// - Hex-encoded revert reason
    /// - Nested error object with message
    pub fn extract_revert_reason(&self) -> Option<String> {
        let data = self.data.as_ref()?;

        // Try to extract from string data
        if let Some(s) = data.as_str() {
            // Check if it's a hex-encoded revert reason
            if s.starts_with("0x") {
                return Self::decode_revert_reason(s);
            }
            return Some(s.to_string());
        }

        // Try to extract from object with "message" field
        if let Some(obj) = data.as_object() {
            if let Some(msg) = obj.get("message").and_then(|v| v.as_str()) {
                return Some(msg.to_string());
            }
            // Try "reason" field
            if let Some(reason) = obj.get("reason").and_then(|v| v.as_str()) {
                return Some(reason.to_string());
            }
            // Try "data" field (nested)
            if let Some(nested_data) = obj.get("data").and_then(|v| v.as_str()) {
                if nested_data.starts_with("0x") {
                    return Self::decode_revert_reason(nested_data);
                }
            }
        }

        None
    }

    /// Decodes a hex-encoded revert reason.
    ///
    /// Revert reasons are typically ABI-encoded as:
    /// - Error(string) selector: 0x08c379a0
    /// - Followed by offset (32 bytes)
    /// - Followed by length (32 bytes)
    /// - Followed by the string data
    fn decode_revert_reason(hex_data: &str) -> Option<String> {
        let hex = hex_data.strip_prefix("0x").unwrap_or(hex_data);
        let bytes = hex::decode(hex).ok()?;

        // Check for Error(string) selector: 0x08c379a0
        if bytes.len() >= 4 && bytes[0..4] == [0x08, 0xc3, 0x79, 0xa0] {
            // Skip selector (4 bytes) + offset (32 bytes) = 36 bytes
            if bytes.len() >= 68 {
                // Read length from bytes 36-68
                let length_bytes = &bytes[36..68];
                let length = u64::from_be_bytes([
                    length_bytes[24],
                    length_bytes[25],
                    length_bytes[26],
                    length_bytes[27],
                    length_bytes[28],
                    length_bytes[29],
                    length_bytes[30],
                    length_bytes[31],
                ]) as usize;

                // Read string data
                if bytes.len() >= 68 + length {
                    let string_data = &bytes[68..68 + length];
                    return String::from_utf8(string_data.to_vec()).ok();
                }
            }
        }

        // Check for Panic(uint256) selector: 0x4e487b71
        if bytes.len() >= 36 && bytes[0..4] == [0x4e, 0x48, 0x7b, 0x71] {
            // Read panic code from bytes 4-36
            let code_bytes = &bytes[4..36];
            let code = u64::from_be_bytes([
                code_bytes[24],
                code_bytes[25],
                code_bytes[26],
                code_bytes[27],
                code_bytes[28],
                code_bytes[29],
                code_bytes[30],
                code_bytes[31],
            ]);

            let panic_reason = match code {
                0x00 => "generic panic",
                0x01 => "assertion failed",
                0x11 => "arithmetic overflow/underflow",
                0x12 => "division by zero",
                0x21 => "invalid enum value",
                0x22 => "storage byte array encoding error",
                0x31 => "pop on empty array",
                0x32 => "array index out of bounds",
                0x41 => "memory allocation error",
                0x51 => "zero-initialized function pointer",
                _ => "unknown panic",
            };

            return Some(format!("Panic: {} (code: 0x{:02x})", panic_reason, code));
        }

        // If we can't decode, return the raw hex
        None
    }

    /// Checks if this is a revert error.
    pub fn is_revert(&self) -> bool {
        // Common revert error codes
        // -32000: Generic execution error (Geth)
        // -32015: VM execution error (Parity/OpenEthereum)
        // 3: Execution reverted (some nodes)
        matches!(self.code, -32000 | -32015 | 3)
    }

    /// Checks if this is a connection/network error.
    pub fn is_connection_error(&self) -> bool {
        // -32603: Internal JSON-RPC error
        // -32600: Invalid Request
        // -32601: Method not found
        matches!(self.code, -32603 | -32600 | -32601)
    }
}

impl From<RpcError> for Error {
    fn from(err: RpcError) -> Self {
        // Check if this is a revert error and extract the reason
        if err.is_revert() {
            if let Some(reason) = err.extract_revert_reason() {
                return Error::Transaction { hash: None, reason };
            }
        }

        Error::Rpc {
            code: err.code,
            message: err.message,
            data: err.data.map(|v| v.to_string()),
        }
    }
}

/// RPC transport for making JSON-RPC calls.
#[derive(Debug, Clone)]
pub struct RpcTransport {
    /// HTTP client
    client: reqwest::Client,
    /// Node URL
    url: String,
    /// Request ID counter (wrapped in Arc for Clone)
    id_counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl RpcTransport {
    /// Creates a new RPC transport.
    pub fn new(url: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.to_string(),
            id_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    /// Creates a new RPC transport with a custom HTTP client.
    pub fn with_client(url: &str, client: reqwest::Client) -> Self {
        Self {
            client,
            url: url.to_string(),
            id_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    /// Gets the next request ID.
    fn next_id(&self) -> u64 {
        self.id_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// Makes an RPC call and returns the result.
    pub async fn call<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let id = self.next_id();
        let request = RpcRequest::new(method, params, id);

        let response = self
            .client
            .post(&self.url)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::Connection(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Connection(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        let rpc_response: RpcResponse<T> = response
            .json()
            .await
            .map_err(|e| Error::Connection(format!("Failed to parse response: {}", e)))?;

        rpc_response.into_result()
    }

    /// Makes an RPC call that may return null.
    pub async fn call_optional<T: DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> Result<Option<T>> {
        let id = self.next_id();
        let request = RpcRequest::new(method, params, id);

        let response = self
            .client
            .post(&self.url)
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::Connection(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::Connection(format!(
                "HTTP error: {}",
                response.status()
            )));
        }

        let rpc_response: RpcResponse<Value> = response
            .json()
            .await
            .map_err(|e| Error::Connection(format!("Failed to parse response: {}", e)))?;

        if let Some(error) = rpc_response.error {
            return Err(error.into());
        }

        match rpc_response.result {
            Some(Value::Null) => Ok(None),
            Some(value) => {
                let result: T = serde_json::from_value(value)?;
                Ok(Some(result))
            }
            None => Ok(None),
        }
    }

    /// Returns the URL of the RPC endpoint.
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// Helper functions for parsing RPC responses.
pub mod parse {
    use super::*;
    use crate::types::U256;

    /// Parses a hex-encoded u64 value.
    pub fn hex_to_u64(hex: &str) -> Result<u64> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        u64::from_str_radix(hex, 16).map_err(|e| Error::Validation {
            field: "hex".to_string(),
            message: format!("Invalid hex u64: {}", e),
        })
    }

    /// Parses a hex-encoded U256 value.
    pub fn hex_to_u256(hex: &str) -> Result<U256> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        U256::from_str_radix(hex, 16).map_err(|_| Error::Validation {
            field: "hex".to_string(),
            message: "Invalid hex U256".to_string(),
        })
    }

    /// Parses a hex-encoded byte array.
    pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        hex::decode(hex).map_err(|e| Error::InvalidHex(e.to_string()))
    }

    /// Converts a u64 to hex string with 0x prefix.
    pub fn u64_to_hex(value: u64) -> String {
        format!("0x{:x}", value)
    }

    /// Converts a U256 to hex string with 0x prefix.
    pub fn u256_to_hex(value: &U256) -> String {
        format!("0x{:x}", value)
    }

    /// Converts bytes to hex string with 0x prefix.
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rpc_request_serialization() {
        let request = RpcRequest::new("eth_blockNumber", serde_json::json!([]), 1);
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("\"jsonrpc\":\"2.0\""));
        assert!(json.contains("\"method\":\"eth_blockNumber\""));
        assert!(json.contains("\"id\":1"));
    }

    #[test]
    fn test_rpc_response_success() {
        let json = r#"{"jsonrpc":"2.0","result":"0x10","id":1}"#;
        let response: RpcResponse<String> = serde_json::from_str(json).unwrap();
        let result = response.into_result().unwrap();
        assert_eq!(result, "0x10");
    }

    #[test]
    fn test_rpc_response_error() {
        let json =
            r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":1}"#;
        let response: RpcResponse<String> = serde_json::from_str(json).unwrap();
        let err = response.into_result().unwrap_err();
        match err {
            Error::Rpc { code, message, .. } => {
                assert_eq!(code, -32600);
                assert_eq!(message, "Invalid Request");
            }
            _ => panic!("Expected RPC error"),
        }
    }

    #[test]
    fn test_rpc_error_is_revert() {
        let revert_error = RpcError {
            code: -32000,
            message: "execution reverted".to_string(),
            data: None,
        };
        assert!(revert_error.is_revert());

        let non_revert_error = RpcError {
            code: -32600,
            message: "Invalid Request".to_string(),
            data: None,
        };
        assert!(!non_revert_error.is_revert());
    }

    #[test]
    fn test_rpc_error_extract_revert_reason_string() {
        let error = RpcError {
            code: -32000,
            message: "execution reverted".to_string(),
            data: Some(serde_json::json!("Insufficient balance")),
        };

        let reason = error.extract_revert_reason();
        assert_eq!(reason, Some("Insufficient balance".to_string()));
    }

    #[test]
    fn test_rpc_error_extract_revert_reason_object() {
        let error = RpcError {
            code: -32000,
            message: "execution reverted".to_string(),
            data: Some(serde_json::json!({"message": "Transfer failed"})),
        };

        let reason = error.extract_revert_reason();
        assert_eq!(reason, Some("Transfer failed".to_string()));
    }

    #[test]
    fn test_rpc_error_extract_revert_reason_hex() {
        // Error(string) with "Insufficient balance"
        // Selector: 0x08c379a0
        // Offset: 32 (0x20)
        // Length: 20 (0x14)
        // Data: "Insufficient balance"
        let hex_data = "0x08c379a0\
            0000000000000000000000000000000000000000000000000000000000000020\
            0000000000000000000000000000000000000000000000000000000000000014\
            496e73756666696369656e742062616c616e6365000000000000000000000000";

        let error = RpcError {
            code: -32000,
            message: "execution reverted".to_string(),
            data: Some(serde_json::json!(hex_data)),
        };

        let reason = error.extract_revert_reason();
        assert_eq!(reason, Some("Insufficient balance".to_string()));
    }

    #[test]
    fn test_rpc_error_extract_panic_reason() {
        // Panic(uint256) with code 0x11 (arithmetic overflow)
        // Selector: 0x4e487b71
        // Code: 0x11
        let hex_data = "0x4e487b71\
            0000000000000000000000000000000000000000000000000000000000000011";

        let error = RpcError {
            code: -32000,
            message: "execution reverted".to_string(),
            data: Some(serde_json::json!(hex_data)),
        };

        let reason = error.extract_revert_reason();
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("arithmetic overflow"));
    }

    #[test]
    fn test_rpc_error_converts_to_transaction_error() {
        let error = RpcError {
            code: -32000,
            message: "execution reverted".to_string(),
            data: Some(serde_json::json!("Transfer failed")),
        };

        let sdk_error: Error = error.into();
        match sdk_error {
            Error::Transaction { hash, reason } => {
                assert!(hash.is_none());
                assert_eq!(reason, "Transfer failed");
            }
            _ => panic!("Expected Transaction error"),
        }
    }

    #[test]
    fn test_rpc_error_is_connection_error() {
        let connection_error = RpcError {
            code: -32603,
            message: "Internal error".to_string(),
            data: None,
        };
        assert!(connection_error.is_connection_error());

        let non_connection_error = RpcError {
            code: -32000,
            message: "execution reverted".to_string(),
            data: None,
        };
        assert!(!non_connection_error.is_connection_error());
    }

    #[test]
    fn test_hex_to_u64() {
        assert_eq!(parse::hex_to_u64("0x10").unwrap(), 16);
        assert_eq!(parse::hex_to_u64("10").unwrap(), 16);
        assert_eq!(parse::hex_to_u64("0xff").unwrap(), 255);
        assert_eq!(parse::hex_to_u64("0x0").unwrap(), 0);
    }

    #[test]
    fn test_hex_to_u256() {
        use crate::types::U256;
        assert_eq!(parse::hex_to_u256("0x10").unwrap(), U256::from(16));
        assert_eq!(
            parse::hex_to_u256("0xffffffff").unwrap(),
            U256::from(0xffffffffu64)
        );
    }

    #[test]
    fn test_u64_to_hex() {
        assert_eq!(parse::u64_to_hex(16), "0x10");
        assert_eq!(parse::u64_to_hex(255), "0xff");
        assert_eq!(parse::u64_to_hex(0), "0x0");
    }

    #[test]
    fn test_bytes_to_hex() {
        assert_eq!(parse::bytes_to_hex(&[0x12, 0x34]), "0x1234");
        assert_eq!(parse::bytes_to_hex(&[]), "0x");
    }

    #[test]
    fn test_hex_to_bytes() {
        assert_eq!(parse::hex_to_bytes("0x1234").unwrap(), vec![0x12, 0x34]);
        assert_eq!(parse::hex_to_bytes("1234").unwrap(), vec![0x12, 0x34]);
        let empty: Vec<u8> = vec![];
        assert_eq!(parse::hex_to_bytes("0x").unwrap(), empty);
    }
}
