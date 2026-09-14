// Quantaureum Rust SDK source, version 1.0.0.
//! Error types for the SDK.
//!
//! This module defines custom error types using `thiserror` for different
//! error categories, supporting pattern matching for error handling.

use thiserror::Error;

/// SDK error type.
///
/// This enum represents all possible errors that can occur when using the SDK.
/// Each variant provides specific context about the error.
#[derive(Error, Debug)]
pub enum Error {
    /// RPC error from the blockchain node.
    #[error("RPC error: code={code}, message={message}")]
    Rpc {
        /// The RPC error code.
        code: i64,
        /// The error message from the node.
        message: String,
        /// Optional additional data.
        data: Option<String>,
    },

    /// Transaction-related error.
    #[error("Transaction error: {reason}")]
    Transaction {
        /// The transaction hash as hex string, if available.
        hash: Option<String>,
        /// The reason for the error.
        reason: String,
    },

    /// Validation error for invalid parameters.
    #[error("Validation error: {field} - {message}")]
    Validation {
        /// The field that failed validation.
        field: String,
        /// Description of the validation failure.
        message: String,
    },

    /// Signing error.
    #[error("Signing error: {0}")]
    Signing(String),

    /// ABI encoding/decoding error.
    #[error("ABI error: {0}")]
    Abi(String),

    /// Connection error.
    #[error("Connection error: {0}")]
    Connection(String),

    /// Invalid address format.
    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid private key.
    #[error("Invalid private key")]
    InvalidPrivateKey,

    /// Invalid mnemonic phrase.
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Invalid hexadecimal string.
    #[error("Invalid hex: {0}")]
    InvalidHex(String),

    /// HTTP request error.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Result type alias using the SDK's Error type.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::InvalidAddress("too short".to_string());
        assert_eq!(err.to_string(), "Invalid address: too short");
    }

    #[test]
    fn test_validation_error() {
        let err = Error::Validation {
            field: "address".to_string(),
            message: "must be 20 bytes".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Validation error: address - must be 20 bytes"
        );
    }

    #[test]
    fn test_rpc_error() {
        let err = Error::Rpc {
            code: -32600,
            message: "Invalid Request".to_string(),
            data: None,
        };
        assert_eq!(
            err.to_string(),
            "RPC error: code=-32600, message=Invalid Request"
        );
    }

    #[test]
    fn test_error_pattern_matching() {
        let err = Error::InvalidPrivateKey;

        match err {
            Error::InvalidPrivateKey => (),
            _ => panic!("Expected InvalidPrivateKey"),
        }
    }
}
