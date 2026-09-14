// Quantaureum Rust SDK source, version 1.0.0.
//! ABI parsing and encoding/decoding.
//!
//! This module provides ABI (Application Binary Interface) support for
//! encoding and decoding smart contract function calls and events.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{Error, Result};
use crate::types::{Address, H256, U256};
use crate::utils::keccak256;

/// ABI type representing a parsed contract ABI.
#[derive(Debug, Clone, Default)]
pub struct Abi {
    /// Functions indexed by name
    functions: HashMap<String, Vec<AbiFunction>>,
    /// Events indexed by name
    events: HashMap<String, Vec<AbiEvent>>,
    /// Constructor (if present)
    constructor: Option<AbiConstructor>,
    /// Fallback function (if present)
    fallback: Option<AbiFallback>,
    /// Receive function (if present)
    receive: Option<AbiReceive>,
}

/// An ABI function definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiFunction {
    /// Function name
    pub name: String,
    /// Input parameters
    pub inputs: Vec<AbiParam>,
    /// Output parameters
    pub outputs: Vec<AbiParam>,
    /// State mutability
    #[serde(default)]
    pub state_mutability: StateMutability,
}

/// An ABI event definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiEvent {
    /// Event name
    pub name: String,
    /// Event parameters
    pub inputs: Vec<AbiEventParam>,
    /// Whether the event is anonymous
    #[serde(default)]
    pub anonymous: bool,
}

/// An ABI constructor definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiConstructor {
    /// Input parameters
    pub inputs: Vec<AbiParam>,
    /// State mutability
    #[serde(default)]
    pub state_mutability: StateMutability,
}

/// An ABI fallback function definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiFallback {
    /// State mutability
    #[serde(default)]
    pub state_mutability: StateMutability,
}

/// An ABI receive function definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiReceive {
    /// State mutability
    #[serde(default)]
    pub state_mutability: StateMutability,
}

/// An ABI parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiParam {
    /// Parameter name
    pub name: String,
    /// Parameter type
    #[serde(rename = "type")]
    pub param_type: String,
    /// Components for tuple types
    #[serde(default)]
    pub components: Vec<AbiParam>,
}

/// An ABI event parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiEventParam {
    /// Parameter name
    pub name: String,
    /// Parameter type
    #[serde(rename = "type")]
    pub param_type: String,
    /// Whether the parameter is indexed
    #[serde(default)]
    pub indexed: bool,
    /// Components for tuple types
    #[serde(default)]
    pub components: Vec<AbiParam>,
}

/// State mutability of a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateMutability {
    /// Function does not read or modify state
    Pure,
    /// Function reads but does not modify state
    View,
    /// Function does not accept Ether
    #[default]
    NonPayable,
    /// Function accepts Ether
    Payable,
}

/// A token value that can be encoded/decoded.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// Address (20 bytes)
    Address(Address),
    /// Fixed-size bytes (bytes1 to bytes32)
    FixedBytes(Vec<u8>),
    /// Dynamic bytes
    Bytes(Vec<u8>),
    /// Signed integer (int8 to int256)
    Int(U256),
    /// Unsigned integer (uint8 to uint256)
    Uint(U256),
    /// Boolean
    Bool(bool),
    /// String
    String(String),
    /// Fixed-size array
    FixedArray(Vec<Token>),
    /// Dynamic array
    Array(Vec<Token>),
    /// Tuple
    Tuple(Vec<Token>),
}

/// Trait for types that can be converted to ABI tokens.
pub trait Tokenize {
    /// Converts self into a vector of tokens.
    fn into_tokens(self) -> Vec<Token>;
}

/// Trait for types that can be converted from ABI tokens.
pub trait Detokenize: Sized {
    /// Converts tokens into self.
    fn from_tokens(tokens: Vec<Token>) -> Result<Self>;
}

// Implement Tokenize for common types

impl Tokenize for () {
    fn into_tokens(self) -> Vec<Token> {
        vec![]
    }
}

impl Tokenize for Token {
    fn into_tokens(self) -> Vec<Token> {
        vec![self]
    }
}

impl Tokenize for Vec<Token> {
    fn into_tokens(self) -> Vec<Token> {
        self
    }
}

impl Tokenize for Address {
    fn into_tokens(self) -> Vec<Token> {
        vec![Token::Address(self)]
    }
}

impl Tokenize for U256 {
    fn into_tokens(self) -> Vec<Token> {
        vec![Token::Uint(self)]
    }
}

impl Tokenize for bool {
    fn into_tokens(self) -> Vec<Token> {
        vec![Token::Bool(self)]
    }
}

impl Tokenize for String {
    fn into_tokens(self) -> Vec<Token> {
        vec![Token::String(self)]
    }
}

impl Tokenize for &str {
    fn into_tokens(self) -> Vec<Token> {
        vec![Token::String(self.to_string())]
    }
}

impl Tokenize for Vec<u8> {
    fn into_tokens(self) -> Vec<Token> {
        vec![Token::Bytes(self)]
    }
}

impl Tokenize for u64 {
    fn into_tokens(self) -> Vec<Token> {
        vec![Token::Uint(U256::from(self))]
    }
}

impl Tokenize for u128 {
    fn into_tokens(self) -> Vec<Token> {
        vec![Token::Uint(U256::from(self))]
    }
}

impl Tokenize for i64 {
    fn into_tokens(self) -> Vec<Token> {
        if self >= 0 {
            vec![Token::Int(U256::from(self as u64))]
        } else {
            // Two's complement for negative numbers
            let abs = (-self) as u64;
            let max = U256::MAX;
            vec![Token::Int(max - U256::from(abs) + U256::from(1))]
        }
    }
}

// Implement Tokenize for tuples
impl<A: Tokenize> Tokenize for (A,) {
    fn into_tokens(self) -> Vec<Token> {
        self.0.into_tokens()
    }
}

impl<A: Tokenize, B: Tokenize> Tokenize for (A, B) {
    fn into_tokens(self) -> Vec<Token> {
        let mut tokens = self.0.into_tokens();
        tokens.extend(self.1.into_tokens());
        tokens
    }
}

impl<A: Tokenize, B: Tokenize, C: Tokenize> Tokenize for (A, B, C) {
    fn into_tokens(self) -> Vec<Token> {
        let mut tokens = self.0.into_tokens();
        tokens.extend(self.1.into_tokens());
        tokens.extend(self.2.into_tokens());
        tokens
    }
}

impl<A: Tokenize, B: Tokenize, C: Tokenize, D: Tokenize> Tokenize for (A, B, C, D) {
    fn into_tokens(self) -> Vec<Token> {
        let mut tokens = self.0.into_tokens();
        tokens.extend(self.1.into_tokens());
        tokens.extend(self.2.into_tokens());
        tokens.extend(self.3.into_tokens());
        tokens
    }
}

// Implement Detokenize for common types

impl Detokenize for () {
    fn from_tokens(tokens: Vec<Token>) -> Result<Self> {
        if tokens.is_empty() {
            Ok(())
        } else {
            Err(Error::Abi("expected no tokens".to_string()))
        }
    }
}

impl Detokenize for Token {
    fn from_tokens(tokens: Vec<Token>) -> Result<Self> {
        if tokens.len() == 1 {
            Ok(tokens.into_iter().next().unwrap())
        } else {
            Err(Error::Abi(format!(
                "expected 1 token, got {}",
                tokens.len()
            )))
        }
    }
}

impl Detokenize for Vec<Token> {
    fn from_tokens(tokens: Vec<Token>) -> Result<Self> {
        Ok(tokens)
    }
}

impl Detokenize for Address {
    fn from_tokens(tokens: Vec<Token>) -> Result<Self> {
        if tokens.len() != 1 {
            return Err(Error::Abi(format!(
                "expected 1 token, got {}",
                tokens.len()
            )));
        }
        match tokens.into_iter().next().unwrap() {
            Token::Address(addr) => Ok(addr),
            _ => Err(Error::Abi("expected address token".to_string())),
        }
    }
}

impl Detokenize for U256 {
    fn from_tokens(tokens: Vec<Token>) -> Result<Self> {
        if tokens.len() != 1 {
            return Err(Error::Abi(format!(
                "expected 1 token, got {}",
                tokens.len()
            )));
        }
        match tokens.into_iter().next().unwrap() {
            Token::Uint(v) | Token::Int(v) => Ok(v),
            _ => Err(Error::Abi("expected uint/int token".to_string())),
        }
    }
}

impl Detokenize for bool {
    fn from_tokens(tokens: Vec<Token>) -> Result<Self> {
        if tokens.len() != 1 {
            return Err(Error::Abi(format!(
                "expected 1 token, got {}",
                tokens.len()
            )));
        }
        match tokens.into_iter().next().unwrap() {
            Token::Bool(b) => Ok(b),
            _ => Err(Error::Abi("expected bool token".to_string())),
        }
    }
}

impl Detokenize for String {
    fn from_tokens(tokens: Vec<Token>) -> Result<Self> {
        if tokens.len() != 1 {
            return Err(Error::Abi(format!(
                "expected 1 token, got {}",
                tokens.len()
            )));
        }
        match tokens.into_iter().next().unwrap() {
            Token::String(s) => Ok(s),
            _ => Err(Error::Abi("expected string token".to_string())),
        }
    }
}

impl Detokenize for Vec<u8> {
    fn from_tokens(tokens: Vec<Token>) -> Result<Self> {
        if tokens.len() != 1 {
            return Err(Error::Abi(format!(
                "expected 1 token, got {}",
                tokens.len()
            )));
        }
        match tokens.into_iter().next().unwrap() {
            Token::Bytes(b) | Token::FixedBytes(b) => Ok(b),
            _ => Err(Error::Abi("expected bytes token".to_string())),
        }
    }
}

impl Detokenize for u64 {
    fn from_tokens(tokens: Vec<Token>) -> Result<Self> {
        let u = U256::from_tokens(tokens)?;
        if u > U256::from(u64::MAX) {
            return Err(Error::Abi("value too large for u64".to_string()));
        }
        Ok(u.as_u64())
    }
}

impl Detokenize for u128 {
    fn from_tokens(tokens: Vec<Token>) -> Result<Self> {
        let u = U256::from_tokens(tokens)?;
        if u > U256::from(u128::MAX) {
            return Err(Error::Abi("value too large for u128".to_string()));
        }
        Ok(u.as_u128())
    }
}

// Implement Detokenize for tuples
impl<A: Detokenize> Detokenize for (A,) {
    fn from_tokens(tokens: Vec<Token>) -> Result<Self> {
        Ok((A::from_tokens(tokens)?,))
    }
}

impl<A: Detokenize, B: Detokenize> Detokenize for (A, B) {
    fn from_tokens(mut tokens: Vec<Token>) -> Result<Self> {
        if tokens.len() < 2 {
            return Err(Error::Abi(format!(
                "expected at least 2 tokens, got {}",
                tokens.len()
            )));
        }
        let b = tokens.pop().unwrap();
        let a = tokens.pop().unwrap();
        Ok((A::from_tokens(vec![a])?, B::from_tokens(vec![b])?))
    }
}

impl<A: Detokenize, B: Detokenize, C: Detokenize> Detokenize for (A, B, C) {
    fn from_tokens(mut tokens: Vec<Token>) -> Result<Self> {
        if tokens.len() < 3 {
            return Err(Error::Abi(format!(
                "expected at least 3 tokens, got {}",
                tokens.len()
            )));
        }
        let c = tokens.pop().unwrap();
        let b = tokens.pop().unwrap();
        let a = tokens.pop().unwrap();
        Ok((
            A::from_tokens(vec![a])?,
            B::from_tokens(vec![b])?,
            C::from_tokens(vec![c])?,
        ))
    }
}

impl<A: Detokenize, B: Detokenize, C: Detokenize, D: Detokenize> Detokenize for (A, B, C, D) {
    fn from_tokens(mut tokens: Vec<Token>) -> Result<Self> {
        if tokens.len() < 4 {
            return Err(Error::Abi(format!(
                "expected at least 4 tokens, got {}",
                tokens.len()
            )));
        }
        let d = tokens.pop().unwrap();
        let c = tokens.pop().unwrap();
        let b = tokens.pop().unwrap();
        let a = tokens.pop().unwrap();
        Ok((
            A::from_tokens(vec![a])?,
            B::from_tokens(vec![b])?,
            C::from_tokens(vec![c])?,
            D::from_tokens(vec![d])?,
        ))
    }
}

impl Abi {
    /// Creates a new empty ABI.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses an ABI from a JSON string.
    pub fn from_json(json: &str) -> Result<Self> {
        let items: Vec<AbiItem> =
            serde_json::from_str(json).map_err(|e| Error::Abi(format!("invalid JSON: {}", e)))?;

        let mut abi = Abi::new();

        for item in items {
            match item {
                AbiItem::Function(f) => {
                    abi.functions.entry(f.name.clone()).or_default().push(f);
                }
                AbiItem::Event(e) => {
                    abi.events.entry(e.name.clone()).or_default().push(e);
                }
                AbiItem::Constructor(c) => {
                    abi.constructor = Some(c);
                }
                AbiItem::Fallback(f) => {
                    abi.fallback = Some(f);
                }
                AbiItem::Receive(r) => {
                    abi.receive = Some(r);
                }
                AbiItem::Error => {
                    // Errors are informational, we don't need to store them
                }
            }
        }

        Ok(abi)
    }

    /// Gets a function by name.
    pub fn function(&self, name: &str) -> Result<&AbiFunction> {
        self.functions
            .get(name)
            .and_then(|funcs| funcs.first())
            .ok_or_else(|| Error::Abi(format!("function '{}' not found", name)))
    }

    /// Gets all overloads of a function by name.
    pub fn functions(&self, name: &str) -> Option<&Vec<AbiFunction>> {
        self.functions.get(name)
    }

    /// Gets an event by name.
    pub fn event(&self, name: &str) -> Result<&AbiEvent> {
        self.events
            .get(name)
            .and_then(|events| events.first())
            .ok_or_else(|| Error::Abi(format!("event '{}' not found", name)))
    }

    /// Gets all overloads of an event by name.
    pub fn events(&self, name: &str) -> Option<&Vec<AbiEvent>> {
        self.events.get(name)
    }

    /// Gets the constructor.
    pub fn constructor(&self) -> Option<&AbiConstructor> {
        self.constructor.as_ref()
    }
}

impl AbiFunction {
    /// Computes the function selector (first 4 bytes of keccak256 hash of signature).
    pub fn selector(&self) -> [u8; 4] {
        let sig = self.signature();
        let hash = keccak256(sig.as_bytes());
        let mut selector = [0u8; 4];
        selector.copy_from_slice(&hash[..4]);
        selector
    }

    /// Returns the function signature (e.g., "transfer(address,uint256)").
    pub fn signature(&self) -> String {
        let params: Vec<String> = self.inputs.iter().map(|p| p.canonical_type()).collect();
        format!("{}({})", self.name, params.join(","))
    }

    /// Encodes a function call with the given arguments.
    pub fn encode(&self, args: impl Tokenize) -> Result<Vec<u8>> {
        let tokens = args.into_tokens();
        if tokens.len() != self.inputs.len() {
            return Err(Error::Abi(format!(
                "expected {} arguments, got {}",
                self.inputs.len(),
                tokens.len()
            )));
        }

        let mut data = self.selector().to_vec();
        let encoded = encode_tokens(&tokens, &self.inputs)?;
        data.extend(encoded);
        Ok(data)
    }

    /// Decodes the return value of a function call.
    pub fn decode_output<T: Detokenize>(&self, data: &[u8]) -> Result<T> {
        let tokens = decode_tokens(data, &self.outputs)?;
        T::from_tokens(tokens)
    }
}

impl AbiEvent {
    /// Computes the event topic (keccak256 hash of signature).
    pub fn topic(&self) -> H256 {
        if self.anonymous {
            return H256::ZERO;
        }
        let sig = self.signature();
        H256::from_bytes(keccak256(sig.as_bytes()))
    }

    /// Returns the event signature (e.g., "Transfer(address,address,uint256)").
    pub fn signature(&self) -> String {
        let params: Vec<String> = self.inputs.iter().map(|p| p.canonical_type()).collect();
        format!("{}({})", self.name, params.join(","))
    }
}

impl AbiParam {
    /// Returns the canonical type string for the parameter.
    pub fn canonical_type(&self) -> String {
        if self.param_type.starts_with("tuple") {
            let components: Vec<String> =
                self.components.iter().map(|c| c.canonical_type()).collect();
            let tuple_type = format!("({})", components.join(","));
            if self.param_type.ends_with("[]") {
                format!("{}[]", tuple_type)
            } else if self.param_type.contains('[') {
                // Fixed size array like tuple[3]
                let bracket_pos = self.param_type.find('[').unwrap();
                format!("{}{}", tuple_type, &self.param_type[bracket_pos..])
            } else {
                tuple_type
            }
        } else {
            self.param_type.clone()
        }
    }
}

impl AbiEventParam {
    /// Returns the canonical type string for the parameter.
    pub fn canonical_type(&self) -> String {
        if self.param_type.starts_with("tuple") {
            let components: Vec<String> =
                self.components.iter().map(|c| c.canonical_type()).collect();
            let tuple_type = format!("({})", components.join(","));
            if self.param_type.ends_with("[]") {
                format!("{}[]", tuple_type)
            } else if self.param_type.contains('[') {
                let bracket_pos = self.param_type.find('[').unwrap();
                format!("{}{}", tuple_type, &self.param_type[bracket_pos..])
            } else {
                tuple_type
            }
        } else {
            self.param_type.clone()
        }
    }
}

/// Encodes tokens according to ABI specification.
pub fn encode_tokens(tokens: &[Token], params: &[AbiParam]) -> Result<Vec<u8>> {
    if tokens.len() != params.len() {
        return Err(Error::Abi(format!(
            "token count mismatch: {} tokens, {} params",
            tokens.len(),
            params.len()
        )));
    }

    // Calculate head and tail parts
    let mut head = Vec::new();
    let mut tail = Vec::new();

    for (token, param) in tokens.iter().zip(params.iter()) {
        if is_dynamic_type(&param.param_type) {
            // Dynamic type: head contains offset, tail contains data
            let offset = 32 * params.len() + tail.len();
            head.extend(encode_uint(&U256::from(offset)));
            tail.extend(encode_token(token, param)?);
        } else {
            // Static type: head contains data directly
            head.extend(encode_token(token, param)?);
        }
    }

    head.extend(tail);
    Ok(head)
}

/// Decodes tokens from ABI-encoded data.
pub fn decode_tokens(data: &[u8], params: &[AbiParam]) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut offset = 0;

    for param in params {
        let (token, consumed) = decode_token(data, offset, param)?;
        tokens.push(token);
        if is_dynamic_type(&param.param_type) {
            offset += 32; // Only consume the offset pointer
        } else {
            offset += consumed;
        }
    }

    Ok(tokens)
}

/// Checks if a type is dynamic (variable length).
fn is_dynamic_type(type_str: &str) -> bool {
    type_str == "string"
        || type_str == "bytes"
        || type_str.ends_with("[]")
        || type_str.starts_with("tuple")
}

/// Encodes a single token.
fn encode_token(token: &Token, param: &AbiParam) -> Result<Vec<u8>> {
    match token {
        Token::Address(addr) => Ok(encode_address(addr)),
        Token::Uint(v) => Ok(encode_uint(v)),
        Token::Int(v) => Ok(encode_int(v)),
        Token::Bool(b) => Ok(encode_bool(*b)),
        Token::FixedBytes(bytes) => encode_fixed_bytes(bytes, &param.param_type),
        Token::Bytes(bytes) => Ok(encode_bytes(bytes)),
        Token::String(s) => Ok(encode_string(s)),
        Token::Array(items) => encode_array(items, param),
        Token::FixedArray(items) => encode_fixed_array(items, param),
        Token::Tuple(items) => encode_tuple(items, &param.components),
    }
}

/// Decodes a single token from data at the given offset.
fn decode_token(data: &[u8], offset: usize, param: &AbiParam) -> Result<(Token, usize)> {
    let type_str = &param.param_type;

    if type_str == "address" {
        let (addr, consumed) = decode_address(data, offset)?;
        Ok((Token::Address(addr), consumed))
    } else if type_str.starts_with("uint") {
        let (v, consumed) = decode_uint(data, offset)?;
        Ok((Token::Uint(v), consumed))
    } else if type_str.starts_with("int") {
        let (v, consumed) = decode_uint(data, offset)?;
        Ok((Token::Int(v), consumed))
    } else if type_str == "bool" {
        let (b, consumed) = decode_bool(data, offset)?;
        Ok((Token::Bool(b), consumed))
    } else if type_str.starts_with("bytes") && type_str.len() > 5 && !type_str.ends_with("[]") {
        // Fixed bytes (bytes1 to bytes32)
        let size: usize = type_str[5..]
            .parse()
            .map_err(|_| Error::Abi(format!("invalid fixed bytes type: {}", type_str)))?;
        let (bytes, consumed) = decode_fixed_bytes(data, offset, size)?;
        Ok((Token::FixedBytes(bytes), consumed))
    } else if type_str == "bytes" {
        let (bytes, consumed) = decode_bytes(data, offset)?;
        Ok((Token::Bytes(bytes), consumed))
    } else if type_str == "string" {
        let (s, consumed) = decode_string(data, offset)?;
        Ok((Token::String(s), consumed))
    } else if type_str.ends_with("[]") {
        let (arr, consumed) = decode_array(data, offset, param)?;
        Ok((Token::Array(arr), consumed))
    } else if type_str.starts_with("tuple") {
        let (tuple, consumed) = decode_tuple(data, offset, &param.components)?;
        Ok((Token::Tuple(tuple), consumed))
    } else {
        Err(Error::Abi(format!("unsupported type: {}", type_str)))
    }
}

// Encoding helpers

fn encode_address(addr: &Address) -> Vec<u8> {
    let mut result = vec![0u8; 32];
    result[12..].copy_from_slice(addr.as_bytes());
    result
}

fn encode_uint(v: &U256) -> Vec<u8> {
    let mut result = vec![0u8; 32];
    v.to_big_endian(&mut result);
    result
}

fn encode_int(v: &U256) -> Vec<u8> {
    encode_uint(v)
}

fn encode_bool(b: bool) -> Vec<u8> {
    let mut result = vec![0u8; 32];
    if b {
        result[31] = 1;
    }
    result
}

fn encode_fixed_bytes(bytes: &[u8], type_str: &str) -> Result<Vec<u8>> {
    let size: usize = type_str
        .strip_prefix("bytes")
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::Abi(format!("invalid fixed bytes type: {}", type_str)))?;

    if bytes.len() > size {
        return Err(Error::Abi(format!(
            "bytes too long for {}: {} > {}",
            type_str,
            bytes.len(),
            size
        )));
    }

    let mut result = vec![0u8; 32];
    result[..bytes.len()].copy_from_slice(bytes);
    Ok(result)
}

fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut result = encode_uint(&U256::from(bytes.len()));
    result.extend(bytes);
    // Pad to 32-byte boundary
    let padding = (32 - (bytes.len() % 32)) % 32;
    result.extend(vec![0u8; padding]);
    result
}

fn encode_string(s: &str) -> Vec<u8> {
    encode_bytes(s.as_bytes())
}

fn encode_array(items: &[Token], param: &AbiParam) -> Result<Vec<u8>> {
    let element_type = param
        .param_type
        .strip_suffix("[]")
        .ok_or_else(|| Error::Abi("invalid array type".to_string()))?;

    let element_param = AbiParam {
        name: String::new(),
        param_type: element_type.to_string(),
        components: param.components.clone(),
    };

    let mut result = encode_uint(&U256::from(items.len()));
    let params: Vec<AbiParam> = (0..items.len()).map(|_| element_param.clone()).collect();
    result.extend(encode_tokens(items, &params)?);
    Ok(result)
}

fn encode_fixed_array(items: &[Token], param: &AbiParam) -> Result<Vec<u8>> {
    // Extract element type from something like "uint256[3]"
    let bracket_pos = param
        .param_type
        .find('[')
        .ok_or_else(|| Error::Abi("invalid fixed array type".to_string()))?;
    let element_type = &param.param_type[..bracket_pos];

    let element_param = AbiParam {
        name: String::new(),
        param_type: element_type.to_string(),
        components: param.components.clone(),
    };

    let params: Vec<AbiParam> = (0..items.len()).map(|_| element_param.clone()).collect();
    encode_tokens(items, &params)
}

fn encode_tuple(items: &[Token], components: &[AbiParam]) -> Result<Vec<u8>> {
    encode_tokens(items, components)
}

// Decoding helpers

fn decode_address(data: &[u8], offset: usize) -> Result<(Address, usize)> {
    if offset + 32 > data.len() {
        return Err(Error::Abi("insufficient data for address".to_string()));
    }
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&data[offset + 12..offset + 32]);
    Ok((Address::from_bytes(bytes), 32))
}

fn decode_uint(data: &[u8], offset: usize) -> Result<(U256, usize)> {
    if offset + 32 > data.len() {
        return Err(Error::Abi("insufficient data for uint".to_string()));
    }
    let v = U256::from_big_endian(&data[offset..offset + 32]);
    Ok((v, 32))
}

fn decode_bool(data: &[u8], offset: usize) -> Result<(bool, usize)> {
    if offset + 32 > data.len() {
        return Err(Error::Abi("insufficient data for bool".to_string()));
    }
    let b = data[offset + 31] != 0;
    Ok((b, 32))
}

fn decode_fixed_bytes(data: &[u8], offset: usize, size: usize) -> Result<(Vec<u8>, usize)> {
    if offset + 32 > data.len() {
        return Err(Error::Abi("insufficient data for fixed bytes".to_string()));
    }
    let bytes = data[offset..offset + size].to_vec();
    Ok((bytes, 32))
}

fn decode_bytes(data: &[u8], offset: usize) -> Result<(Vec<u8>, usize)> {
    // First, read the offset pointer
    if offset + 32 > data.len() {
        return Err(Error::Abi("insufficient data for bytes offset".to_string()));
    }
    let data_offset = U256::from_big_endian(&data[offset..offset + 32]).as_usize();

    // Then read length at the offset
    if data_offset + 32 > data.len() {
        return Err(Error::Abi("insufficient data for bytes length".to_string()));
    }
    let length = U256::from_big_endian(&data[data_offset..data_offset + 32]).as_usize();

    // Then read the actual bytes
    if data_offset + 32 + length > data.len() {
        return Err(Error::Abi(
            "insufficient data for bytes content".to_string(),
        ));
    }
    let bytes = data[data_offset + 32..data_offset + 32 + length].to_vec();

    Ok((bytes, 32))
}

fn decode_string(data: &[u8], offset: usize) -> Result<(String, usize)> {
    let (bytes, consumed) = decode_bytes(data, offset)?;
    let s = String::from_utf8(bytes).map_err(|e| Error::Abi(format!("invalid UTF-8: {}", e)))?;
    Ok((s, consumed))
}

fn decode_array(data: &[u8], offset: usize, param: &AbiParam) -> Result<(Vec<Token>, usize)> {
    // Read offset pointer
    if offset + 32 > data.len() {
        return Err(Error::Abi("insufficient data for array offset".to_string()));
    }
    let data_offset = U256::from_big_endian(&data[offset..offset + 32]).as_usize();

    // Read length
    if data_offset + 32 > data.len() {
        return Err(Error::Abi("insufficient data for array length".to_string()));
    }
    let length = U256::from_big_endian(&data[data_offset..data_offset + 32]).as_usize();

    // Get element type
    let element_type = param
        .param_type
        .strip_suffix("[]")
        .ok_or_else(|| Error::Abi("invalid array type".to_string()))?;

    let element_param = AbiParam {
        name: String::new(),
        param_type: element_type.to_string(),
        components: param.components.clone(),
    };

    // Decode elements
    let mut items = Vec::new();
    let mut elem_offset = data_offset + 32;
    for _ in 0..length {
        let (token, consumed) = decode_token(data, elem_offset, &element_param)?;
        items.push(token);
        elem_offset += consumed;
    }

    Ok((items, 32))
}

fn decode_tuple(
    data: &[u8],
    offset: usize,
    components: &[AbiParam],
) -> Result<(Vec<Token>, usize)> {
    let tokens = decode_tokens(&data[offset..], components)?;
    let consumed = components.len() * 32; // Simplified - doesn't account for dynamic types
    Ok((tokens, consumed))
}

// Internal ABI item type for JSON parsing

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum AbiItem {
    Function(AbiFunction),
    Event(AbiEvent),
    Constructor(AbiConstructor),
    Fallback(AbiFallback),
    Receive(AbiReceive),
    #[serde(other)]
    Error,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_abi() {
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
        assert_eq!(func.inputs.len(), 2);
        assert_eq!(func.outputs.len(), 1);
    }

    #[test]
    fn test_function_selector() {
        let func = AbiFunction {
            name: "transfer".to_string(),
            inputs: vec![
                AbiParam {
                    name: "to".to_string(),
                    param_type: "address".to_string(),
                    components: vec![],
                },
                AbiParam {
                    name: "amount".to_string(),
                    param_type: "uint256".to_string(),
                    components: vec![],
                },
            ],
            outputs: vec![],
            state_mutability: StateMutability::NonPayable,
        };

        let selector = func.selector();
        // transfer(address,uint256) = 0xa9059cbb
        assert_eq!(selector, [0xa9, 0x05, 0x9c, 0xbb]);
    }

    #[test]
    fn test_encode_address() {
        let addr = Address::from_hex("0x1234567890123456789012345678901234567890").unwrap();
        let encoded = encode_address(&addr);
        assert_eq!(encoded.len(), 32);
        assert_eq!(&encoded[12..], addr.as_bytes());
    }

    #[test]
    fn test_encode_uint() {
        let v = U256::from(1000);
        let encoded = encode_uint(&v);
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded[31], 0xe8);
        assert_eq!(encoded[30], 0x03);
    }

    #[test]
    fn test_encode_bool() {
        let encoded_true = encode_bool(true);
        let encoded_false = encode_bool(false);
        assert_eq!(encoded_true[31], 1);
        assert_eq!(encoded_false[31], 0);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    // Feature: quantaureum-rust-sdk, Property 9: ABI Encoding Round-Trip
    // Validates: Requirements 4.4, 5.6
    // For any valid ABI type and corresponding Rust value, encoding with encode()
    // then decoding with decode() SHALL return the original value.

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        // Property 9: ABI Encoding Round-Trip for Address
        #[test]
        fn abi_address_roundtrip(bytes in prop::array::uniform20(any::<u8>())) {
            let addr = Address::from_bytes(bytes);
            let token = Token::Address(addr);
            let param = AbiParam {
                name: "addr".to_string(),
                param_type: "address".to_string(),
                components: vec![],
            };

            let encoded = encode_tokens(std::slice::from_ref(&token), std::slice::from_ref(&param)).unwrap();
            let decoded = decode_tokens(&encoded, std::slice::from_ref(&param)).unwrap();

            prop_assert_eq!(decoded.len(), 1);
            prop_assert_eq!(&decoded[0], &token);
        }

        // Property 9: ABI Encoding Round-Trip for Uint256
        #[test]
        fn abi_uint256_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
            let value = U256::from_big_endian(&bytes);
            let token = Token::Uint(value);
            let param = AbiParam {
                name: "value".to_string(),
                param_type: "uint256".to_string(),
                components: vec![],
            };

            let encoded = encode_tokens(std::slice::from_ref(&token), std::slice::from_ref(&param)).unwrap();
            let decoded = decode_tokens(&encoded, std::slice::from_ref(&param)).unwrap();

            prop_assert_eq!(decoded.len(), 1);
            prop_assert_eq!(&decoded[0], &token);
        }

        // Property 9: ABI Encoding Round-Trip for Bool
        #[test]
        fn abi_bool_roundtrip(b in any::<bool>()) {
            let token = Token::Bool(b);
            let param = AbiParam {
                name: "flag".to_string(),
                param_type: "bool".to_string(),
                components: vec![],
            };

            let encoded = encode_tokens(std::slice::from_ref(&token), std::slice::from_ref(&param)).unwrap();
            let decoded = decode_tokens(&encoded, std::slice::from_ref(&param)).unwrap();

            prop_assert_eq!(decoded.len(), 1);
            prop_assert_eq!(&decoded[0], &token);
        }

        // Property 9: ABI Encoding Round-Trip for Fixed Bytes (bytes32)
        #[test]
        fn abi_bytes32_roundtrip(bytes in prop::array::uniform32(any::<u8>())) {
            let token = Token::FixedBytes(bytes.to_vec());
            let param = AbiParam {
                name: "data".to_string(),
                param_type: "bytes32".to_string(),
                components: vec![],
            };

            let encoded = encode_tokens(std::slice::from_ref(&token), std::slice::from_ref(&param)).unwrap();
            let decoded = decode_tokens(&encoded, std::slice::from_ref(&param)).unwrap();

            prop_assert_eq!(decoded.len(), 1);
            if let Token::FixedBytes(decoded_bytes) = &decoded[0] {
                prop_assert_eq!(decoded_bytes.as_slice(), &bytes[..]);
            } else {
                prop_assert!(false, "expected FixedBytes token");
            }
        }

        // Property 9: ABI Encoding Round-Trip for Multiple Parameters
        #[test]
        fn abi_multiple_params_roundtrip(
            addr_bytes in prop::array::uniform20(any::<u8>()),
            value_bytes in prop::array::uniform32(any::<u8>()),
            flag in any::<bool>()
        ) {
            let addr = Address::from_bytes(addr_bytes);
            let value = U256::from_big_endian(&value_bytes);

            let tokens = vec![
                Token::Address(addr),
                Token::Uint(value),
                Token::Bool(flag),
            ];

            let params = vec![
                AbiParam {
                    name: "to".to_string(),
                    param_type: "address".to_string(),
                    components: vec![],
                },
                AbiParam {
                    name: "amount".to_string(),
                    param_type: "uint256".to_string(),
                    components: vec![],
                },
                AbiParam {
                    name: "approved".to_string(),
                    param_type: "bool".to_string(),
                    components: vec![],
                },
            ];

            let encoded = encode_tokens(&tokens, &params).unwrap();
            let decoded = decode_tokens(&encoded, &params).unwrap();

            prop_assert_eq!(decoded.len(), 3);
            prop_assert_eq!(&decoded[0], &tokens[0]);
            prop_assert_eq!(&decoded[1], &tokens[1]);
            prop_assert_eq!(&decoded[2], &tokens[2]);
        }
    }
}
