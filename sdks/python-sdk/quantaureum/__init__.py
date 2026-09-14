# Quantaureum Python SDK source, version 1.0.0.
"""
Quantaureum Python SDK

A Pythonic, type-safe SDK for interacting with the Quantaureum quantum-safe blockchain.

This SDK provides:
- Provider classes for connecting to Quantaureum nodes (sync and async)
- Wallet management with BIP-39 mnemonic support
- Smart contract interaction with ABI encoding/decoding
- Utility functions for formatting, hashing, and validation
- Full type hints for IDE autocompletion and type safety

Example:
    >>> from quantaureum import JsonRpcProvider, Wallet
    >>> provider = JsonRpcProvider("http://localhost:8545")
    >>> wallet = Wallet.create_random()
    >>> wallet = wallet.connect(provider)
    >>> balance = provider.get_balance(wallet.address)
"""

# Exceptions
from .exceptions import (
    ContractError,
    ErrorCode,
    NetworkError,
    QuantaureumError,
    RpcError,
    SignerError,
    TransactionError,
    ValidationError,
)

# Providers
from .providers import (
    AsyncJsonRpcProvider,
    AsyncProvider,
    JsonRpcProvider,
    Provider,
)

# Signers
from .signers import (
    DEFAULT_PATH,
    Signer,
    Wallet,
    hash_message,
    recover_message_signer,
    recover_transaction_sender,
)

# Contracts
from .contracts import (
    Contract,
    ContractEvent,
    ContractFunction,
    ContractFunctionCall,
    ErrorFragment,
    EventFragment,
    FunctionFragment,
    Interface,
)

# Types
from .types import (
    AccessListEntry,
    Block,
    BlockIdentifier,
    BlockWithTransactions,
    FeeData,
    Log,
    Network,
    TransactionReceipt,
    TransactionRequest,
    TransactionResponse,
)

# Utils
from .utils import (
    # ABI utilities
    decode_abi,
    decode_function_result,
    encode_abi,
    encode_function_data,
    encode_packed,
    # Address utilities
    compute_address,
    get_address,
    is_address,
    is_checksum_address,
    zero_address,
    # Formatting utilities
    format_ether,
    format_gwei,
    format_units,
    parse_ether,
    parse_gwei,
    parse_units,
    # Hash utilities
    event_topic,
    function_selector,
    id,
    keccak256,
    sha256,
    # Hex utilities
    from_hex,
    is_hex_string,
    to_hex,
    to_hex_with_size,
    # Validation utilities
    validate_abi,
    validate_address,
    validate_block_hash,
    validate_block_tag,
    validate_bytes,
    validate_chain_id,
    validate_gas_limit,
    validate_hex_string,
    validate_mnemonic,
    validate_nonce,
    validate_positive_int,
    validate_private_key,
    validate_string,
    validate_tx_hash,
    validate_url,
    validate_wei_value,
    # Error utilities
    classify_rpc_error,
    create_contract_error_from_rpc,
    create_transaction_error_from_rpc,
    decode_custom_error,
    extract_revert_reason,
    parse_rpc_error,
)

__version__ = "0.1.0"

__all__ = [
    # Version
    "__version__",
    # Exceptions
    "QuantaureumError",
    "RpcError",
    "TransactionError",
    "ValidationError",
    "NetworkError",
    "SignerError",
    "ContractError",
    "ErrorCode",
    # Providers
    "Provider",
    "AsyncProvider",
    "JsonRpcProvider",
    "AsyncJsonRpcProvider",
    # Signers
    "Signer",
    "Wallet",
    "DEFAULT_PATH",
    "hash_message",
    "recover_message_signer",
    "recover_transaction_sender",
    # Contracts
    "Contract",
    "ContractFunction",
    "ContractFunctionCall",
    "ContractEvent",
    "Interface",
    "FunctionFragment",
    "EventFragment",
    "ErrorFragment",
    # Types
    "Block",
    "BlockIdentifier",
    "BlockWithTransactions",
    "TransactionRequest",
    "TransactionResponse",
    "TransactionReceipt",
    "Log",
    "AccessListEntry",
    "FeeData",
    "Network",
    # ABI utilities
    "encode_abi",
    "decode_abi",
    "encode_function_data",
    "decode_function_result",
    "encode_packed",
    # Address utilities
    "is_address",
    "get_address",
    "compute_address",
    "is_checksum_address",
    "zero_address",
    # Formatting utilities
    "format_ether",
    "parse_ether",
    "format_units",
    "parse_units",
    "format_gwei",
    "parse_gwei",
    # Hash utilities
    "keccak256",
    "sha256",
    "id",
    "function_selector",
    "event_topic",
    # Hex utilities
    "to_hex",
    "from_hex",
    "to_hex_with_size",
    "is_hex_string",
    # Validation utilities
    "validate_address",
    "validate_tx_hash",
    "validate_block_hash",
    "validate_block_tag",
    "validate_hex_string",
    "validate_positive_int",
    "validate_wei_value",
    "validate_gas_limit",
    "validate_nonce",
    "validate_chain_id",
    "validate_private_key",
    "validate_mnemonic",
    "validate_abi",
    "validate_url",
    "validate_bytes",
    "validate_string",
    # Error utilities
    "parse_rpc_error",
    "extract_revert_reason",
    "classify_rpc_error",
    "create_transaction_error_from_rpc",
    "create_contract_error_from_rpc",
    "decode_custom_error",
]
