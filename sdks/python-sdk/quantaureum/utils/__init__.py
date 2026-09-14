# Quantaureum Python SDK source, version 1.0.0.
"""Utility functions for the SDK."""

from .abi import (
    decode_abi,
    decode_function_result,
    encode_abi,
    encode_function_data,
    encode_packed,
)
from .address import (
    compute_address,
    get_address,
    is_address,
    is_checksum_address,
    zero_address,
)
from .formatting import (
    format_ether,
    format_gwei,
    format_units,
    parse_ether,
    parse_gwei,
    parse_units,
)
from .hash import event_topic, function_selector, id, keccak256, sha256
from .hex import from_hex, is_hex_string, to_hex, to_hex_with_size
from .validation import (
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
)
from .errors import (
    classify_rpc_error,
    create_contract_error_from_rpc,
    create_transaction_error_from_rpc,
    decode_custom_error,
    extract_revert_reason,
    parse_rpc_error,
)

__all__ = [
    # hex utilities
    "to_hex",
    "from_hex",
    "to_hex_with_size",
    "is_hex_string",
    # hash utilities
    "keccak256",
    "sha256",
    "id",
    "function_selector",
    "event_topic",
    # address utilities
    "is_address",
    "get_address",
    "compute_address",
    "is_checksum_address",
    "zero_address",
    # formatting utilities
    "format_ether",
    "parse_ether",
    "format_units",
    "parse_units",
    "format_gwei",
    "parse_gwei",
    # ABI utilities
    "encode_abi",
    "decode_abi",
    "encode_function_data",
    "decode_function_result",
    "encode_packed",
    # validation utilities
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
    # error utilities
    "parse_rpc_error",
    "extract_revert_reason",
    "classify_rpc_error",
    "create_transaction_error_from_rpc",
    "create_contract_error_from_rpc",
    "decode_custom_error",
]
