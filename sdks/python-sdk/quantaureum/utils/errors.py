# Quantaureum Python SDK source, version 1.0.0.
"""Error handling utilities for the SDK.

This module provides utilities for:
- Parsing RPC error responses
- Extracting transaction revert reasons
- Decoding error data from contract calls

Validates: Requirements 7.1, 7.2
"""

from typing import Any, Dict, Optional, Tuple

from ..exceptions import (
    ContractError,
    ErrorCode,
    RpcError,
    TransactionError,
)


# Standard JSON-RPC error codes
# https://www.jsonrpc.org/specification#error_object
RPC_ERROR_CODES = {
    -32700: "Parse error",
    -32600: "Invalid Request",
    -32601: "Method not found",
    -32602: "Invalid params",
    -32603: "Internal error",
}

# Ethereum-specific error codes
ETH_ERROR_CODES = {
    3: "Execution reverted",
    -32000: "Server error",
    -32001: "Resource not found",
    -32002: "Resource unavailable",
    -32003: "Transaction rejected",
    -32004: "Method not supported",
    -32005: "Limit exceeded",
}

# Error selector for standard Solidity errors
# Error(string) = keccak256("Error(string)")[:4] = 0x08c379a0
ERROR_SELECTOR = "0x08c379a0"

# Panic selector for Solidity panic errors
# Panic(uint256) = keccak256("Panic(uint256)")[:4] = 0x4e487b71
PANIC_SELECTOR = "0x4e487b71"

# Custom error selector pattern (any 4-byte selector)
CUSTOM_ERROR_MIN_LENGTH = 10  # 0x + 8 hex chars

# Panic codes
PANIC_CODES = {
    0x00: "Generic compiler panic",
    0x01: "Assertion failed",
    0x11: "Arithmetic overflow/underflow",
    0x12: "Division or modulo by zero",
    0x21: "Invalid enum value",
    0x22: "Storage byte array encoding error",
    0x31: "pop() on empty array",
    0x32: "Array index out of bounds",
    0x41: "Memory allocation overflow",
    0x51: "Zero-initialized function pointer call",
}


def parse_rpc_error(error_data: Dict[str, Any]) -> RpcError:
    """Parse an RPC error response into an RpcError exception.

    Args:
        error_data: The error object from the JSON-RPC response.

    Returns:
        An RpcError with parsed information.

    Example:
        >>> error_data = {"code": -32600, "message": "Invalid Request"}
        >>> error = parse_rpc_error(error_data)
        >>> error.rpc_code
        -32600
    """
    rpc_code = error_data.get("code", -1)
    rpc_message = error_data.get("message", "Unknown RPC error")
    rpc_data = error_data.get("data")

    # Try to get a more descriptive message
    description = RPC_ERROR_CODES.get(rpc_code) or ETH_ERROR_CODES.get(rpc_code)
    if description and rpc_message == "Unknown RPC error":
        rpc_message = description

    return RpcError(
        message=rpc_message,
        rpc_code=rpc_code,
        rpc_message=rpc_message,
        rpc_data=rpc_data,
    )


def extract_revert_reason(data: Optional[str]) -> Optional[str]:
    """Extract the revert reason from error data.

    Supports:
    - Standard Error(string) reverts
    - Panic(uint256) errors
    - Custom errors (returns hex data)

    Args:
        data: The hex-encoded error data from the RPC response.

    Returns:
        The decoded revert reason string, or None if not decodable.

    Example:
        >>> # Error("Insufficient balance")
        >>> data = "0x08c379a0...encoded_string..."
        >>> reason = extract_revert_reason(data)
        >>> reason
        'Insufficient balance'
    """
    if not data or not isinstance(data, str):
        return None

    # Normalize the data
    if not data.startswith("0x"):
        data = "0x" + data

    # Check minimum length for any error
    if len(data) < CUSTOM_ERROR_MIN_LENGTH:
        return None

    selector = data[:10].lower()

    # Standard Error(string) revert
    if selector == ERROR_SELECTOR.lower():
        return _decode_error_string(data)

    # Panic(uint256) error
    if selector == PANIC_SELECTOR.lower():
        return _decode_panic_error(data)

    # Custom error - return the selector and data
    return f"Custom error: {data}"


def _decode_error_string(data: str) -> Optional[str]:
    """Decode a standard Error(string) revert message.

    The ABI encoding for Error(string) is:
    - 4 bytes: selector (0x08c379a0)
    - 32 bytes: offset to string data (usually 0x20 = 32)
    - 32 bytes: string length
    - N bytes: string data (padded to 32-byte boundary)

    Args:
        data: The hex-encoded error data.

    Returns:
        The decoded string, or None if decoding fails.
    """
    try:
        # Remove selector (first 4 bytes = 8 hex chars + 0x)
        encoded = data[10:]

        # Need at least offset (32 bytes) + length (32 bytes) = 128 hex chars
        if len(encoded) < 128:
            return None

        # Read offset (first 32 bytes)
        offset = int(encoded[:64], 16)

        # Read string length (at offset position)
        # offset is in bytes, convert to hex position
        length_start = offset * 2
        if length_start + 64 > len(encoded):
            return None

        string_length = int(encoded[length_start : length_start + 64], 16)

        # Read string data
        data_start = length_start + 64
        data_end = data_start + string_length * 2

        if data_end > len(encoded):
            # Truncated data, read what we can
            data_end = len(encoded)

        string_hex = encoded[data_start:data_end]
        string_bytes = bytes.fromhex(string_hex)

        return string_bytes.decode("utf-8", errors="replace")

    except (ValueError, UnicodeDecodeError):
        return None


def _decode_panic_error(data: str) -> str:
    """Decode a Panic(uint256) error.

    Args:
        data: The hex-encoded panic error data.

    Returns:
        A description of the panic error.
    """
    try:
        # Remove selector (first 4 bytes = 8 hex chars + 0x)
        encoded = data[10:]

        # Read panic code (32 bytes = 64 hex chars)
        if len(encoded) < 64:
            return "Panic: unknown code"

        panic_code = int(encoded[:64], 16)
        description = PANIC_CODES.get(panic_code, f"Unknown panic code: {panic_code}")

        return f"Panic: {description}"

    except ValueError:
        return "Panic: failed to decode"


def classify_rpc_error(error: RpcError) -> Tuple[ErrorCode, str]:
    """Classify an RPC error into a specific error type.

    Args:
        error: The RpcError to classify.

    Returns:
        A tuple of (ErrorCode, reason_string).

    Example:
        >>> error = RpcError("nonce too low", -32000, "nonce too low")
        >>> code, reason = classify_rpc_error(error)
        >>> code
        ErrorCode.NONCE_TOO_LOW
    """
    message_lower = error.rpc_message.lower()

    # Check for nonce errors
    if "nonce" in message_lower:
        if "too low" in message_lower or "already known" in message_lower:
            return ErrorCode.NONCE_TOO_LOW, error.rpc_message

    # Check for insufficient funds
    if "insufficient" in message_lower and ("funds" in message_lower or "balance" in message_lower):
        return ErrorCode.INSUFFICIENT_FUNDS, error.rpc_message

    # Check for gas errors
    if "gas" in message_lower:
        if "too low" in message_lower or "limit" in message_lower or "intrinsic" in message_lower:
            return ErrorCode.GAS_TOO_LOW, error.rpc_message

    # Check for execution reverted
    if "revert" in message_lower or "execution" in message_lower:
        reason = extract_revert_reason(error.rpc_data) if isinstance(error.rpc_data, str) else None
        return ErrorCode.TRANSACTION_REVERTED, reason or error.rpc_message

    # Check for contract errors
    if error.rpc_code == 3:  # Execution reverted
        reason = extract_revert_reason(error.rpc_data) if isinstance(error.rpc_data, str) else None
        return ErrorCode.CALL_EXCEPTION, reason or error.rpc_message

    # Default to RPC error
    return ErrorCode.RPC_ERROR, error.rpc_message


def create_transaction_error_from_rpc(
    error: RpcError,
    tx_hash: Optional[str] = None,
) -> TransactionError:
    """Create a TransactionError from an RpcError.

    Args:
        error: The RpcError to convert.
        tx_hash: Optional transaction hash.

    Returns:
        A TransactionError with appropriate error code and reason.
    """
    code, reason = classify_rpc_error(error)

    return TransactionError(
        message=error.rpc_message,
        code=code,
        tx_hash=tx_hash,
        reason=reason,
    )


def create_contract_error_from_rpc(error: RpcError) -> ContractError:
    """Create a ContractError from an RpcError.

    Args:
        error: The RpcError to convert.

    Returns:
        A ContractError with decoded revert reason if available.
    """
    reason = None
    if isinstance(error.rpc_data, str):
        reason = extract_revert_reason(error.rpc_data)

    return ContractError(
        message=reason or error.rpc_message,
        code=ErrorCode.CALL_EXCEPTION,
        data=error.rpc_data if isinstance(error.rpc_data, str) else None,
    )


def decode_custom_error(
    data: str,
    error_abi: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Decode a custom error using its ABI.

    Args:
        data: The hex-encoded error data.
        error_abi: The ABI definition for the custom error.

    Returns:
        A dictionary with error name and decoded parameters,
        or None if decoding fails.

    Example:
        >>> error_abi = {
        ...     "name": "InsufficientBalance",
        ...     "inputs": [{"name": "available", "type": "uint256"}]
        ... }
        >>> result = decode_custom_error(data, error_abi)
        >>> result
        {'name': 'InsufficientBalance', 'args': {'available': 1000}}
    """
    if not data or not error_abi:
        return None

    # This is a placeholder for full ABI decoding
    # In a complete implementation, this would use the ABI decoder
    # to decode the error parameters

    try:
        selector = data[:10]
        return {
            "name": error_abi.get("name", "Unknown"),
            "selector": selector,
            "data": data[10:] if len(data) > 10 else "",
        }
    except Exception:
        return None


__all__ = [
    "parse_rpc_error",
    "extract_revert_reason",
    "classify_rpc_error",
    "create_transaction_error_from_rpc",
    "create_contract_error_from_rpc",
    "decode_custom_error",
    "RPC_ERROR_CODES",
    "ETH_ERROR_CODES",
    "PANIC_CODES",
]
