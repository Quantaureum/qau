# Quantaureum Python SDK source, version 1.0.0.
"""Input validation utilities for the SDK.

Property 9: Invalid Input Validation
For any invalid input (wrong type, malformed data), the SDK should raise a
ValidationError with a descriptive message.
Validates: Requirements 7.3

This module provides validation functions for all public API inputs including:
- Addresses
- Transaction hashes
- Block numbers/tags
- Hex strings
- Numeric values
- ABI types
"""

from typing import Any, Dict, List, Optional, Sequence, Union
import re

from ..exceptions import ValidationError


# Regex patterns for validation
ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
TX_HASH_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")
BLOCK_HASH_PATTERN = re.compile(r"^0x[0-9a-fA-F]{64}$")
HEX_PATTERN = re.compile(r"^0x[0-9a-fA-F]*$")
VALID_BLOCK_TAGS = {"latest", "earliest", "pending", "safe", "finalized"}


def validate_address(address: Any, field_name: str = "address") -> str:
    """Validate and normalize an Ethereum-style address.

    Args:
        address: The address to validate.
        field_name: The field name for error messages.

    Returns:
        The validated address (unchanged).

    Raises:
        ValidationError: If the address is invalid.
    """
    if not isinstance(address, str):
        raise ValidationError(
            message=f"Address must be a string, got {type(address).__name__}",
            field=field_name,
            value=address,
            expected="string",
        )

    if not ADDRESS_PATTERN.match(address):
        raise ValidationError(
            message=f"Invalid address format: {address}",
            field=field_name,
            value=address,
            expected="0x followed by 40 hex characters",
        )

    return address


def validate_tx_hash(tx_hash: Any, field_name: str = "tx_hash") -> str:
    """Validate a transaction hash.

    Args:
        tx_hash: The transaction hash to validate.
        field_name: The field name for error messages.

    Returns:
        The validated transaction hash.

    Raises:
        ValidationError: If the hash is invalid.
    """
    if not isinstance(tx_hash, str):
        raise ValidationError(
            message=f"Transaction hash must be a string, got {type(tx_hash).__name__}",
            field=field_name,
            value=tx_hash,
            expected="string",
        )

    if not TX_HASH_PATTERN.match(tx_hash):
        raise ValidationError(
            message=f"Invalid transaction hash format: {tx_hash}",
            field=field_name,
            value=tx_hash,
            expected="0x followed by 64 hex characters",
        )

    return tx_hash


def validate_block_hash(block_hash: Any, field_name: str = "block_hash") -> str:
    """Validate a block hash.

    Args:
        block_hash: The block hash to validate.
        field_name: The field name for error messages.

    Returns:
        The validated block hash.

    Raises:
        ValidationError: If the hash is invalid.
    """
    if not isinstance(block_hash, str):
        raise ValidationError(
            message=f"Block hash must be a string, got {type(block_hash).__name__}",
            field=field_name,
            value=block_hash,
            expected="string",
        )

    if not BLOCK_HASH_PATTERN.match(block_hash):
        raise ValidationError(
            message=f"Invalid block hash format: {block_hash}",
            field=field_name,
            value=block_hash,
            expected="0x followed by 64 hex characters",
        )

    return block_hash


def validate_block_tag(
    block_tag: Any, field_name: str = "block_tag"
) -> Union[str, int]:
    """Validate a block tag or number.

    Args:
        block_tag: The block tag or number to validate.
        field_name: The field name for error messages.

    Returns:
        The validated block tag or number.

    Raises:
        ValidationError: If the block tag is invalid.
    """
    if isinstance(block_tag, int):
        if block_tag < 0:
            raise ValidationError(
                message=f"Block number cannot be negative: {block_tag}",
                field=field_name,
                value=block_tag,
                expected="non-negative integer",
            )
        return block_tag

    if isinstance(block_tag, str):
        # Check if it's a valid block tag
        if block_tag.lower() in VALID_BLOCK_TAGS:
            return block_tag.lower()

        # Check if it's a hex block number
        if block_tag.startswith("0x"):
            try:
                block_num = int(block_tag, 16)
                if block_num < 0:
                    raise ValidationError(
                        message=f"Block number cannot be negative: {block_tag}",
                        field=field_name,
                        value=block_tag,
                        expected="non-negative integer",
                    )
                return block_num
            except ValueError:
                pass

        raise ValidationError(
            message=f"Invalid block tag: {block_tag}",
            field=field_name,
            value=block_tag,
            expected=f"integer, hex string, or one of {VALID_BLOCK_TAGS}",
        )

    raise ValidationError(
        message=f"Block tag must be string or int, got {type(block_tag).__name__}",
        field=field_name,
        value=block_tag,
        expected="string or int",
    )


def validate_hex_string(
    hex_str: Any,
    field_name: str = "hex_string",
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    exact_length: Optional[int] = None,
) -> str:
    """Validate a hex string.

    Args:
        hex_str: The hex string to validate.
        field_name: The field name for error messages.
        min_length: Minimum length in bytes (excluding 0x prefix).
        max_length: Maximum length in bytes (excluding 0x prefix).
        exact_length: Exact length in bytes (excluding 0x prefix).

    Returns:
        The validated hex string.

    Raises:
        ValidationError: If the hex string is invalid.
    """
    if not isinstance(hex_str, str):
        raise ValidationError(
            message=f"Hex string must be a string, got {type(hex_str).__name__}",
            field=field_name,
            value=hex_str,
            expected="string",
        )

    if not HEX_PATTERN.match(hex_str):
        raise ValidationError(
            message=f"Invalid hex string format: {hex_str}",
            field=field_name,
            value=hex_str,
            expected="0x followed by hex characters",
        )

    # Calculate byte length (excluding 0x prefix)
    hex_chars = hex_str[2:]
    # Pad odd-length hex strings
    if len(hex_chars) % 2 != 0:
        hex_chars = "0" + hex_chars
    byte_length = len(hex_chars) // 2

    if exact_length is not None and byte_length != exact_length:
        raise ValidationError(
            message=f"Hex string must be exactly {exact_length} bytes, got {byte_length}",
            field=field_name,
            value=hex_str,
            expected=f"{exact_length} bytes",
        )

    if min_length is not None and byte_length < min_length:
        raise ValidationError(
            message=f"Hex string must be at least {min_length} bytes, got {byte_length}",
            field=field_name,
            value=hex_str,
            expected=f"at least {min_length} bytes",
        )

    if max_length is not None and byte_length > max_length:
        raise ValidationError(
            message=f"Hex string must be at most {max_length} bytes, got {byte_length}",
            field=field_name,
            value=hex_str,
            expected=f"at most {max_length} bytes",
        )

    return hex_str


def validate_positive_int(
    value: Any,
    field_name: str = "value",
    allow_zero: bool = True,
) -> int:
    """Validate a positive integer.

    Args:
        value: The value to validate.
        field_name: The field name for error messages.
        allow_zero: Whether to allow zero.

    Returns:
        The validated integer.

    Raises:
        ValidationError: If the value is invalid.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(
            message=f"Value must be an integer, got {type(value).__name__}",
            field=field_name,
            value=value,
            expected="integer",
        )

    if allow_zero:
        if value < 0:
            raise ValidationError(
                message=f"Value cannot be negative: {value}",
                field=field_name,
                value=value,
                expected="non-negative integer",
            )
    else:
        if value <= 0:
            raise ValidationError(
                message=f"Value must be positive: {value}",
                field=field_name,
                value=value,
                expected="positive integer",
            )

    return value


def validate_wei_value(value: Any, field_name: str = "value") -> int:
    """Validate a wei value (non-negative integer).

    Args:
        value: The wei value to validate.
        field_name: The field name for error messages.

    Returns:
        The validated wei value.

    Raises:
        ValidationError: If the value is invalid.
    """
    return validate_positive_int(value, field_name, allow_zero=True)


def validate_gas_limit(value: Any, field_name: str = "gas_limit") -> int:
    """Validate a gas limit (positive integer).

    Args:
        value: The gas limit to validate.
        field_name: The field name for error messages.

    Returns:
        The validated gas limit.

    Raises:
        ValidationError: If the value is invalid.
    """
    return validate_positive_int(value, field_name, allow_zero=False)


def validate_nonce(value: Any, field_name: str = "nonce") -> int:
    """Validate a nonce (non-negative integer).

    Args:
        value: The nonce to validate.
        field_name: The field name for error messages.

    Returns:
        The validated nonce.

    Raises:
        ValidationError: If the value is invalid.
    """
    return validate_positive_int(value, field_name, allow_zero=True)


def validate_chain_id(value: Any, field_name: str = "chain_id") -> int:
    """Validate a chain ID (positive integer).

    Args:
        value: The chain ID to validate.
        field_name: The field name for error messages.

    Returns:
        The validated chain ID.

    Raises:
        ValidationError: If the value is invalid.
    """
    return validate_positive_int(value, field_name, allow_zero=False)


def validate_private_key(
    private_key: Any, field_name: str = "private_key"
) -> Union[str, bytes]:
    """Validate a private key.

    Args:
        private_key: The private key to validate (hex string or bytes).
        field_name: The field name for error messages.

    Returns:
        The validated private key.

    Raises:
        ValidationError: If the private key is invalid.
    """
    if isinstance(private_key, bytes):
        if len(private_key) != 32:
            raise ValidationError(
                message=f"Private key must be 32 bytes, got {len(private_key)}",
                field=field_name,
                value="[redacted]",
                expected="32 bytes",
            )
        return private_key

    if isinstance(private_key, str):
        # Remove 0x prefix if present
        key_hex = private_key
        if key_hex.startswith(("0x", "0X")):
            key_hex = key_hex[2:]

        if len(key_hex) != 64:
            raise ValidationError(
                message=f"Private key must be 64 hex characters, got {len(key_hex)}",
                field=field_name,
                value="[redacted]",
                expected="64 hex characters",
            )

        # Validate hex characters
        try:
            bytes.fromhex(key_hex)
        except ValueError:
            raise ValidationError(
                message="Private key contains invalid hex characters",
                field=field_name,
                value="[redacted]",
                expected="valid hex string",
            )

        return private_key

    raise ValidationError(
        message=f"Private key must be string or bytes, got {type(private_key).__name__}",
        field=field_name,
        value="[redacted]",
        expected="string or bytes",
    )


def validate_mnemonic(mnemonic: Any, field_name: str = "mnemonic") -> str:
    """Validate a BIP-39 mnemonic phrase.

    Args:
        mnemonic: The mnemonic phrase to validate.
        field_name: The field name for error messages.

    Returns:
        The validated mnemonic (stripped).

    Raises:
        ValidationError: If the mnemonic is invalid.
    """
    if not isinstance(mnemonic, str):
        raise ValidationError(
            message=f"Mnemonic must be a string, got {type(mnemonic).__name__}",
            field=field_name,
            value="[redacted]",
            expected="string",
        )

    validated_mnemonic: str = mnemonic.strip()
    words = validated_mnemonic.split()

    # Valid BIP-39 mnemonic lengths
    valid_lengths = {12, 15, 18, 21, 24}
    if len(words) not in valid_lengths:
        raise ValidationError(
            message=f"Mnemonic must have 12, 15, 18, 21, or 24 words, got {len(words)}",
            field=field_name,
            value="[redacted]",
            expected="12, 15, 18, 21, or 24 words",
        )

    return validated_mnemonic


def validate_abi(abi: Any, field_name: str = "abi") -> List[Dict[str, Any]]:
    """Validate a contract ABI.

    Args:
        abi: The ABI to validate.
        field_name: The field name for error messages.

    Returns:
        The validated ABI.

    Raises:
        ValidationError: If the ABI is invalid.
    """
    if not isinstance(abi, list):
        raise ValidationError(
            message=f"ABI must be a list, got {type(abi).__name__}",
            field=field_name,
            value=abi,
            expected="list",
        )

    result: List[Dict[str, Any]] = []
    for i, item in enumerate(abi):
        if not isinstance(item, dict):
            raise ValidationError(
                message=f"ABI item {i} must be a dict, got {type(item).__name__}",
                field=f"{field_name}[{i}]",
                value=item,
                expected="dict",
            )

        # Check for required 'type' field
        if "type" not in item:
            raise ValidationError(
                message=f"ABI item {i} missing 'type' field",
                field=f"{field_name}[{i}]",
                value=item,
                expected="dict with 'type' field",
            )
        result.append(item)

    return result


def validate_url(url: Any, field_name: str = "url") -> str:
    """Validate a URL.

    Args:
        url: The URL to validate.
        field_name: The field name for error messages.

    Returns:
        The validated URL.

    Raises:
        ValidationError: If the URL is invalid.
    """
    if not isinstance(url, str):
        raise ValidationError(
            message=f"URL must be a string, got {type(url).__name__}",
            field=field_name,
            value=url,
            expected="string",
        )

    validated_url: str = url.strip()
    if not validated_url:
        raise ValidationError(
            message="URL cannot be empty",
            field=field_name,
            value=validated_url,
            expected="non-empty string",
        )

    # Basic URL validation
    if not (validated_url.startswith("http://") or validated_url.startswith("https://") or
            validated_url.startswith("ws://") or validated_url.startswith("wss://")):
        raise ValidationError(
            message=f"Invalid URL scheme: {validated_url}",
            field=field_name,
            value=validated_url,
            expected="http://, https://, ws://, or wss:// URL",
        )

    return validated_url


def validate_bytes(
    data: Any,
    field_name: str = "data",
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    exact_length: Optional[int] = None,
) -> bytes:
    """Validate bytes data.

    Args:
        data: The data to validate.
        field_name: The field name for error messages.
        min_length: Minimum length in bytes.
        max_length: Maximum length in bytes.
        exact_length: Exact length in bytes.

    Returns:
        The validated bytes.

    Raises:
        ValidationError: If the data is invalid.
    """
    if not isinstance(data, bytes):
        raise ValidationError(
            message=f"Data must be bytes, got {type(data).__name__}",
            field=field_name,
            value=data,
            expected="bytes",
        )

    if exact_length is not None and len(data) != exact_length:
        raise ValidationError(
            message=f"Data must be exactly {exact_length} bytes, got {len(data)}",
            field=field_name,
            value=data,
            expected=f"{exact_length} bytes",
        )

    if min_length is not None and len(data) < min_length:
        raise ValidationError(
            message=f"Data must be at least {min_length} bytes, got {len(data)}",
            field=field_name,
            value=data,
            expected=f"at least {min_length} bytes",
        )

    if max_length is not None and len(data) > max_length:
        raise ValidationError(
            message=f"Data must be at most {max_length} bytes, got {len(data)}",
            field=field_name,
            value=data,
            expected=f"at most {max_length} bytes",
        )

    return data


def validate_string(
    value: Any,
    field_name: str = "value",
    min_length: Optional[int] = None,
    max_length: Optional[int] = None,
    allow_empty: bool = True,
) -> str:
    """Validate a string value.

    Args:
        value: The value to validate.
        field_name: The field name for error messages.
        min_length: Minimum length.
        max_length: Maximum length.
        allow_empty: Whether to allow empty strings.

    Returns:
        The validated string.

    Raises:
        ValidationError: If the value is invalid.
    """
    if not isinstance(value, str):
        raise ValidationError(
            message=f"Value must be a string, got {type(value).__name__}",
            field=field_name,
            value=value,
            expected="string",
        )

    if not allow_empty and not value:
        raise ValidationError(
            message="Value cannot be empty",
            field=field_name,
            value=value,
            expected="non-empty string",
        )

    if min_length is not None and len(value) < min_length:
        raise ValidationError(
            message=f"Value must be at least {min_length} characters, got {len(value)}",
            field=field_name,
            value=value,
            expected=f"at least {min_length} characters",
        )

    if max_length is not None and len(value) > max_length:
        raise ValidationError(
            message=f"Value must be at most {max_length} characters, got {len(value)}",
            field=field_name,
            value=value,
            expected=f"at most {max_length} characters",
        )

    return value


__all__ = [
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
]
