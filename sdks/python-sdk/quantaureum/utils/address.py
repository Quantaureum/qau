# Quantaureum Python SDK source, version 1.0.0.
"""Address utilities for the SDK.

Property 7: Address Validation Correctness
For any string, is_address should return True only for valid 40-character hex strings
with 0x prefix (42 chars total).
Validates: Requirements 5.3
"""

import re
from typing import Any, Union

from eth_hash.auto import keccak as eth_keccak

from ..exceptions import ValidationError


# Regex pattern for valid Ethereum-style addresses
ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")


def is_address(address: Any) -> bool:
    """Check if a value is a valid Ethereum-style address.

    A valid address is a 42-character string starting with '0x' followed by
    40 hexadecimal characters.

    Args:
        address: The value to check.

    Returns:
        True if the value is a valid address, False otherwise.

    Examples:
        >>> is_address('0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b1')
        True
        >>> is_address('0x123')
        False
        >>> is_address(123)
        False
    """
    if not isinstance(address, str):
        return False

    return bool(ADDRESS_PATTERN.match(address))


def get_address(address: str) -> str:
    """Get the checksummed version of an address (EIP-55).

    Args:
        address: The address to checksum.

    Returns:
        The checksummed address.

    Raises:
        ValidationError: If the address is invalid.

    Examples:
        >>> get_address('0x742d35cc6634c0532925a3b844bc9e7595f1b2b1')
        '0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b1'
    """
    if not isinstance(address, str):
        raise ValidationError(
            message=f"Expected string, got {type(address).__name__}",
            field="address",
            value=address,
            expected="string",
        )

    # Normalize to lowercase and check format
    lower_address = address.lower()
    if not ADDRESS_PATTERN.match(lower_address):
        raise ValidationError(
            message=f"Invalid address format: {address}",
            field="address",
            value=address,
            expected="0x followed by 40 hex characters",
        )

    # Remove 0x prefix for hashing
    address_bytes = lower_address[2:].encode("ascii")
    hash_bytes = eth_keccak(address_bytes)
    hash_hex = hash_bytes.hex()

    # Apply EIP-55 checksum
    checksummed = "0x"
    for i, char in enumerate(lower_address[2:]):
        if char in "0123456789":
            checksummed += char
        else:
            # If the corresponding nibble in the hash is >= 8, uppercase
            if int(hash_hex[i], 16) >= 8:
                checksummed += char.upper()
            else:
                checksummed += char

    return checksummed


def compute_address(public_key: Union[str, bytes]) -> str:
    """Compute an address from a public key.

    The address is the last 20 bytes of the Keccak-256 hash of the public key.

    Args:
        public_key: The public key as hex string (with or without 0x prefix)
                   or bytes. Should be 64 bytes (uncompressed without prefix)
                   or 65 bytes (with 0x04 prefix).

    Returns:
        The checksummed address.

    Raises:
        ValidationError: If the public key is invalid.

    Examples:
        >>> compute_address('0x04...')  # 65 bytes with prefix
        '0x...'
    """
    if isinstance(public_key, str):
        # Remove 0x prefix if present
        if public_key.startswith(("0x", "0X")):
            public_key = public_key[2:]
        try:
            public_key = bytes.fromhex(public_key)
        except ValueError as e:
            raise ValidationError(
                message=f"Invalid public key hex: {e}",
                field="public_key",
                value=public_key,
                expected="valid hex string",
            ) from e

    if not isinstance(public_key, bytes):
        raise ValidationError(
            message=f"Expected str or bytes, got {type(public_key).__name__}",
            field="public_key",
            value=public_key,
            expected="str or bytes",
        )

    # Handle different public key formats
    if len(public_key) == 65:
        # Uncompressed public key with 0x04 prefix
        if public_key[0] != 0x04:
            raise ValidationError(
                message="65-byte public key must start with 0x04",
                field="public_key",
                value=public_key,
                expected="0x04 prefix for uncompressed key",
            )
        public_key = public_key[1:]  # Remove prefix
    elif len(public_key) != 64:
        raise ValidationError(
            message=f"Invalid public key length: {len(public_key)}",
            field="public_key",
            value=public_key,
            expected="64 or 65 bytes",
        )

    # Hash the public key and take last 20 bytes
    hash_bytes = eth_keccak(public_key)
    address_bytes = hash_bytes[-20:]

    # Return checksummed address
    raw_address = "0x" + address_bytes.hex()
    return get_address(raw_address)


def is_checksum_address(address: str) -> bool:
    """Check if an address has a valid EIP-55 checksum.

    Args:
        address: The address to check.

    Returns:
        True if the address has a valid checksum, False otherwise.

    Examples:
        >>> is_checksum_address('0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b1')
        True
        >>> is_checksum_address('0x742d35cc6634c0532925a3b844bc9e7595f1b2b1')
        False
    """
    if not is_address(address):
        return False

    try:
        return get_address(address) == address
    except ValidationError:
        return False


def zero_address() -> str:
    """Return the zero address.

    Returns:
        The zero address (0x0000...0000).
    """
    return "0x" + "0" * 40


__all__ = [
    "is_address",
    "get_address",
    "compute_address",
    "is_checksum_address",
    "zero_address",
]
