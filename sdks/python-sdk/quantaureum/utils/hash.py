# Quantaureum Python SDK source, version 1.0.0.
"""Hash utilities for the SDK.

Property 8: Keccak256 Hash Consistency
For any input data, keccak256 should always produce a 32-byte (64 hex chars + 0x prefix)
deterministic hash.
Validates: Requirements 5.4
"""

import hashlib
from typing import Union

from eth_hash.auto import keccak as eth_keccak

from ..exceptions import ValidationError


def keccak256(data: Union[str, bytes]) -> str:
    """Compute the Keccak-256 hash of the input data.

    Args:
        data: Input data as string (UTF-8 encoded) or bytes.

    Returns:
        The hash as a hex string with 0x prefix (66 characters total).

    Raises:
        ValidationError: If the input type is invalid.

    Examples:
        >>> keccak256(b'hello')
        '0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8'
        >>> keccak256('hello')
        '0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8'
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    elif not isinstance(data, bytes):
        raise ValidationError(
            message=f"Expected str or bytes, got {type(data).__name__}",
            field="data",
            value=data,
            expected="str or bytes",
        )

    hash_bytes = eth_keccak(data)
    return "0x" + hash_bytes.hex()


def sha256(data: Union[str, bytes]) -> str:
    """Compute the SHA-256 hash of the input data.

    Args:
        data: Input data as string (UTF-8 encoded) or bytes.

    Returns:
        The hash as a hex string with 0x prefix (66 characters total).

    Raises:
        ValidationError: If the input type is invalid.

    Examples:
        >>> sha256(b'hello')
        '0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    elif not isinstance(data, bytes):
        raise ValidationError(
            message=f"Expected str or bytes, got {type(data).__name__}",
            field="data",
            value=data,
            expected="str or bytes",
        )

    hash_bytes = hashlib.sha256(data).digest()
    return "0x" + hash_bytes.hex()


def id(text: str) -> str:
    """Compute the Keccak-256 hash of a UTF-8 string.

    This is a convenience function equivalent to keccak256(text.encode('utf-8')).
    Commonly used for computing function selectors and event topics.

    Args:
        text: The UTF-8 string to hash.

    Returns:
        The hash as a hex string with 0x prefix.

    Raises:
        ValidationError: If the input is not a string.

    Examples:
        >>> id('transfer(address,uint256)')
        '0xa9059cbb2ab09eb219583f4a59a5d0623ade346d962bcd4e46b11da047c9049b'
    """
    if not isinstance(text, str):
        raise ValidationError(
            message=f"Expected str, got {type(text).__name__}",
            field="text",
            value=text,
            expected="str",
        )

    return keccak256(text)


def function_selector(signature: str) -> str:
    """Compute the 4-byte function selector from a function signature.

    Args:
        signature: The function signature (e.g., 'transfer(address,uint256)').

    Returns:
        The 4-byte selector as a hex string with 0x prefix (10 characters).

    Examples:
        >>> function_selector('transfer(address,uint256)')
        '0xa9059cbb'
    """
    full_hash = id(signature)
    return full_hash[:10]  # 0x + 8 hex chars = 4 bytes


def event_topic(signature: str) -> str:
    """Compute the event topic from an event signature.

    Args:
        signature: The event signature (e.g., 'Transfer(address,address,uint256)').

    Returns:
        The full 32-byte topic as a hex string with 0x prefix.

    Examples:
        >>> event_topic('Transfer(address,address,uint256)')
        '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef'
    """
    return id(signature)


__all__ = ["keccak256", "sha256", "id", "function_selector", "event_topic"]
