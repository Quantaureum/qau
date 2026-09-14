# Quantaureum Python SDK source, version 1.0.0.
"""Hexadecimal conversion utilities for the SDK.

Property 5: Hex Conversion Round-Trip
For any bytes object, from_hex(to_hex(data)) should equal the original data.
Validates: Requirements 5.5
"""

from typing import Union

from ..exceptions import ValidationError


def to_hex(value: Union[int, bytes]) -> str:
    """Convert an integer or bytes to a hex string with 0x prefix.

    Args:
        value: An integer or bytes object to convert.

    Returns:
        A hex string with 0x prefix.

    Raises:
        ValidationError: If the value is not an int or bytes.

    Examples:
        >>> to_hex(255)
        '0xff'
        >>> to_hex(b'\\x00\\x01\\x02')
        '0x000102'
    """
    if isinstance(value, int):
        if value < 0:
            raise ValidationError(
                message="Cannot convert negative integer to hex",
                field="value",
                value=value,
                expected="non-negative integer",
            )
        # Handle zero case
        if value == 0:
            return "0x0"
        return hex(value)
    elif isinstance(value, bytes):
        return "0x" + value.hex()
    else:
        raise ValidationError(
            message=f"Cannot convert {type(value).__name__} to hex",
            field="value",
            value=value,
            expected="int or bytes",
        )


def from_hex(hex_str: str) -> bytes:
    """Convert a hex string to bytes.

    Args:
        hex_str: A hex string, optionally with 0x prefix.

    Returns:
        The decoded bytes.

    Raises:
        ValidationError: If the hex string is invalid.

    Examples:
        >>> from_hex('0x000102')
        b'\\x00\\x01\\x02'
        >>> from_hex('ff')
        b'\\xff'
    """
    if not isinstance(hex_str, str):
        raise ValidationError(
            message=f"Expected string, got {type(hex_str).__name__}",
            field="hex_str",
            value=hex_str,
            expected="string",
        )

    # Remove 0x prefix if present
    if hex_str.startswith(("0x", "0X")):
        hex_str = hex_str[2:]

    # Handle empty string
    if not hex_str:
        return b""

    # Pad with leading zero if odd length
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str

    try:
        return bytes.fromhex(hex_str)
    except ValueError as e:
        raise ValidationError(
            message=f"Invalid hex string: {e}",
            field="hex_str",
            value=hex_str,
            expected="valid hex characters (0-9, a-f, A-F)",
        ) from e


def to_hex_with_size(value: int, byte_size: int) -> str:
    """Convert an integer to a hex string with a specific byte size.

    Args:
        value: An integer to convert.
        byte_size: The number of bytes in the output.

    Returns:
        A hex string with 0x prefix, zero-padded to the specified size.

    Raises:
        ValidationError: If the value doesn't fit in the specified size.

    Examples:
        >>> to_hex_with_size(255, 2)
        '0x00ff'
        >>> to_hex_with_size(1, 32)
        '0x0000000000000000000000000000000000000000000000000000000000000001'
    """
    if not isinstance(value, int):
        raise ValidationError(
            message=f"Expected int, got {type(value).__name__}",
            field="value",
            value=value,
            expected="int",
        )

    if value < 0:
        raise ValidationError(
            message="Cannot convert negative integer to hex",
            field="value",
            value=value,
            expected="non-negative integer",
        )

    max_value = (1 << (byte_size * 8)) - 1
    if value > max_value:
        raise ValidationError(
            message=f"Value {value} exceeds maximum for {byte_size} bytes",
            field="value",
            value=value,
            expected=f"value <= {max_value}",
        )

    hex_chars = byte_size * 2
    return "0x" + format(value, f"0{hex_chars}x")


def is_hex_string(value: str) -> bool:
    """Check if a string is a valid hex string.

    Args:
        value: The string to check.

    Returns:
        True if the string is a valid hex string, False otherwise.

    Examples:
        >>> is_hex_string('0x1234')
        True
        >>> is_hex_string('1234')
        True
        >>> is_hex_string('0xGHIJ')
        False
    """
    if not isinstance(value, str):
        return False

    # Remove 0x prefix if present
    if value.startswith(("0x", "0X")):
        value = value[2:]

    if not value:
        return True  # Empty hex string is valid

    # Check all characters are valid hex
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


__all__ = ["to_hex", "from_hex", "to_hex_with_size", "is_hex_string"]
