# Quantaureum Python SDK source, version 1.0.0.
"""Formatting utilities for the SDK.

Property 4: Ether Format Round-Trip
For any valid integer wei value, parse_ether(format_ether(wei)) should equal
the original wei value (within precision limits for values that can be exactly represented).
Validates: Requirements 5.1, 5.2
"""

from typing import Union

from ..exceptions import ValidationError

# Constants
WEI_PER_ETHER = 10**18
ETHER_DECIMALS = 18


def format_ether(wei: int) -> str:
    """Convert wei to ether string.

    Args:
        wei: The amount in wei (smallest unit).

    Returns:
        The amount in ether as a decimal string.

    Raises:
        ValidationError: If wei is not a valid integer.

    Examples:
        >>> format_ether(1000000000000000000)
        '1.0'
        >>> format_ether(1500000000000000000)
        '1.5'
        >>> format_ether(1)
        '0.000000000000000001'
    """
    if not isinstance(wei, int):
        raise ValidationError(
            message=f"Expected int, got {type(wei).__name__}",
            field="wei",
            value=wei,
            expected="int",
        )

    if wei < 0:
        raise ValidationError(
            message="Wei value cannot be negative",
            field="wei",
            value=wei,
            expected="non-negative integer",
        )

    # Use string manipulation for exact precision
    wei_str = str(wei)

    if len(wei_str) <= ETHER_DECIMALS:
        # Value is less than 1 ether - need to pad with leading zeros
        decimal_part = wei_str.zfill(ETHER_DECIMALS)  # Pad to exactly 18 digits
        integer_part = "0"
    else:
        # Value is 1 ether or more
        split_point = len(wei_str) - ETHER_DECIMALS
        integer_part = wei_str[:split_point]
        decimal_part = wei_str[split_point:]

    # Remove trailing zeros from decimal part but keep at least one digit
    decimal_part = decimal_part.rstrip("0") or "0"

    return f"{integer_part}.{decimal_part}"


def parse_ether(ether: str) -> int:
    """Convert ether string to wei.

    Args:
        ether: The amount in ether as a string.

    Returns:
        The amount in wei as an integer.

    Raises:
        ValidationError: If the ether string is invalid.

    Examples:
        >>> parse_ether('1.0')
        1000000000000000000
        >>> parse_ether('1.5')
        1500000000000000000
        >>> parse_ether('0.000000000000000001')
        1
    """
    if not isinstance(ether, str):
        raise ValidationError(
            message=f"Expected str, got {type(ether).__name__}",
            field="ether",
            value=ether,
            expected="str",
        )

    # Validate the string is a valid decimal
    ether = ether.strip()
    if not ether:
        raise ValidationError(
            message="Empty ether value",
            field="ether",
            value=ether,
            expected="valid decimal string",
        )

    if ether.startswith("-"):
        raise ValidationError(
            message="Ether value cannot be negative",
            field="ether",
            value=ether,
            expected="non-negative value",
        )

    # Split into integer and decimal parts
    if "." in ether:
        parts = ether.split(".")
        if len(parts) != 2:
            raise ValidationError(
                message=f"Invalid ether value: {ether}",
                field="ether",
                value=ether,
                expected="valid decimal string",
            )
        integer_part, decimal_part = parts
    else:
        integer_part = ether
        decimal_part = ""

    # Validate parts contain only digits
    if integer_part and not integer_part.isdigit():
        raise ValidationError(
            message=f"Invalid ether value: {ether}",
            field="ether",
            value=ether,
            expected="valid decimal string",
        )
    if decimal_part and not decimal_part.isdigit():
        raise ValidationError(
            message=f"Invalid ether value: {ether}",
            field="ether",
            value=ether,
            expected="valid decimal string",
        )

    # Pad or truncate decimal part to exactly ETHER_DECIMALS digits
    if len(decimal_part) <= ETHER_DECIMALS:
        decimal_part = decimal_part.ljust(ETHER_DECIMALS, "0")
    else:
        # Truncate (round down) - discard extra precision
        decimal_part = decimal_part[:ETHER_DECIMALS]

    # Combine and convert to integer
    wei_str = (integer_part or "0") + decimal_part
    return int(wei_str)


def format_units(value: int, decimals: int) -> str:
    """Format a value with custom decimal places.

    Args:
        value: The raw value (smallest unit).
        decimals: The number of decimal places.

    Returns:
        The formatted value as a decimal string.

    Raises:
        ValidationError: If inputs are invalid.

    Examples:
        >>> format_units(1000000, 6)  # USDC with 6 decimals
        '1.0'
        >>> format_units(1500000, 6)
        '1.5'
    """
    if not isinstance(value, int):
        raise ValidationError(
            message=f"Expected int, got {type(value).__name__}",
            field="value",
            value=value,
            expected="int",
        )

    if not isinstance(decimals, int) or decimals < 0:
        raise ValidationError(
            message=f"Decimals must be a non-negative integer, got {decimals}",
            field="decimals",
            value=decimals,
            expected="non-negative int",
        )

    if value < 0:
        raise ValidationError(
            message="Value cannot be negative",
            field="value",
            value=value,
            expected="non-negative integer",
        )

    if decimals == 0:
        return str(value)

    # Use string manipulation for exact precision
    value_str = str(value)

    if len(value_str) <= decimals:
        # Value is less than 1 unit - need to pad with leading zeros
        # For value=1, decimals=6: "1" -> "0.000001"
        decimal_part = value_str.zfill(decimals)  # Pad to exactly 'decimals' digits
        integer_part = "0"
    else:
        # Value is 1 unit or more
        split_point = len(value_str) - decimals
        integer_part = value_str[:split_point]
        decimal_part = value_str[split_point:]

    # Remove trailing zeros from decimal part but keep at least one digit
    decimal_part = decimal_part.rstrip("0") or "0"

    return f"{integer_part}.{decimal_part}"


def parse_units(value: Union[str, int, float], decimals: int) -> int:
    """Parse a value with custom decimal places.

    Args:
        value: The value as a string, int, or float.
        decimals: The number of decimal places.

    Returns:
        The raw value (smallest unit) as an integer.

    Raises:
        ValidationError: If inputs are invalid.

    Examples:
        >>> parse_units('1.0', 6)  # USDC with 6 decimals
        1000000
        >>> parse_units('1.5', 6)
        1500000
    """
    if not isinstance(decimals, int) or decimals < 0:
        raise ValidationError(
            message=f"Decimals must be a non-negative integer, got {decimals}",
            field="decimals",
            value=decimals,
            expected="non-negative int",
        )

    # Convert value to string
    if isinstance(value, (int, float)):
        value = str(value)
    elif not isinstance(value, str):
        raise ValidationError(
            message=f"Expected str, int, or float, got {type(value).__name__}",
            field="value",
            value=value,
            expected="str, int, or float",
        )

    value = value.strip()
    if not value:
        raise ValidationError(
            message="Empty value",
            field="value",
            value=value,
            expected="valid decimal string",
        )

    if value.startswith("-"):
        raise ValidationError(
            message="Value cannot be negative",
            field="value",
            value=value,
            expected="non-negative value",
        )

    if decimals == 0:
        # No decimal places - just parse as integer
        if "." in value:
            # Truncate decimal part
            value = value.split(".")[0]
        if not value.isdigit():
            raise ValidationError(
                message=f"Invalid value: {value}",
                field="value",
                value=value,
                expected="valid decimal string",
            )
        return int(value) if value else 0

    # Split into integer and decimal parts
    if "." in value:
        parts = value.split(".")
        if len(parts) != 2:
            raise ValidationError(
                message=f"Invalid value: {value}",
                field="value",
                value=value,
                expected="valid decimal string",
            )
        integer_part, decimal_part = parts
    else:
        integer_part = value
        decimal_part = ""

    # Validate parts contain only digits
    if integer_part and not integer_part.isdigit():
        raise ValidationError(
            message=f"Invalid value: {value}",
            field="value",
            value=value,
            expected="valid decimal string",
        )
    if decimal_part and not decimal_part.isdigit():
        raise ValidationError(
            message=f"Invalid value: {value}",
            field="value",
            value=value,
            expected="valid decimal string",
        )

    # Pad or truncate decimal part to exactly 'decimals' digits
    if len(decimal_part) <= decimals:
        decimal_part = decimal_part.ljust(decimals, "0")
    else:
        # Truncate (round down) - discard extra precision
        decimal_part = decimal_part[:decimals]

    # Combine and convert to integer
    result_str = (integer_part or "0") + decimal_part
    return int(result_str)


def format_gwei(wei: int) -> str:
    """Format wei as gwei (10^9 wei).

    Args:
        wei: The amount in wei.

    Returns:
        The amount in gwei as a decimal string.

    Examples:
        >>> format_gwei(1000000000)
        '1.0'
    """
    return format_units(wei, 9)


def parse_gwei(gwei: str) -> int:
    """Parse gwei string to wei.

    Args:
        gwei: The amount in gwei as a string.

    Returns:
        The amount in wei as an integer.

    Examples:
        >>> parse_gwei('1.0')
        1000000000
    """
    return parse_units(gwei, 9)


__all__ = [
    "format_ether",
    "parse_ether",
    "format_units",
    "parse_units",
    "format_gwei",
    "parse_gwei",
]
