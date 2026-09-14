# Quantaureum Python SDK source, version 1.0.0.
"""ABI encoding and decoding utilities for the SDK.

Property 6: ABI Encoding Round-Trip
For any valid ABI types and values, decode_abi(encode_abi(types, values)) should
equal the original values.
Validates: Requirements 5.6, 4.4
"""

from typing import Any, Callable, Dict, List, Tuple, Union, cast

import eth_abi
from eth_abi.exceptions import DecodingError, EncodingError

from ..exceptions import ValidationError
from .hash import keccak256

# eth_abi doesn't have proper type stubs, so we use getattr to avoid mypy errors
_eth_abi_encode_raw: Any = getattr(eth_abi, "encode")
_eth_abi_decode_raw: Any = getattr(eth_abi, "decode")

eth_abi_encode: Callable[[List[str], List[Any]], bytes] = cast(
    Callable[[List[str], List[Any]], bytes], _eth_abi_encode_raw
)
eth_abi_decode: Callable[[List[str], bytes], Tuple[Any, ...]] = cast(
    Callable[[List[str], bytes], Tuple[Any, ...]], _eth_abi_decode_raw
)


def encode_abi(types: List[str], values: List[Any]) -> str:
    """ABI encode values according to the specified types.

    Args:
        types: List of ABI type strings (e.g., ['uint256', 'address', 'bool']).
        values: List of values to encode.

    Returns:
        The ABI-encoded data as a hex string with 0x prefix.

    Raises:
        ValidationError: If encoding fails.

    Examples:
        >>> encode_abi(['uint256', 'address'], [100, '0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b1'])
        '0x0000000000000000000000000000000000000000000000000000000000000064000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f1b2b1'
    """
    if not isinstance(types, list):
        raise ValidationError(
            message=f"Expected list for types, got {type(types).__name__}",
            field="types",
            value=types,
            expected="list of type strings",
        )

    if not isinstance(values, list):
        raise ValidationError(
            message=f"Expected list for values, got {type(values).__name__}",
            field="values",
            value=values,
            expected="list of values",
        )

    if len(types) != len(values):
        raise ValidationError(
            message=f"Types and values length mismatch: {len(types)} vs {len(values)}",
            field="values",
            value=values,
            expected=f"list of {len(types)} values",
        )

    try:
        encoded = eth_abi_encode(types, values)
        return "0x" + encoded.hex()
    except EncodingError as e:
        raise ValidationError(
            message=f"ABI encoding failed: {e}",
            field="values",
            value=values,
            expected="valid values for the specified types",
        ) from e
    except Exception as e:
        raise ValidationError(
            message=f"ABI encoding failed: {e}",
            field="values",
            value=values,
            expected="valid values for the specified types",
        ) from e


def decode_abi(types: List[str], data: Union[str, bytes]) -> Tuple[Any, ...]:
    """ABI decode data according to the specified types.

    Args:
        types: List of ABI type strings.
        data: The ABI-encoded data as hex string or bytes.

    Returns:
        A tuple of decoded values.

    Raises:
        ValidationError: If decoding fails.

    Examples:
        >>> decode_abi(['uint256', 'address'], '0x0000...0064000...b2b1')
        (100, '0x742d35Cc6634C0532925a3b844Bc9e7595f1b2b1')
    """
    if not isinstance(types, list):
        raise ValidationError(
            message=f"Expected list for types, got {type(types).__name__}",
            field="types",
            value=types,
            expected="list of type strings",
        )

    # Convert hex string to bytes
    if isinstance(data, str):
        if data.startswith(("0x", "0X")):
            data = data[2:]
        try:
            data = bytes.fromhex(data)
        except ValueError as e:
            raise ValidationError(
                message=f"Invalid hex data: {e}",
                field="data",
                value=data,
                expected="valid hex string",
            ) from e
    elif not isinstance(data, bytes):
        raise ValidationError(
            message=f"Expected str or bytes for data, got {type(data).__name__}",
            field="data",
            value=data,
            expected="hex string or bytes",
        )

    try:
        decoded = eth_abi_decode(types, data)
        return decoded
    except DecodingError as e:
        raise ValidationError(
            message=f"ABI decoding failed: {e}",
            field="data",
            value=data,
            expected="valid ABI-encoded data",
        ) from e
    except Exception as e:
        raise ValidationError(
            message=f"ABI decoding failed: {e}",
            field="data",
            value=data,
            expected="valid ABI-encoded data",
        ) from e


def encode_function_data(
    abi: List[Dict[str, Any]],
    function_name: str,
    args: List[Any],
) -> str:
    """Encode a function call with its arguments.

    Args:
        abi: The contract ABI.
        function_name: The name of the function to call.
        args: The arguments to pass to the function.

    Returns:
        The encoded function call data as a hex string with 0x prefix.

    Raises:
        ValidationError: If encoding fails or function not found.

    Examples:
        >>> abi = [{'type': 'function', 'name': 'transfer', 'inputs': [...]}]
        >>> encode_function_data(abi, 'transfer', ['0x...', 100])
        '0xa9059cbb...'
    """
    # Find the function in the ABI
    function_abi = None
    for item in abi:
        if item.get("type") == "function" and item.get("name") == function_name:
            function_abi = item
            break

    if function_abi is None:
        raise ValidationError(
            message=f"Function '{function_name}' not found in ABI",
            field="function_name",
            value=function_name,
            expected="function name present in ABI",
        )

    # Get input types
    inputs = function_abi.get("inputs", [])
    types = [inp["type"] for inp in inputs]

    if len(args) != len(types):
        raise ValidationError(
            message=f"Expected {len(types)} arguments, got {len(args)}",
            field="args",
            value=args,
            expected=f"list of {len(types)} arguments",
        )

    # Compute function selector
    signature = _get_function_signature(function_name, inputs)
    selector = keccak256(signature)[:10]  # First 4 bytes (8 hex chars + 0x)

    # Encode arguments
    if types:
        encoded_args = encode_abi(types, args)
        return selector + encoded_args[2:]  # Remove 0x from encoded args
    else:
        return selector


def decode_function_result(
    abi: List[Dict[str, Any]],
    function_name: str,
    data: Union[str, bytes],
) -> Any:
    """Decode a function call result.

    Args:
        abi: The contract ABI.
        function_name: The name of the function.
        data: The encoded result data.

    Returns:
        The decoded result. Returns a single value if there's one output,
        or a tuple if there are multiple outputs.

    Raises:
        ValidationError: If decoding fails or function not found.
    """
    # Find the function in the ABI
    function_abi = None
    for item in abi:
        if item.get("type") == "function" and item.get("name") == function_name:
            function_abi = item
            break

    if function_abi is None:
        raise ValidationError(
            message=f"Function '{function_name}' not found in ABI",
            field="function_name",
            value=function_name,
            expected="function name present in ABI",
        )

    # Get output types
    outputs = function_abi.get("outputs", [])
    types = [out["type"] for out in outputs]

    if not types:
        return None

    # Decode the result
    decoded = decode_abi(types, data)

    # Return single value if only one output
    if len(decoded) == 1:
        return decoded[0]
    return decoded


def _get_function_signature(name: str, inputs: List[Dict[str, Any]]) -> str:
    """Get the canonical function signature.

    Args:
        name: The function name.
        inputs: The function inputs from ABI.

    Returns:
        The canonical signature (e.g., 'transfer(address,uint256)').
    """
    types = [_get_canonical_type(inp) for inp in inputs]
    return f"{name}({','.join(types)})"


def _get_canonical_type(param: Dict[str, Any]) -> str:
    """Get the canonical type string for an ABI parameter.

    Handles tuple types (structs) recursively.
    """
    param_type: str = str(param["type"])

    if param_type == "tuple":
        # Handle struct types
        components = param.get("components", [])
        inner_types = [_get_canonical_type(c) for c in components]
        return f"({','.join(inner_types)})"
    elif param_type.startswith("tuple["):
        # Handle array of structs
        components = param.get("components", [])
        inner_types = [_get_canonical_type(c) for c in components]
        array_suffix = param_type[5:]  # Get the array part (e.g., "[]" or "[5]")
        return f"({','.join(inner_types)}){array_suffix}"
    else:
        return param_type


def encode_packed(*args: Tuple[str, Any]) -> str:
    """Encode values using non-standard packed encoding.

    This is similar to Solidity's abi.encodePacked().

    Args:
        *args: Tuples of (type, value) pairs.

    Returns:
        The packed encoded data as a hex string with 0x prefix.

    Examples:
        >>> encode_packed(('address', '0x...'), ('uint256', 100))
        '0x...'
    """
    result = b""

    for type_str, value in args:
        if type_str == "address":
            # Address is 20 bytes
            if isinstance(value, str):
                if value.startswith(("0x", "0X")):
                    value = value[2:]
                result += bytes.fromhex(value)
            else:
                raise ValidationError(
                    message=f"Invalid address value: {value}",
                    field="value",
                    value=value,
                    expected="hex string",
                )
        elif type_str.startswith("uint"):
            # Get bit size
            bits = int(type_str[4:]) if len(type_str) > 4 else 256
            byte_size = bits // 8
            if isinstance(value, int):
                result += value.to_bytes(byte_size, "big")
            else:
                raise ValidationError(
                    message=f"Invalid uint value: {value}",
                    field="value",
                    value=value,
                    expected="integer",
                )
        elif type_str.startswith("int"):
            # Get bit size
            bits = int(type_str[3:]) if len(type_str) > 3 else 256
            byte_size = bits // 8
            if isinstance(value, int):
                result += value.to_bytes(byte_size, "big", signed=True)
            else:
                raise ValidationError(
                    message=f"Invalid int value: {value}",
                    field="value",
                    value=value,
                    expected="integer",
                )
        elif type_str.startswith("bytes"):
            if type_str == "bytes":
                # Dynamic bytes
                if isinstance(value, bytes):
                    result += value
                elif isinstance(value, str):
                    if value.startswith(("0x", "0X")):
                        value = value[2:]
                    result += bytes.fromhex(value)
                else:
                    raise ValidationError(
                        message=f"Invalid bytes value: {value}",
                        field="value",
                        value=value,
                        expected="bytes or hex string",
                    )
            else:
                # Fixed size bytes (bytes1, bytes32, etc.)
                size = int(type_str[5:])
                if isinstance(value, bytes):
                    if len(value) != size:
                        raise ValidationError(
                            message=f"Expected {size} bytes, got {len(value)}",
                            field="value",
                            value=value,
                            expected=f"{size} bytes",
                        )
                    result += value
                elif isinstance(value, str):
                    if value.startswith(("0x", "0X")):
                        value = value[2:]
                    value_bytes = bytes.fromhex(value)
                    if len(value_bytes) != size:
                        raise ValidationError(
                            message=f"Expected {size} bytes, got {len(value_bytes)}",
                            field="value",
                            value=value,
                            expected=f"{size} bytes",
                        )
                    result += value_bytes
                else:
                    raise ValidationError(
                        message=f"Invalid bytes value: {value}",
                        field="value",
                        value=value,
                        expected="bytes or hex string",
                    )
        elif type_str == "string":
            if isinstance(value, str):
                result += value.encode("utf-8")
            else:
                raise ValidationError(
                    message=f"Invalid string value: {value}",
                    field="value",
                    value=value,
                    expected="string",
                )
        elif type_str == "bool":
            if isinstance(value, bool):
                result += b"\x01" if value else b"\x00"
            else:
                raise ValidationError(
                    message=f"Invalid bool value: {value}",
                    field="value",
                    value=value,
                    expected="boolean",
                )
        else:
            raise ValidationError(
                message=f"Unsupported type for packed encoding: {type_str}",
                field="type",
                value=type_str,
                expected="supported ABI type",
            )

    return "0x" + result.hex()


__all__ = [
    "encode_abi",
    "decode_abi",
    "encode_function_data",
    "decode_function_result",
    "encode_packed",
]
