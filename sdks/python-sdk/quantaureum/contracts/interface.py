# Quantaureum Python SDK source, version 1.0.0.
"""ABI Interface handling for smart contracts.

The Interface class parses contract ABIs and provides methods for encoding
function calls and decoding results.
"""

from typing import Any, Dict, List, Optional, Tuple, Union

from ..exceptions import ValidationError
from ..utils.abi import decode_abi, encode_abi
from ..utils.hash import keccak256


class FunctionFragment:
    """Represents a function in the ABI."""

    def __init__(self, abi_item: Dict[str, Any]) -> None:
        """Initialize a FunctionFragment from an ABI item.

        Args:
            abi_item: The ABI item dictionary for this function.
        """
        self.name: str = abi_item.get("name", "")
        self.inputs: List[Dict[str, Any]] = abi_item.get("inputs", [])
        self.outputs: List[Dict[str, Any]] = abi_item.get("outputs", [])
        self.state_mutability: str = abi_item.get("stateMutability", "nonpayable")
        self.payable: bool = self.state_mutability == "payable"
        self.constant: bool = self.state_mutability in ("view", "pure")
        self._abi_item = abi_item

    @property
    def signature(self) -> str:
        """Get the canonical function signature.

        Returns:
            The signature like 'transfer(address,uint256)'.
        """
        types = [self._get_canonical_type(inp) for inp in self.inputs]
        return f"{self.name}({','.join(types)})"

    @property
    def selector(self) -> str:
        """Get the 4-byte function selector.

        Returns:
            The selector as hex string with 0x prefix.
        """
        full_hash = keccak256(self.signature)
        return full_hash[:10]

    @property
    def input_types(self) -> List[str]:
        """Get the list of input types."""
        return [self._get_canonical_type(inp) for inp in self.inputs]

    @property
    def output_types(self) -> List[str]:
        """Get the list of output types."""
        return [self._get_canonical_type(out) for out in self.outputs]

    def _get_canonical_type(self, param: Dict[str, Any]) -> str:
        """Get the canonical type string for an ABI parameter."""
        param_type: str = str(param.get("type", ""))

        if param_type == "tuple":
            components = param.get("components", [])
            inner_types = [self._get_canonical_type(c) for c in components]
            return f"({','.join(inner_types)})"
        elif param_type.startswith("tuple["):
            components = param.get("components", [])
            inner_types = [self._get_canonical_type(c) for c in components]
            array_suffix = param_type[5:]
            return f"({','.join(inner_types)}){array_suffix}"
        else:
            return param_type

    def __repr__(self) -> str:
        return f"FunctionFragment({self.signature})"


class EventFragment:
    """Represents an event in the ABI."""

    def __init__(self, abi_item: Dict[str, Any]) -> None:
        """Initialize an EventFragment from an ABI item.

        Args:
            abi_item: The ABI item dictionary for this event.
        """
        self.name: str = abi_item.get("name", "")
        self.inputs: List[Dict[str, Any]] = abi_item.get("inputs", [])
        self.anonymous: bool = abi_item.get("anonymous", False)
        self._abi_item = abi_item

    @property
    def signature(self) -> str:
        """Get the canonical event signature.

        Returns:
            The signature like 'Transfer(address,address,uint256)'.
        """
        types = [self._get_canonical_type(inp) for inp in self.inputs]
        return f"{self.name}({','.join(types)})"

    @property
    def topic(self) -> str:
        """Get the event topic (keccak256 of signature).

        Returns:
            The topic as hex string with 0x prefix.
        """
        return keccak256(self.signature)

    @property
    def indexed_inputs(self) -> List[Dict[str, Any]]:
        """Get the list of indexed inputs."""
        return [inp for inp in self.inputs if inp.get("indexed", False)]

    @property
    def non_indexed_inputs(self) -> List[Dict[str, Any]]:
        """Get the list of non-indexed inputs."""
        return [inp for inp in self.inputs if not inp.get("indexed", False)]

    def _get_canonical_type(self, param: Dict[str, Any]) -> str:
        """Get the canonical type string for an ABI parameter."""
        param_type: str = str(param.get("type", ""))

        if param_type == "tuple":
            components = param.get("components", [])
            inner_types = [self._get_canonical_type(c) for c in components]
            return f"({','.join(inner_types)})"
        elif param_type.startswith("tuple["):
            components = param.get("components", [])
            inner_types = [self._get_canonical_type(c) for c in components]
            array_suffix = param_type[5:]
            return f"({','.join(inner_types)}){array_suffix}"
        else:
            return param_type

    def __repr__(self) -> str:
        return f"EventFragment({self.signature})"


class ErrorFragment:
    """Represents a custom error in the ABI."""

    def __init__(self, abi_item: Dict[str, Any]) -> None:
        """Initialize an ErrorFragment from an ABI item.

        Args:
            abi_item: The ABI item dictionary for this error.
        """
        self.name: str = abi_item.get("name", "")
        self.inputs: List[Dict[str, Any]] = abi_item.get("inputs", [])
        self._abi_item = abi_item

    @property
    def signature(self) -> str:
        """Get the canonical error signature."""
        types = [self._get_canonical_type(inp) for inp in self.inputs]
        return f"{self.name}({','.join(types)})"

    @property
    def selector(self) -> str:
        """Get the 4-byte error selector."""
        full_hash = keccak256(self.signature)
        return full_hash[:10]

    def _get_canonical_type(self, param: Dict[str, Any]) -> str:
        """Get the canonical type string for an ABI parameter."""
        param_type: str = str(param.get("type", ""))

        if param_type == "tuple":
            components = param.get("components", [])
            inner_types = [self._get_canonical_type(c) for c in components]
            return f"({','.join(inner_types)})"
        elif param_type.startswith("tuple["):
            components = param.get("components", [])
            inner_types = [self._get_canonical_type(c) for c in components]
            array_suffix = param_type[5:]
            return f"({','.join(inner_types)}){array_suffix}"
        else:
            return param_type

    def __repr__(self) -> str:
        return f"ErrorFragment({self.signature})"


class Interface:
    """ABI Interface for encoding/decoding contract interactions.

    The Interface class parses a contract ABI and provides methods for:
    - Encoding function call data
    - Decoding function results
    - Encoding/decoding event logs
    - Looking up functions and events by name or selector
    """

    def __init__(self, abi: List[Dict[str, Any]]) -> None:
        """Initialize an Interface from a contract ABI.

        Args:
            abi: The contract ABI as a list of dictionaries.

        Raises:
            ValidationError: If the ABI is invalid.
        """
        if not isinstance(abi, list):
            raise ValidationError(
                message=f"Expected list for ABI, got {type(abi).__name__}",
                field="abi",
                value=abi,
                expected="list of ABI items",
            )

        self._abi = abi
        self._functions: Dict[str, FunctionFragment] = {}
        self._functions_by_selector: Dict[str, FunctionFragment] = {}
        self._events: Dict[str, EventFragment] = {}
        self._events_by_topic: Dict[str, EventFragment] = {}
        self._errors: Dict[str, ErrorFragment] = {}
        self._errors_by_selector: Dict[str, ErrorFragment] = {}

        self._parse_abi(abi)

    def _parse_abi(self, abi: List[Dict[str, Any]]) -> None:
        """Parse the ABI and populate internal mappings."""
        for item in abi:
            item_type = item.get("type", "")

            if item_type == "function":
                func_fragment = FunctionFragment(item)
                self._functions[func_fragment.name] = func_fragment
                self._functions_by_selector[func_fragment.selector] = func_fragment

            elif item_type == "event":
                event_fragment = EventFragment(item)
                self._events[event_fragment.name] = event_fragment
                self._events_by_topic[event_fragment.topic] = event_fragment

            elif item_type == "error":
                error_fragment = ErrorFragment(item)
                self._errors[error_fragment.name] = error_fragment
                self._errors_by_selector[error_fragment.selector] = error_fragment

    @property
    def functions(self) -> Dict[str, FunctionFragment]:
        """Get all function fragments by name."""
        return self._functions.copy()

    @property
    def events(self) -> Dict[str, EventFragment]:
        """Get all event fragments by name."""
        return self._events.copy()

    @property
    def errors(self) -> Dict[str, ErrorFragment]:
        """Get all error fragments by name."""
        return self._errors.copy()

    def get_function(self, name_or_selector: str) -> Optional[FunctionFragment]:
        """Get a function fragment by name or selector.

        Args:
            name_or_selector: Function name or 4-byte selector (with 0x prefix).

        Returns:
            The FunctionFragment or None if not found.
        """
        if name_or_selector.startswith("0x") and len(name_or_selector) == 10:
            return self._functions_by_selector.get(name_or_selector.lower())
        return self._functions.get(name_or_selector)

    def get_event(self, name_or_topic: str) -> Optional[EventFragment]:
        """Get an event fragment by name or topic.

        Args:
            name_or_topic: Event name or 32-byte topic (with 0x prefix).

        Returns:
            The EventFragment or None if not found.
        """
        if name_or_topic.startswith("0x") and len(name_or_topic) == 66:
            return self._events_by_topic.get(name_or_topic.lower())
        return self._events.get(name_or_topic)

    def get_error(self, name_or_selector: str) -> Optional[ErrorFragment]:
        """Get an error fragment by name or selector.

        Args:
            name_or_selector: Error name or 4-byte selector (with 0x prefix).

        Returns:
            The ErrorFragment or None if not found.
        """
        if name_or_selector.startswith("0x") and len(name_or_selector) == 10:
            return self._errors_by_selector.get(name_or_selector.lower())
        return self._errors.get(name_or_selector)

    def encode_function_data(
        self,
        function_name: str,
        args: Optional[List[Any]] = None,
    ) -> str:
        """Encode a function call with arguments.

        Args:
            function_name: The name of the function to call.
            args: The arguments to pass to the function.

        Returns:
            The encoded function call data as hex string with 0x prefix.

        Raises:
            ValidationError: If the function is not found or encoding fails.
        """
        func = self.get_function(function_name)
        if func is None:
            raise ValidationError(
                message=f"Function '{function_name}' not found in ABI",
                field="function_name",
                value=function_name,
                expected="function name present in ABI",
            )

        args = args or []
        if len(args) != len(func.inputs):
            raise ValidationError(
                message=f"Expected {len(func.inputs)} arguments, got {len(args)}",
                field="args",
                value=args,
                expected=f"list of {len(func.inputs)} arguments",
            )

        if func.input_types:
            encoded_args = encode_abi(func.input_types, args)
            return func.selector + encoded_args[2:]
        else:
            return func.selector

    def decode_function_result(
        self,
        function_name: str,
        data: Union[str, bytes],
    ) -> Any:
        """Decode a function call result.

        Args:
            function_name: The name of the function.
            data: The encoded result data.

        Returns:
            The decoded result. Single value if one output, tuple if multiple.

        Raises:
            ValidationError: If the function is not found or decoding fails.
        """
        func = self.get_function(function_name)
        if func is None:
            raise ValidationError(
                message=f"Function '{function_name}' not found in ABI",
                field="function_name",
                value=function_name,
                expected="function name present in ABI",
            )

        if not func.output_types:
            return None

        decoded = decode_abi(func.output_types, data)

        if len(decoded) == 1:
            return decoded[0]
        return decoded

    def decode_function_data(
        self,
        data: Union[str, bytes],
    ) -> Tuple[FunctionFragment, Tuple[Any, ...]]:
        """Decode function call data (selector + arguments).

        Args:
            data: The encoded function call data.

        Returns:
            A tuple of (FunctionFragment, decoded_args).

        Raises:
            ValidationError: If the function is not found or decoding fails.
        """
        if isinstance(data, bytes):
            data = "0x" + data.hex()

        if not data.startswith("0x"):
            data = "0x" + data

        if len(data) < 10:
            raise ValidationError(
                message="Data too short to contain function selector",
                field="data",
                value=data,
                expected="at least 10 characters (0x + 4 bytes)",
            )

        selector = data[:10].lower()
        func = self._functions_by_selector.get(selector)

        if func is None:
            raise ValidationError(
                message=f"Function with selector '{selector}' not found in ABI",
                field="data",
                value=data,
                expected="valid function selector",
            )

        if len(data) > 10 and func.input_types:
            args_data = "0x" + data[10:]
            decoded_args = decode_abi(func.input_types, args_data)
        else:
            decoded_args = ()

        return func, decoded_args

    def encode_event_topics(
        self,
        event_name: str,
        indexed_values: Optional[List[Any]] = None,
    ) -> List[Optional[str]]:
        """Encode event filter topics.

        Args:
            event_name: The name of the event.
            indexed_values: Values for indexed parameters (None for wildcard).

        Returns:
            List of topics for filtering.

        Raises:
            ValidationError: If the event is not found.
        """
        event = self.get_event(event_name)
        if event is None:
            raise ValidationError(
                message=f"Event '{event_name}' not found in ABI",
                field="event_name",
                value=event_name,
                expected="event name present in ABI",
            )

        topics: List[Optional[str]] = []

        if not event.anonymous:
            topics.append(event.topic)

        indexed_values = indexed_values or []
        indexed_inputs = event.indexed_inputs

        for i, inp in enumerate(indexed_inputs):
            if i < len(indexed_values) and indexed_values[i] is not None:
                value = indexed_values[i]
                inp_type = inp.get("type", "")

                if inp_type in ("string", "bytes"):
                    topic = keccak256(
                        value if isinstance(value, bytes) else value.encode("utf-8")
                    )
                else:
                    encoded = encode_abi([inp_type], [value])
                    topic = encoded
                topics.append(topic)
            else:
                topics.append(None)

        return topics

    def decode_event_log(
        self,
        topics: List[str],
        data: str,
        event_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Decode an event log.

        Args:
            topics: The log topics.
            data: The log data.
            event_name: Optional event name (auto-detected if not provided).

        Returns:
            Dictionary with decoded event data.

        Raises:
            ValidationError: If the event cannot be decoded.
        """
        if event_name:
            event = self.get_event(event_name)
        elif topics:
            event = self._events_by_topic.get(topics[0].lower())
        else:
            event = None

        if event is None:
            raise ValidationError(
                message="Could not identify event from topics",
                field="topics",
                value=topics,
                expected="valid event topic",
            )

        result: Dict[str, Any] = {"event": event.name, "args": {}}

        topic_index = 0 if event.anonymous else 1
        indexed_inputs = event.indexed_inputs

        for inp in indexed_inputs:
            if topic_index < len(topics):
                inp_name = inp.get("name", f"arg{topic_index}")
                inp_type = inp.get("type", "")

                if inp_type in ("string", "bytes", "tuple") or inp_type.endswith("[]"):
                    result["args"][inp_name] = topics[topic_index]
                else:
                    decoded = decode_abi([inp_type], topics[topic_index])
                    result["args"][inp_name] = decoded[0]
                topic_index += 1

        non_indexed = event.non_indexed_inputs
        if non_indexed and data and data != "0x":
            types = [inp.get("type", "") for inp in non_indexed]
            decoded_data = decode_abi(types, data)

            for i, inp in enumerate(non_indexed):
                inp_name = inp.get("name", f"data{i}")
                result["args"][inp_name] = decoded_data[i]

        return result

    def format_error(self, data: Union[str, bytes]) -> Optional[str]:
        """Format an error from revert data.

        Args:
            data: The revert data.

        Returns:
            Formatted error string or None if not recognized.
        """
        if isinstance(data, bytes):
            data = "0x" + data.hex()

        if not data.startswith("0x"):
            data = "0x" + data

        if len(data) < 10:
            return None

        selector = data[:10].lower()

        if selector == "0x08c379a0":
            try:
                decoded = decode_abi(["string"], "0x" + data[10:])
                return f"Error: {decoded[0]}"
            except Exception:
                return None

        if selector == "0x4e487b71":
            try:
                decoded = decode_abi(["uint256"], "0x" + data[10:])
                panic_codes = {
                    0x00: "generic panic",
                    0x01: "assertion failed",
                    0x11: "arithmetic overflow/underflow",
                    0x12: "division by zero",
                    0x21: "invalid enum value",
                    0x22: "storage encoding error",
                    0x31: "pop on empty array",
                    0x32: "array index out of bounds",
                    0x41: "memory allocation error",
                    0x51: "zero-initialized function pointer",
                }
                code = decoded[0]
                reason = panic_codes.get(code, f"unknown panic code {code}")
                return f"Panic: {reason}"
            except Exception:
                return None

        error = self._errors_by_selector.get(selector)
        if error:
            try:
                types = [inp.get("type", "") for inp in error.inputs]
                if types:
                    decoded = decode_abi(types, "0x" + data[10:])
                    args_str = ", ".join(str(v) for v in decoded)
                    return f"{error.name}({args_str})"
                return error.name
            except Exception:
                return error.name

        return None

    def __repr__(self) -> str:
        return (
            f"Interface(functions={len(self._functions)}, "
            f"events={len(self._events)}, errors={len(self._errors)})"
        )


__all__ = [
    "Interface",
    "FunctionFragment",
    "EventFragment",
    "ErrorFragment",
]
