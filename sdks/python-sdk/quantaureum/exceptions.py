# Quantaureum Python SDK source, version 1.0.0.
"""Custom exception classes for Quantaureum SDK."""

from enum import Enum
from typing import Any, Optional

from .types.transaction import TransactionReceipt


class ErrorCode(str, Enum):
    """Error codes for SDK exceptions."""

    # Network errors
    NETWORK_ERROR = "NETWORK_ERROR"
    TIMEOUT = "TIMEOUT"
    CONNECTION_REFUSED = "CONNECTION_REFUSED"

    # RPC errors
    RPC_ERROR = "RPC_ERROR"
    INVALID_RESPONSE = "INVALID_RESPONSE"

    # Transaction errors
    TRANSACTION_FAILED = "TRANSACTION_FAILED"
    TRANSACTION_REVERTED = "TRANSACTION_REVERTED"
    INSUFFICIENT_FUNDS = "INSUFFICIENT_FUNDS"
    NONCE_TOO_LOW = "NONCE_TOO_LOW"
    GAS_TOO_LOW = "GAS_TOO_LOW"

    # Validation errors
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    INVALID_ADDRESS = "INVALID_ADDRESS"
    INVALID_PRIVATE_KEY = "INVALID_PRIVATE_KEY"
    INVALID_MNEMONIC = "INVALID_MNEMONIC"
    INVALID_HEX = "INVALID_HEX"

    # Contract errors
    CALL_EXCEPTION = "CALL_EXCEPTION"
    CONTRACT_NOT_DEPLOYED = "CONTRACT_NOT_DEPLOYED"

    # Signer errors
    NO_PROVIDER = "NO_PROVIDER"
    SIGNING_ERROR = "SIGNING_ERROR"


class QuantaureumError(Exception):
    """Base exception for all SDK errors."""

    def __init__(self, message: str, code: ErrorCode | str) -> None:
        super().__init__(message)
        self.code = code if isinstance(code, ErrorCode) else ErrorCode(code)
        self.message = message

    def __str__(self) -> str:
        return f"[{self.code.value}] {self.message}"

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, code={self.code!r})"


class RpcError(QuantaureumError):
    """RPC-related errors."""

    def __init__(
        self,
        message: str,
        rpc_code: int,
        rpc_message: str,
        rpc_data: Any = None,
    ) -> None:
        super().__init__(message, ErrorCode.RPC_ERROR)
        self.rpc_code = rpc_code
        self.rpc_message = rpc_message
        self.rpc_data = rpc_data

    def __str__(self) -> str:
        return f"[{self.code.value}] {self.message} (RPC code: {self.rpc_code})"

    def __repr__(self) -> str:
        return (
            f"RpcError(message={self.message!r}, rpc_code={self.rpc_code}, "
            f"rpc_message={self.rpc_message!r})"
        )


class TransactionError(QuantaureumError):
    """Transaction-related errors."""

    def __init__(
        self,
        message: str,
        code: ErrorCode | str = ErrorCode.TRANSACTION_FAILED,
        tx_hash: Optional[str] = None,
        receipt: Optional[TransactionReceipt] = None,
        reason: Optional[str] = None,
    ) -> None:
        super().__init__(message, code)
        self.tx_hash = tx_hash
        self.receipt = receipt
        self.reason = reason

    def __str__(self) -> str:
        base = f"[{self.code.value}] {self.message}"
        if self.reason:
            base += f" (reason: {self.reason})"
        if self.tx_hash:
            base += f" [tx: {self.tx_hash}]"
        return base


class ValidationError(QuantaureumError):
    """Input validation errors."""

    def __init__(
        self,
        message: str,
        field: str,
        value: Any,
        expected: Optional[str] = None,
    ) -> None:
        super().__init__(message, ErrorCode.INVALID_ARGUMENT)
        self.field = field
        self.value = value
        self.expected = expected

    def __str__(self) -> str:
        base = f"[{self.code.value}] {self.message}"
        if self.expected:
            base += f" (expected: {self.expected})"
        return base


class NetworkError(QuantaureumError):
    """Network connection errors."""

    def __init__(
        self,
        message: str,
        url: str,
        status_code: Optional[int] = None,
        code: ErrorCode = ErrorCode.NETWORK_ERROR,
    ) -> None:
        super().__init__(message, code)
        self.url = url
        self.status_code = status_code

    def __str__(self) -> str:
        base = f"[{self.code.value}] {self.message}"
        if self.status_code:
            base += f" (status: {self.status_code})"
        return base


class SignerError(QuantaureumError):
    """Signer-related errors."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.SIGNING_ERROR,
    ) -> None:
        super().__init__(message, code)


class ContractError(QuantaureumError):
    """Contract-related errors."""

    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.CALL_EXCEPTION,
        data: Optional[str] = None,
    ) -> None:
        super().__init__(message, code)
        self.data = data
