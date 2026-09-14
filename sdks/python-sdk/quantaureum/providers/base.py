# Quantaureum Python SDK source, version 1.0.0.
"""Abstract base classes for blockchain providers.

Providers are responsible for communicating with blockchain nodes.
They abstract away the details of RPC communication and provide
a clean interface for querying blockchain state and sending transactions.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, Union

if TYPE_CHECKING:
    from ..types.block import Block, BlockWithTransactions
    from ..types.network import Network
    from ..types.transaction import (
        Log,
        TransactionReceipt,
        TransactionRequest,
        TransactionResponse,
    )


class Provider(ABC):
    """Abstract base class for synchronous blockchain providers.

    A Provider is responsible for:
    - Connecting to blockchain nodes
    - Querying blockchain state (blocks, transactions, balances)
    - Sending transactions
    - Estimating gas

    Implementations include:
    - JsonRpcProvider: HTTP JSON-RPC provider
    """

    @abstractmethod
    def get_network(self) -> "Network":
        """Get network information.

        Returns:
            Network information including name and chain ID.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    def get_block_number(self) -> int:
        """Get the current block number.

        Returns:
            The current block height as an integer.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    def get_gas_price(self) -> int:
        """Get the current gas price in wei.

        Returns:
            The current gas price in wei.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    def get_block(
        self,
        block_hash_or_number: Union[str, int],
        include_transactions: bool = False,
    ) -> Optional[Union["Block", "BlockWithTransactions"]]:
        """Get a block by hash or number.

        Args:
            block_hash_or_number: Block hash (hex string) or block number.
            include_transactions: If True, include full transaction objects.

        Returns:
            The block data, or None if not found.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    def get_transaction(self, tx_hash: str) -> Optional["TransactionResponse"]:
        """Get a transaction by hash.

        Args:
            tx_hash: The transaction hash (hex string with 0x prefix).

        Returns:
            The transaction data, or None if not found.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    def get_transaction_receipt(
        self, tx_hash: str
    ) -> Optional["TransactionReceipt"]:
        """Get a transaction receipt by hash.

        Args:
            tx_hash: The transaction hash (hex string with 0x prefix).

        Returns:
            The transaction receipt, or None if not found or not yet mined.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    def get_balance(
        self,
        address: str,
        block_tag: Union[str, int] = "latest",
    ) -> int:
        """Get the balance of an address in wei.

        Args:
            address: The address to query (hex string with 0x prefix).
            block_tag: Block number or tag ("latest", "pending", "earliest").

        Returns:
            The balance in wei.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    def get_code(
        self,
        address: str,
        block_tag: Union[str, int] = "latest",
    ) -> str:
        """Get the code at an address.

        Args:
            address: The address to query (hex string with 0x prefix).
            block_tag: Block number or tag ("latest", "pending", "earliest").

        Returns:
            The code as a hex string with 0x prefix.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    def get_transaction_count(
        self,
        address: str,
        block_tag: Union[str, int] = "latest",
    ) -> int:
        """Get the transaction count (nonce) of an address.

        Args:
            address: The address to query (hex string with 0x prefix).
            block_tag: Block number or tag ("latest", "pending", "earliest").

        Returns:
            The transaction count (nonce).

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    def send_raw_transaction(self, signed_tx: str) -> "TransactionResponse":
        """Broadcast a signed transaction.

        Args:
            signed_tx: The signed transaction as a hex string with 0x prefix.

        Returns:
            The transaction response with hash and other details.

        Raises:
            RpcError: If the RPC call fails.
            TransactionError: If the transaction is rejected.
        """
        ...

    @abstractmethod
    def call(
        self,
        transaction: "TransactionRequest",
        block_tag: Union[str, int] = "latest",
    ) -> str:
        """Execute a read-only call.

        Args:
            transaction: The transaction request (to, data, etc.).
            block_tag: Block number or tag ("latest", "pending", "earliest").

        Returns:
            The result as a hex string with 0x prefix.

        Raises:
            RpcError: If the RPC call fails.
            ContractError: If the call reverts.
        """
        ...

    @abstractmethod
    def estimate_gas(self, transaction: "TransactionRequest") -> int:
        """Estimate gas for a transaction.

        Args:
            transaction: The transaction request.

        Returns:
            The estimated gas amount.

        Raises:
            RpcError: If the RPC call fails.
            ContractError: If the call would revert.
        """
        ...

    @abstractmethod
    def get_logs(
        self,
        address: Optional[Union[str, list[str]]] = None,
        topics: Optional[list[Optional[Union[str, list[str]]]]] = None,
        from_block: Union[str, int] = "earliest",
        to_block: Union[str, int] = "latest",
    ) -> list["Log"]:
        """Get logs matching the filter criteria.

        Args:
            address: Contract address or list of addresses to filter.
            topics: List of topic filters (None for wildcard).
            from_block: Starting block number or tag.
            to_block: Ending block number or tag.

        Returns:
            List of matching Log objects.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...


class AsyncProvider(ABC):
    """Abstract base class for asynchronous blockchain providers.

    Provides the same functionality as Provider but with async/await support.
    All I/O operations are non-blocking.
    """

    @abstractmethod
    async def get_network(self) -> "Network":
        """Get network information.

        Returns:
            Network information including name and chain ID.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    async def get_block_number(self) -> int:
        """Get the current block number.

        Returns:
            The current block height as an integer.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    async def get_gas_price(self) -> int:
        """Get the current gas price in wei.

        Returns:
            The current gas price in wei.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    async def get_block(
        self,
        block_hash_or_number: Union[str, int],
        include_transactions: bool = False,
    ) -> Optional[Union["Block", "BlockWithTransactions"]]:
        """Get a block by hash or number.

        Args:
            block_hash_or_number: Block hash (hex string) or block number.
            include_transactions: If True, include full transaction objects.

        Returns:
            The block data, or None if not found.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    async def get_transaction(self, tx_hash: str) -> Optional["TransactionResponse"]:
        """Get a transaction by hash.

        Args:
            tx_hash: The transaction hash (hex string with 0x prefix).

        Returns:
            The transaction data, or None if not found.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    async def get_transaction_receipt(
        self, tx_hash: str
    ) -> Optional["TransactionReceipt"]:
        """Get a transaction receipt by hash.

        Args:
            tx_hash: The transaction hash (hex string with 0x prefix).

        Returns:
            The transaction receipt, or None if not found or not yet mined.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    async def get_balance(
        self,
        address: str,
        block_tag: Union[str, int] = "latest",
    ) -> int:
        """Get the balance of an address in wei.

        Args:
            address: The address to query (hex string with 0x prefix).
            block_tag: Block number or tag ("latest", "pending", "earliest").

        Returns:
            The balance in wei.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    async def get_code(
        self,
        address: str,
        block_tag: Union[str, int] = "latest",
    ) -> str:
        """Get the code at an address.

        Args:
            address: The address to query (hex string with 0x prefix).
            block_tag: Block number or tag ("latest", "pending", "earliest").

        Returns:
            The code as a hex string with 0x prefix.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    async def get_transaction_count(
        self,
        address: str,
        block_tag: Union[str, int] = "latest",
    ) -> int:
        """Get the transaction count (nonce) of an address.

        Args:
            address: The address to query (hex string with 0x prefix).
            block_tag: Block number or tag ("latest", "pending", "earliest").

        Returns:
            The transaction count (nonce).

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    @abstractmethod
    async def send_raw_transaction(self, signed_tx: str) -> "TransactionResponse":
        """Broadcast a signed transaction.

        Args:
            signed_tx: The signed transaction as a hex string with 0x prefix.

        Returns:
            The transaction response with hash and other details.

        Raises:
            RpcError: If the RPC call fails.
            TransactionError: If the transaction is rejected.
        """
        ...

    @abstractmethod
    async def call(
        self,
        transaction: "TransactionRequest",
        block_tag: Union[str, int] = "latest",
    ) -> str:
        """Execute a read-only call.

        Args:
            transaction: The transaction request (to, data, etc.).
            block_tag: Block number or tag ("latest", "pending", "earliest").

        Returns:
            The result as a hex string with 0x prefix.

        Raises:
            RpcError: If the RPC call fails.
            ContractError: If the call reverts.
        """
        ...

    @abstractmethod
    async def estimate_gas(self, transaction: "TransactionRequest") -> int:
        """Estimate gas for a transaction.

        Args:
            transaction: The transaction request.

        Returns:
            The estimated gas amount.

        Raises:
            RpcError: If the RPC call fails.
            ContractError: If the call would revert.
        """
        ...

    @abstractmethod
    async def get_logs(
        self,
        address: Optional[Union[str, list[str]]] = None,
        topics: Optional[list[Optional[Union[str, list[str]]]]] = None,
        from_block: Union[str, int] = "earliest",
        to_block: Union[str, int] = "latest",
    ) -> list["Log"]:
        """Get logs matching the filter criteria.

        Args:
            address: Contract address or list of addresses to filter.
            topics: List of topic filters (None for wildcard).
            from_block: Starting block number or tag.
            to_block: Ending block number or tag.

        Returns:
            List of matching Log objects.

        Raises:
            RpcError: If the RPC call fails.
        """
        ...

    async def __aenter__(self) -> "AsyncProvider":
        """Enter async context manager."""
        return self

    async def __aexit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[object],
    ) -> None:
        """Exit async context manager and cleanup resources."""
        await self.close()

    @abstractmethod
    async def close(self) -> None:
        """Close connections and cleanup resources.

        Should be called when the provider is no longer needed.
        """
        ...


__all__ = ["Provider", "AsyncProvider"]
