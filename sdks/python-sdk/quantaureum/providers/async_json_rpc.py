# Quantaureum Python SDK source, version 1.0.0.
"""Async JSON-RPC provider implementation for asynchronous blockchain communication.

This module provides an asynchronous HTTP-based JSON-RPC provider for
communicating with Quantaureum and Ethereum-compatible blockchain nodes.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Dict, List, Optional, Union

import aiohttp

from ..exceptions import (
    ContractError,
    ErrorCode,
    NetworkError,
    RpcError,
    TransactionError,
)
from ..types.block import Block, BlockWithTransactions
from ..types.network import Network
from ..types.transaction import (
    Log,
    TransactionReceipt,
    TransactionRequest,
    TransactionResponse,
)
from .base import AsyncProvider


# Default timeout for HTTP requests (seconds)
DEFAULT_TIMEOUT = 30

# Default retry configuration
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_DELAY = 1.0


class AsyncJsonRpcProvider(AsyncProvider):
    """Asynchronous JSON-RPC provider for blockchain communication.

    This provider uses aiohttp to communicate with blockchain nodes via
    the JSON-RPC protocol. It supports all standard Ethereum JSON-RPC
    methods with async/await syntax.

    Example:
        >>> async with AsyncJsonRpcProvider("http://localhost:8545") as provider:
        ...     block_number = await provider.get_block_number()
        ...     print(f"Current block: {block_number}")
    """

    def __init__(
        self,
        url: str,
        timeout: float = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_delay: float = DEFAULT_RETRY_DELAY,
    ) -> None:
        """Initialize the async JSON-RPC provider.

        Args:
            url: The RPC endpoint URL.
            timeout: Request timeout in seconds.
            max_retries: Maximum number of retry attempts for failed requests.
            retry_delay: Delay between retries in seconds.
        """
        self._url = url
        self._timeout = aiohttp.ClientTimeout(total=timeout)
        self._max_retries = max_retries
        self._retry_delay = retry_delay
        self._request_id = 0
        self._session: Optional[aiohttp.ClientSession] = None
        self._network: Optional[Network] = None
        self._owns_session = True

    @property
    def url(self) -> str:
        """Get the RPC endpoint URL."""
        return self._url

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create the aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(timeout=self._timeout)
            self._owns_session = True
        return self._session

    def _next_request_id(self) -> int:
        """Get the next request ID."""
        self._request_id += 1
        return self._request_id

    async def _make_request(
        self,
        method: str,
        params: Optional[List[Any]] = None,
    ) -> Any:
        """Make an async JSON-RPC request.

        Args:
            method: The RPC method name.
            params: The method parameters.

        Returns:
            The result from the RPC response.

        Raises:
            RpcError: If the RPC call returns an error.
            NetworkError: If the network request fails.
        """
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": self._next_request_id(),
        }

        last_error: Optional[Exception] = None
        session = await self._get_session()

        for attempt in range(self._max_retries):
            try:
                async with session.post(
                    self._url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                ) as response:
                    if response.status != 200:
                        raise NetworkError(
                            message=f"HTTP error: {response.status}",
                            url=self._url,
                            status_code=response.status,
                        )

                    data = await response.json()

                    # Check for RPC error
                    if "error" in data:
                        error = data["error"]
                        raise RpcError(
                            message=error.get("message", "Unknown RPC error"),
                            rpc_code=error.get("code", -1),
                            rpc_message=error.get("message", ""),
                            rpc_data=error.get("data"),
                        )

                    return data.get("result")

            except asyncio.TimeoutError:
                last_error = NetworkError(
                    message=f"Request timeout",
                    url=self._url,
                    code=ErrorCode.TIMEOUT,
                )
            except aiohttp.ClientConnectionError as e:
                last_error = NetworkError(
                    message=f"Connection failed: {e}",
                    url=self._url,
                    code=ErrorCode.CONNECTION_REFUSED,
                )
            except json.JSONDecodeError as e:
                last_error = NetworkError(
                    message=f"Invalid JSON response: {e}",
                    url=self._url,
                    code=ErrorCode.INVALID_RESPONSE,
                )
            except (RpcError, NetworkError):
                raise
            except Exception as e:
                last_error = NetworkError(
                    message=f"Request failed: {e}",
                    url=self._url,
                )

            # Wait before retry
            if attempt < self._max_retries - 1:
                await asyncio.sleep(self._retry_delay)

        # All retries exhausted
        if last_error:
            raise last_error
        raise NetworkError(
            message="Request failed after all retries",
            url=self._url,
        )

    @staticmethod
    def _format_block_tag(block_tag: Union[str, int]) -> str:
        """Format a block tag for RPC calls."""
        if isinstance(block_tag, int):
            return hex(block_tag)
        return block_tag

    async def get_network(self) -> Network:
        """Get network information."""
        if self._network is not None:
            return self._network

        chain_id_hex = await self._make_request("eth_chainId")
        chain_id = int(chain_id_hex, 16)

        # Map common chain IDs to names
        chain_names = {
            1: "mainnet",
            3: "ropsten",
            4: "rinkeby",
            5: "goerli",
            11155111: "sepolia",
            137: "polygon",
            80001: "mumbai",
            42161: "arbitrum",
            10: "optimism",
            56: "bsc",
            43114: "avalanche",
            250: "fantom",
            1337: "localhost",
            31337: "hardhat",
            # Quantaureum networks
            8888: "quantaureum-mainnet",
            8889: "quantaureum-testnet",
        }

        name = chain_names.get(chain_id, f"chain-{chain_id}")
        self._network = Network(name=name, chain_id=chain_id)
        return self._network

    async def get_block_number(self) -> int:
        """Get the current block number."""
        result = await self._make_request("eth_blockNumber")
        return int(result, 16)

    async def get_gas_price(self) -> int:
        """Get the current gas price in wei."""
        result = await self._make_request("eth_gasPrice")
        return int(result, 16)

    async def get_block(
        self,
        block_hash_or_number: Union[str, int],
        include_transactions: bool = False,
    ) -> Optional[Union[Block, BlockWithTransactions]]:
        """Get a block by hash or number."""
        # Determine if it's a hash or number
        if isinstance(block_hash_or_number, int):
            method = "eth_getBlockByNumber"
            params = [hex(block_hash_or_number), include_transactions]
        elif block_hash_or_number.startswith("0x") and len(block_hash_or_number) == 66:
            method = "eth_getBlockByHash"
            params = [block_hash_or_number, include_transactions]
        else:
            # Assume it's a block tag like "latest"
            method = "eth_getBlockByNumber"
            params = [block_hash_or_number, include_transactions]

        result = await self._make_request(method, params)

        if result is None:
            return None

        return self._parse_block(result, include_transactions)

    def _parse_block(
        self,
        data: Dict[str, Any],
        include_transactions: bool,
    ) -> Union[Block, BlockWithTransactions]:
        """Parse block data from RPC response."""
        base_data = {
            "number": int(data["number"], 16),
            "hash": data["hash"],
            "parent_hash": data["parentHash"],
            "timestamp": int(data["timestamp"], 16),
            "nonce": data.get("nonce", "0x0"),
            "difficulty": int(data.get("difficulty", "0x0"), 16),
            "gas_limit": int(data["gasLimit"], 16),
            "gas_used": int(data["gasUsed"], 16),
            "miner": data["miner"],
            "extra_data": data.get("extraData", "0x"),
        }

        if include_transactions and data.get("transactions"):
            # Parse full transaction objects
            transactions = [
                self._parse_transaction(tx)
                for tx in data["transactions"]
                if isinstance(tx, dict)
            ]
            return BlockWithTransactions(**base_data, transactions=transactions)
        else:
            # Just transaction hashes
            transactions = data.get("transactions", [])
            return Block(**base_data, transactions=transactions)

    def _parse_transaction(self, data: Dict[str, Any]) -> TransactionResponse:
        """Parse transaction data from RPC response."""
        return TransactionResponse(
            hash=data["hash"],
            block_number=int(data["blockNumber"], 16) if data.get("blockNumber") else None,
            block_hash=data.get("blockHash"),
            from_address=data["from"],
            to=data.get("to"),
            value=int(data["value"], 16),
            nonce=int(data["nonce"], 16),
            gas_limit=int(data["gas"], 16),
            gas_price=int(data.get("gasPrice", "0x0"), 16),
            data=data.get("input", "0x"),
            chain_id=int(data["chainId"], 16) if data.get("chainId") else None,
        )

    async def get_transaction(self, tx_hash: str) -> Optional[TransactionResponse]:
        """Get a transaction by hash."""
        result = await self._make_request("eth_getTransactionByHash", [tx_hash])

        if result is None:
            return None

        return self._parse_transaction(result)

    async def get_transaction_receipt(
        self, tx_hash: str
    ) -> Optional[TransactionReceipt]:
        """Get a transaction receipt by hash."""
        result = await self._make_request("eth_getTransactionReceipt", [tx_hash])

        if result is None:
            return None

        return self._parse_receipt(result)

    def _parse_receipt(self, data: Dict[str, Any]) -> TransactionReceipt:
        """Parse transaction receipt from RPC response."""
        logs = [
            Log(
                address=log["address"],
                topics=log.get("topics", []),
                data=log.get("data", "0x"),
                block_number=int(log["blockNumber"], 16),
                block_hash=log["blockHash"],
                transaction_hash=log["transactionHash"],
                transaction_index=int(log["transactionIndex"], 16),
                log_index=int(log["logIndex"], 16),
                removed=log.get("removed", False),
            )
            for log in data.get("logs", [])
        ]

        return TransactionReceipt(
            transaction_hash=data["transactionHash"],
            block_number=int(data["blockNumber"], 16),
            block_hash=data["blockHash"],
            from_address=data["from"],
            to=data.get("to"),
            contract_address=data.get("contractAddress"),
            gas_used=int(data["gasUsed"], 16),
            cumulative_gas_used=int(data["cumulativeGasUsed"], 16),
            effective_gas_price=int(data["effectiveGasPrice"], 16) if data.get("effectiveGasPrice") else None,
            status=int(data["status"], 16),
            logs=logs,
        )

    async def get_balance(
        self,
        address: str,
        block_tag: Union[str, int] = "latest",
    ) -> int:
        """Get the balance of an address in wei."""
        result = await self._make_request(
            "eth_getBalance",
            [address, self._format_block_tag(block_tag)],
        )
        return int(result, 16)

    async def get_code(
        self,
        address: str,
        block_tag: Union[str, int] = "latest",
    ) -> str:
        """Get the code at an address."""
        result = await self._make_request(
            "eth_getCode",
            [address, self._format_block_tag(block_tag)],
        )
        return str(result)

    async def get_transaction_count(
        self,
        address: str,
        block_tag: Union[str, int] = "latest",
    ) -> int:
        """Get the transaction count (nonce) of an address."""
        result = await self._make_request(
            "eth_getTransactionCount",
            [address, self._format_block_tag(block_tag)],
        )
        return int(result, 16)

    async def send_raw_transaction(self, signed_tx: str) -> TransactionResponse:
        """Broadcast a signed transaction."""
        from ..utils.errors import classify_rpc_error

        try:
            tx_hash = await self._make_request("eth_sendRawTransaction", [signed_tx])
        except RpcError as e:
            # Use enhanced error classification
            error_code, reason = classify_rpc_error(e)
            raise TransactionError(
                message=e.rpc_message,
                code=error_code,
                reason=reason,
            ) from e

        # Return a minimal TransactionResponse with just the hash
        return TransactionResponse(
            hash=tx_hash,
            block_number=None,
            block_hash=None,
            from_address="0x" + "0" * 40,  # Placeholder
            to=None,
            value=0,
            nonce=0,
            gas_limit=0,
            gas_price=0,
            data="0x",
            chain_id=None,
        )

    async def call(
        self,
        transaction: TransactionRequest,
        block_tag: Union[str, int] = "latest",
    ) -> str:
        """Execute a read-only call."""
        from ..utils.errors import create_contract_error_from_rpc

        tx_dict = self._format_transaction_request(transaction)

        try:
            result = await self._make_request(
                "eth_call",
                [tx_dict, self._format_block_tag(block_tag)],
            )
            return str(result)
        except RpcError as e:
            # Use enhanced error handling with revert reason extraction
            error = create_contract_error_from_rpc(e)
            raise error from e

    async def estimate_gas(self, transaction: TransactionRequest) -> int:
        """Estimate gas for a transaction."""
        from ..utils.errors import create_contract_error_from_rpc

        tx_dict = self._format_transaction_request(transaction)

        try:
            result = await self._make_request("eth_estimateGas", [tx_dict])
            return int(result, 16)
        except RpcError as e:
            # Use enhanced error handling with revert reason extraction
            error = create_contract_error_from_rpc(e)
            raise ContractError(
                message=f"Gas estimation failed: {error.message}",
                code=ErrorCode.CALL_EXCEPTION,
                data=error.data,
            ) from e

    def _format_transaction_request(
        self, transaction: TransactionRequest
    ) -> Dict[str, Any]:
        """Format a TransactionRequest for RPC calls."""
        tx_dict: Dict[str, Any] = {}

        if transaction.from_address:
            tx_dict["from"] = transaction.from_address
        if transaction.to:
            tx_dict["to"] = transaction.to
        if transaction.gas_limit is not None:
            tx_dict["gas"] = hex(transaction.gas_limit)
        if transaction.gas_price is not None:
            tx_dict["gasPrice"] = hex(transaction.gas_price)
        if transaction.max_fee_per_gas is not None:
            tx_dict["maxFeePerGas"] = hex(transaction.max_fee_per_gas)
        if transaction.max_priority_fee_per_gas is not None:
            tx_dict["maxPriorityFeePerGas"] = hex(transaction.max_priority_fee_per_gas)
        if transaction.value is not None:
            tx_dict["value"] = hex(transaction.value)
        if transaction.data:
            tx_dict["data"] = transaction.data
        if transaction.nonce is not None:
            tx_dict["nonce"] = hex(transaction.nonce)

        return tx_dict

    async def wait_for_transaction(
        self,
        tx_hash: str,
        confirmations: int = 1,
        timeout: float = 120.0,
        poll_interval: float = 1.0,
    ) -> TransactionReceipt:
        """Wait for a transaction to be confirmed.

        Args:
            tx_hash: The transaction hash.
            confirmations: Number of confirmations to wait for.
            timeout: Maximum time to wait in seconds.
            poll_interval: Time between polls in seconds.

        Returns:
            The transaction receipt.

        Raises:
            TransactionError: If the transaction fails or times out.
        """
        elapsed = 0.0

        while elapsed < timeout:
            receipt = await self.get_transaction_receipt(tx_hash)

            if receipt is not None:
                # Check confirmations
                if confirmations > 1:
                    current_block = await self.get_block_number()
                    tx_confirmations = current_block - receipt.block_number + 1
                    if tx_confirmations >= confirmations:
                        if receipt.status == 0:
                            raise TransactionError(
                                message="Transaction reverted",
                                code=ErrorCode.TRANSACTION_REVERTED,
                                tx_hash=tx_hash,
                                receipt=receipt,
                            )
                        return receipt
                else:
                    if receipt.status == 0:
                        raise TransactionError(
                            message="Transaction reverted",
                            code=ErrorCode.TRANSACTION_REVERTED,
                            tx_hash=tx_hash,
                            receipt=receipt,
                        )
                    return receipt

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        raise TransactionError(
            message=f"Transaction not confirmed after {timeout}s",
            code=ErrorCode.TIMEOUT,
            tx_hash=tx_hash,
        )

    async def get_logs(
        self,
        address: Optional[Union[str, List[str]]] = None,
        topics: Optional[List[Optional[Union[str, List[str]]]]] = None,
        from_block: Union[str, int] = "earliest",
        to_block: Union[str, int] = "latest",
    ) -> List[Log]:
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
        filter_params: Dict[str, Any] = {
            "fromBlock": self._format_block_tag(from_block),
            "toBlock": self._format_block_tag(to_block),
        }

        if address is not None:
            filter_params["address"] = address

        if topics is not None:
            # Filter out trailing None values
            cleaned_topics: List[Optional[Union[str, List[str]]]] = []
            for topic in topics:
                cleaned_topics.append(topic)
            filter_params["topics"] = cleaned_topics

        result = await self._make_request("eth_getLogs", [filter_params])

        logs: List[Log] = []
        for log_data in result:
            logs.append(
                Log(
                    address=log_data["address"],
                    topics=log_data.get("topics", []),
                    data=log_data.get("data", "0x"),
                    block_number=int(log_data["blockNumber"], 16),
                    block_hash=log_data["blockHash"],
                    transaction_hash=log_data["transactionHash"],
                    transaction_index=int(log_data["transactionIndex"], 16),
                    log_index=int(log_data["logIndex"], 16),
                    removed=log_data.get("removed", False),
                )
            )

        return logs

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self._session is not None and self._owns_session:
            await self._session.close()
            self._session = None


__all__ = ["AsyncJsonRpcProvider"]
