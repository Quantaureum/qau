# Quantaureum Python SDK source, version 1.0.0.
"""Smart contract interaction class.

The Contract class provides a high-level interface for interacting with
smart contracts on the blockchain.
"""

from typing import Any, Dict, List, Optional, Union

from ..exceptions import ContractError, ErrorCode, SignerError, ValidationError
from ..providers.base import Provider
from ..signers.base import Signer
from ..types.transaction import Log, TransactionReceipt, TransactionRequest
from ..utils.address import get_address, is_address
from .interface import EventFragment, FunctionFragment, Interface


class ContractFunction:
    """Represents a callable contract function.

    This class is returned when accessing a function on a Contract instance.
    It provides methods for calling (read-only) or sending transactions.
    """

    def __init__(
        self,
        contract: "Contract",
        fragment: FunctionFragment,
    ) -> None:
        """Initialize a ContractFunction.

        Args:
            contract: The parent Contract instance.
            fragment: The function fragment from the ABI.
        """
        self._contract = contract
        self._fragment = fragment

    @property
    def name(self) -> str:
        """Get the function name."""
        return self._fragment.name

    @property
    def fragment(self) -> FunctionFragment:
        """Get the function fragment."""
        return self._fragment

    def __call__(self, *args: Any) -> "ContractFunctionCall":
        """Create a function call with arguments.

        Args:
            *args: The arguments to pass to the function.

        Returns:
            A ContractFunctionCall that can be executed.
        """
        return ContractFunctionCall(self._contract, self._fragment, list(args))

    def __repr__(self) -> str:
        return f"ContractFunction({self._fragment.signature})"


class ContractFunctionCall:
    """Represents a prepared contract function call with arguments.

    This class provides methods to execute the call as either a read-only
    call or a state-changing transaction.
    """

    def __init__(
        self,
        contract: "Contract",
        fragment: FunctionFragment,
        args: List[Any],
    ) -> None:
        """Initialize a ContractFunctionCall.

        Args:
            contract: The parent Contract instance.
            fragment: The function fragment from the ABI.
            args: The arguments for the function call.
        """
        self._contract = contract
        self._fragment = fragment
        self._args = args

    def _encode_data(self) -> str:
        """Encode the function call data."""
        return self._contract.interface.encode_function_data(
            self._fragment.name, self._args
        )

    def call(
        self,
        block_tag: Union[str, int] = "latest",
        from_address: Optional[str] = None,
        gas_limit: Optional[int] = None,
        gas_price: Optional[int] = None,
        value: int = 0,
    ) -> Any:
        """Execute a read-only call.

        Args:
            block_tag: Block number or tag for the call.
            from_address: Optional sender address for the call.
            gas_limit: Optional gas limit.
            gas_price: Optional gas price.
            value: Optional value to send (for payable functions).

        Returns:
            The decoded result of the function call.

        Raises:
            ContractError: If the call fails or reverts.
            SignerError: If no provider is available.
        """
        provider = self._contract._get_provider()
        if provider is None:
            raise SignerError(
                message="No provider available. Connect a provider first.",
                code=ErrorCode.NO_PROVIDER,
            )

        tx = TransactionRequest(
            to=self._contract.address,
            data=self._encode_data(),
            value=value,
        )

        if from_address:
            tx = TransactionRequest(
                to=self._contract.address,
                from_address=from_address,
                data=self._encode_data(),
                value=value,
                gas_limit=gas_limit,
                gas_price=gas_price,
            )

        try:
            result = provider.call(tx, block_tag)
            return self._contract.interface.decode_function_result(
                self._fragment.name, result
            )
        except Exception as e:
            error_msg = self._contract.interface.format_error(str(e))
            if error_msg:
                raise ContractError(
                    message=f"Call reverted: {error_msg}",
                    code=ErrorCode.CALL_EXCEPTION,
                ) from e
            raise

    def send(
        self,
        gas_limit: Optional[int] = None,
        gas_price: Optional[int] = None,
        value: int = 0,
        nonce: Optional[int] = None,
    ) -> TransactionReceipt:
        """Send a state-changing transaction.

        Args:
            gas_limit: Optional gas limit.
            gas_price: Optional gas price.
            value: Optional value to send (for payable functions).
            nonce: Optional nonce override.

        Returns:
            The transaction receipt after confirmation.

        Raises:
            ContractError: If the transaction fails.
            SignerError: If no signer is available.
        """
        signer = self._contract._signer
        if signer is None:
            raise SignerError(
                message="No signer available. Connect a signer first.",
                code=ErrorCode.NO_PROVIDER,
            )

        provider = self._contract._get_provider()
        if provider is None:
            raise SignerError(
                message="No provider available. Connect a provider first.",
                code=ErrorCode.NO_PROVIDER,
            )

        tx = TransactionRequest(
            to=self._contract.address,
            data=self._encode_data(),
            value=value,
            gas_limit=gas_limit,
            gas_price=gas_price,
            nonce=nonce,
        )

        if gas_limit is None:
            estimated = provider.estimate_gas(tx)
            tx = TransactionRequest(
                to=self._contract.address,
                data=self._encode_data(),
                value=value,
                gas_limit=int(estimated * 1.2),
                gas_price=gas_price,
                nonce=nonce,
            )

        if gas_price is None:
            current_gas_price = provider.get_gas_price()
            tx = TransactionRequest(
                to=self._contract.address,
                data=self._encode_data(),
                value=value,
                gas_limit=tx.gas_limit,
                gas_price=current_gas_price,
                nonce=nonce,
            )

        response = signer.send_transaction(tx)

        receipt = None
        while receipt is None:
            receipt = provider.get_transaction_receipt(response.hash)

        if receipt.status == 0:
            raise ContractError(
                message="Transaction reverted",
                code=ErrorCode.TRANSACTION_REVERTED,
            )

        return receipt

    def estimate_gas(
        self,
        from_address: Optional[str] = None,
        value: int = 0,
    ) -> int:
        """Estimate gas for this function call.

        Args:
            from_address: Optional sender address.
            value: Optional value to send.

        Returns:
            The estimated gas amount.

        Raises:
            SignerError: If no provider is available.
        """
        provider = self._contract._get_provider()
        if provider is None:
            raise SignerError(
                message="No provider available. Connect a provider first.",
                code=ErrorCode.NO_PROVIDER,
            )

        tx = TransactionRequest(
            to=self._contract.address,
            from_address=from_address,
            data=self._encode_data(),
            value=value,
        )

        return provider.estimate_gas(tx)

    def build_transaction(
        self,
        gas_limit: Optional[int] = None,
        gas_price: Optional[int] = None,
        value: int = 0,
        nonce: Optional[int] = None,
        chain_id: Optional[int] = None,
    ) -> TransactionRequest:
        """Build a transaction request without sending.

        Args:
            gas_limit: Optional gas limit.
            gas_price: Optional gas price.
            value: Optional value to send.
            nonce: Optional nonce.
            chain_id: Optional chain ID.

        Returns:
            The prepared TransactionRequest.
        """
        return TransactionRequest(
            to=self._contract.address,
            data=self._encode_data(),
            value=value,
            gas_limit=gas_limit,
            gas_price=gas_price,
            nonce=nonce,
            chain_id=chain_id,
        )

    def __repr__(self) -> str:
        return f"ContractFunctionCall({self._fragment.name}, args={self._args})"


class ContractEvent:
    """Represents a decoded contract event."""

    def __init__(
        self,
        fragment: EventFragment,
        log: Log,
        args: Dict[str, Any],
    ) -> None:
        """Initialize a ContractEvent.

        Args:
            fragment: The event fragment from the ABI.
            log: The raw log data.
            args: The decoded event arguments.
        """
        self.fragment = fragment
        self.log = log
        self.args = args

    @property
    def event(self) -> str:
        """Get the event name."""
        return self.fragment.name

    @property
    def address(self) -> str:
        """Get the contract address that emitted the event."""
        return self.log.address

    @property
    def block_number(self) -> int:
        """Get the block number."""
        return self.log.block_number

    @property
    def transaction_hash(self) -> str:
        """Get the transaction hash."""
        return self.log.transaction_hash

    def __repr__(self) -> str:
        return f"ContractEvent({self.event}, args={self.args})"


class Contract:
    """Smart contract interaction class.

    The Contract class provides a high-level interface for interacting with
    smart contracts. It supports:
    - Calling read-only functions
    - Sending state-changing transactions
    - Querying historical events
    - Dynamic method generation from ABI
    """

    def __init__(
        self,
        address: str,
        abi: List[Dict[str, Any]],
        signer_or_provider: Optional[Union[Signer, Provider]] = None,
    ) -> None:
        """Initialize a Contract instance.

        Args:
            address: The contract address.
            abi: The contract ABI.
            signer_or_provider: Optional signer or provider to connect.

        Raises:
            ValidationError: If the address is invalid.
        """
        if not is_address(address):
            raise ValidationError(
                message=f"Invalid contract address: {address}",
                field="address",
                value=address,
                expected="valid Ethereum address",
            )

        self._address = get_address(address)
        self._interface = Interface(abi)
        self._signer: Optional[Signer] = None
        self._provider: Optional[Provider] = None

        if signer_or_provider is not None:
            if isinstance(signer_or_provider, Signer):
                self._signer = signer_or_provider
                self._provider = signer_or_provider.provider
            elif isinstance(signer_or_provider, Provider):
                self._provider = signer_or_provider

        self._functions: Dict[str, ContractFunction] = {}
        self._setup_functions()

    def _setup_functions(self) -> None:
        """Set up contract functions from the interface."""
        for name, fragment in self._interface.functions.items():
            self._functions[name] = ContractFunction(self, fragment)

    @property
    def address(self) -> str:
        """Get the contract address."""
        return self._address

    @property
    def interface(self) -> Interface:
        """Get the contract interface."""
        return self._interface

    @property
    def signer(self) -> Optional[Signer]:
        """Get the connected signer."""
        return self._signer

    @property
    def provider(self) -> Optional[Provider]:
        """Get the connected provider."""
        return self._provider

    def _get_provider(self) -> Optional[Provider]:
        """Get the provider (from signer or direct connection)."""
        if self._provider:
            return self._provider
        if self._signer and self._signer.provider:
            return self._signer.provider
        return None

    def connect(
        self,
        signer_or_provider: Union[Signer, Provider],
    ) -> "Contract":
        """Connect to a new signer or provider.

        Args:
            signer_or_provider: The signer or provider to connect.

        Returns:
            A new Contract instance with the new connection.
        """
        return Contract(
            address=self._address,
            abi=self._interface._abi,
            signer_or_provider=signer_or_provider,
        )

    def __getattr__(self, name: str) -> ContractFunction:
        """Get a contract function by name.

        Args:
            name: The function name.

        Returns:
            The ContractFunction for the given name.

        Raises:
            AttributeError: If the function is not found.
        """
        if name.startswith("_"):
            raise AttributeError(f"'{type(self).__name__}' has no attribute '{name}'")

        if name in self._functions:
            return self._functions[name]

        raise AttributeError(
            f"Contract has no function '{name}'. "
            f"Available functions: {list(self._functions.keys())}"
        )

    def get_function(self, name: str) -> Optional[ContractFunction]:
        """Get a contract function by name.

        Args:
            name: The function name.

        Returns:
            The ContractFunction or None if not found.
        """
        return self._functions.get(name)

    def query_filter(
        self,
        event_name: str,
        from_block: Union[str, int] = 0,
        to_block: Union[str, int] = "latest",
        **indexed_values: Any,
    ) -> List[ContractEvent]:
        """Query historical events.

        Args:
            event_name: The name of the event to query.
            from_block: Starting block number or tag.
            to_block: Ending block number or tag.
            **indexed_values: Filter values for indexed parameters.

        Returns:
            List of decoded ContractEvent objects.

        Raises:
            ValidationError: If the event is not found.
            SignerError: If no provider is available.
        """
        provider = self._get_provider()
        if provider is None:
            raise SignerError(
                message="No provider available. Connect a provider first.",
                code=ErrorCode.NO_PROVIDER,
            )

        event = self._interface.get_event(event_name)
        if event is None:
            raise ValidationError(
                message=f"Event '{event_name}' not found in ABI",
                field="event_name",
                value=event_name,
                expected="event name present in ABI",
            )

        indexed_list: List[Any] = []
        for inp in event.indexed_inputs:
            inp_name = inp.get("name", "")
            if inp_name in indexed_values:
                indexed_list.append(indexed_values[inp_name])
            else:
                indexed_list.append(None)

        topics = self._interface.encode_event_topics(event_name, indexed_list)

        logs = self._get_logs(from_block, to_block, topics)

        events: List[ContractEvent] = []
        for log in logs:
            try:
                decoded = self._interface.decode_event_log(
                    log.topics, log.data, event_name
                )
                events.append(ContractEvent(event, log, decoded.get("args", {})))
            except Exception:
                continue

        return events

    def _get_logs(
        self,
        from_block: Union[str, int],
        to_block: Union[str, int],
        topics: List[Optional[str]],
    ) -> List[Log]:
        """Get logs from the provider.

        Args:
            from_block: Starting block number or tag.
            to_block: Ending block number or tag.
            topics: List of topic filters.

        Returns:
            List of matching Log objects.
        """
        provider = self._get_provider()
        if provider is None:
            return []

        # Check if provider has get_logs method
        if not hasattr(provider, "get_logs"):
            return []

        # Filter out trailing None topics
        filtered_topics: List[Optional[Union[str, List[str]]]] = []
        for topic in topics:
            filtered_topics.append(topic)

        # Remove trailing None values
        while filtered_topics and filtered_topics[-1] is None:
            filtered_topics.pop()

        return provider.get_logs(
            address=self._address,
            topics=filtered_topics if filtered_topics else None,
            from_block=from_block,
            to_block=to_block,
        )

    def __repr__(self) -> str:
        return f"Contract(address={self._address}, functions={list(self._functions.keys())})"


__all__ = [
    "Contract",
    "ContractFunction",
    "ContractFunctionCall",
    "ContractEvent",
]
