# Quantaureum Python SDK source, version 1.0.0.
"""Abstract base class for signers.

Signers are responsible for signing transactions and messages.
They abstract away the details of key management and signing algorithms.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional, Union

if TYPE_CHECKING:
    from ..providers.base import Provider
    from ..types.transaction import TransactionRequest, TransactionResponse


class Signer(ABC):
    """Abstract base class for transaction signers.

    A Signer is responsible for:
    - Managing private keys securely
    - Signing transactions
    - Signing messages (EIP-191)
    - Deriving addresses from keys

    Implementations include:
    - Wallet: Local private key management
    - (Future) HardwareWallet: Hardware wallet integration
    - (Future) RemoteSigner: Remote signing service
    """

    @property
    @abstractmethod
    def address(self) -> str:
        """Get the address associated with this signer.

        Returns:
            The checksummed Ethereum-style address.
        """
        ...

    @property
    @abstractmethod
    def provider(self) -> Optional["Provider"]:
        """Get the connected provider, if any.

        Returns:
            The connected provider or None.
        """
        ...

    @abstractmethod
    def connect(self, provider: "Provider") -> "Signer":
        """Connect this signer to a provider.

        Args:
            provider: The provider to connect to.

        Returns:
            A new Signer instance connected to the provider.
        """
        ...

    @abstractmethod
    def sign_transaction(self, transaction: "TransactionRequest") -> str:
        """Sign a transaction.

        Args:
            transaction: The transaction to sign.

        Returns:
            The signed transaction as a hex string with 0x prefix.

        Raises:
            SignerError: If signing fails.
        """
        ...

    @abstractmethod
    def sign_message(self, message: Union[str, bytes]) -> str:
        """Sign a message using EIP-191 personal_sign.

        Args:
            message: The message to sign (string or bytes).

        Returns:
            The signature as a hex string with 0x prefix.

        Raises:
            SignerError: If signing fails.
        """
        ...

    def send_transaction(
        self, transaction: "TransactionRequest"
    ) -> "TransactionResponse":
        """Sign and send a transaction.

        This is a convenience method that signs the transaction and
        broadcasts it through the connected provider.

        Args:
            transaction: The transaction to send.

        Returns:
            The transaction response.

        Raises:
            SignerError: If no provider is connected or signing fails.
            RpcError: If broadcasting fails.
        """
        from ..exceptions import ErrorCode, SignerError

        if self.provider is None:
            raise SignerError(
                message="No provider connected. Call connect() first.",
                code=ErrorCode.NO_PROVIDER,
            )

        signed_tx = self.sign_transaction(transaction)
        result: "TransactionResponse" = self.provider.send_raw_transaction(signed_tx)
        return result


__all__ = ["Signer"]
