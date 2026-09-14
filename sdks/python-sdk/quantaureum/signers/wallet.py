# Quantaureum Python SDK source, version 1.0.0.
"""Wallet implementation for local key management.

Property 1: Wallet Address Derivation Consistency
For any valid private key, creating a Wallet and getting its address should always
produce the same deterministic address.
Validates: Requirements 2.2

Property 2: Message Signature Round-Trip
For any wallet and any message, signing the message and then recovering the signer
address from the signature should return the original wallet address.
Validates: Requirements 2.4

Property 3: Wallet Import/Export Round-Trip
For any wallet created from a mnemonic, exporting the mnemonic and importing it again
should produce a wallet with the same address and private key.
Validates: Requirements 2.6, 2.7
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from typing import TYPE_CHECKING, Optional, Union

from eth_keys import keys as eth_keys  # type: ignore[attr-defined]
from eth_keys.exceptions import BadSignature, ValidationError as EthValidationError  # type: ignore[attr-defined]
from mnemonic import Mnemonic

from ..exceptions import SignerError, ValidationError
from ..utils.address import compute_address, get_address
from .base import Signer

if TYPE_CHECKING:
    from ..providers.base import Provider
    from ..types.transaction import TransactionRequest, TransactionResponse


# BIP-39 English wordlist
MNEMONIC_GENERATOR = Mnemonic("english")

# Default derivation path (BIP-44 for Ethereum)
DEFAULT_PATH = "m/44'/60'/0'/0/0"


class Wallet(Signer):
    """Wallet for managing private keys and signing transactions.

    A Wallet holds a private key and can:
    - Sign transactions
    - Sign messages (EIP-191)
    - Derive addresses
    - Connect to providers for sending transactions

    Wallets can be created from:
    - Random entropy (create_random)
    - Private key (from_private_key)
    - Mnemonic phrase (from_mnemonic)
    """

    def __init__(
        self,
        private_key: bytes,
        mnemonic: Optional[str] = None,
        path: Optional[str] = None,
        provider: Optional["Provider"] = None,
    ) -> None:
        """Initialize a wallet with a private key.

        Args:
            private_key: The 32-byte private key.
            mnemonic: Optional mnemonic phrase used to derive this key.
            path: Optional derivation path used with the mnemonic.
            provider: Optional provider to connect to.

        Raises:
            ValidationError: If the private key is invalid.
        """
        if not isinstance(private_key, bytes):
            raise ValidationError(
                message=f"Private key must be bytes, got {type(private_key).__name__}",
                field="private_key",
                value=type(private_key).__name__,
                expected="bytes",
            )

        if len(private_key) != 32:
            raise ValidationError(
                message=f"Private key must be 32 bytes, got {len(private_key)}",
                field="private_key",
                value=len(private_key),
                expected="32 bytes",
            )

        # Validate the private key is in valid range
        try:
            self._eth_key = eth_keys.PrivateKey(private_key)
        except EthValidationError as e:
            raise ValidationError(
                message=f"Invalid private key: {e}",
                field="private_key",
                value="[redacted]",
                expected="valid secp256k1 private key",
            ) from e

        self._private_key = private_key
        self._mnemonic = mnemonic
        self._path = path
        self._provider = provider

        # Derive public key and address
        self._public_key = self._eth_key.public_key
        self._address = get_address(
            "0x" + self._public_key.to_checksum_address()[2:]
        )

    @property
    def address(self) -> str:
        """Get the checksummed address for this wallet."""
        return self._address

    @property
    def public_key(self) -> str:
        """Get the public key as a hex string."""
        return "0x" + self._public_key.to_bytes().hex()

    @property
    def provider(self) -> Optional["Provider"]:
        """Get the connected provider."""
        return self._provider

    @property
    def mnemonic(self) -> Optional[str]:
        """Get the mnemonic phrase if available."""
        return self._mnemonic

    @property
    def path(self) -> Optional[str]:
        """Get the derivation path if available."""
        return self._path

    @classmethod
    def create_random(cls, provider: Optional["Provider"] = None) -> "Wallet":
        """Create a new wallet with a random private key.

        Args:
            provider: Optional provider to connect to.

        Returns:
            A new Wallet with a randomly generated private key.
        """
        # Generate 32 bytes of cryptographically secure random data
        private_key = secrets.token_bytes(32)

        # Ensure the key is valid (in the valid range for secp256k1)
        # The probability of generating an invalid key is astronomically low
        # but we check anyway
        while True:
            try:
                return cls(private_key=private_key, provider=provider)
            except ValidationError:
                private_key = secrets.token_bytes(32)

    @classmethod
    def from_private_key(
        cls,
        private_key: Union[str, bytes],
        provider: Optional["Provider"] = None,
    ) -> "Wallet":
        """Create a wallet from a private key.

        Args:
            private_key: The private key as hex string (with or without 0x)
                        or bytes.
            provider: Optional provider to connect to.

        Returns:
            A new Wallet with the given private key.

        Raises:
            ValidationError: If the private key is invalid.
        """
        if isinstance(private_key, str):
            # Remove 0x prefix if present
            if private_key.startswith(("0x", "0X")):
                private_key = private_key[2:]
            try:
                private_key = bytes.fromhex(private_key)
            except ValueError as e:
                raise ValidationError(
                    message=f"Invalid private key hex: {e}",
                    field="private_key",
                    value="[redacted]",
                    expected="valid hex string",
                ) from e

        return cls(private_key=private_key, provider=provider)

    @classmethod
    def from_mnemonic(
        cls,
        mnemonic: str,
        path: str = DEFAULT_PATH,
        provider: Optional["Provider"] = None,
    ) -> "Wallet":
        """Create a wallet from a BIP-39 mnemonic phrase.

        Args:
            mnemonic: The mnemonic phrase (12, 15, 18, 21, or 24 words).
            path: The BIP-44 derivation path. Defaults to m/44'/60'/0'/0/0.
            provider: Optional provider to connect to.

        Returns:
            A new Wallet derived from the mnemonic.

        Raises:
            ValidationError: If the mnemonic or path is invalid.
        """
        # Validate mnemonic
        mnemonic = mnemonic.strip()
        if not MNEMONIC_GENERATOR.check(mnemonic):
            raise ValidationError(
                message="Invalid mnemonic phrase",
                field="mnemonic",
                value="[redacted]",
                expected="valid BIP-39 mnemonic",
            )

        # Derive seed from mnemonic (BIP-39)
        seed = MNEMONIC_GENERATOR.to_seed(mnemonic)

        # Derive private key using BIP-32/BIP-44
        private_key = cls._derive_key_from_seed(seed, path)

        return cls(
            private_key=private_key,
            mnemonic=mnemonic,
            path=path,
            provider=provider,
        )

    @classmethod
    def generate_mnemonic(cls, strength: int = 128) -> str:
        """Generate a new random mnemonic phrase.

        Args:
            strength: The entropy strength in bits (128, 160, 192, 224, or 256).
                     128 bits = 12 words, 256 bits = 24 words.

        Returns:
            A new random mnemonic phrase.

        Raises:
            ValidationError: If the strength is invalid.
        """
        if strength not in (128, 160, 192, 224, 256):
            raise ValidationError(
                message=f"Invalid mnemonic strength: {strength}",
                field="strength",
                value=strength,
                expected="128, 160, 192, 224, or 256",
            )

        return MNEMONIC_GENERATOR.generate(strength)

    @staticmethod
    def _derive_key_from_seed(seed: bytes, path: str) -> bytes:
        """Derive a private key from a seed using BIP-32.

        Args:
            seed: The 64-byte seed from BIP-39.
            path: The derivation path (e.g., "m/44'/60'/0'/0/0").

        Returns:
            The 32-byte private key.

        Raises:
            ValidationError: If the path is invalid.
        """
        # Parse the path
        if not path.startswith("m/"):
            raise ValidationError(
                message=f"Invalid derivation path: {path}",
                field="path",
                value=path,
                expected="path starting with 'm/'",
            )

        # BIP-32 master key derivation
        I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
        master_key = I[:32]
        master_chain_code = I[32:]

        key = master_key
        chain_code = master_chain_code

        # Parse and apply each path component
        components = path.split("/")[1:]  # Skip 'm'
        for component in components:
            hardened = component.endswith("'")
            if hardened:
                component = component[:-1]

            try:
                index = int(component)
            except ValueError as e:
                raise ValidationError(
                    message=f"Invalid path component: {component}",
                    field="path",
                    value=path,
                    expected="valid BIP-32 path",
                ) from e

            if hardened:
                index += 0x80000000

            # Child key derivation
            if index >= 0x80000000:
                # Hardened child
                data = b"\x00" + key + index.to_bytes(4, "big")
            else:
                # Normal child - need public key
                pk = eth_keys.PrivateKey(key)
                public_key = pk.public_key.to_bytes()
                data = public_key + index.to_bytes(4, "big")

            I = hmac.new(chain_code, data, hashlib.sha512).digest()
            child_key = I[:32]
            chain_code = I[32:]

            # Add parent key to child key (mod n)
            key_int = int.from_bytes(key, "big")
            child_int = int.from_bytes(child_key, "big")
            # secp256k1 curve order
            n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            key = ((key_int + child_int) % n).to_bytes(32, "big")

        return key

    def connect(self, provider: "Provider") -> "Wallet":
        """Connect this wallet to a provider.

        Args:
            provider: The provider to connect to.

        Returns:
            A new Wallet instance connected to the provider.
        """
        return Wallet(
            private_key=self._private_key,
            mnemonic=self._mnemonic,
            path=self._path,
            provider=provider,
        )

    def send_transaction(
        self, transaction: "TransactionRequest"
    ) -> "TransactionResponse":
        """Sign and send a transaction.

        This method will automatically:
        - Fetch the nonce if not provided
        - Estimate gas if not provided
        - Get gas price if not provided (for legacy transactions)
        - Set chain_id if not provided

        Args:
            transaction: The transaction to send.

        Returns:
            The transaction response with hash.

        Raises:
            SignerError: If no provider is connected or signing fails.
            RpcError: If broadcasting fails.
            TransactionError: If the transaction is rejected.
        """
        from ..exceptions import ErrorCode, SignerError
        from ..types.transaction import TransactionRequest

        if self._provider is None:
            raise SignerError(
                message="No provider connected. Call connect() first.",
                code=ErrorCode.NO_PROVIDER,
            )

        # Create a mutable copy of the transaction
        tx_dict = transaction.model_dump(by_alias=True, exclude_none=True)

        # Auto-fill missing fields
        if transaction.nonce is None:
            tx_dict["nonce"] = self._provider.get_transaction_count(
                self._address, "pending"
            )

        if transaction.chain_id is None:
            network = self._provider.get_network()
            tx_dict["chainId"] = network.chain_id

        # Determine if EIP-1559 or legacy
        is_eip1559 = (
            transaction.max_fee_per_gas is not None
            or transaction.max_priority_fee_per_gas is not None
        )

        if not is_eip1559 and transaction.gas_price is None:
            tx_dict["gasPrice"] = self._provider.get_gas_price()

        # Set from address for gas estimation
        tx_dict["from"] = self._address

        # Estimate gas if not provided
        if transaction.gas_limit is None:
            estimate_tx = TransactionRequest.model_validate(tx_dict)
            estimated_gas = self._provider.estimate_gas(estimate_tx)
            # Add 10% buffer for safety
            tx_dict["gas"] = int(estimated_gas * 1.1)

        # Create the final transaction request
        final_tx = TransactionRequest.model_validate(tx_dict)

        # Sign and send
        signed_tx = self.sign_transaction(final_tx)
        return self._provider.send_raw_transaction(signed_tx)

    def populate_transaction(
        self, transaction: "TransactionRequest"
    ) -> "TransactionRequest":
        """Populate a transaction with missing fields.

        This method will automatically fill in:
        - nonce (from pending transaction count)
        - chain_id (from network)
        - gas_price (for legacy transactions)
        - gas_limit (estimated)

        Args:
            transaction: The transaction to populate.

        Returns:
            A new TransactionRequest with all fields populated.

        Raises:
            SignerError: If no provider is connected.
        """
        from ..exceptions import ErrorCode, SignerError
        from ..types.transaction import TransactionRequest

        if self._provider is None:
            raise SignerError(
                message="No provider connected. Call connect() first.",
                code=ErrorCode.NO_PROVIDER,
            )

        tx_dict = transaction.model_dump(by_alias=True, exclude_none=True)

        # Auto-fill missing fields
        if transaction.nonce is None:
            tx_dict["nonce"] = self._provider.get_transaction_count(
                self._address, "pending"
            )

        if transaction.chain_id is None:
            network = self._provider.get_network()
            tx_dict["chainId"] = network.chain_id

        # Determine if EIP-1559 or legacy
        is_eip1559 = (
            transaction.max_fee_per_gas is not None
            or transaction.max_priority_fee_per_gas is not None
        )

        if not is_eip1559 and transaction.gas_price is None:
            tx_dict["gasPrice"] = self._provider.get_gas_price()

        # Set from address
        tx_dict["from"] = self._address

        # Estimate gas if not provided
        if transaction.gas_limit is None:
            estimate_tx = TransactionRequest.model_validate(tx_dict)
            estimated_gas = self._provider.estimate_gas(estimate_tx)
            # Add 10% buffer for safety
            tx_dict["gas"] = int(estimated_gas * 1.1)

        return TransactionRequest.model_validate(tx_dict)

    def export_private_key(self) -> str:
        """Export the private key as a hex string.

        Returns:
            The private key as a hex string with 0x prefix.
        """
        return "0x" + self._private_key.hex()

    def sign_message(self, message: Union[str, bytes]) -> str:
        """Sign a message using EIP-191 personal_sign.

        The message is prefixed with "\\x19Ethereum Signed Message:\\n{length}"
        before hashing and signing.

        Args:
            message: The message to sign.

        Returns:
            The signature as a hex string with 0x prefix (65 bytes = 130 hex + 0x).

        Raises:
            SignerError: If signing fails.
        """
        from eth_hash.auto import keccak as eth_keccak

        try:
            # Convert message to bytes if string
            if isinstance(message, str):
                message_bytes = message.encode("utf-8")
            else:
                message_bytes = message

            # Create EIP-191 prefixed message
            prefix = f"\x19Ethereum Signed Message:\n{len(message_bytes)}".encode(
                "utf-8"
            )
            prefixed_message = prefix + message_bytes

            # Hash the prefixed message
            message_hash = eth_keccak(prefixed_message)

            # Sign the hash
            signature = self._eth_key.sign_msg_hash(message_hash)

            # Return signature as hex (r + s + v format, 65 bytes)
            # eth_keys returns signature with v as 0 or 1, we need to add 27
            r = signature.r.to_bytes(32, "big")
            s = signature.s.to_bytes(32, "big")
            v = (signature.v + 27).to_bytes(1, "big")

            sig_hex: str = (r + s + v).hex()
            return "0x" + sig_hex

        except Exception as e:
            raise SignerError(
                message=f"Failed to sign message: {e}",
            ) from e

    def sign_transaction(self, transaction: "TransactionRequest") -> str:
        """Sign a transaction.

        Supports both legacy (type 0) and EIP-1559 (type 2) transactions.

        Args:
            transaction: The transaction to sign.

        Returns:
            The signed transaction as a hex string with 0x prefix.

        Raises:
            SignerError: If signing fails.
            ValidationError: If required transaction fields are missing.
        """
        from eth_hash.auto import keccak as eth_keccak
        import rlp

        try:
            # Import TransactionRequest if needed
            from ..types.transaction import TransactionRequest as TxRequest

            # Determine transaction type
            is_eip1559 = (
                transaction.max_fee_per_gas is not None
                or transaction.max_priority_fee_per_gas is not None
            )

            # Validate required fields
            if transaction.chain_id is None:
                raise ValidationError(
                    message="chain_id is required for signing",
                    field="chain_id",
                    value=None,
                    expected="integer chain ID",
                )

            if transaction.nonce is None:
                raise ValidationError(
                    message="nonce is required for signing",
                    field="nonce",
                    value=None,
                    expected="integer nonce",
                )

            if transaction.gas_limit is None:
                raise ValidationError(
                    message="gas_limit is required for signing",
                    field="gas_limit",
                    value=None,
                    expected="integer gas limit",
                )

            # Get values with defaults
            to_address = (
                bytes.fromhex(transaction.to[2:]) if transaction.to else b""
            )
            value = transaction.value or 0
            data = (
                bytes.fromhex(transaction.data[2:])
                if transaction.data and transaction.data != "0x"
                else b""
            )

            if is_eip1559:
                # EIP-1559 transaction (type 2)
                max_priority_fee = transaction.max_priority_fee_per_gas or 0
                max_fee = transaction.max_fee_per_gas or 0

                # RLP encode for signing (without signature)
                # [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
                #  gas_limit, to, value, data, access_list]
                unsigned_tx = [
                    transaction.chain_id,
                    transaction.nonce,
                    max_priority_fee,
                    max_fee,
                    transaction.gas_limit,
                    to_address,
                    value,
                    data,
                    [],  # access_list (empty for now)
                ]

                # Encode with type prefix
                encoded = b"\x02" + rlp.encode(unsigned_tx)
                tx_hash = eth_keccak(encoded)

                # Sign the hash
                signature = self._eth_key.sign_msg_hash(tx_hash)

                # Create signed transaction
                # [chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
                #  gas_limit, to, value, data, access_list, v, r, s]
                signed_tx = [
                    transaction.chain_id,
                    transaction.nonce,
                    max_priority_fee,
                    max_fee,
                    transaction.gas_limit,
                    to_address,
                    value,
                    data,
                    [],  # access_list
                    signature.v,  # y_parity (0 or 1)
                    signature.r,
                    signature.s,
                ]

                # Encode with type prefix
                encoded_tx: bytes = rlp.encode(signed_tx)
                return "0x02" + encoded_tx.hex()

            else:
                # Legacy transaction (type 0) with EIP-155 replay protection
                gas_price = transaction.gas_price or 0

                # RLP encode for signing (EIP-155)
                # [nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0]
                unsigned_tx = [
                    transaction.nonce,
                    gas_price,
                    transaction.gas_limit,
                    to_address,
                    value,
                    data,
                    transaction.chain_id,
                    0,
                    0,
                ]

                encoded = rlp.encode(unsigned_tx)
                tx_hash = eth_keccak(encoded)

                # Sign the hash
                signature = self._eth_key.sign_msg_hash(tx_hash)

                # Calculate v with EIP-155 chain ID
                # v = chain_id * 2 + 35 + recovery_id
                v = transaction.chain_id * 2 + 35 + signature.v

                # Create signed transaction
                # [nonce, gas_price, gas_limit, to, value, data, v, r, s]
                signed_tx = [
                    transaction.nonce,
                    gas_price,
                    transaction.gas_limit,
                    to_address,
                    value,
                    data,
                    v,
                    signature.r,
                    signature.s,
                ]

                legacy_encoded_tx: bytes = rlp.encode(signed_tx)
                return "0x" + legacy_encoded_tx.hex()

        except ValidationError:
            raise
        except Exception as e:
            raise SignerError(
                message=f"Failed to sign transaction: {e}",
            ) from e


__all__ = [
    "Wallet",
    "DEFAULT_PATH",
    "recover_message_signer",
    "hash_message",
    "recover_transaction_sender",
]


def hash_message(message: Union[str, bytes]) -> bytes:
    """Hash a message using EIP-191 personal_sign format.

    Args:
        message: The message to hash.

    Returns:
        The 32-byte hash of the prefixed message.
    """
    from eth_hash.auto import keccak as eth_keccak

    if isinstance(message, str):
        message_bytes = message.encode("utf-8")
    else:
        message_bytes = message

    prefix = f"\x19Ethereum Signed Message:\n{len(message_bytes)}".encode("utf-8")
    prefixed_message = prefix + message_bytes

    return eth_keccak(prefixed_message)


def recover_message_signer(message: Union[str, bytes], signature: str) -> str:
    """Recover the signer address from a signed message.

    Args:
        message: The original message that was signed.
        signature: The signature as a hex string with 0x prefix.

    Returns:
        The checksummed address of the signer.

    Raises:
        ValidationError: If the signature is invalid.
    """
    try:
        # Remove 0x prefix if present
        if signature.startswith(("0x", "0X")):
            signature = signature[2:]

        sig_bytes = bytes.fromhex(signature)

        if len(sig_bytes) != 65:
            raise ValidationError(
                message=f"Invalid signature length: {len(sig_bytes)}",
                field="signature",
                value=signature,
                expected="65 bytes",
            )

        # Parse r, s, v from signature
        r = int.from_bytes(sig_bytes[:32], "big")
        s = int.from_bytes(sig_bytes[32:64], "big")
        v = sig_bytes[64]

        # Normalize v (could be 0, 1, 27, or 28)
        if v >= 27:
            v -= 27

        # Hash the message
        message_hash = hash_message(message)

        # Create signature object and recover public key
        from eth_keys.datatypes import Signature

        sig = Signature(vrs=(v, r, s))
        public_key = sig.recover_public_key_from_msg_hash(message_hash)

        # Return checksummed address
        address_str: str = get_address("0x" + public_key.to_checksum_address()[2:])
        return address_str

    except ValidationError:
        raise
    except Exception as e:
        raise ValidationError(
            message=f"Failed to recover signer: {e}",
            field="signature",
            value=signature[:20] + "..." if len(signature) > 20 else signature,
            expected="valid EIP-191 signature",
        ) from e


def recover_transaction_sender(signed_tx: str) -> str:
    """Recover the sender address from a signed transaction.

    Args:
        signed_tx: The signed transaction as a hex string with 0x prefix.

    Returns:
        The checksummed address of the sender.

    Raises:
        ValidationError: If the transaction is invalid.
    """
    from eth_hash.auto import keccak as eth_keccak
    from eth_keys.datatypes import Signature
    import rlp

    try:
        # Remove 0x prefix
        if signed_tx.startswith(("0x", "0X")):
            signed_tx = signed_tx[2:]

        tx_bytes = bytes.fromhex(signed_tx)

        # Check transaction type
        if tx_bytes[0] == 0x02:
            # EIP-1559 transaction
            decoded = rlp.decode(tx_bytes[1:])
            if len(decoded) != 12:
                raise ValidationError(
                    message="Invalid EIP-1559 transaction format",
                    field="signed_tx",
                    value=signed_tx[:40] + "...",
                    expected="12 RLP elements",
                )

            chain_id = _decode_int(decoded[0])
            nonce = _decode_int(decoded[1])
            max_priority_fee = _decode_int(decoded[2])
            max_fee = _decode_int(decoded[3])
            gas_limit = _decode_int(decoded[4])
            to = decoded[5]
            value = _decode_int(decoded[6])
            data = decoded[7]
            access_list = decoded[8]
            v = _decode_int(decoded[9])
            r = _decode_int(decoded[10])
            s = _decode_int(decoded[11])

            # Reconstruct unsigned transaction for hash
            unsigned_tx = [
                chain_id,
                nonce,
                max_priority_fee,
                max_fee,
                gas_limit,
                to,
                value,
                data,
                access_list,
            ]
            encoded = b"\x02" + rlp.encode(unsigned_tx)
            tx_hash = eth_keccak(encoded)

            # Recover public key
            sig = Signature(vrs=(v, r, s))
            public_key = sig.recover_public_key_from_msg_hash(tx_hash)

        else:
            # Legacy transaction
            decoded = rlp.decode(tx_bytes)
            if len(decoded) != 9:
                raise ValidationError(
                    message="Invalid legacy transaction format",
                    field="signed_tx",
                    value=signed_tx[:40] + "...",
                    expected="9 RLP elements",
                )

            nonce = _decode_int(decoded[0])
            gas_price = _decode_int(decoded[1])
            gas_limit = _decode_int(decoded[2])
            to = decoded[3]
            value = _decode_int(decoded[4])
            data = decoded[5]
            v = _decode_int(decoded[6])
            r = _decode_int(decoded[7])
            s = _decode_int(decoded[8])

            # Determine chain_id from v (EIP-155)
            if v >= 35:
                chain_id = (v - 35) // 2
                recovery_id = v - (chain_id * 2 + 35)
            else:
                chain_id = None
                recovery_id = v - 27

            # Reconstruct unsigned transaction for hash
            if chain_id is not None:
                unsigned_tx = [nonce, gas_price, gas_limit, to, value, data, chain_id, 0, 0]
            else:
                unsigned_tx = [nonce, gas_price, gas_limit, to, value, data]

            encoded = rlp.encode(unsigned_tx)
            tx_hash = eth_keccak(encoded)

            # Recover public key
            sig = Signature(vrs=(recovery_id, r, s))
            public_key = sig.recover_public_key_from_msg_hash(tx_hash)

        # Return checksummed address
        address_str: str = get_address("0x" + public_key.to_checksum_address()[2:])
        return address_str

    except ValidationError:
        raise
    except Exception as e:
        raise ValidationError(
            message=f"Failed to recover sender: {e}",
            field="signed_tx",
            value=signed_tx[:40] + "..." if len(signed_tx) > 40 else signed_tx,
            expected="valid signed transaction",
        ) from e


def _decode_int(value: bytes) -> int:
    """Decode RLP bytes to integer."""
    if isinstance(value, int):
        return value
    if len(value) == 0:
        return 0
    return int.from_bytes(value, "big")
