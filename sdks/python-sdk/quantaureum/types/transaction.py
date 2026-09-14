# Quantaureum Python SDK source, version 1.0.0.
"""Transaction type definitions."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class TransactionRequest(BaseModel):
    """Transaction request for sending."""

    to: Optional[str] = Field(default=None, description="Recipient address")
    from_address: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("from_address", "from"),
        serialization_alias="from",
        description="Sender address",
    )
    nonce: Optional[int] = Field(default=None, description="Transaction nonce")
    gas_limit: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices("gas_limit", "gas"),
        serialization_alias="gas",
        description="Gas limit",
    )
    gas_price: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices("gas_price", "gasPrice"),
        serialization_alias="gasPrice",
        description="Gas price in wei",
    )
    max_fee_per_gas: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices("max_fee_per_gas", "maxFeePerGas"),
        serialization_alias="maxFeePerGas",
        description="Max fee per gas (EIP-1559)",
    )
    max_priority_fee_per_gas: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices("max_priority_fee_per_gas", "maxPriorityFeePerGas"),
        serialization_alias="maxPriorityFeePerGas",
        description="Max priority fee per gas (EIP-1559)",
    )
    data: Optional[str] = Field(default=None, description="Transaction data")
    value: Optional[int] = Field(default=None, description="Value in wei")
    chain_id: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices("chain_id", "chainId"),
        serialization_alias="chainId",
        description="Chain ID",
    )

    model_config = ConfigDict(populate_by_name=True)


class TransactionResponse(BaseModel):
    """Transaction response from node."""

    hash: str = Field(description="Transaction hash")
    block_number: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices("block_number", "blockNumber"),
        serialization_alias="blockNumber",
        description="Block number",
    )
    block_hash: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("block_hash", "blockHash"),
        serialization_alias="blockHash",
        description="Block hash",
    )
    timestamp: Optional[int] = Field(default=None, description="Transaction timestamp")
    from_address: str = Field(
        validation_alias=AliasChoices("from_address", "from"),
        serialization_alias="from",
        description="Sender address",
    )
    to: Optional[str] = Field(default=None, description="Recipient address")
    value: int = Field(description="Value in wei")
    nonce: int = Field(description="Transaction nonce")
    gas_limit: int = Field(
        validation_alias=AliasChoices("gas_limit", "gas"),
        serialization_alias="gas",
        description="Gas limit",
    )
    gas_price: int = Field(
        validation_alias=AliasChoices("gas_price", "gasPrice"),
        serialization_alias="gasPrice",
        description="Gas price in wei",
    )
    data: str = Field(
        default="0x",
        validation_alias=AliasChoices("data", "input"),
        serialization_alias="input",
        description="Transaction data",
    )
    chain_id: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices("chain_id", "chainId"),
        serialization_alias="chainId",
        description="Chain ID",
    )

    model_config = ConfigDict(populate_by_name=True, frozen=True)


class Log(BaseModel):
    """Event log."""

    address: str = Field(description="Contract address")
    topics: list[str] = Field(default_factory=list, description="Log topics")
    data: str = Field(default="0x", description="Log data")
    block_number: int = Field(
        validation_alias=AliasChoices("block_number", "blockNumber"),
        serialization_alias="blockNumber",
        description="Block number",
    )
    block_hash: str = Field(
        validation_alias=AliasChoices("block_hash", "blockHash"),
        serialization_alias="blockHash",
        description="Block hash",
    )
    transaction_hash: str = Field(
        validation_alias=AliasChoices("transaction_hash", "transactionHash"),
        serialization_alias="transactionHash",
        description="Transaction hash",
    )
    transaction_index: int = Field(
        validation_alias=AliasChoices("transaction_index", "transactionIndex"),
        serialization_alias="transactionIndex",
        description="Transaction index",
    )
    log_index: int = Field(
        validation_alias=AliasChoices("log_index", "logIndex"),
        serialization_alias="logIndex",
        description="Log index",
    )
    removed: bool = Field(default=False, description="Whether log was removed")

    model_config = ConfigDict(populate_by_name=True, frozen=True)


class TransactionReceipt(BaseModel):
    """Transaction receipt after confirmation."""

    transaction_hash: str = Field(
        validation_alias=AliasChoices("transaction_hash", "transactionHash"),
        serialization_alias="transactionHash",
        description="Transaction hash",
    )
    block_number: int = Field(
        validation_alias=AliasChoices("block_number", "blockNumber"),
        serialization_alias="blockNumber",
        description="Block number",
    )
    block_hash: str = Field(
        validation_alias=AliasChoices("block_hash", "blockHash"),
        serialization_alias="blockHash",
        description="Block hash",
    )
    from_address: str = Field(
        validation_alias=AliasChoices("from_address", "from"),
        serialization_alias="from",
        description="Sender address",
    )
    to: Optional[str] = Field(default=None, description="Recipient address")
    contract_address: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices("contract_address", "contractAddress"),
        serialization_alias="contractAddress",
        description="Created contract address",
    )
    gas_used: int = Field(
        validation_alias=AliasChoices("gas_used", "gasUsed"),
        serialization_alias="gasUsed",
        description="Gas used",
    )
    cumulative_gas_used: int = Field(
        validation_alias=AliasChoices("cumulative_gas_used", "cumulativeGasUsed"),
        serialization_alias="cumulativeGasUsed",
        description="Cumulative gas used",
    )
    effective_gas_price: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices("effective_gas_price", "effectiveGasPrice"),
        serialization_alias="effectiveGasPrice",
        description="Effective gas price",
    )
    status: int = Field(description="Status (1=success, 0=failure)")
    logs: list[Log] = Field(default_factory=list, description="Event logs")

    model_config = ConfigDict(populate_by_name=True, frozen=True)

    @property
    def success(self) -> bool:
        """Check if transaction was successful."""
        return self.status == 1


class AccessListEntry(BaseModel):
    """Access list entry for EIP-2930 transactions."""

    address: str = Field(description="Contract address")
    storage_keys: list[str] = Field(
        validation_alias=AliasChoices("storage_keys", "storageKeys"),
        serialization_alias="storageKeys",
        default_factory=list,
        description="Storage keys",
    )

    model_config = ConfigDict(populate_by_name=True)


class FeeData(BaseModel):
    """Fee data for gas estimation."""

    gas_price: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices("gas_price", "gasPrice"),
        serialization_alias="gasPrice",
        description="Legacy gas price",
    )
    max_fee_per_gas: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices("max_fee_per_gas", "maxFeePerGas"),
        serialization_alias="maxFeePerGas",
        description="Max fee per gas (EIP-1559)",
    )
    max_priority_fee_per_gas: Optional[int] = Field(
        default=None,
        validation_alias=AliasChoices("max_priority_fee_per_gas", "maxPriorityFeePerGas"),
        serialization_alias="maxPriorityFeePerGas",
        description="Max priority fee per gas (EIP-1559)",
    )

    model_config = ConfigDict(populate_by_name=True, frozen=True)
