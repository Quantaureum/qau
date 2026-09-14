# Quantaureum Python SDK source, version 1.0.0.
"""Block type definitions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Union

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from .transaction import TransactionResponse


class Block(BaseModel):
    """Block data model."""

    number: int = Field(description="Block number")
    hash: str = Field(description="Block hash")
    parent_hash: str = Field(description="Parent block hash")
    timestamp: int = Field(description="Block timestamp (Unix)")
    nonce: str = Field(description="Block nonce")
    difficulty: int = Field(default=0, description="Block difficulty")
    gas_limit: int = Field(description="Gas limit")
    gas_used: int = Field(description="Gas used")
    miner: str = Field(description="Miner address")
    extra_data: str = Field(default="0x", description="Extra data")
    transactions: list[str] = Field(
        default_factory=list, description="Transaction hashes"
    )

    model_config = {"frozen": True}


class BlockWithTransactions(BaseModel):
    """Block with full transaction objects."""

    number: int = Field(description="Block number")
    hash: str = Field(description="Block hash")
    parent_hash: str = Field(description="Parent block hash")
    timestamp: int = Field(description="Block timestamp (Unix)")
    nonce: str = Field(description="Block nonce")
    difficulty: int = Field(default=0, description="Block difficulty")
    gas_limit: int = Field(description="Gas limit")
    gas_used: int = Field(description="Gas used")
    miner: str = Field(description="Miner address")
    extra_data: str = Field(default="0x", description="Extra data")
    transactions: list["TransactionResponse"] = Field(
        default_factory=list, description="Full transaction objects"
    )

    model_config = {"frozen": True}


BlockIdentifier = Union[int, str]
"""Block identifier: block number (int) or block hash/tag (str)."""
