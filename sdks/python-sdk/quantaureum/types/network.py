# Quantaureum Python SDK source, version 1.0.0.
"""Network type definitions."""

from pydantic import BaseModel, Field


class Network(BaseModel):
    """Network information."""

    name: str = Field(description="Network name")
    chain_id: int = Field(description="Chain ID")

    model_config = {"frozen": True}
