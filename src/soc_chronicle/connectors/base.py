"""Base classes for ingest connectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Any


@dataclass
class ConnectorConfig:
    source_name: str
    batch_size: int = 1000
    poll_interval_seconds: float = 1.0
    
class IngestConnector(ABC):
    """Abstract base class for all ingest connectors."""
    
    def __init__(self, config: ConnectorConfig) -> None:
        self.config = config
        
    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the source if required."""
        
    @abstractmethod
    async def stream(self) -> AsyncGenerator[dict[str, Any], None]:
        """Stream raw records from the source."""
        yield {} # Type hint helper
        
    @abstractmethod
    async def close(self) -> None:
        """Close connection and clean up."""
