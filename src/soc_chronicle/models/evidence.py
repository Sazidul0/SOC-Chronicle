"""Evidence models — every conclusion traces back to evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class EvidenceRef(BaseModel):
    """Lightweight reference to supporting evidence."""

    id: str
    summary: str
    source: str
    timestamp: datetime | None = None


class Evidence(BaseModel):
    """Concrete evidence artifact supporting an investigation finding."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    summary: str
    detail: str | None = None
    source: str
    timestamp: datetime | None = None
    event_id: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    def to_ref(self) -> EvidenceRef:
        return EvidenceRef(
            id=self.id,
            summary=self.summary,
            source=self.source,
            timestamp=self.timestamp,
        )
