"""Timeline models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from soc_chronicle.models.evidence import EvidenceRef


class TimelineEntry(BaseModel):
    timestamp: datetime
    phase: str | None = None
    summary: str
    detail: str | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)


class Timeline(BaseModel):
    entries: list[TimelineEntry] = Field(default_factory=list)
    timezone: str = "UTC"

    def sorted_entries(self) -> list[TimelineEntry]:
        return sorted(self.entries, key=lambda e: e.timestamp)
