"""Models for Case Management."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class CaseStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    PENDING_CLOSURE = "pending_closure"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"

class CasePriority(StrEnum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"

class TLP(StrEnum):
    RED = "RED"
    AMBER = "AMBER"
    GREEN = "GREEN"
    CLEAR = "CLEAR"

class CaseNote(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    id: str
    case_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    author: str
    content: str
    evidence_refs: list[str] = Field(default_factory=list)

class CaseArtifact(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    id: str
    case_id: str
    name: str
    artifact_type: str
    path: str | None = None
    hash_value: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

class Case(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    
    id: str
    title: str
    status: CaseStatus = CaseStatus.OPEN
    priority: CasePriority = CasePriority.P3_MEDIUM
    alert_id: str | None = None
    report_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    assigned_to: str | None = None
    severity: str = "medium"
    tlp: TLP = TLP.GREEN
    notes: list[CaseNote] = Field(default_factory=list)
    artifacts: list[CaseArtifact] = Field(default_factory=list)
    iocs: list[str] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    resolution_notes: str | None = None
    closed_at: datetime | None = None
