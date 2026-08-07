"""Investigation report and risk assessment models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from soc_chronicle.models.alert import Alert
from soc_chronicle.models.evidence import Evidence, EvidenceRef
from soc_chronicle.models.graph import InvestigationGraph
from soc_chronicle.models.ioc import IOC
from soc_chronicle.models.mitre import MitreMapping
from soc_chronicle.models.timeline import Timeline


class RiskFactor(BaseModel):
    label: str
    score: int
    confidence: float = 1.0
    evidence: list[EvidenceRef] = Field(default_factory=list)


class RiskAssessment(BaseModel):
    total_score: int = Field(ge=0, le=100)
    max_score: int = 100
    severity: str = "INFORMATIONAL"
    severity_justification: str = ""
    factors: list[RiskFactor] = Field(default_factory=list)

    @property
    def severity_label(self) -> str:
        return self.severity.lower()


class RecommendedAction(BaseModel):
    priority: str
    action: str
    rationale: str
    evidence: list[EvidenceRef] = Field(default_factory=list)


class InvestigationReport(BaseModel):
    """Complete investigation output with traceable evidence."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    alert: Alert
    summary: str
    narrative: str
    executive_summary: str
    timeline: Timeline
    graph: InvestigationGraph
    iocs: list[IOC] = Field(default_factory=list)
    mitre_mappings: list[MitreMapping] = Field(default_factory=list)
    risk: RiskAssessment
    evidence: list[Evidence] = Field(default_factory=list)
    affected_assets: list[str] = Field(default_factory=list)
    patient_zero: str | None = None
    root_cause: str | None = None
    blast_radius: int = 0
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")
