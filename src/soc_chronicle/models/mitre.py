"""MITRE ATT&CK mapping models."""

from __future__ import annotations

from pydantic import BaseModel, Field

from soc_chronicle.models.evidence import EvidenceRef


class MitreMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.9)
    evidence: list[EvidenceRef] = Field(default_factory=list)
    description: str | None = None
