"""Structured threat intelligence result models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ProviderResult(BaseModel):
    """Result from a single threat intelligence provider."""

    provider: str
    status: str  # ok | error | not_found | skipped | cached
    ioc_value: str = ""
    ioc_type: str = ""

    is_malicious: bool = False
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    threat_score: float = Field(ge=0.0, le=100.0, default=0.0)
    tags: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    geo_country: str | None = None
    geo_city: str | None = None
    geo_asn: str | None = None
    geo_org: str | None = None

    open_ports: list[int] = Field(default_factory=list)
    cpes: list[str] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)

    greynoise_classification: str | None = None
    greynoise_name: str | None = None

    raw: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class ThreatIntelResult(BaseModel):
    """Aggregated threat intelligence result across all providers for one IOC."""

    ioc_value: str
    ioc_type: str

    is_malicious: bool = False
    threat_score: float = Field(ge=0.0, le=100.0, default=0.0)
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)

    tags: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    campaigns: list[str] = Field(default_factory=list)
    related_cves: list[str] = Field(default_factory=list)

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    geo_country: str | None = None
    geo_city: str | None = None
    geo_asn: str | None = None
    geo_org: str | None = None

    open_ports: list[int] = Field(default_factory=list)
    cpes: list[str] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)

    provider_results: list[ProviderResult] = Field(default_factory=list)

    cached: bool = False
    enriched_at: datetime | None = None
