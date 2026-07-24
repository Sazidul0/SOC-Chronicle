"""Alert and intake models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class AlertSource(StrEnum):
    JSON = "json"
    YAML = "yaml"
    SYSLOG = "syslog"
    WEBHOOK = "webhook"
    REST = "rest"
    KAFKA = "kafka"
    RABBITMQ = "rabbitmq"
    FILE = "file"
    SIEM_EXPORT = "siem_export"
    UNKNOWN = "unknown"


class Alert(BaseModel):
    """Normalized security alert from any detection platform."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str | None = None
    severity: str = "medium"
    source: AlertSource = AlertSource.UNKNOWN
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    raw: dict[str, Any] = Field(default_factory=dict)
    host: str | None = None
    user: str | None = None
    rule_id: str | None = None
    rule_name: str | None = None
    tags: list[str] = Field(default_factory=list)

    model_config = {"extra": "allow"}
