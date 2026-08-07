"""Configuration management."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ThreatIntelProviderConfig(BaseSettings):
    enabled: bool = False
    api_key: str | None = None
    base_url: str | None = None
    rate_limit_per_minute: int = 4
    timeout_seconds: float = 30.0


class ChronicleSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CHRONICLE_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    log_level: str = "INFO"
    cache_dir: Path = Path.home() / ".cache" / "soc-chronicle"
    default_timezone: str = "UTC"
    correlation_window_seconds: int = 3600
    deduplicate_iocs: bool = True

    # Threat intel settings
    threat_intel: dict[str, ThreatIntelProviderConfig] = Field(default_factory=dict)
    cache_ttl_seconds: int = 14400          # 4 hours
    max_enrichment_concurrency: int = 10

    # Optional API keys for keyed providers (convenience shortcuts)
    otx_api_key: str | None = None
    greynoise_api_key: str | None = None

    @classmethod
    def from_file(cls, path: Path) -> ChronicleSettings:
        if not path.exists():
            return cls()
        with path.open() as f:
            data: dict[str, Any] = yaml.safe_load(f) or {}
        return cls(**data)


def get_settings(config_path: Path | None = None) -> ChronicleSettings:
    if config_path and config_path.exists():
        return ChronicleSettings.from_file(config_path)
    for candidate in (
        Path("chronicle.yaml"),
        Path("chronicle.yml"),
        Path("config/chronicle.yaml"),
    ):
        if candidate.exists():
            return ChronicleSettings.from_file(candidate)
    return ChronicleSettings()
