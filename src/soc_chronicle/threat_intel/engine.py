"""Threat intelligence enrichment engine."""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import Any, cast

import httpx

from soc_chronicle.config.settings import ChronicleSettings, ThreatIntelProviderConfig
from soc_chronicle.models.ioc import IOC, IOCType


class ThreatIntelProvider(ABC):
    """Base class for threat intelligence enrichment providers."""

    name: str = "base"

    def __init__(self, config: ThreatIntelProviderConfig) -> None:
        self.config = config

    @abstractmethod
    async def enrich(self, ioc: IOC) -> dict[str, Any]:
        """Enrich a single IOC. Returns provider-specific result dict."""


class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"

    async def enrich(self, ioc: IOC) -> dict[str, Any]:
        if not self.config.api_key:
            return {"provider": self.name, "status": "disabled", "reason": "missing_api_key"}
        endpoint = self._endpoint(ioc)
        if not endpoint:
            return {"provider": self.name, "status": "unsupported", "ioc": ioc.value}
        headers = {"x-apikey": self.config.api_key}
        async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
            response = await client.get(endpoint, headers=headers)
            response.raise_for_status()
            data = response.json()
        malicious = self._malicious_count(data, ioc.type)
        return {
            "provider": self.name,
            "status": "ok",
            "ioc": ioc.value,
            "malicious": malicious,
            "raw": data,
        }

    def _endpoint(self, ioc: IOC) -> str | None:
        base = self.config.base_url or "https://www.virustotal.com/api/v3"
        if ioc.type == IOCType.SHA256:
            return f"{base}/files/{ioc.value}"
        if ioc.type in {IOCType.DOMAIN, IOCType.IPV4}:
            return f"{base}/{ioc.type.value}s/{ioc.value}"
        return None

    @staticmethod
    def _malicious_count(data: dict[str, Any], ioc_type: IOCType) -> int:
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return int(stats.get("malicious", 0))


class AbuseIPDBProvider(ThreatIntelProvider):
    name = "abuseipdb"

    async def enrich(self, ioc: IOC) -> dict[str, Any]:
        if ioc.type != IOCType.IPV4 or not self.config.api_key:
            return {"provider": self.name, "status": "skipped"}
        base = self.config.base_url or "https://api.abuseipdb.com/api/v2"
        headers = {"Key": self.config.api_key, "Accept": "application/json"}
        params: dict[str, str | int] = {"ipAddress": ioc.value, "maxAgeInDays": 90}
        async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
            response = await client.get(f"{base}/check", headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
        score = data.get("data", {}).get("abuseConfidenceScore", 0)
        return {"provider": self.name, "status": "ok", "ioc": ioc.value, "abuse_score": score}


PROVIDER_REGISTRY: dict[str, type[ThreatIntelProvider]] = {
    "virustotal": VirusTotalProvider,
    "abuseipdb": AbuseIPDBProvider,
}


class ThreatIntelEngine:
    """Asynchronously enrich indicators with configurable providers."""

    def __init__(self, settings: ChronicleSettings | None = None) -> None:
        self.settings = settings or ChronicleSettings()
        self.providers = self._load_providers()

    def _load_providers(self) -> list[ThreatIntelProvider]:
        providers: list[ThreatIntelProvider] = []
        for name, config in self.settings.threat_intel.items():
            if not config.enabled:
                continue
            cls = PROVIDER_REGISTRY.get(name)
            if cls:
                providers.append(cls(config))
        return providers

    async def enrich_all(self, iocs: list[IOC]) -> list[dict[str, Any]]:
        if not self.providers:
            return [{"status": "no_providers_configured"}]
        tasks = [self._enrich_ioc(ioc) for ioc in iocs]
        return await asyncio.gather(*tasks)

    async def _fetch(self, url: str, headers: dict[str, str], params: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            return cast(dict[str, Any], response.json())

    async def _enrich_ioc(self, ioc: IOC) -> dict[str, Any]:
        results: list[dict[str, Any]] = []
        for provider in self.providers:
            try:
                result = await provider.enrich(ioc)
                results.append(result)
            except Exception as exc:  # noqa: BLE001 — aggregate provider failures
                results.append({"provider": provider.name, "status": "error", "error": str(exc)})
        return {"ioc": ioc.value, "type": ioc.type.value, "results": results}

    def malicious_hashes(self, enrichment: list[dict[str, Any]]) -> set[str]:
        malicious: set[str] = set()
        for item in enrichment:
            for result in item.get("results", []):
                if result.get("malicious", 0) > 0:
                    malicious.add(str(item.get("ioc", "")))
        return malicious
