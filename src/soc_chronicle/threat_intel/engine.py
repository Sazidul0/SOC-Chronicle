"""Threat intelligence enrichment engine — industry-standard multi-provider enrichment."""

from __future__ import annotations

import asyncio
import hashlib
import json
import shelve  # nosec B403
import time
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from soc_chronicle.config.settings import ChronicleSettings, ThreatIntelProviderConfig
from soc_chronicle.models.ioc import IOC, IOCType
from soc_chronicle.models.threat_intel import ProviderResult, ThreatIntelResult


# ---------------------------------------------------------------------------
# Rate limiter (token bucket)
# ---------------------------------------------------------------------------

class _TokenBucket:
    """Simple token bucket rate limiter."""

    def __init__(self, rate_per_minute: int) -> None:
        self.capacity = max(rate_per_minute, 1)
        self.tokens = float(self.capacity)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * (self.capacity / 60.0))
            self._last_refill = now
            if self.tokens < 1:
                wait = (1 - self.tokens) * 60.0 / self.capacity
                await asyncio.sleep(wait)
                self.tokens = 0
            else:
                self.tokens -= 1


# ---------------------------------------------------------------------------
# Base provider
# ---------------------------------------------------------------------------

class ThreatIntelProvider(ABC):
    """Base class for threat intelligence enrichment providers."""

    name: str = "base"
    supported_types: frozenset[IOCType] = frozenset()

    def __init__(self, config: ThreatIntelProviderConfig) -> None:
        self.config = config
        self._rate_limiter = _TokenBucket(config.rate_limit_per_minute)

    @abstractmethod
    async def enrich(self, ioc: IOC) -> ProviderResult:
        """Enrich a single IOC. Returns a structured ProviderResult."""

    def supports(self, ioc: IOC) -> bool:
        return not self.supported_types or ioc.type in self.supported_types

    async def _get(self, url: str, headers: dict[str, str] | None = None,
                   params: dict[str, Any] | None = None) -> dict[str, Any]:
        await self._rate_limiter.acquire()
        async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
            resp = await client.get(url, headers=headers or {}, params=params)
            resp.raise_for_status()
            return dict(resp.json())

    async def _post(self, url: str, data: dict[str, Any],
                    headers: dict[str, str] | None = None) -> dict[str, Any]:
        await self._rate_limiter.acquire()
        async with httpx.AsyncClient(timeout=self.config.timeout_seconds) as client:
            resp = await client.post(url, data=data, headers=headers or {})
            resp.raise_for_status()
            return dict(resp.json())


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

class VirusTotalProvider(ThreatIntelProvider):
    name = "virustotal"
    supported_types = frozenset({IOCType.SHA256, IOCType.SHA1, IOCType.MD5, IOCType.DOMAIN, IOCType.IPV4, IOCType.URL})

    async def enrich(self, ioc: IOC) -> ProviderResult:
        if not self.config.api_key:
            return ProviderResult(provider=self.name, status="disabled", reason="missing_api_key",
                                   ioc_value=ioc.value, ioc_type=ioc.type)
        endpoint = self._endpoint(ioc)
        if not endpoint:
            return ProviderResult(provider=self.name, status="unsupported",
                                   ioc_value=ioc.value, ioc_type=ioc.type)
        try:
            data = await self._get(endpoint, headers={"x-apikey": self.config.api_key})
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return ProviderResult(provider=self.name, status="not_found",
                                       ioc_value=ioc.value, ioc_type=ioc.type)
            return ProviderResult(provider=self.name, status="error", error=str(e),
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        total = sum(stats.values()) or 1
        score = min(100.0, malicious * 100.0 / total)
        names = attrs.get("popular_threat_names", []) or []
        families = [n.get("value", "") for n in names if n.get("value")]
        tags = attrs.get("tags", []) or []
        return ProviderResult(
            provider=self.name,
            status="ok",
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            is_malicious=malicious > 3,
            confidence=min(1.0, malicious / max(total, 1)),
            threat_score=score,
            tags=list(tags),
            malware_families=families,
            raw=data,
        )

    def _endpoint(self, ioc: IOC) -> str | None:
        base = self.config.base_url or "https://www.virustotal.com/api/v3"
        if ioc.type in {IOCType.SHA256, IOCType.SHA1, IOCType.MD5}:
            return f"{base}/files/{ioc.value}"
        if ioc.type == IOCType.DOMAIN:
            return f"{base}/domains/{ioc.value}"
        if ioc.type == IOCType.IPV4:
            return f"{base}/ip_addresses/{ioc.value}"
        return None


# ---------------------------------------------------------------------------
# AbuseIPDB
# ---------------------------------------------------------------------------

class AbuseIPDBProvider(ThreatIntelProvider):
    name = "abuseipdb"
    supported_types = frozenset({IOCType.IPV4})

    async def enrich(self, ioc: IOC) -> ProviderResult:
        if not self.config.api_key:
            return ProviderResult(provider=self.name, status="disabled",
                                   ioc_value=ioc.value, ioc_type=ioc.type)
        base = self.config.base_url or "https://api.abuseipdb.com/api/v2"
        try:
            data = await self._get(
                f"{base}/check",
                headers={"Key": self.config.api_key, "Accept": "application/json"},
                params={"ipAddress": ioc.value, "maxAgeInDays": 90},
            )
        except httpx.HTTPStatusError as e:
            return ProviderResult(provider=self.name, status="error", error=str(e),
                                   ioc_value=ioc.value, ioc_type=ioc.type)
        d = data.get("data", {})
        score = int(d.get("abuseConfidenceScore", 0))
        country = d.get("countryCode") or d.get("country")
        return ProviderResult(
            provider=self.name,
            status="ok",
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            is_malicious=score >= 50,
            confidence=score / 100.0,
            threat_score=float(score),
            geo_country=country,
            raw=data,
        )


# ---------------------------------------------------------------------------
# MalwareBazaar (abuse.ch) — free, no key required
# ---------------------------------------------------------------------------

class MalwareBazaarProvider(ThreatIntelProvider):
    name = "malwarebazaar"
    supported_types = frozenset({IOCType.SHA256, IOCType.SHA1, IOCType.MD5})
    _BASE = "https://mb-api.abuse.ch/api/v1/"

    async def enrich(self, ioc: IOC) -> ProviderResult:
        query_map = {IOCType.SHA256: "get_info", IOCType.MD5: "get_info", IOCType.SHA1: "get_info"}
        if ioc.type not in query_map:
            return ProviderResult(provider=self.name, status="unsupported",
                                   ioc_value=ioc.value, ioc_type=ioc.type)
        try:
            data = await self._post(self._BASE, data={"query": "get_info", "hash": ioc.value})
        except Exception as e:  # noqa: BLE001
            return ProviderResult(provider=self.name, status="error", error=str(e),
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        query_status = data.get("query_status", "")
        if query_status == "hash_not_found":
            return ProviderResult(provider=self.name, status="not_found",
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        items = data.get("data", [])
        if not items:
            return ProviderResult(provider=self.name, status="not_found",
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        item = items[0]
        families = [item.get("signature")] if item.get("signature") else []
        tags = item.get("tags") or []
        first_seen_str = item.get("first_seen")
        first_seen = None
        if first_seen_str:
            try:
                first_seen = datetime.fromisoformat(first_seen_str.replace(" ", "T")).replace(tzinfo=UTC)
            except ValueError:
                pass
        return ProviderResult(
            provider=self.name,
            status="ok",
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            is_malicious=True,  # If found in MalwareBazaar, it's malicious
            confidence=0.95,
            threat_score=90.0,
            malware_families=families,
            tags=list(tags),
            first_seen=first_seen,
            raw=data,
        )


# ---------------------------------------------------------------------------
# URLhaus (abuse.ch) — free, no key required
# ---------------------------------------------------------------------------

class URLhausProvider(ThreatIntelProvider):
    name = "urlhaus"
    supported_types = frozenset({IOCType.URL, IOCType.DOMAIN, IOCType.IPV4})
    _BASE = "https://urlhaus-api.abuse.ch/v1/"

    async def enrich(self, ioc: IOC) -> ProviderResult:
        if ioc.type == IOCType.URL:
            endpoint = f"{self._BASE}url/"
            payload = {"url": ioc.value}
        elif ioc.type == IOCType.DOMAIN:
            endpoint = f"{self._BASE}host/"
            payload = {"host": ioc.value}
        elif ioc.type == IOCType.IPV4:
            endpoint = f"{self._BASE}host/"
            payload = {"host": ioc.value}
        else:
            return ProviderResult(provider=self.name, status="unsupported",
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        try:
            data = await self._post(endpoint, data=payload)
        except Exception as e:  # noqa: BLE001
            return ProviderResult(provider=self.name, status="error", error=str(e),
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        query_status = data.get("query_status", "")
        if query_status in {"no_results", "invalid_url"}:
            return ProviderResult(provider=self.name, status="not_found",
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        urls = data.get("urls", []) or []
        malicious_urls = [u for u in urls if u.get("url_status") == "online"]
        tags_raw = data.get("tags") or []
        return ProviderResult(
            provider=self.name,
            status="ok",
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            is_malicious=len(malicious_urls) > 0 or data.get("blacklists", {}).get("surbl") == "listed",
            confidence=0.90 if malicious_urls else 0.60,
            threat_score=85.0 if malicious_urls else 40.0,
            tags=list(tags_raw),
            raw=data,
        )


# ---------------------------------------------------------------------------
# ThreatFox (abuse.ch) — free, no key required
# ---------------------------------------------------------------------------

class ThreatFoxProvider(ThreatIntelProvider):
    name = "threatfox"
    supported_types = frozenset({IOCType.IPV4, IOCType.DOMAIN, IOCType.URL,
                                  IOCType.SHA256, IOCType.MD5, IOCType.SHA1})
    _BASE = "https://threatfox-api.abuse.ch/api/v1/"

    async def enrich(self, ioc: IOC) -> ProviderResult:
        payload: dict[str, Any] = {"query": "search_ioc", "search_term": ioc.value}
        try:
            data = await self._post(self._BASE, data={k: v for k, v in payload.items()})
        except Exception as e:  # noqa: BLE001
            return ProviderResult(provider=self.name, status="error", error=str(e),
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        if data.get("query_status") == "no_result":
            return ProviderResult(provider=self.name, status="not_found",
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        items = data.get("data") or []
        if not items:
            return ProviderResult(provider=self.name, status="not_found",
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        item = items[0]
        families = [item.get("malware")] if item.get("malware") else []
        actors = [item.get("threat_actor")] if item.get("threat_actor") else []
        tags = item.get("tags") or []
        return ProviderResult(
            provider=self.name,
            status="ok",
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            is_malicious=True,
            confidence=float(item.get("confidence_level", 50)) / 100.0,
            threat_score=float(item.get("confidence_level", 50)),
            malware_families=families,
            threat_actors=actors,
            tags=list(tags),
            raw=data,
        )


# ---------------------------------------------------------------------------
# Shodan InternetDB — free, no key required
# ---------------------------------------------------------------------------

class ShodanInternetDBProvider(ThreatIntelProvider):
    name = "shodan_internetdb"
    supported_types = frozenset({IOCType.IPV4})
    _BASE = "https://internetdb.shodan.io"

    async def enrich(self, ioc: IOC) -> ProviderResult:
        try:
            data = await self._get(f"{self._BASE}/{ioc.value}")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return ProviderResult(provider=self.name, status="not_found",
                                       ioc_value=ioc.value, ioc_type=ioc.type)
            return ProviderResult(provider=self.name, status="error", error=str(e),
                                   ioc_value=ioc.value, ioc_type=ioc.type)
        except Exception as e:  # noqa: BLE001
            return ProviderResult(provider=self.name, status="error", error=str(e),
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        vulns = data.get("vulns") or []
        ports = data.get("ports") or []
        cpes = data.get("cpes") or []
        tags = data.get("tags") or []
        hostnames = data.get("hostnames") or []
        is_malicious = len(vulns) > 0
        return ProviderResult(
            provider=self.name,
            status="ok",
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            is_malicious=is_malicious,
            confidence=0.85 if is_malicious else 0.40,
            threat_score=min(100.0, len(vulns) * 10.0),
            open_ports=[int(p) for p in ports],
            cpes=list(cpes),
            vulns=list(vulns),
            tags=list(tags),
            raw=data,
        )


# ---------------------------------------------------------------------------
# IP-API Geolocation — free, no key required
# ---------------------------------------------------------------------------

class IPAPIProvider(ThreatIntelProvider):
    name = "ip_api"
    supported_types = frozenset({IOCType.IPV4})
    _BASE = "http://ip-api.com/json"
    _FIELDS = "status,country,countryCode,city,org,as,query"

    async def enrich(self, ioc: IOC) -> ProviderResult:
        try:
            data = await self._get(
                f"{self._BASE}/{ioc.value}",
                params={"fields": self._FIELDS},
            )
        except Exception as e:  # noqa: BLE001
            return ProviderResult(provider=self.name, status="error", error=str(e),
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        if data.get("status") != "success":
            return ProviderResult(provider=self.name, status="not_found",
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        return ProviderResult(
            provider=self.name,
            status="ok",
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            is_malicious=False,  # Geo only — not a verdict provider
            confidence=0.0,
            geo_country=data.get("country"),
            geo_city=data.get("city"),
            geo_asn=data.get("as"),
            geo_org=data.get("org"),
            raw=data,
        )


# ---------------------------------------------------------------------------
# AlienVault OTX — requires API key
# ---------------------------------------------------------------------------

class AlienVaultOTXProvider(ThreatIntelProvider):
    name = "otx"
    supported_types = frozenset({IOCType.IPV4, IOCType.DOMAIN, IOCType.URL,
                                  IOCType.SHA256, IOCType.MD5, IOCType.SHA1})
    _BASE = "https://otx.alienvault.com/api/v1/indicators"

    async def enrich(self, ioc: IOC) -> ProviderResult:
        if not self.config.api_key:
            return ProviderResult(provider=self.name, status="disabled",
                                   ioc_value=ioc.value, ioc_type=ioc.type)
        section, indicator = self._endpoint(ioc)
        if not section:
            return ProviderResult(provider=self.name, status="unsupported",
                                   ioc_value=ioc.value, ioc_type=ioc.type)
        try:
            data = await self._get(
                f"{self._BASE}/{section}/{indicator}/general",
                headers={"X-OTX-API-KEY": self.config.api_key},
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return ProviderResult(provider=self.name, status="not_found",
                                       ioc_value=ioc.value, ioc_type=ioc.type)
            return ProviderResult(provider=self.name, status="error", error=str(e),
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        malware_families = []
        tags: list[str] = []
        for pulse in (data.get("pulse_info", {}).get("pulses") or [])[:5]:
            tags.extend(pulse.get("tags") or [])
            if pulse.get("malware_families"):
                malware_families.extend([f.get("display_name", "") for f in pulse["malware_families"]])
        return ProviderResult(
            provider=self.name,
            status="ok",
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            is_malicious=pulse_count > 0,
            confidence=min(1.0, pulse_count * 0.1),
            threat_score=min(100.0, pulse_count * 5.0),
            tags=list(set(tags)),
            malware_families=list(set(malware_families)),
            raw=data,
        )

    def _endpoint(self, ioc: IOC) -> tuple[str, str]:
        if ioc.type == IOCType.IPV4:
            return "IPv4", ioc.value
        if ioc.type == IOCType.DOMAIN:
            return "domain", ioc.value
        if ioc.type in {IOCType.SHA256, IOCType.MD5, IOCType.SHA1}:
            return "file", ioc.value
        if ioc.type == IOCType.URL:
            return "url", ioc.value
        return "", ""


# ---------------------------------------------------------------------------
# GreyNoise Community — requires free API key
# ---------------------------------------------------------------------------

class GreyNoiseProvider(ThreatIntelProvider):
    name = "greynoise"
    supported_types = frozenset({IOCType.IPV4})
    _BASE = "https://api.greynoise.io/v3/community"

    async def enrich(self, ioc: IOC) -> ProviderResult:
        if not self.config.api_key:
            return ProviderResult(provider=self.name, status="disabled",
                                   ioc_value=ioc.value, ioc_type=ioc.type)
        try:
            data = await self._get(
                f"{self._BASE}/{ioc.value}",
                headers={"key": self.config.api_key},
            )
        except httpx.HTTPStatusError as e:
            if e.response.status_code in {404, 400}:
                return ProviderResult(provider=self.name, status="not_found",
                                       ioc_value=ioc.value, ioc_type=ioc.type)
            return ProviderResult(provider=self.name, status="error", error=str(e),
                                   ioc_value=ioc.value, ioc_type=ioc.type)

        classification = data.get("classification", "unknown")
        is_malicious = classification == "malicious"
        noise = data.get("noise", False)
        riot = data.get("riot", False)  # RIOT = benign/known safe
        return ProviderResult(
            provider=self.name,
            status="ok",
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            is_malicious=is_malicious,
            confidence=0.85 if is_malicious else (0.10 if riot else 0.40),
            threat_score=85.0 if is_malicious else (0.0 if riot else 30.0),
            greynoise_classification=classification,
            greynoise_name=data.get("name"),
            tags=["internet-scanner"] if noise else [],
            raw=data,
        )


# ---------------------------------------------------------------------------
# Provider registry
# ---------------------------------------------------------------------------

PROVIDER_REGISTRY: dict[str, type[ThreatIntelProvider]] = {
    "virustotal": VirusTotalProvider,
    "abuseipdb": AbuseIPDBProvider,
    "malwarebazaar": MalwareBazaarProvider,
    "urlhaus": URLhausProvider,
    "threatfox": ThreatFoxProvider,
    "shodan_internetdb": ShodanInternetDBProvider,
    "ip_api": IPAPIProvider,
    "otx": AlienVaultOTXProvider,
    "greynoise": GreyNoiseProvider,
}

# Default free providers (no API key required)
DEFAULT_FREE_PROVIDERS = {
    "malwarebazaar": True,
    "urlhaus": True,
    "threatfox": True,
    "shodan_internetdb": True,
    "ip_api": True,
}


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class ThreatIntelEngine:
    """Asynchronously enrich indicators with configurable providers.

    Features:
    - 9 providers (5 free, 4 optional with API keys)
    - Disk-backed TTL cache (default 4 hours)
    - Per-provider token bucket rate limiting
    - Structured ThreatIntelResult output with aggregated verdicts
    - Configurable max concurrency
    """

    def __init__(self, settings: ChronicleSettings | None = None) -> None:
        self.settings = settings or ChronicleSettings()
        self.providers = self._load_providers()
        self._cache_dir = self.settings.cache_dir
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_ttl = getattr(self.settings, "cache_ttl_seconds", 14400)
        self._max_concurrency = getattr(self.settings, "max_enrichment_concurrency", 10)

    def _load_providers(self) -> list[ThreatIntelProvider]:
        providers: list[ThreatIntelProvider] = []
        configured = dict(self.settings.threat_intel)

        # Auto-enable free providers if not explicitly configured
        for pname, enabled in DEFAULT_FREE_PROVIDERS.items():
            if pname not in configured:
                from soc_chronicle.config.settings import ThreatIntelProviderConfig
                configured[pname] = ThreatIntelProviderConfig(enabled=enabled)

        for name, config in configured.items():
            if not config.enabled:
                continue
            cls = PROVIDER_REGISTRY.get(name)
            if cls:
                providers.append(cls(config))
        return providers

    def _cache_key(self, ioc: IOC) -> str:
        raw = f"{ioc.type}:{ioc.value.lower()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _cache_get(self, ioc: IOC) -> ThreatIntelResult | None:
        key = self._cache_key(ioc)
        cache_path = str(self._cache_dir / "ti_cache")
        try:
            with shelve.open(cache_path, flag="r") as db:  # nosec B301
                entry = db.get(key)
                if entry and (time.time() - entry["ts"]) < self._cache_ttl:
                    return ThreatIntelResult.model_validate(entry["data"])
        except Exception:  # noqa: BLE001 # nosec B110
            pass
        return None

    def _cache_set(self, ioc: IOC, result: ThreatIntelResult) -> None:
        key = self._cache_key(ioc)
        cache_path = str(self._cache_dir / "ti_cache")
        try:
            with shelve.open(cache_path) as db:  # nosec B301
                db[key] = {"ts": time.time(), "data": result.model_dump(mode="json")}
        except Exception:  # noqa: BLE001 # nosec B110
            pass

    async def enrich_all(self, iocs: list[IOC]) -> list[ThreatIntelResult]:
        """Enrich all IOCs concurrently, respecting max_concurrency."""
        if not self.providers:
            return [ThreatIntelResult(ioc_value=i.value, ioc_type=i.type) for i in iocs]
        sem = asyncio.Semaphore(self._max_concurrency)
        async def _bounded(ioc: IOC) -> ThreatIntelResult:
            async with sem:
                return await self._enrich_ioc(ioc)
        return list(await asyncio.gather(*[_bounded(i) for i in iocs]))

    async def _enrich_ioc(self, ioc: IOC) -> ThreatIntelResult:
        # Check cache first
        cached = self._cache_get(ioc)
        if cached:
            cached.cached = True
            return cached

        results: list[ProviderResult] = []
        eligible = [p for p in self.providers if p.supports(ioc)]
        tasks = [self._run_provider(p, ioc) for p in eligible]
        provider_results = await asyncio.gather(*tasks)
        results.extend(provider_results)

        aggregated = self._aggregate(ioc, results)
        self._cache_set(ioc, aggregated)
        return aggregated

    async def _run_provider(self, provider: ThreatIntelProvider, ioc: IOC) -> ProviderResult:
        try:
            return await provider.enrich(ioc)
        except Exception as exc:  # noqa: BLE001
            return ProviderResult(
                provider=provider.name,
                status="error",
                ioc_value=ioc.value,
                ioc_type=ioc.type,
                error=str(exc),
            )

    @staticmethod
    def _aggregate(ioc: IOC, results: list[ProviderResult]) -> ThreatIntelResult:
        """Merge provider results into a single verdict."""
        ok_results = [r for r in results if r.status == "ok"]
        is_malicious = any(r.is_malicious for r in ok_results)
        # Weighted average threat score from providers that returned ok
        scores = [r.threat_score for r in ok_results if r.is_malicious]
        threat_score = max(scores) if scores else 0.0
        # Confidence = max confidence across malicious providers, or 0
        confidence = max((r.confidence for r in ok_results if r.is_malicious), default=0.0)

        # Aggregate tags, families, actors
        all_tags: set[str] = set()
        all_families: set[str] = set()
        all_actors: set[str] = set()
        all_campaigns: set[str] = set()
        all_cves: set[str] = set()
        all_ports: set[int] = set()
        all_cpes: set[str] = set()
        all_vulns: set[str] = set()
        first_seen: datetime | None = None
        last_seen: datetime | None = None
        geo_country = geo_city = geo_asn = geo_org = None

        for r in results:
            all_tags.update(r.tags)
            all_families.update(r.malware_families)
            all_actors.update(r.threat_actors)
            all_campaigns.update(r.campaigns)
            all_ports.update(r.open_ports)
            all_cpes.update(r.cpes)
            all_vulns.update(r.vulns)
            if r.first_seen and (first_seen is None or r.first_seen < first_seen):
                first_seen = r.first_seen
            if r.last_seen and (last_seen is None or r.last_seen > last_seen):
                last_seen = r.last_seen
            if r.geo_country and not geo_country:
                geo_country, geo_city, geo_asn, geo_org = r.geo_country, r.geo_city, r.geo_asn, r.geo_org
            # Collect CVEs from vulns
            for v in r.vulns:
                if v.upper().startswith("CVE-"):
                    all_cves.add(v.upper())

        return ThreatIntelResult(
            ioc_value=ioc.value,
            ioc_type=ioc.type,
            is_malicious=is_malicious,
            threat_score=threat_score,
            confidence=confidence,
            tags=sorted(all_tags),
            malware_families=sorted(f for f in all_families if f),
            threat_actors=sorted(a for a in all_actors if a),
            campaigns=sorted(all_campaigns),
            related_cves=sorted(all_cves),
            first_seen=first_seen,
            last_seen=last_seen,
            geo_country=geo_country,
            geo_city=geo_city,
            geo_asn=geo_asn,
            geo_org=geo_org,
            open_ports=sorted(all_ports),
            cpes=sorted(all_cpes),
            vulns=sorted(all_vulns),
            provider_results=results,
            enriched_at=datetime.now(tz=UTC),
        )

    def malicious_hashes(self, results: list[ThreatIntelResult]) -> set[str]:
        """Return set of values that were confirmed malicious across any provider."""
        return {
            r.ioc_value
            for r in results
            if r.is_malicious and r.ioc_type in {IOCType.SHA256, IOCType.MD5, IOCType.SHA1}
        }
