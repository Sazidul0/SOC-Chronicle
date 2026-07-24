"""IOC extraction engine with regex pipelines and normalization."""

from __future__ import annotations

import re
from collections.abc import Iterable

from soc_chronicle.models.alert import Alert
from soc_chronicle.models.ioc import IOC, IOCType

# Defanging patterns
DEFANG_MAP = {
    "[.]": ".",
    "(.)": ".",
    "[@]": "@",
    "[:]": ":",
    "hxxp": "http",
    "hxxps": "https",
}


class IOCExtractionEngine:
    """Extract and normalize indicators from alerts and raw text."""

    PATTERNS: dict[IOCType, re.Pattern[str]] = {
        IOCType.IPV4: re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
        ),
        IOCType.IPV6: re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
        IOCType.DOMAIN: re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.|\[\.\]|\(\.\)))+"
            r"(?:[a-zA-Z]{2,63})\b"
        ),
        IOCType.URL: re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
        IOCType.EMAIL: re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        IOCType.SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
        IOCType.SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
        IOCType.MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
        IOCType.FILE_PATH: re.compile(
            r"(?:[A-Za-z]:\\|/)[^\s\"'<>|*?]+(?:\.(?:exe|dll|bat|ps1|doc|docx|js|vbs|scr|lnk))\b",
            re.IGNORECASE,
        ),
        IOCType.REGISTRY_KEY: re.compile(
            r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s\"']+",
            re.IGNORECASE,
        ),
        IOCType.MUTEX: re.compile(r"\b(?:Global\\|Local\\)[A-Za-z0-9_\\-]+\b"),
    }

    PROCESS_PATTERN = re.compile(
        r"\b(?:[A-Za-z]:\\)?(?:[^\\/\s]+\\)*([A-Za-z0-9_\-. ]+\.(?:exe|dll|sys))\b",
        re.IGNORECASE,
    )

    FALSE_POSITIVE_DOMAINS = {"example.com", "localhost", "microsoft.com", "windows.com"}

    def __init__(self, deduplicate: bool = True) -> None:
        self.deduplicate = deduplicate

    def extract_from_alert(self, alert: Alert) -> list[IOC]:
        texts = [alert.title, alert.description or "", str(alert.raw)]
        return self.extract_from_texts(texts, source=f"alert:{alert.id}")

    def extract_from_texts(self, texts: Iterable[str], source: str = "text") -> list[IOC]:
        combined = "\n".join(texts)
        iocs: list[IOC] = []
        for ioc_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(combined):
                raw_value = match.group()
                value = self._normalize(ioc_type, self._refang(raw_value))
                if not self._is_valid(ioc_type, value):
                    continue
                iocs.append(
                    IOC(
                        type=ioc_type,
                        value=value,
                        original_value=raw_value,
                        confidence=self._confidence(ioc_type, value),
                        source=source,
                        defanged=raw_value != self._refang(raw_value),
                    )
                )
        for match in self.PROCESS_PATTERN.finditer(combined):
            name = match.group(1).lower()
            iocs.append(
                IOC(
                    type=IOCType.PROCESS,
                    value=name,
                    original_value=match.group(),
                    confidence=0.7,
                    source=source,
                )
            )
        if alert_user := self._extract_structured_users(combined):
            iocs.extend(alert_user)
        return self._dedupe(iocs) if self.deduplicate else iocs

    def _extract_structured_users(self, text: str) -> list[IOC]:
        user_pattern = re.compile(r"\b(?:user(?:name)?|account)\s*[=:]\s*([^\s,;]+)", re.I)
        return [
            IOC(type=IOCType.USER, value=m.group(1).lower(), confidence=0.85, source="structured")
            for m in user_pattern.finditer(text)
        ]

    def _refang(self, text: str) -> str:
        result = text
        for defanged, clean in DEFANG_MAP.items():
            result = result.replace(defanged, clean)
        return result

    @staticmethod
    def _normalize(ioc_type: IOCType, value: str) -> str:
        value = value.strip().rstrip(".,;)")
        if ioc_type in {IOCType.SHA1, IOCType.SHA256, IOCType.MD5}:
            return value.lower()
        if ioc_type == IOCType.DOMAIN:
            return value.lower().lstrip("*.")
        if ioc_type == IOCType.URL:
            return value.rstrip("/")
        if ioc_type == IOCType.PROCESS:
            return value.split("\\")[-1].lower()
        return value

    def _is_valid(self, ioc_type: IOCType, value: str) -> bool:
        if ioc_type == IOCType.DOMAIN and value.lower() in self.FALSE_POSITIVE_DOMAINS:
            return False
        if ioc_type == IOCType.IPV4 and value.startswith(("127.", "0.", "255.")):
            return False
        return len(value) >= 3

    @staticmethod
    def _confidence(ioc_type: IOCType, value: str) -> float:
        if ioc_type in {IOCType.SHA256, IOCType.SHA1, IOCType.MD5}:
            return 0.95
        if ioc_type in {IOCType.IPV4, IOCType.URL}:
            return 0.85
        if ioc_type == IOCType.DOMAIN and len(value) > 8:
            return 0.75
        return 0.7

    @staticmethod
    def _dedupe(iocs: list[IOC]) -> list[IOC]:
        seen: dict[str, IOC] = {}
        for ioc in iocs:
            key = ioc.normalized_key()
            existing = seen.get(key)
            if existing is None or ioc.confidence > existing.confidence:
                seen[key] = ioc
        return list(seen.values())
