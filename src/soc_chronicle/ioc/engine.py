"""IOC extraction engine — industry-standard regex pipelines and normalization."""

from __future__ import annotations

import base64
import ipaddress
import re
from collections.abc import Iterable

from soc_chronicle.models.alert import Alert
from soc_chronicle.models.ioc import IOC, IOCType, KillChainPhase, TLPLevel

# ---------------------------------------------------------------------------
# Defanging / refanging
# ---------------------------------------------------------------------------

DEFANG_MAP = {
    "[.]": ".",
    "(.)" : ".",
    "[@]": "@",
    "[:]": ":",
    "hxxp": "http",
    "hxxps": "https",
    "fxp": "ftp",
}

# ---------------------------------------------------------------------------
# RFC 1918 / Reserved private IP ranges (suppress false positives)
# ---------------------------------------------------------------------------

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("100.64.0.0/10"),     # CGN
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
]

# Known safe/CDN domains to exclude from IOC extraction
_FALSE_POSITIVE_DOMAINS: frozenset[str] = frozenset({
    "example.com", "localhost", "microsoft.com", "windows.com",
    "google.com", "cloudflare.com", "akamai.com", "fastly.com",
    "amazon.com", "amazonaws.com", "azure.com", "windowsupdate.com",
    "msftconnecttest.com", "msftncsi.com", "office.com", "office365.com",
    "live.com", "outlook.com", "microsoftonline.com",
    "apple.com", "icloud.com",
})

# PowerShell download cradle / AMSI bypass patterns
_PS_DOWNLOAD_CRADLE_RE = re.compile(
    r"(?:Invoke-WebRequest|IWR|wget|curl|Net\.WebClient|DownloadString|DownloadFile"
    r"|Start-BitsTransfer|Invoke-RestMethod)\s*['\"]?(https?://[^\s\"']+)",
    re.IGNORECASE,
)
_PS_ENCODED_CMD_RE = re.compile(
    r"-(?:enc(?:odedcommand)?|en)\s+([A-Za-z0-9+/=]{20,})",
    re.IGNORECASE,
)
_AMSI_BYPASS_RE = re.compile(
    r"(?:amsiInitFailed|AmsiScanBuffer|amsiContext|bypass|disable)\s*(?:amsi|AMSI)",
    re.IGNORECASE,
)


class IOCExtractionEngine:
    """Extract and normalize indicators from alerts and raw text.

    Covers:
      - Network: IPv4/IPv6, domains, URLs, email, ASN, CIDR
      - File/Hash: MD5, SHA1, SHA256, SHA512, IMPHASH, SSDEEP, TLSH
      - TLS fingerprints: JA3, JA3S, JARM
      - Vulnerability: CVE IDs
      - Endpoint: file paths, registry keys, mutexes, processes
      - Identity: usernames, hostnames
      - Crypto: BTC / XMR wallets
      - Behavioral: PowerShell encoded commands, download cradles
    """

    PATTERNS: dict[IOCType, re.Pattern[str]] = {
        IOCType.IPV4: re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
        ),
        IOCType.IPV6: re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
            r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
            r"|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
        ),
        IOCType.DOMAIN: re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.|(?:\[\.\])|(?:\(\.\))))"
            r"+(?:[a-zA-Z]{2,63})\b"
        ),
        IOCType.URL: re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
        IOCType.EMAIL: re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        IOCType.CIDR: re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d?\d)/(?:[12]?\d|3[0-2])\b"
        ),
        IOCType.ASN: re.compile(r"\bAS\d{1,10}\b", re.IGNORECASE),
        IOCType.CVE: re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),
        IOCType.SHA256: re.compile(r"\b[a-fA-F0-9]{64}\b"),
        IOCType.SHA512: re.compile(r"\b[a-fA-F0-9]{128}\b"),
        IOCType.SHA1: re.compile(r"\b[a-fA-F0-9]{40}\b"),
        IOCType.MD5: re.compile(r"\b[a-fA-F0-9]{32}\b"),
        # JARM: 62-char hex fingerprint
        IOCType.JARM: re.compile(r"\b[a-fA-F0-9]{62}\b"),
        IOCType.FILE_PATH: re.compile(
            r"(?:[A-Za-z]:\\|/)[^\s\"'<>|*?]+(?:\.(?:exe|dll|bat|ps1|sh|py|doc|docx"
            r"|js|vbs|scr|lnk|hta|msi|iso|img|zip|rar|7z|tar|gz))\b",
            re.IGNORECASE,
        ),
        IOCType.REGISTRY_KEY: re.compile(
            r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER"
            r"|HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU"
            r"|HKEY_CURRENT_CONFIG|HKCC)\\[^\s\"']+",
            re.IGNORECASE,
        ),
        IOCType.MUTEX: re.compile(r"\b(?:Global\\|Local\\)[A-Za-z0-9_\\-]+\b"),
        # Bitcoin P2PKH/P2SH/Bech32 addresses
        IOCType.BTCWALLET: re.compile(
            r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,39}|[13][a-zA-HJ-NP-Z0-9]{25,34})\b"
        ),
        # Monero addresses (95 chars starting with 4)
        IOCType.XMRWALLET: re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    }

    PROCESS_PATTERN = re.compile(
        r"\b(?:[A-Za-z]:\\)?(?:[^\\/\s]+\\)*([A-Za-z0-9_\-. ]+\.(?:exe|dll|sys))\b",
        re.IGNORECASE,
    )

    # JA3/JA3S: 32-char MD5 in TLS context keywords
    _JA3_CONTEXT_RE = re.compile(
        r"(?:ja3s?|tls_fingerprint|ssl_fingerprint)[=:\s\"]+([a-fA-F0-9]{32})",
        re.IGNORECASE,
    )

    # IMPHASH: 32-char MD5 in PE/import context
    _IMPHASH_CONTEXT_RE = re.compile(
        r"(?:imphash|import_hash|pe_imphash)[=:\s\"]+([a-fA-F0-9]{32})",
        re.IGNORECASE,
    )

    # SSDEEP: starts with block:hash:hash format
    _SSDEEP_RE = re.compile(r"\b\d+:[A-Za-z0-9+/]+:[A-Za-z0-9+/]+\b")

    # TLSH: starts with T1 followed by 70 hex chars
    _TLSH_RE = re.compile(r"\bT1[A-F0-9]{70}\b", re.IGNORECASE)

    def __init__(self, deduplicate: bool = True) -> None:
        self.deduplicate = deduplicate

    def extract_from_alert(self, alert: Alert) -> list[IOC]:
        texts = [alert.title, alert.description or "", str(alert.raw)]
        return self.extract_from_texts(texts, source=f"alert:{alert.id}")

    def extract_from_texts(self, texts: Iterable[str], source: str = "text") -> list[IOC]:
        combined = "\n".join(texts)
        refanged = self._refang(combined)
        iocs: list[IOC] = []

        # Standard pattern matching
        for ioc_type, pattern in self.PATTERNS.items():
            for match in pattern.finditer(refanged):
                raw_value = match.group()
                value = self._normalize(ioc_type, raw_value)
                if not self._is_valid(ioc_type, value):
                    continue
                iocs.append(
                    IOC(
                        type=ioc_type,
                        value=value,
                        original_value=match.group(),
                        confidence=self._confidence(ioc_type, value),
                        source=source,
                        defanged=raw_value.lower() not in combined.lower(),
                        tags=self._context_tags(ioc_type),
                    )
                )

        # Contextual extractions
        iocs.extend(self._extract_ja3(refanged, source))
        iocs.extend(self._extract_imphash(refanged, source))
        iocs.extend(self._extract_ssdeep(refanged, source))
        iocs.extend(self._extract_tlsh(refanged, source))
        iocs.extend(self._extract_processes(refanged, source))
        iocs.extend(self._extract_structured_users(refanged, source))
        iocs.extend(self.extract_from_command_line(refanged, source))

        return self._dedupe(iocs) if self.deduplicate else iocs

    def extract_from_command_line(self, cmdline: str, source: str = "cmdline") -> list[IOC]:
        """Analyze command-line arguments for PowerShell and shell attack patterns.

        Detects:
          - Base64-encoded PowerShell commands (decodes and re-extracts IOCs)
          - Download cradle URLs
          - AMSI bypass patterns
        """
        iocs: list[IOC] = []

        # Decode base64-encoded PowerShell commands
        for m in _PS_ENCODED_CMD_RE.finditer(cmdline):
            b64 = m.group(1)
            try:
                # PS uses UTF-16LE encoding
                decoded = base64.b64decode(b64 + "==").decode("utf-16-le", errors="ignore")
                # Re-extract IOCs from decoded payload
                for ioc in self.extract_from_texts([decoded], source=f"{source}:decoded_ps"):
                    ioc.tags.append("encoded-command")
                    ioc.kill_chain_phase = KillChainPhase.INSTALLATION
                    iocs.append(ioc)
            except Exception:  # noqa: BLE001 # nosec B112
                continue

        # Extract download cradle URLs
        for m in _PS_DOWNLOAD_CRADLE_RE.finditer(cmdline):
            url = m.group(1).strip("\"'")
            iocs.append(IOC(
                type=IOCType.URL,
                value=url,
                confidence=0.95,
                source=source,
                tags=["download-cradle", "living-off-the-land"],
                kill_chain_phase=KillChainPhase.DELIVERY,
            ))

        # Flag AMSI bypass patterns (no IOC value, but flag the event)
        if _AMSI_BYPASS_RE.search(cmdline):
            iocs.append(IOC(
                type=IOCType.YARA_RULE,
                value="amsi_bypass_pattern",
                confidence=0.90,
                source=source,
                tags=["amsi-bypass", "defense-evasion"],
                kill_chain_phase=KillChainPhase.EXPLOITATION,
            ))

        return iocs

    # ── Context-specific extractors ──────────────────────────────────────────

    def _extract_ja3(self, text: str, source: str) -> list[IOC]:
        iocs: list[IOC] = []
        for m in self._JA3_CONTEXT_RE.finditer(text):
            raw = m.group(1).lower()
            ioc_type = IOCType.JA3S if "ja3s" in m.group(0).lower() else IOCType.JA3
            iocs.append(IOC(
                type=ioc_type,
                value=raw,
                confidence=0.90,
                source=source,
                tags=["tls-fingerprint", "network"],
            ))
        return iocs

    def _extract_imphash(self, text: str, source: str) -> list[IOC]:
        return [
            IOC(
                type=IOCType.IMPHASH,
                value=m.group(1).lower(),
                confidence=0.90,
                source=source,
                tags=["pe-fingerprint", "file"],
            )
            for m in self._IMPHASH_CONTEXT_RE.finditer(text)
        ]

    def _extract_ssdeep(self, text: str, source: str) -> list[IOC]:
        return [
            IOC(
                type=IOCType.SSDEEP,
                value=m.group(),
                confidence=0.80,
                source=source,
                tags=["fuzzy-hash", "file"],
            )
            for m in self._SSDEEP_RE.finditer(text)
            if len(m.group()) > 10  # basic length sanity check
        ]

    def _extract_tlsh(self, text: str, source: str) -> list[IOC]:
        return [
            IOC(
                type=IOCType.TLSH,
                value=m.group().upper(),
                confidence=0.80,
                source=source,
                tags=["fuzzy-hash", "file"],
            )
            for m in self._TLSH_RE.finditer(text)
        ]

    def _extract_processes(self, text: str, source: str) -> list[IOC]:
        iocs: list[IOC] = []
        for match in self.PROCESS_PATTERN.finditer(text):
            name = match.group(1).lower()
            iocs.append(IOC(
                type=IOCType.PROCESS,
                value=name,
                original_value=match.group(),
                confidence=0.70,
                source=source,
                tags=["endpoint"],
            ))
        return iocs

    def _extract_structured_users(self, text: str, source: str) -> list[IOC]:
        user_pattern = re.compile(r"\b(?:user(?:name)?|account)\s*[=:]\s*([^\s,;]+)", re.I)
        return [
            IOC(
                type=IOCType.USER,
                value=m.group(1).lower(),
                confidence=0.85,
                source=source,
                tags=["identity"],
            )
            for m in user_pattern.finditer(text)
        ]

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _refang(self, text: str) -> str:
        result = text
        for defanged, clean in DEFANG_MAP.items():
            result = result.replace(defanged, clean)
        return result

    @staticmethod
    def _normalize(ioc_type: IOCType, value: str) -> str:
        value = value.strip().rstrip(".,;)")
        if ioc_type in {IOCType.SHA1, IOCType.SHA256, IOCType.SHA512, IOCType.MD5, IOCType.JARM}:
            return value.lower()
        if ioc_type == IOCType.DOMAIN:
            return value.lower().lstrip("*.")
        if ioc_type == IOCType.URL:
            return value.rstrip("/")
        if ioc_type == IOCType.PROCESS:
            return value.split("\\")[-1].lower()
        if ioc_type == IOCType.CVE:
            return value.upper()
        if ioc_type == IOCType.ASN:
            return value.upper()
        return value

    def _is_valid(self, ioc_type: IOCType, value: str) -> bool:
        if len(value) < 3:
            return False

        if ioc_type == IOCType.DOMAIN:
            if value.lower() in _FALSE_POSITIVE_DOMAINS:
                return False
            # Must have at least one dot and a valid TLD
            parts = value.split(".")
            if len(parts) < 2 or len(parts[-1]) < 2:
                return False

        if ioc_type == IOCType.IPV4:
            if self._is_private_ip(value):
                return False

        if ioc_type == IOCType.CIDR:
            if self._is_private_cidr(value):
                return False

        # MD5 must be exactly 32 chars
        if ioc_type == IOCType.MD5 and len(value) != 32:
            return False
        # SHA1 must be exactly 40 chars
        if ioc_type == IOCType.SHA1 and len(value) != 40:
            return False
        # SHA256 must be exactly 64 chars
        if ioc_type == IOCType.SHA256 and len(value) != 64:
            return False
        # JARM must be exactly 62 chars
        if ioc_type == IOCType.JARM and len(value) != 62:
            return False
        # CVE validation
        if ioc_type == IOCType.CVE and not value.upper().startswith("CVE-"):
            return False

        return True

    @staticmethod
    def _is_private_ip(value: str) -> bool:
        try:
            addr = ipaddress.ip_address(value)
            return any(addr in net for net in _PRIVATE_NETWORKS)
        except ValueError:
            return False

    @staticmethod
    def _is_private_cidr(value: str) -> bool:
        try:
            net = ipaddress.ip_network(value, strict=False)
            return net.is_private or net.is_loopback or net.is_link_local
        except ValueError:
            return False

    @staticmethod
    def _context_tags(ioc_type: IOCType) -> list[str]:
        """Assign semantic context tags to an IOC type."""
        network_types = {IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL, IOCType.ASN, IOCType.CIDR}
        file_types = {IOCType.MD5, IOCType.SHA1, IOCType.SHA256, IOCType.SHA512,
                      IOCType.IMPHASH, IOCType.SSDEEP, IOCType.TLSH, IOCType.FILE_PATH}
        endpoint_types = {IOCType.REGISTRY_KEY, IOCType.MUTEX, IOCType.PROCESS, IOCType.PARENT_PROCESS}
        identity_types = {IOCType.USER, IOCType.HOSTNAME, IOCType.EMAIL}
        tls_types = {IOCType.JA3, IOCType.JA3S, IOCType.JARM}

        if ioc_type in network_types:
            return ["network"]
        if ioc_type in file_types:
            return ["file"]
        if ioc_type in endpoint_types:
            return ["endpoint"]
        if ioc_type in identity_types:
            return ["identity"]
        if ioc_type in tls_types:
            return ["tls-fingerprint", "network"]
        if ioc_type == IOCType.CVE:
            return ["vulnerability"]
        if ioc_type in {IOCType.BTCWALLET, IOCType.XMRWALLET}:
            return ["cryptocurrency", "financial"]
        return []

    @staticmethod
    def _confidence(ioc_type: IOCType, value: str) -> float:
        """Assign confidence score based on indicator type specificity."""
        # Very high fidelity — near-zero false positives
        if ioc_type in {IOCType.SHA256, IOCType.SHA512, IOCType.JARM}:
            return 0.98
        if ioc_type in {IOCType.JA3, IOCType.JA3S, IOCType.IMPHASH}:
            return 0.93
        if ioc_type == IOCType.CVE:
            return 0.99
        if ioc_type in {IOCType.BTCWALLET, IOCType.XMRWALLET}:
            return 0.95
        # High fidelity
        if ioc_type in {IOCType.SHA1, IOCType.SSDEEP, IOCType.TLSH}:
            return 0.90
        if ioc_type in {IOCType.IPV4, IOCType.URL}:
            return 0.85
        if ioc_type == IOCType.EMAIL:
            return 0.85
        if ioc_type == IOCType.CIDR:
            return 0.80
        # Medium fidelity
        if ioc_type == IOCType.DOMAIN and len(value) > 8:
            return 0.75
        if ioc_type == IOCType.MD5:
            return 0.72  # MD5 collision risk
        if ioc_type == IOCType.ASN:
            return 0.65
        return 0.70

    @staticmethod
    def _dedupe(iocs: list[IOC]) -> list[IOC]:
        seen: dict[str, IOC] = {}
        for ioc in iocs:
            key = ioc.normalized_key()
            existing = seen.get(key)
            if existing is None or ioc.confidence > existing.confidence:
                seen[key] = ioc
        return list(seen.values())
