"""Indicator of Compromise models — industry-standard fields and types."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class IOCType(StrEnum):
    # Network indicators
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    ASN = "asn"
    CIDR = "cidr"

    # Cryptographic hashes
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    IMPHASH = "imphash"  # PE import hash
    SSDEEP = "ssdeep"    # Fuzzy hash
    TLSH = "tlsh"        # Trend Micro Locality Sensitive Hash

    # TLS/Network fingerprints
    JA3 = "ja3"          # TLS client fingerprint (MD5 of ClientHello fields)
    JA3S = "ja3s"        # TLS server fingerprint
    JARM = "jarm"        # Active TLS server fingerprint (62-char)

    # Vulnerability
    CVE = "cve"

    # Filesystem / endpoint
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    PROCESS = "process"
    PARENT_PROCESS = "parent_process"
    YARA_RULE = "yara_rule"

    # Identity
    USER = "user"
    HOSTNAME = "hostname"

    # Cryptocurrency wallets
    BTCWALLET = "btcwallet"
    XMRWALLET = "xmrwallet"


class TLPLevel(StrEnum):
    """Traffic Light Protocol 2.0 classification levels."""
    CLEAR = "TLP:CLEAR"            # No restriction (previously TLP:WHITE)
    GREEN = "TLP:GREEN"            # Community-wide sharing
    AMBER = "TLP:AMBER"            # Limited to org and trusted partners
    AMBER_STRICT = "TLP:AMBER+STRICT"  # Limited to org only
    RED = "TLP:RED"                # Not for disclosure, recipients only


class KillChainPhase(StrEnum):
    """Unified Kill Chain / Lockheed Martin Kill Chain phases."""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command-and-control"
    ACTIONS_ON_OBJECTIVES = "actions-on-objectives"
    # Unified Kill Chain extensions
    INITIAL_FOOTHOLD = "initial-foothold"
    NETWORK_PROPAGATION = "network-propagation"
    EXFILTRATION = "exfiltration"


class IOC(BaseModel):
    """Extracted and normalized indicator of compromise.

    Follows STIX 2.1 Indicator object conventions where applicable.
    """

    type: IOCType
    value: str
    original_value: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    source: str = "extraction"
    defanged: bool = False

    # Context and classification
    context: str | None = None
    tags: list[str] = Field(default_factory=list)
    tlp: TLPLevel = TLPLevel.CLEAR

    # Threat intelligence attribution
    threat_actor: str | None = None
    malware_family: str | None = None
    campaign: str | None = None
    kill_chain_phase: KillChainPhase | None = None

    # Temporal metadata
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    # Enrichment data from threat intel providers
    enrichment: dict[str, Any] = Field(default_factory=dict)

    # Related indicators (list of normalized_key strings)
    related_iocs: list[str] = Field(default_factory=list)

    def normalized_key(self) -> str:
        return f"{self.type}:{self.value.lower()}"

    def is_network_indicator(self) -> bool:
        """True for network-observable indicators."""
        return self.type in {
            IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN,
            IOCType.URL, IOCType.EMAIL, IOCType.ASN, IOCType.CIDR,
        }

    def is_file_indicator(self) -> bool:
        """True for file/endpoint indicators."""
        return self.type in {
            IOCType.MD5, IOCType.SHA1, IOCType.SHA256, IOCType.SHA512,
            IOCType.IMPHASH, IOCType.SSDEEP, IOCType.TLSH,
            IOCType.FILE_PATH, IOCType.YARA_RULE,
        }

    def is_high_fidelity(self) -> bool:
        """True for indicators that rarely produce false positives."""
        return self.type in {
            IOCType.SHA256, IOCType.SHA512, IOCType.JA3, IOCType.JA3S,
            IOCType.JARM, IOCType.CVE, IOCType.IMPHASH,
        }
