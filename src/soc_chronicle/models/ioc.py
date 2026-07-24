"""Indicator of Compromise models."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class IOCType(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    SHA1 = "sha1"
    SHA256 = "sha256"
    MD5 = "md5"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    USER = "user"
    HOSTNAME = "hostname"
    MUTEX = "mutex"
    PROCESS = "process"
    PARENT_PROCESS = "parent_process"


class IOC(BaseModel):
    """Extracted and normalized indicator of compromise."""

    type: IOCType
    value: str
    original_value: str | None = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    source: str = "extraction"
    defanged: bool = False
    context: str | None = None

    def normalized_key(self) -> str:
        return f"{self.type}:{self.value.lower()}"
