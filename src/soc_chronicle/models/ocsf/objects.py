"""OCSF nested object models (actor, device, process, file, network)."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator

from soc_chronicle.models.ocsf.validators import (
    coerce_int,
    coerce_ip,
    coerce_port,
    coerce_sha256,
)

StrictModel = ConfigDict(extra="ignore", str_strip_whitespace=True, validate_assignment=True)


class Fingerprint(BaseModel):
    """Cryptographic fingerprint of an object (OCSF fingerprint object)."""

    model_config = StrictModel

    algorithm: str | None = None
    algorithm_id: int | None = None
    value: Annotated[str | None, Field(default=None, max_length=256)] = None

    @field_validator("value", mode="before")
    @classmethod
    def validate_hash(cls, value: object) -> str | None:
        normalized = coerce_sha256(value)
        if normalized is not None:
            return normalized
        if value is None:
            return None
        text = str(value).strip()
        return text or None


class User(BaseModel):
    """OCSF user object."""

    model_config = StrictModel

    name: str | None = None
    uid: str | None = None
    uid_alt: str | None = None
    domain: str | None = None
    type: str | None = None
    type_id: int | None = None


class Session(BaseModel):
    """OCSF session object for authentication correlation."""

    model_config = StrictModel

    uid: str | None = None
    credential_uid: str | None = None
    issuer: str | None = None
    created_time: str | None = None


class File(BaseModel):
    """OCSF file object."""

    model_config = StrictModel

    name: str | None = None
    path: str | None = None
    type: str | None = None
    type_id: int | None = None
    size: int | None = None
    hashes: list[Fingerprint] | None = None
    uid: str | None = None

    @field_validator("size", mode="before")
    @classmethod
    def validate_size(cls, value: object) -> int | None:
        return coerce_int(value, minimum=0)


class Process(BaseModel):
    """OCSF process object."""

    model_config = StrictModel

    name: str | None = None
    pid: int | None = None
    uid: str | None = None
    cmd_line: str | None = None
    file: File | None = None
    parent_process: Process | None = None
    created_time: str | None = None
    integrity: str | None = None
    integrity_id: int | None = None
    session: Session | None = None

    @field_validator("pid", mode="before")
    @classmethod
    def validate_pid(cls, value: object) -> int | None:
        return coerce_int(value, minimum=0)


class Actor(BaseModel):
    """OCSF actor — the entity performing an action."""

    model_config = StrictModel

    user: User | None = None
    process: Process | None = None


class Device(BaseModel):
    """OCSF device (host/endpoint) object."""

    model_config = StrictModel

    hostname: str | None = None
    name: str | None = None
    uid: str | None = None
    ip: str | None = None
    mac: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    type: str | None = None
    type_id: int | None = None

    @field_validator("ip", mode="before")
    @classmethod
    def validate_ip(cls, value: object) -> str | None:
        return coerce_ip(value)


class NetworkEndpoint(BaseModel):
    """OCSF network endpoint (source or destination)."""

    model_config = StrictModel

    ip: str | None = None
    port: int | None = None
    hostname: str | None = None
    domain: str | None = None
    mac: str | None = None
    interface_name: str | None = None
    interface_uid: str | None = None

    @field_validator("ip", mode="before")
    @classmethod
    def validate_ip(cls, value: object) -> str | None:
        return coerce_ip(value)

    @field_validator("port", mode="before")
    @classmethod
    def validate_port(cls, value: object) -> int | None:
        return coerce_port(value)


class NetworkConnection(BaseModel):
    """OCSF network connection object."""

    model_config = StrictModel

    protocol_name: str | None = None
    protocol_num: int | None = None
    direction: str | None = None
    direction_id: int | None = None
    src_endpoint: NetworkEndpoint | None = None
    dst_endpoint: NetworkEndpoint | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None


class Feature(BaseModel):
    """OCSF product feature metadata."""

    model_config = StrictModel

    name: str | None = None
    uid: str | None = None
    version: str | None = None


class Product(BaseModel):
    """OCSF product (log source) metadata."""

    model_config = StrictModel

    name: str | None = None
    vendor_name: str | None = None
    version: str | None = None
    uid: str | None = None
    feature: Feature | None = None


class Metadata(BaseModel):
    """OCSF metadata object describing event provenance."""

    model_config = StrictModel

    version: str = "1.3.0"
    product: Product | None = None
    logged_time: str | None = None
    original_time: str | None = None
    uid: str | None = None
    correlation_uid: str | None = None
    event_code: str | None = None
    profiles: list[str] | None = None
