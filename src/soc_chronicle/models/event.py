"""OCSF-normalized event models — production bridge between flat and nested OCSF."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator, model_validator

from soc_chronicle.models.ocsf.enums import (
    ActivityId,
    OCSFClass,
    SeverityId,
    SourceType,
    StatusId,
    compute_type_uid,
)
from soc_chronicle.models.ocsf.events import BaseOCSFEvent, build_typed_event
from soc_chronicle.models.ocsf.objects import (
    Actor,
    Device,
    File,
    Fingerprint,
    Metadata,
    NetworkConnection,
    NetworkEndpoint,
    Process,
    Product,
    Session,
    User,
)
from soc_chronicle.models.ocsf.validators import (
    coerce_int,
    coerce_ip,
    coerce_port,
    coerce_sha256,
    coerce_utc_datetime,
    serialize_raw_data,
)

# Re-export for backward compatibility with existing imports.
__all__ = ["NormalizedEvent", "OCSFClass", "SourceType"]


class NormalizedEvent(BaseModel):
    """Vendor-neutral event normalized to OCSF schema.

    Maintains flat denormalized fields for correlation, DuckDB loading, and
    backward compatibility, while also supporting nested OCSF objects.
    """

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=True, validate_assignment=True)

    # Mandatory normalized fields.
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    source_type: str = "unknown"
    raw_data: str = ""
    timestamp: datetime

    # OCSF identifiers.
    class_uid: OCSFClass
    activity_id: ActivityId = ActivityId.UNKNOWN
    activity_name: str
    severity_id: SeverityId = SeverityId.UNKNOWN
    status_id: StatusId = StatusId.UNKNOWN

    # Nested OCSF objects (optional, populated when available).
    actor: Actor | None = None
    device: Device | None = None
    process: Process | None = None
    file: File | None = None
    connection_info: NetworkConnection | None = None
    session: Session | None = None
    metadata: Metadata | None = None

    # Flat denormalized fields for fast correlation and legacy consumers.
    host: str | None = None
    user: str | None = None
    process_name: str | None = None
    process_pid: int | None = None
    process_guid: str | None = None
    parent_process_name: str | None = None
    parent_process_pid: int | None = None
    parent_process_guid: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None
    domain: str | None = None
    registry_key: str | None = None
    session_id: str | None = None
    auth_id: str | None = None

    # Structured raw payload (legacy; prefer raw_data for audit trail).
    raw: dict[str, Any] = Field(default_factory=dict)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def id(self) -> str:
        """Legacy alias for ``event_id``."""
        return self.event_id

    @computed_field  # type: ignore[prop-decorator]
    @property
    def raw_source(self) -> str:
        """Legacy alias for ``source_type``."""
        return self.source_type

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_fields(cls, data: Any) -> Any:
        """Accept legacy ``id`` and ``raw_source`` field names."""
        if not isinstance(data, dict):
            return data
        payload = dict(data)
        if "id" in payload and "event_id" not in payload:
            payload["event_id"] = payload.pop("id")
        if "raw_source" in payload and "source_type" not in payload:
            payload["source_type"] = payload.pop("raw_source")
        return payload

    @field_validator("timestamp", mode="before")
    @classmethod
    def validate_timestamp(cls, value: object) -> datetime:
        parsed = coerce_utc_datetime(value)
        if parsed is None:
            return datetime.now(tz=UTC)
        return parsed

    @field_validator("process_pid", "parent_process_pid", mode="before")
    @classmethod
    def validate_pids(cls, value: object) -> int | None:
        return coerce_int(value, minimum=0)

    @field_validator("src_port", "dst_port", mode="before")
    @classmethod
    def validate_ports(cls, value: object) -> int | None:
        return coerce_port(value)

    @field_validator("src_ip", "dst_ip", mode="before")
    @classmethod
    def validate_ips(cls, value: object) -> str | None:
        return coerce_ip(value)

    @field_validator("file_hash", mode="before")
    @classmethod
    def validate_file_hash(cls, value: object) -> str | None:
        return coerce_sha256(value)

    @model_validator(mode="after")
    def sync_flat_and_nested(self) -> NormalizedEvent:
        """Synchronize flat fields with nested OCSF objects bidirectionally."""
        if self.raw_data == "" and self.raw:
            object.__setattr__(self, "raw_data", serialize_raw_data(self.raw))

        # Populate flat fields from nested objects when missing.
        if self.device and not self.host:
            object.__setattr__(self, "host", self.device.hostname or self.device.name)
        if self.actor and self.actor.user and not self.user:
            object.__setattr__(self, "user", self.actor.user.name)
        if self.process:
            proc = self.process
            if not self.process_name:
                object.__setattr__(self, "process_name", proc.name)
            if self.process_pid is None:
                object.__setattr__(self, "process_pid", proc.pid)
            if not self.process_guid:
                object.__setattr__(self, "process_guid", proc.uid)
            if proc.parent_process:
                parent = proc.parent_process
                if not self.parent_process_name:
                    object.__setattr__(self, "parent_process_name", parent.name)
                if self.parent_process_pid is None:
                    object.__setattr__(self, "parent_process_pid", parent.pid)
                if not self.parent_process_guid:
                    object.__setattr__(self, "parent_process_guid", parent.uid)
        if self.file:
            if not self.file_path:
                object.__setattr__(self, "file_path", self.file.path)
            if not self.file_hash and self.file.hashes:
                for fp in self.file.hashes:
                    if fp.value:
                        object.__setattr__(self, "file_hash", fp.value)
                        break
        if self.connection_info:
            conn = self.connection_info
            if conn.src_endpoint:
                if not self.src_ip:
                    object.__setattr__(self, "src_ip", conn.src_endpoint.ip)
                if self.src_port is None:
                    object.__setattr__(self, "src_port", conn.src_endpoint.port)
            if conn.dst_endpoint:
                if not self.dst_ip:
                    object.__setattr__(self, "dst_ip", conn.dst_endpoint.ip)
                if self.dst_port is None:
                    object.__setattr__(self, "dst_port", conn.dst_endpoint.port)
                if not self.domain:
                    object.__setattr__(self, "domain", conn.dst_endpoint.domain)
            if not self.protocol:
                object.__setattr__(self, "protocol", conn.protocol_name)
        if self.session and not self.session_id:
            object.__setattr__(self, "session_id", self.session.uid)

        # Build nested objects from flat fields when not provided.
        if self.host and not self.device:
            object.__setattr__(self, "device", Device(hostname=self.host, name=self.host))
        if self.user and not self.actor:
            object.__setattr__(self, "actor", Actor(user=User(name=self.user)))
        if (
            any(
                (
                    self.process_name,
                    self.process_pid,
                    self.process_guid,
                    self.parent_process_name,
                    self.parent_process_pid,
                    self.parent_process_guid,
                )
            )
            and not self.process
        ):
            parent_proc: Process | None = None
            if self.parent_process_name or self.parent_process_pid or self.parent_process_guid:
                parent_proc = Process(
                    name=self.parent_process_name,
                    pid=self.parent_process_pid,
                    uid=self.parent_process_guid,
                )
            object.__setattr__(
                self,
                "process",
                Process(
                    name=self.process_name,
                    pid=self.process_pid,
                    uid=self.process_guid,
                    parent_process=parent_proc,
                ),
            )
        if (self.file_path or self.file_hash) and not self.file:
            hashes = [Fingerprint(value=self.file_hash)] if self.file_hash else None
            object.__setattr__(self, "file", File(path=self.file_path, hashes=hashes))
        if (
            any((self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol, self.domain))
            and not self.connection_info
        ):
            object.__setattr__(
                self,
                "connection_info",
                NetworkConnection(
                    protocol_name=self.protocol,
                    src_endpoint=NetworkEndpoint(ip=self.src_ip, port=self.src_port)
                    if self.src_ip or self.src_port
                    else None,
                    dst_endpoint=NetworkEndpoint(ip=self.dst_ip, port=self.dst_port, domain=self.domain)
                    if self.dst_ip or self.dst_port or self.domain
                    else None,
                ),
            )
        if self.session_id and not self.session:
            object.__setattr__(self, "session", Session(uid=self.session_id))

        if not self.metadata:
            object.__setattr__(
                self,
                "metadata",
                Metadata(
                    product=Product(name=self.source_type),
                    event_code=str(int(self.class_uid)),
                ),
            )

        return self

    @classmethod
    def from_raw(
        cls,
        data: dict[str, Any],
        *,
        raw_payload: Any = None,
        context: Any = None,
    ) -> NormalizedEvent | None:
        """Gracefully construct an event from a parser-produced dictionary.

        Delegates to :func:`safe_build_normalized_event` so parsers never crash
        the normalization engine on malformed vendor data.
        """
        from soc_chronicle.models.ocsf.factory import safe_build_normalized_event

        return safe_build_normalized_event(data, raw_payload=raw_payload, context=context)

    def type_uid(self) -> int:
        """Return the computed OCSF type_uid for this event."""
        return compute_type_uid(self.class_uid, self.activity_id)

    def to_ocsf_event(self) -> BaseOCSFEvent:
        """Convert to a typed OCSF event model."""
        base_kwargs: dict[str, Any] = {
            "event_id": self.event_id,
            "source_type": self.source_type,
            "raw_data": self.raw_data,
            "timestamp": self.timestamp,
            "activity_id": self.activity_id,
            "activity_name": self.activity_name,
            "severity_id": self.severity_id,
            "status_id": self.status_id,
            "actor": self.actor,
            "device": self.device,
            "metadata": self.metadata,
        }
        if self.class_uid == OCSFClass.PROCESS_ACTIVITY:
            return build_typed_event(OCSFClass.PROCESS_ACTIVITY, process=self.process, **base_kwargs)
        if self.class_uid == OCSFClass.FILE_ACTIVITY:
            return build_typed_event(OCSFClass.FILE_ACTIVITY, file=self.file, process=self.process, **base_kwargs)
        if self.class_uid == OCSFClass.NETWORK_ACTIVITY:
            return build_typed_event(
                OCSFClass.NETWORK_ACTIVITY,
                connection_info=self.connection_info,
                process=self.process,
                **base_kwargs,
            )
        if self.class_uid == OCSFClass.AUTHENTICATION:
            src_ep = None
            if self.src_ip or self.src_port:
                src_ep = NetworkEndpoint(ip=self.src_ip, port=self.src_port)
            return build_typed_event(OCSFClass.AUTHENTICATION, session=self.session, src_endpoint=src_ep, **base_kwargs)
        if self.class_uid == OCSFClass.REGISTRY_KEY_ACTIVITY:
            return build_typed_event(
                OCSFClass.REGISTRY_KEY_ACTIVITY,
                reg_key=self.registry_key,
                process=self.process,
                **base_kwargs,
            )
        if self.class_uid == OCSFClass.DNS_ACTIVITY:
            return build_typed_event(
                OCSFClass.DNS_ACTIVITY,
                query=self.domain,
                connection_info=self.connection_info,
                **base_kwargs,
            )
        if self.class_uid == OCSFClass.REGISTRY_VALUE_ACTIVITY:
            return build_typed_event(
                OCSFClass.REGISTRY_VALUE_ACTIVITY,
                reg_key=self.registry_key,
                process=self.process,
                **base_kwargs,
            )
        if self.class_uid == OCSFClass.HTTP_ACTIVITY:
            return build_typed_event(
                OCSFClass.HTTP_ACTIVITY,
                connection_info=self.connection_info,
                **base_kwargs,
            )
        return build_typed_event(self.class_uid, **base_kwargs)

    def correlation_keys(self) -> dict[str, str | int]:
        """Return non-empty fields usable for deterministic correlation."""
        keys: dict[str, str | int] = {}
        for field in (
            "host",
            "user",
            "process_name",
            "parent_process_name",
            "process_pid",
            "parent_process_pid",
            "process_guid",
            "parent_process_guid",
            "file_hash",
            "registry_key",
            "session_id",
            "auth_id",
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "protocol",
            "domain",
        ):
            value = getattr(self, field)
            if value is not None:
                keys[field] = value
        return keys
