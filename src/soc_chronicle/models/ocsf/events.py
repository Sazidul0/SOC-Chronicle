"""OCSF event class hierarchy with typed per-class models."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from soc_chronicle.models.ocsf.enums import (
    CLASS_TO_CATEGORY,
    ActivityId,
    CategoryUid,
    OCSFClass,
    SeverityId,
    StatusId,
    activity_name_for,
    compute_type_uid,
)
from soc_chronicle.models.ocsf.objects import (
    Actor,
    Device,
    File,
    Metadata,
    NetworkConnection,
    NetworkEndpoint,
    Process,
    Session,
)
from soc_chronicle.models.ocsf.validators import coerce_utc_datetime

StrictModel = ConfigDict(extra="ignore", str_strip_whitespace=True, validate_assignment=True)


class BaseOCSFEvent(BaseModel):
    """Base OCSF event containing universal fields shared across all classes."""

    model_config = StrictModel

    # Mandatory normalized fields (soc-chronicle contract).
    event_id: Annotated[str, Field(default_factory=lambda: str(uuid4()))]
    source_type: str = "unknown"
    raw_data: str = ""
    timestamp: datetime

    # OCSF core identifiers.
    class_uid: OCSFClass
    category_uid: CategoryUid | None = None
    activity_id: ActivityId = ActivityId.UNKNOWN
    activity_name: str = "Unknown"
    type_uid: int | None = None
    type_name: str | None = None
    severity_id: SeverityId = SeverityId.UNKNOWN
    status_id: StatusId = StatusId.UNKNOWN
    message: str | None = None
    duration: int | None = None
    count: int | None = None

    # Nested OCSF objects.
    actor: Actor | None = None
    device: Device | None = None
    metadata: Metadata | None = None

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_timestamp(cls, value: object) -> datetime:
        parsed = coerce_utc_datetime(value)
        if parsed is None:
            return datetime.now(tz=UTC)
        return parsed

    @model_validator(mode="after")
    def infer_category_and_type_uid(self) -> BaseOCSFEvent:
        if self.category_uid is None:
            inferred = CLASS_TO_CATEGORY.get(int(self.class_uid))
            if inferred is not None:
                object.__setattr__(self, "category_uid", inferred)
        if self.type_uid is None:
            object.__setattr__(
                self,
                "type_uid",
                compute_type_uid(self.class_uid, self.activity_id),
            )
        if self.activity_name == "Unknown" and self.activity_id != ActivityId.UNKNOWN:
            object.__setattr__(self, "activity_name", activity_name_for(self.activity_id))
        return self


class ProcessActivityEvent(BaseOCSFEvent):
    """OCSF Process Activity (class_uid=1007)."""

    class_uid: Literal[OCSFClass.PROCESS_ACTIVITY] = OCSFClass.PROCESS_ACTIVITY
    process: Process | None = None


class FileActivityEvent(BaseOCSFEvent):
    """OCSF File Activity (class_uid=1001)."""

    class_uid: Literal[OCSFClass.FILE_ACTIVITY] = OCSFClass.FILE_ACTIVITY
    file: File | None = None
    process: Process | None = None


class NetworkActivityEvent(BaseOCSFEvent):
    """OCSF Network Activity (class_uid=4001)."""

    class_uid: Literal[OCSFClass.NETWORK_ACTIVITY] = OCSFClass.NETWORK_ACTIVITY
    connection_info: NetworkConnection | None = None
    process: Process | None = None


class AuthenticationEvent(BaseOCSFEvent):
    """OCSF Authentication (class_uid=3002)."""

    class_uid: Literal[OCSFClass.AUTHENTICATION] = OCSFClass.AUTHENTICATION
    session: Session | None = None
    src_endpoint: NetworkEndpoint | None = None


class RegistryKeyActivityEvent(BaseOCSFEvent):
    """OCSF Registry Key Activity (class_uid=201001)."""

    class_uid: Literal[OCSFClass.REGISTRY_KEY_ACTIVITY] = OCSFClass.REGISTRY_KEY_ACTIVITY
    reg_key: str | None = None
    reg_value: str | None = None
    process: Process | None = None


class DNSActivityEvent(BaseOCSFEvent):
    """OCSF DNS Activity (class_uid=4003)."""

    class_uid: Literal[OCSFClass.DNS_ACTIVITY] = OCSFClass.DNS_ACTIVITY
    query: str | None = None
    answers: list[str] | None = None
    connection_info: NetworkConnection | None = None


class DetectionFindingEvent(BaseOCSFEvent):
    """OCSF Detection Finding (class_uid=2004)."""

    class_uid: Literal[OCSFClass.DETECTION_FINDING] = OCSFClass.DETECTION_FINDING
    finding: str | None = None
    confidence_id: int | None = None


class RegistryValueActivityEvent(BaseOCSFEvent):
    """OCSF Registry Value Activity (class_uid=201002)."""

    class_uid: Literal[OCSFClass.REGISTRY_VALUE_ACTIVITY] = OCSFClass.REGISTRY_VALUE_ACTIVITY
    reg_key: str | None = None
    reg_value: str | None = None
    process: Process | None = None


class HTTPActivityEvent(BaseOCSFEvent):
    """OCSF HTTP Activity (class_uid=4002)."""

    class_uid: Literal[OCSFClass.HTTP_ACTIVITY] = OCSFClass.HTTP_ACTIVITY
    http_request: str | None = None
    http_response: str | None = None
    url: str | None = None
    connection_info: NetworkConnection | None = None


class ScheduledJobActivityEvent(BaseOCSFEvent):
    """OCSF Scheduled Job Activity (class_uid=1006)."""

    class_uid: Literal[OCSFClass.SCHEDULED_JOB_ACTIVITY] = OCSFClass.SCHEDULED_JOB_ACTIVITY
    job: str | None = None
    process: Process | None = None


OCSFEvent = (
    ProcessActivityEvent
    | FileActivityEvent
    | NetworkActivityEvent
    | AuthenticationEvent
    | RegistryKeyActivityEvent
    | RegistryValueActivityEvent
    | DNSActivityEvent
    | HTTPActivityEvent
    | DetectionFindingEvent
    | ScheduledJobActivityEvent
)

# Registry for constructing typed events from class_uid.
EVENT_CLASS_REGISTRY: dict[OCSFClass, type[BaseOCSFEvent]] = {
    OCSFClass.PROCESS_ACTIVITY: ProcessActivityEvent,
    OCSFClass.FILE_ACTIVITY: FileActivityEvent,
    OCSFClass.NETWORK_ACTIVITY: NetworkActivityEvent,
    OCSFClass.AUTHENTICATION: AuthenticationEvent,
    OCSFClass.REGISTRY_KEY_ACTIVITY: RegistryKeyActivityEvent,
    OCSFClass.REGISTRY_VALUE_ACTIVITY: RegistryValueActivityEvent,
    OCSFClass.DNS_ACTIVITY: DNSActivityEvent,
    OCSFClass.HTTP_ACTIVITY: HTTPActivityEvent,
    OCSFClass.DETECTION_FINDING: DetectionFindingEvent,
    OCSFClass.SCHEDULED_JOB_ACTIVITY: ScheduledJobActivityEvent,
}


def build_typed_event(class_uid: OCSFClass, **kwargs: object) -> BaseOCSFEvent:
    """Construct the appropriate typed OCSF event for a given class_uid."""
    event_cls = EVENT_CLASS_REGISTRY.get(class_uid, BaseOCSFEvent)
    return event_cls(class_uid=class_uid, **kwargs)  # type: ignore[arg-type]
