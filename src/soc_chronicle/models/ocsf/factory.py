"""Safe event construction factories for normalization parsers."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from soc_chronicle.models.event import NormalizedEvent
from soc_chronicle.models.ocsf.context import NormalizationContext
from soc_chronicle.models.ocsf.enums import ActivityId, OCSFClass, SeverityId, StatusId
from soc_chronicle.models.ocsf.validators import (
    coerce_utc_datetime,
    serialize_raw_data,
)

logger = logging.getLogger(__name__)

# Fields validated individually by NormalizedEvent; safe to pass through.
_SAFE_SCALAR_FIELDS = frozenset(
    {
        "event_id",
        "source_type",
        "raw_data",
        "class_uid",
        "activity_id",
        "activity_name",
        "severity_id",
        "status_id",
        "host",
        "user",
        "process_name",
        "process_pid",
        "process_guid",
        "parent_process_name",
        "parent_process_pid",
        "parent_process_guid",
        "file_path",
        "file_hash",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "domain",
        "registry_key",
        "session_id",
        "auth_id",
    }
)

_NESTED_FIELDS = frozenset(
    {"actor", "device", "process", "file", "connection_info", "session", "metadata"}
)


def safe_build_normalized_event(
    data: dict[str, Any],
    *,
    raw_payload: Any = None,
    context: NormalizationContext | None = None,
) -> NormalizedEvent | None:
    """Construct a :class:`NormalizedEvent` without crashing on bad vendor data.

    Invalid scalar fields are dropped; nested objects are passed through for
    Pydantic to validate. Returns ``None`` when mandatory fields cannot be
    resolved and ``context.strict_mode`` is enabled.

    Parameters
    ----------
    data:
        Partial event dictionary produced by a vendor parser.
    raw_payload:
        Original unparsed log record. Serialized into ``raw_data`` when
        ``data`` does not already contain it.
    context:
        Optional normalization context for skew offsets and defaults.
    """
    ctx = context or NormalizationContext()
    payload: dict[str, Any] = {}

    # --- Mandatory: raw_data ---
    if "raw_data" in data and data["raw_data"]:
        payload["raw_data"] = str(data["raw_data"])
    elif raw_payload is not None:
        payload["raw_data"] = serialize_raw_data(raw_payload)
    elif "raw" in data and data["raw"]:
        payload["raw_data"] = serialize_raw_data(data["raw"])
    else:
        payload["raw_data"] = serialize_raw_data(data)

    # --- Mandatory: event_id ---
    payload["event_id"] = str(data.get("event_id") or data.get("id") or uuid4())

    # --- Mandatory: source_type ---
    payload["source_type"] = str(
        data.get("source_type") or data.get("raw_source") or ctx.source_type
    )

    # --- Mandatory: class_uid ---
    class_uid = data.get("class_uid")
    if class_uid is None:
        if ctx.strict_mode:
            logger.debug("Dropping event: missing class_uid")
            return None
        class_uid = OCSFClass.DETECTION_FINDING
    if isinstance(class_uid, int) and not isinstance(class_uid, OCSFClass):
        try:
            class_uid = OCSFClass(class_uid)
        except ValueError:
            class_uid = OCSFClass.DETECTION_FINDING
    payload["class_uid"] = class_uid

    # --- Mandatory: activity_name ---
    activity_name = data.get("activity_name")
    if not activity_name:
        if ctx.strict_mode:
            logger.debug("Dropping event: missing activity_name")
            return None
        activity_name = "Unknown"
    payload["activity_name"] = str(activity_name)

    # --- Mandatory: timestamp (UTC) ---
    host = data.get("host")
    skew = ctx.skew_for_host(host if isinstance(host, str) else None)
    ts_raw = data.get("timestamp") or data.get("time") or data.get("@timestamp")
    parsed_ts = coerce_utc_datetime(ts_raw, skew_offset_seconds=skew)
    if parsed_ts is None:
        if ctx.strict_mode:
            logger.debug("Dropping event: unparseable timestamp %r", ts_raw)
            return None
        parsed_ts = datetime.now(tz=UTC)
    payload["timestamp"] = parsed_ts

    # --- Optional OCSF identifiers ---
    for enum_field, enum_cls, default in (
        ("activity_id", ActivityId, ActivityId.UNKNOWN),
        ("severity_id", SeverityId, SeverityId.UNKNOWN),
        ("status_id", StatusId, StatusId.UNKNOWN),
    ):
        val = data.get(enum_field, default)
        if isinstance(val, int) and not isinstance(val, enum_cls):
            try:
                val = enum_cls(val)
            except ValueError:
                val = default
        payload[enum_field] = val

    # --- Scalar correlation fields (validated by NormalizedEvent) ---
    for field_name in _SAFE_SCALAR_FIELDS:
        if field_name in data and data[field_name] is not None:
            payload[field_name] = data[field_name]

    # --- Nested OCSF objects ---
    for field_name in _NESTED_FIELDS:
        if field_name in data and data[field_name] is not None:
            payload[field_name] = data[field_name]

    # --- Legacy raw dict ---
    if "raw" in data and isinstance(data["raw"], dict):
        payload["raw"] = data["raw"]

    try:
        return NormalizedEvent.model_validate(payload)
    except Exception:
        logger.exception("Failed to construct NormalizedEvent from %r", data)
        return None
