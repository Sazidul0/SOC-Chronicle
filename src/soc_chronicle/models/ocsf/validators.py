"""Graceful field validators for OCSF model construction.

Invalid individual fields are dropped or coerced rather than crashing the parser.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Any, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def coerce_utc_datetime(value: Any) -> datetime | None:
    """Parse a timestamp and normalize it to UTC.

    Returns ``None`` when the value cannot be parsed.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        text = str(value).strip()
        if not text:
            return None
        text = text.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def coerce_int(value: Any, *, minimum: int | None = None, maximum: int | None = None) -> int | None:
    """Coerce a value to int within optional bounds, returning ``None`` on failure."""
    if value is None:
        return None
    try:
        result = int(value)
    except (TypeError, ValueError):
        return None
    if minimum is not None and result < minimum:
        return None
    if maximum is not None and result > maximum:
        return None
    return result


def coerce_port(value: Any) -> int | None:
    """Coerce a network port (1-65535)."""
    return coerce_int(value, minimum=1, maximum=65535)


def coerce_ipv4(value: Any) -> str | None:
    """Validate and return a canonical IPv4 address string."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.version != 4:
        return None
    return str(addr)


def coerce_ipv6(value: Any) -> str | None:
    """Validate and return a canonical IPv6 address string."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if addr.version != 6:
        return None
    return str(addr)


def coerce_ip(value: Any) -> str | None:
    """Validate and return a canonical IP address (v4 or v6)."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def coerce_sha256(value: Any) -> str | None:
    """Validate a SHA-256 hash, stripping common prefix formats."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.upper().startswith("SHA256="):
        text = text.split("=", 1)[1].strip()
    if _SHA256_RE.match(text):
        return text.lower()
    return None


def serialize_raw_data(raw: Any) -> str:
    """Serialize the original log payload to a string for audit retention."""
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw
    try:
        return json.dumps(raw, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(raw)


def safe_model_construct(model_cls: type[T], data: dict[str, Any]) -> T:
    """Construct a Pydantic model, dropping fields that fail validation.

    Each field is validated individually; invalid fields are omitted rather than
    raising ``ValidationError``.
    """
    clean: dict[str, Any] = {}
    for key, value in data.items():
        if value is None:
            continue
        field = model_cls.model_fields.get(key)
        if field is None:
            continue
        try:
            if isinstance(value, BaseModel):
                clean[key] = value
            elif field.annotation is not None:
                # Use pydantic's field validator via model_validate on a single-field dict.
                validated = model_cls.model_validate({key: value})
                clean[key] = getattr(validated, key)
            else:
                clean[key] = value
        except Exception:
            continue
    return model_cls.model_construct(**clean)
