"""Graceful field validators for OCSF model construction.

Invalid individual fields are dropped or coerced rather than crashing the parser.
Production parsers should use :func:`safe_build_normalized_event` to guarantee
the normalization engine never raises on malformed vendor logs.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)

_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")

# Windows FILETIME epoch: 1601-01-01 UTC in microseconds.
_FILETIME_EPOCH_US = 11644473600000000


def coerce_utc_datetime(
    value: Any,
    *,
    skew_offset_seconds: float = 0.0,
) -> datetime | None:
    """Parse a timestamp and normalize it to UTC.

    Supports ISO-8601 strings, ``datetime`` objects, Unix epoch (int/float),
    and Windows FILETIME integers (100-ns intervals since 1601-01-01).

    Parameters
    ----------
    value:
        Raw timestamp from a vendor log.
    skew_offset_seconds:
        Optional clock-skew correction applied after parsing. Positive values
        shift the timestamp forward; negative values shift it backward.

    Returns
    -------
    datetime | None
        UTC-normalized timestamp, or ``None`` when parsing fails.
    """
    if value is None:
        return None

    dt: datetime | None = None

    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = _parse_numeric_timestamp(value)
    else:
        text = str(value).strip()
        if not text:
            return None
        if text.isdigit():
            dt = _parse_numeric_timestamp(int(text))
        else:
            text = text.replace("Z", "+00:00")
            try:
                dt = datetime.fromisoformat(text)
            except ValueError:
                return None

    if dt is None:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    else:
        dt = dt.astimezone(UTC)

    if skew_offset_seconds:
        dt = dt + timedelta(seconds=skew_offset_seconds)

    return dt


def _parse_numeric_timestamp(value: int | float) -> datetime | None:
    """Parse Unix epoch or Windows FILETIME numeric timestamps."""
    numeric = float(value)
    if numeric <= 0:
        return None

    # Windows FILETIME: values > 1e17 are 100-ns intervals since 1601-01-01.
    if numeric > 1e17:
        try:
            micros = (numeric / 10) - _FILETIME_EPOCH_US
            return datetime.fromtimestamp(micros / 1_000_000, tz=UTC)
        except (OSError, OverflowError, ValueError):
            return None

    # Millisecond epoch (13 digits).
    if numeric > 1e12:
        return datetime.fromtimestamp(numeric / 1000, tz=UTC)

    # Second epoch.
    try:
        return datetime.fromtimestamp(numeric, tz=UTC)
    except (OSError, OverflowError, ValueError):
        return None


def coerce_int(
    value: Any,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int | None:
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
    """Validate and return a canonical IP address (v4 or v6).

    If the value looks like a hostname rather than an IP, returns ``None``
    without raising — callers should store hostnames in ``domain`` fields.
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def coerce_domain(value: Any) -> str | None:
    """Validate a domain/hostname string, returning ``None`` for IPs or invalid values."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text or len(text) > 253:
        return None
    if coerce_ip(text) is not None:
        return None
    if not re.match(r"^[a-z0-9]([a-z0-9\-._]*[a-z0-9])?$", text):
        return None
    return text


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


def coerce_sha1(value: Any) -> str | None:
    """Validate a SHA-1 hash."""
    if value is None:
        return None
    text = str(value).strip()
    if text.upper().startswith("SHA1="):
        text = text.split("=", 1)[1].strip()
    if _SHA1_RE.match(text):
        return text.lower()
    return None


def coerce_md5(value: Any) -> str | None:
    """Validate an MD5 hash."""
    if value is None:
        return None
    text = str(value).strip()
    if text.upper().startswith("MD5="):
        text = text.split("=", 1)[1].strip()
    if _MD5_RE.match(text):
        return text.lower()
    return None


def serialize_raw_data(raw: Any) -> str:
    """Serialize the original log payload to a string for audit retention.

    Every normalized event MUST retain the exact original log in ``raw_data``.
    """
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
                validated = model_cls.model_validate({key: value})
                clean[key] = getattr(validated, key)
            else:
                clean[key] = value
        except (ValidationError, TypeError, ValueError):
            continue
    return model_cls.model_construct(**clean)
