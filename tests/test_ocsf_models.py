"""Tests for OCSF Pydantic models and graceful validation."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from soc_chronicle.models.event import NormalizedEvent, OCSFClass
from soc_chronicle.models.ocsf.enums import ActivityId, SeverityId
from soc_chronicle.models.ocsf.objects import Device, NetworkEndpoint, Process, User
from soc_chronicle.models.ocsf.validators import (
    coerce_int,
    coerce_ip,
    coerce_port,
    coerce_sha256,
    coerce_utc_datetime,
)


def test_coerce_utc_datetime_from_z_suffix() -> None:
    result = coerce_utc_datetime("2026-07-22T09:01:00Z")
    assert result is not None
    assert result.tzinfo is not None
    assert result.year == 2026
    assert result.hour == 9


def test_coerce_utc_datetime_invalid_returns_none() -> None:
    assert coerce_utc_datetime("not-a-date") is None


def test_coerce_port_bounds() -> None:
    assert coerce_port(443) == 443
    assert coerce_port(0) is None
    assert coerce_port(70000) is None
    assert coerce_port("abc") is None


def test_coerce_ip_validation() -> None:
    assert coerce_ip("192.0.2.50") == "192.0.2.50"
    assert coerce_ip("999.999.999.999") is None
    assert coerce_ip("") is None


def test_coerce_sha256_strips_prefix() -> None:
    raw = "SHA256=" + "a" * 64
    assert coerce_sha256(raw) == "a" * 64


def test_coerce_int_with_bounds() -> None:
    assert coerce_int(42, minimum=0, maximum=100) == 42
    assert coerce_int(-1, minimum=0) is None


def test_normalized_event_mandatory_fields() -> None:
    event = NormalizedEvent(
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        activity_name="Process Create",
        timestamp=datetime(2026, 7, 22, 9, 1, tzinfo=UTC),
        source_type="sysmon",
        raw_data='{"EventID": 1}',
    )
    assert event.event_id
    assert event.source_type == "sysmon"
    assert event.raw_data == '{"EventID": 1}'
    assert event.timestamp.tzinfo is not None


def test_normalized_event_legacy_id_alias() -> None:
    event = NormalizedEvent.model_validate(
        {
            "id": "legacy-uuid-1234",
            "class_uid": OCSFClass.PROCESS_ACTIVITY,
            "activity_name": "Process Create",
            "timestamp": "2026-07-22T09:01:00Z",
            "raw_source": "sysmon",
            "raw_data": "{}",
        }
    )
    assert event.event_id == "legacy-uuid-1234"
    assert event.id == "legacy-uuid-1234"
    assert event.source_type == "sysmon"
    assert event.raw_source == "sysmon"


def test_normalized_event_graceful_invalid_port() -> None:
    event = NormalizedEvent(
        class_uid=OCSFClass.NETWORK_ACTIVITY,
        activity_name="Network Connection",
        timestamp=datetime(2026, 7, 22, 9, 2, tzinfo=UTC),
        source_type="sysmon",
        raw_data="{}",
        dst_port="not-a-port",
    )
    assert event.dst_port is None


def test_normalized_event_graceful_invalid_ip() -> None:
    event = NormalizedEvent(
        class_uid=OCSFClass.NETWORK_ACTIVITY,
        activity_name="Network Connection",
        timestamp=datetime(2026, 7, 22, 9, 2, tzinfo=UTC),
        source_type="sysmon",
        raw_data="{}",
        dst_ip="invalid-ip",
    )
    assert event.dst_ip is None


def test_normalized_event_syncs_flat_to_nested() -> None:
    event = NormalizedEvent(
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        activity_name="Process Create",
        timestamp=datetime(2026, 7, 22, 9, 1, tzinfo=UTC),
        source_type="sysmon",
        raw_data="{}",
        host="FIN-23",
        user="Alice",
        process_name="powershell.exe",
        process_pid=5678,
        process_guid="{GUID-5678}",
        parent_process_name="WINWORD.EXE",
        parent_process_pid=1234,
        parent_process_guid="{GUID-1234}",
    )
    assert event.device is not None
    assert event.device.hostname == "FIN-23"
    assert event.actor is not None
    assert event.actor.user is not None
    assert event.actor.user.name == "Alice"
    assert event.process is not None
    assert event.process.uid == "{GUID-5678}"
    assert event.process.parent_process is not None
    assert event.process.parent_process.uid == "{GUID-1234}"


def test_normalized_event_syncs_nested_to_flat() -> None:
    event = NormalizedEvent(
        class_uid=OCSFClass.NETWORK_ACTIVITY,
        activity_name="Network Connection",
        timestamp=datetime(2026, 7, 22, 9, 2, tzinfo=UTC),
        source_type="sysmon",
        raw_data="{}",
        device=Device(hostname="FIN-23"),
        process=Process(name="powershell.exe", pid=5678),
        connection_info={
            "protocol_name": "tcp",
            "dst_endpoint": {"ip": "192.0.2.50", "port": 443},
        },
    )
    assert event.host == "FIN-23"
    assert event.process_name == "powershell.exe"
    assert event.process_pid == 5678
    assert event.dst_ip == "192.0.2.50"
    assert event.dst_port == 443
    assert event.protocol == "tcp"


def test_normalized_event_correlation_keys_include_guids() -> None:
    event = NormalizedEvent(
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        activity_name="Process Create",
        timestamp=datetime(2026, 7, 22, 9, 1, tzinfo=UTC),
        source_type="sysmon",
        raw_data="{}",
        host="FIN-23",
        process_guid="{GUID-1}",
        parent_process_guid="{GUID-0}",
        src_port=49152,
        protocol="tcp",
    )
    keys = event.correlation_keys()
    assert keys["process_guid"] == "{GUID-1}"
    assert keys["parent_process_guid"] == "{GUID-0}"
    assert keys["src_port"] == 49152
    assert keys["protocol"] == "tcp"


def test_normalized_event_to_ocsf_event() -> None:
    event = NormalizedEvent(
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        activity_name="Process Create",
        activity_id=ActivityId.LAUNCH,
        severity_id=SeverityId.INFORMATIONAL,
        timestamp=datetime(2026, 7, 22, 9, 1, tzinfo=UTC),
        source_type="sysmon",
        raw_data="{}",
        process=Process(name="cmd.exe", pid=100),
    )
    ocsf = event.to_ocsf_event()
    assert ocsf.class_uid == OCSFClass.PROCESS_ACTIVITY
    assert ocsf.event_id == event.event_id
    assert ocsf.process is not None
    assert ocsf.process.name == "cmd.exe"


def test_network_endpoint_drops_invalid_port() -> None:
    endpoint = NetworkEndpoint(ip="10.0.0.1", port=99999)
    assert endpoint.port is None


def test_user_model_accepts_valid_data() -> None:
    user = User(name="Alice", domain="CORP")
    assert user.name == "Alice"
    assert user.domain == "CORP"
