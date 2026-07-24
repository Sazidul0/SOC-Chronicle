"""Tests for log normalization."""

from pathlib import Path

from soc_chronicle.models.event import OCSFClass
from soc_chronicle.normalization.engine import LogNormalizationEngine


def test_normalize_sysmon_logs(examples_dir: Path) -> None:
    engine = LogNormalizationEngine()
    events = engine.normalize_file(examples_dir / "logs" / "sysmon.jsonl", parser="sysmon")
    assert len(events) == 5
    assert events[0].process_name.endswith("WINWORD.EXE")
    assert events[2].class_uid == OCSFClass.NETWORK_ACTIVITY
    assert events[2].dst_ip == "192.0.2.50"


def test_correlation_keys() -> None:
    engine = LogNormalizationEngine()
    event = engine.normalize_record(
        {"EventID": 1, "Computer": "HOST1", "Image": "cmd.exe", "ProcessId": 99},
        parser="sysmon",
    )
    keys = event.correlation_keys()
    assert keys["host"] == "HOST1"
    assert keys["process_name"].endswith("cmd.exe")


def test_parse_windows_security() -> None:
    engine = LogNormalizationEngine()
    event = engine.normalize_record(
        {"EventID": 4624, "Computer": "DC01", "TargetUserName": "admin", "IpAddress": "10.0.0.5"},
        parser="windows_security",
    )
    assert event.class_uid == OCSFClass.AUTHENTICATION
    assert event.host == "DC01"
    assert event.user == "admin"
    assert event.src_ip == "10.0.0.5"

    event2 = engine.normalize_record(
        {"EventID": 4688, "Computer": "DC01", "NewProcessName": "cmd.exe", "NewProcessId": "0x1fc"},
        parser="windows_security",
    )
    assert event2.class_uid == OCSFClass.PROCESS_ACTIVITY
    assert event2.process_name == "cmd.exe"


def test_parse_auditd() -> None:
    engine = LogNormalizationEngine()
    event = engine.normalize_record(
        {"type": "SYSCALL", "node": "linux-srv", "uid": "1000", "exe": "/bin/bash", "pid": "1234"},
        parser="auditd",
    )
    assert event.class_uid == OCSFClass.PROCESS_ACTIVITY
    assert event.host == "linux-srv"
    assert event.user == "1000"
    assert event.process_name == "/bin/bash"
    assert event.process_pid == 1234


def test_parse_zeek() -> None:
    engine = LogNormalizationEngine()
    event = engine.normalize_record(
        {"_path": "conn", "ts": 1600000000.0, "id.orig_h": "192.168.1.10", "id.resp_h": "8.8.8.8", "proto": "udp"},
        parser="zeek",
    )
    assert event.class_uid == OCSFClass.NETWORK_ACTIVITY
    assert event.src_ip == "192.168.1.10"
    assert event.dst_ip == "8.8.8.8"
    assert event.protocol == "udp"

    event2 = engine.normalize_record(
        {"_path": "dns", "ts": 1600000000.0, "query": "example.com"},
        parser="zeek",
    )
    assert event2.class_uid == OCSFClass.DNS_ACTIVITY
    assert event2.domain == "example.com"


def test_parse_wazuh() -> None:
    engine = LogNormalizationEngine()
    event = engine.normalize_record(
        {"rule": {"description": "Suspicious login"}, "agent": {"name": "agent-1"}, "data": {"srcuser": "root"}},
        parser="wazuh",
    )
    assert event.class_uid == OCSFClass.DETECTION_FINDING
    assert event.host == "agent-1"
    assert event.user == "root"
    assert event.activity_name == "Suspicious login"


def test_parse_azure_activity() -> None:
    engine = LogNormalizationEngine()
    event = engine.normalize_record(
        {"operationName": "Sign-in", "caller": "user@example.com", "callerIpAddress": "1.2.3.4"},
        parser="azure_activity",
    )
    assert event.class_uid == OCSFClass.AUTHENTICATION
    assert event.user == "user@example.com"
    assert event.src_ip == "1.2.3.4"
