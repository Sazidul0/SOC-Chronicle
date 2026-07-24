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
