"""Tests for alert intake."""

from pathlib import Path

from soc_chronicle.intake.engine import AlertIntakeEngine


def test_ingest_json_alert(examples_dir: Path) -> None:
    engine = AlertIntakeEngine()
    alert = engine.ingest_json(examples_dir / "alert.json")
    assert alert.title == "Suspicious PowerShell Execution"
    assert alert.host == "FIN-23"
    assert alert.user == "Alice"
    assert alert.severity == "high"


def test_deduplication(examples_dir: Path) -> None:
    engine = AlertIntakeEngine()
    alerts = engine.ingest_batch([examples_dir / "alert.json", examples_dir / "alert.json"])
    assert len(alerts) == 1
