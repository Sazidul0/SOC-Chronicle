"""End-to-end investigation tests."""

from pathlib import Path

from soc_chronicle import InvestigationEngine
from soc_chronicle.correlation.engine import CorrelationEngine
from soc_chronicle.graph.engine import InvestigationGraphEngine
from soc_chronicle.mitre.mapper import MitreMapper
from soc_chronicle.normalization.engine import LogNormalizationEngine
from soc_chronicle.report.generator import ReportGenerator
from soc_chronicle.risk.engine import RiskAssessmentEngine


def test_full_investigation(examples_dir: Path) -> None:
    engine = InvestigationEngine()
    report = engine.investigate(
        alert=examples_dir / "alert.json",
        logs=examples_dir / "logs",
    )
    assert report.alert.title == "Suspicious PowerShell Execution"
    assert report.patient_zero == "FIN-23"
    assert report.root_cause is not None
    assert "powershell" in report.root_cause.lower() or "WINWORD" in report.root_cause
    assert len(report.timeline.entries) >= 4
    assert report.graph.node_count() > 0
    assert report.risk.total_score > 0
    assert len(report.mitre_mappings) >= 1
    assert len(report.iocs) >= 1
    assert len(report.recommended_actions) >= 1


def test_correlation_groups_events(examples_dir: Path) -> None:
    normalizer = LogNormalizationEngine()
    events = normalizer.normalize_directory(examples_dir / "logs")
    correlator = CorrelationEngine()
    groups = correlator.correlate(events)
    assert len(groups) >= 1
    assert sum(len(g) for g in groups) == len(events)


def test_mitre_mapping(examples_dir: Path) -> None:
    normalizer = LogNormalizationEngine()
    events = normalizer.normalize_directory(examples_dir / "logs")
    mapper = MitreMapper()
    mappings = mapper.map_events(events)
    technique_ids = {m.technique_id for m in mappings}
    assert "T1059.001" in technique_ids or "T1566.001" in technique_ids


def test_risk_scoring(examples_dir: Path) -> None:
    engine = InvestigationEngine()
    report = engine.investigate(alert=examples_dir / "alert.json", logs=examples_dir / "logs")
    risk_engine = RiskAssessmentEngine()
    normalizer = LogNormalizationEngine()
    events = normalizer.normalize_directory(examples_dir / "logs")
    risk = risk_engine.assess(events, report.iocs)
    assert risk.total_score >= 20
    assert len(risk.factors) >= 1


def test_markdown_report_export(examples_dir: Path, tmp_path: Path) -> None:
    engine = InvestigationEngine()
    report = engine.investigate(alert=examples_dir / "alert.json", logs=examples_dir / "logs")
    out = tmp_path / "report.md"
    ReportGenerator().export_markdown(report, out)
    content = out.read_text()
    assert "Investigation Report" in content
    assert "FIN-23" in content
    assert "MITRE ATT&CK" in content


def test_graph_blast_radius(examples_dir: Path) -> None:
    normalizer = LogNormalizationEngine()
    events = normalizer.normalize_directory(examples_dir / "logs")
    graph_engine = InvestigationGraphEngine()
    graph = graph_engine.build(events)
    radius = graph_engine.blast_radius(graph, "device:fin-23")
    assert radius >= 0
