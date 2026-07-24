"""Main investigation engine — orchestrates all analysis modules."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from soc_chronicle.config.settings import ChronicleSettings, get_settings
from soc_chronicle.correlation.engine import CorrelationEngine
from soc_chronicle.graph.engine import InvestigationGraphEngine
from soc_chronicle.intake.engine import AlertIntakeEngine
from soc_chronicle.ioc.engine import IOCExtractionEngine
from soc_chronicle.mitre.mapper import MitreMapper
from soc_chronicle.models.event import NormalizedEvent
from soc_chronicle.models.evidence import Evidence
from soc_chronicle.models.report import InvestigationReport
from soc_chronicle.narrative.generator import NarrativeGenerator
from soc_chronicle.normalization.engine import LogNormalizationEngine
from soc_chronicle.plugins.registry import PluginRegistry
from soc_chronicle.report.generator import ReportGenerator
from soc_chronicle.risk.engine import RiskAssessmentEngine
from soc_chronicle.root_cause.analyzer import RootCauseAnalyzer
from soc_chronicle.threat_intel.engine import ThreatIntelEngine
from soc_chronicle.timeline.engine import TimelineEngine


class InvestigationEngine:
    """
    Primary API for soc-chronicle investigations.

    Example::

        from soc_chronicle import InvestigationEngine

        engine = InvestigationEngine()
        report = engine.investigate(alert="alert.json", logs="./logs")
        print(report.summary)
    """

    def __init__(
        self,
        settings: ChronicleSettings | None = None,
        plugins: PluginRegistry | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.plugins = plugins or PluginRegistry()
        self.plugins.discover()

        self.intake = AlertIntakeEngine()
        self.ioc_engine = IOCExtractionEngine(deduplicate=self.settings.deduplicate_iocs)
        self.normalizer = LogNormalizationEngine()
        self.correlator = CorrelationEngine(window_seconds=self.settings.correlation_window_seconds)
        self.graph_engine = InvestigationGraphEngine()
        self.timeline_engine = TimelineEngine()
        self.root_cause = RootCauseAnalyzer()
        self.risk_engine = RiskAssessmentEngine()
        self.mitre_mapper = MitreMapper()
        self.narrative = NarrativeGenerator()
        self.reporter = ReportGenerator()
        self.threat_intel = ThreatIntelEngine(self.settings)

    def investigate(
        self,
        alert: str | Path | dict[str, Any],
        logs: str | Path | None = None,
        enrich: bool = False,
    ) -> InvestigationReport:
        """Run a complete investigation pipeline synchronously."""
        return asyncio.run(self.investigate_async(alert=alert, logs=logs, enrich=enrich))

    async def investigate_async(
        self,
        alert: str | Path | dict[str, Any],
        logs: str | Path | None = None,
        enrich: bool = False,
    ) -> InvestigationReport:
        alert_obj = self.intake.ingest(alert)
        iocs = self.ioc_engine.extract_from_alert(alert_obj)

        events = self._load_events(logs)
        correlated_groups = self.correlator.correlate(events)
        flat_events = [e for group in correlated_groups for e in group] if correlated_groups else events

        enrichment_results: list[dict[str, Any]] = []
        malicious_hashes: set[str] = set()
        if enrich and iocs:
            enrichment_results = await self.threat_intel.enrich_all(iocs)
            malicious_hashes = self.threat_intel.malicious_hashes(enrichment_results)

        evidence = self._build_evidence(flat_events)
        patient_zero, root_cause, rc_evidence = self.root_cause.analyze(flat_events)
        evidence.extend(rc_evidence)

        timeline = self.timeline_engine.build(
            flat_events, evidence=evidence, timezone=self.settings.default_timezone
        )
        graph = self.graph_engine.build(flat_events)
        blast = 0
        if patient_zero:
            origin = f"device:{patient_zero.lower()}"
            blast = self.graph_engine.blast_radius(graph, origin)

        mitre = self.mitre_mapper.map_events(flat_events)
        risk = self.risk_engine.assess(flat_events, iocs, malicious_hashes)
        summary, narrative, executive, actions = self.narrative.generate(
            alert_obj, timeline, flat_events, patient_zero, root_cause, evidence
        )

        affected = sorted(
            h for h in ({e.host for e in flat_events if e.host} | {alert_obj.host}) if h
        )

        return InvestigationReport(
            alert=alert_obj,
            summary=summary,
            narrative=narrative,
            executive_summary=executive,
            timeline=timeline,
            graph=graph,
            iocs=iocs,
            mitre_mappings=mitre,
            risk=risk,
            evidence=evidence,
            affected_assets=[a for a in affected if a],
            patient_zero=patient_zero,
            root_cause=root_cause,
            blast_radius=blast,
            recommended_actions=actions,
            metadata={"enrichment": enrichment_results, "event_count": len(flat_events)},
        )

    def _load_events(self, logs: str | Path | None) -> list[NormalizedEvent]:
        if logs is None:
            return []
        path = Path(logs)
        if path.is_dir():
            return self.normalizer.normalize_directory(path)
        if path.is_file():
            return self.normalizer.normalize_file(path)
        return []

    @staticmethod
    def _build_evidence(events: list[NormalizedEvent]) -> list[Evidence]:
        return [
            Evidence(
                summary=f"{e.activity_name} on {e.host or 'unknown'}",
                source=e.raw_source,
                timestamp=e.timestamp,
                event_id=e.id,
                raw=e.raw,
            )
            for e in events
        ]
