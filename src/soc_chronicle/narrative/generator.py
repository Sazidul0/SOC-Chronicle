"""Incident narrative generator with evidence citations."""

from __future__ import annotations

from soc_chronicle.models.alert import Alert
from soc_chronicle.models.event import NormalizedEvent
from soc_chronicle.models.evidence import Evidence
from soc_chronicle.models.report import RecommendedAction
from soc_chronicle.models.timeline import Timeline


class NarrativeGenerator:
    """Produce analyst-friendly incident narratives backed by evidence."""

    def generate(
        self,
        alert: Alert,
        timeline: Timeline,
        events: list[NormalizedEvent],
        patient_zero: str | None,
        root_cause: str | None,
        evidence: list[Evidence],
    ) -> tuple[str, str, str, list[RecommendedAction]]:
        user = alert.user or self._first_user(events) or "a user"
        host = patient_zero or alert.host or self._first_host(events) or "the affected host"
        first_ts = timeline.sorted_entries()[0].timestamp if timeline.entries else alert.timestamp

        summary = (
            f"Investigation of '{alert.title}' on {host} "
            f"({len(events)} correlated events, {len(evidence)} evidence items)."
        )

        narrative_parts = [
            f"On {first_ts.strftime('%Y-%m-%d %H:%M UTC')}, {user} triggered alert "
            f"'{alert.title}' on workstation {host}."
        ]

        if root_cause:
            narrative_parts.append(root_cause)

        for entry in timeline.sorted_entries()[:8]:
            cite = f" [evidence: {entry.evidence[0].id[:8]}]" if entry.evidence else ""
            narrative_parts.append(f"At {entry.timestamp.strftime('%H:%M')}, {entry.summary}.{cite}")

        if len(timeline.entries) > 8:
            narrative_parts.append(f"... and {len(timeline.entries) - 8} additional timeline events.")

        narrative = " ".join(narrative_parts)

        executive = (
            f"A {alert.severity}-severity security incident was detected on {host}. "
            f"{root_cause or 'Analysis indicates suspicious activity requiring investigation.'} "
            f"Immediate containment and forensic review are recommended."
        )

        actions = self._recommendations(events, host)

        return summary, narrative, executive, actions

    def _recommendations(self, events: list[NormalizedEvent], host: str) -> list[RecommendedAction]:
        actions: list[RecommendedAction] = [
            RecommendedAction(
                priority="high",
                action=f"Isolate host {host} from the network",
                rationale="Prevent further spread while investigation continues",
            ),
            RecommendedAction(
                priority="high",
                action="Collect forensic triage package (memory, disk, logs)",
                rationale="Preserve evidence for root cause confirmation",
            ),
            RecommendedAction(
                priority="medium",
                action="Reset credentials for involved user accounts",
                rationale="Credential exposure cannot be ruled out",
            ),
            RecommendedAction(
                priority="medium",
                action="Hunt for matching IOCs across the environment",
                rationale="Determine scope beyond initial detection",
            ),
        ]
        return actions

    @staticmethod
    def _first_user(events: list[NormalizedEvent]) -> str | None:
        for e in events:
            if e.user:
                return e.user
        return None

    @staticmethod
    def _first_host(events: list[NormalizedEvent]) -> str | None:
        for e in events:
            if e.host:
                return e.host
        return None
