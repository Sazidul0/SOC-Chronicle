"""Timeline reconstruction engine."""

from __future__ import annotations

from datetime import datetime

from soc_chronicle.models.event import NormalizedEvent, OCSFClass
from soc_chronicle.models.evidence import Evidence, EvidenceRef
from soc_chronicle.models.timeline import Timeline, TimelineEntry


class TimelineEngine:
    """Reconstruct chronological attack timelines from events."""

    PHASE_MAP = {
        OCSFClass.PROCESS_ACTIVITY: "execution",
        OCSFClass.FILE_ACTIVITY: "initial_access",
        OCSFClass.NETWORK_ACTIVITY: "command_and_control",
        OCSFClass.AUTHENTICATION: "lateral_movement",
        OCSFClass.REGISTRY_KEY_ACTIVITY: "persistence",
        OCSFClass.DETECTION_FINDING: "discovery",
    }

    def build(
        self,
        events: list[NormalizedEvent],
        evidence: list[Evidence] | None = None,
        timezone: str = "UTC",
    ) -> Timeline:
        evidence_by_event = {e.event_id: e for e in (evidence or []) if e.event_id}
        entries: list[TimelineEntry] = []
        seen: set[str] = set()

        for event in sorted(events, key=lambda e: e.timestamp):
            summary = self._summarize(event)
            dedupe_key = f"{event.timestamp.isoformat()}:{summary}"
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            ev_refs: list[EvidenceRef] = []
            if linked := evidence_by_event.get(event.id):
                ev_refs.append(linked.to_ref())
            entries.append(
                TimelineEntry(
                    timestamp=event.timestamp,
                    phase=self.PHASE_MAP.get(event.class_uid, "activity"),
                    summary=summary,
                    detail=event.activity_name,
                    evidence=ev_refs,
                )
            )
        return Timeline(entries=entries, timezone=timezone)

    def _summarize(self, event: NormalizedEvent) -> str:
        if event.class_uid == OCSFClass.PROCESS_ACTIVITY and event.parent_process_name:
            return f"{event.parent_process_name} → {event.process_name or 'process'}"
        if event.class_uid == OCSFClass.NETWORK_ACTIVITY:
            target = event.domain or event.dst_ip or "remote host"
            actor = event.process_name or event.host or "host"
            return f"{actor} connected to {target}"
        if event.class_uid == OCSFClass.FILE_ACTIVITY and event.file_path:
            return f"File activity: {event.file_path}"
        if event.class_uid == OCSFClass.REGISTRY_KEY_ACTIVITY and event.registry_key:
            return f"Registry modified: {event.registry_key}"
        if event.class_uid == OCSFClass.AUTHENTICATION and event.user:
            return f"Authentication by {event.user}"
        parts = [event.activity_name]
        if event.host:
            parts.append(f"on {event.host}")
        return " ".join(parts)
