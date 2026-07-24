"""Root cause analyzer — patient zero and initial compromise."""

from __future__ import annotations

from soc_chronicle.models.event import NormalizedEvent, OCSFClass
from soc_chronicle.models.evidence import Evidence


class RootCauseAnalyzer:
    """Determine initial compromise with explainable evidence."""

    SUSPICIOUS_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
    SUSPICIOUS_CHILDREN = {"powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe"}

    def analyze(
        self, events: list[NormalizedEvent]
    ) -> tuple[str | None, str | None, list[Evidence]]:
        if not events:
            return None, None, []

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        evidence: list[Evidence] = []

        # Patient zero: earliest host involved
        first_event = sorted_events[0]
        patient_zero = first_event.host

        # Root cause heuristics (deterministic)
        root_cause: str | None = None
        for event in sorted_events:
            parent = self._basename(event.parent_process_name or "")
            child = self._basename(event.process_name or "")
            if parent in self.SUSPICIOUS_PARENTS and child in self.SUSPICIOUS_CHILDREN:
                root_cause = (
                    f"User opened a document ({parent}) that spawned {child}, "
                    f"indicating likely malicious macro or exploit."
                )
                evidence.append(
                    Evidence(
                        summary=f"{parent} spawned {child}",
                        detail=root_cause,
                        source="root_cause_analyzer",
                        timestamp=event.timestamp,
                        event_id=event.id,
                        tags=["initial_access", "execution"],
                    )
                )
                patient_zero = event.host or patient_zero
                break

        if root_cause is None:
            for event in sorted_events:
                if event.class_uid == OCSFClass.NETWORK_ACTIVITY and event.dst_ip:
                    root_cause = f"Earliest suspicious network activity to {event.dst_ip or event.domain}"
                    evidence.append(
                        Evidence(
                            summary=root_cause,
                            source="root_cause_analyzer",
                            timestamp=event.timestamp,
                            event_id=event.id,
                        )
                    )
                    break

        if root_cause is None and first_event:
            root_cause = f"Initial activity: {first_event.activity_name} on {first_event.host or 'unknown host'}"
            evidence.append(
                Evidence(
                    summary=root_cause,
                    source="root_cause_analyzer",
                    timestamp=first_event.timestamp,
                    event_id=first_event.id,
                )
            )

        if patient_zero:
            evidence.append(
                Evidence(
                    summary=f"Patient zero identified as {patient_zero}",
                    source="root_cause_analyzer",
                    timestamp=first_event.timestamp,
                    event_id=first_event.id,
                    tags=["patient_zero"],
                )
            )

        return patient_zero, root_cause, evidence

    @staticmethod
    def _basename(name: str) -> str:
        return name.replace("/", "\\").split("\\")[-1].lower()
