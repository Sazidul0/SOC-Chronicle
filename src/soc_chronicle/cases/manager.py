"""High-level case manager."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

from soc_chronicle.cases.models import Case, CaseArtifact, CaseNote, CasePriority, CaseStatus, TLP
from soc_chronicle.cases.store import CaseStore
from soc_chronicle.models.report import InvestigationReport


class CaseManager:
    """Manages triage workflow and case lifecycle."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.store = CaseStore(db_path)

    def create_case(self, title: str, **kwargs) -> Case:
        """Create a new case manually."""
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        case = Case(id=case_id, title=title, **kwargs)
        self.store.create_case(case)
        return case

    def create_from_report(self, report: InvestigationReport, author: str = "System") -> Case:
        """Auto-populate a case from an InvestigationReport."""
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        priority = CasePriority.P3_MEDIUM
        if report.risk.total_score >= 80:
            priority = CasePriority.P1_CRITICAL
        elif report.risk.total_score >= 60:
            priority = CasePriority.P2_HIGH
        elif report.risk.total_score < 30:
            priority = CasePriority.P4_LOW

        iocs = [ioc.value for ioc in report.iocs]
        
        case = Case(
            id=case_id,
            title=f"Investigation: {report.alert.title}",
            priority=priority,
            alert_id=report.alert.id,
            report_id=report.id,
            severity=report.risk.severity_label,
            iocs=iocs,
            affected_assets=report.affected_assets or [],
        )
        self.store.create_case(case)

        # Add initial note with summary
        self.add_note(
            case_id,
            f"Case automatically created from report {report.id}.\n\nExecutive Summary:\n{report.executive_summary}",
            author=author
        )
        return case

    def get_case(self, case_id: str) -> Case | None:
        return self.store.get_case(case_id)

    def list_cases(self, status: CaseStatus | None = None, priority: CasePriority | None = None) -> list[Case]:
        return self.store.list_cases(status, priority)

    def search_cases(self, query: str) -> list[Case]:
        return self.store.search_cases(query)

    def add_note(self, case_id: str, content: str, author: str = "Analyst", evidence_refs: list[str] | None = None) -> CaseNote:
        case = self.store.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        note = CaseNote(
            id=f"NOTE-{uuid.uuid4().hex[:8].upper()}",
            case_id=case_id,
            content=content,
            author=author,
            evidence_refs=evidence_refs or []
        )
        self.store.add_note(note)
        self.store.update_case(case) # Update updated_at
        return note

    def add_artifact(self, case_id: str, name: str, artifact_type: str, path: str | None = None, hash_value: str | None = None) -> CaseArtifact:
        case = self.store.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        artifact = CaseArtifact(
            id=f"ART-{uuid.uuid4().hex[:8].upper()}",
            case_id=case_id,
            name=name,
            artifact_type=artifact_type,
            path=path,
            hash_value=hash_value
        )
        self.store.add_artifact(artifact)
        self.store.update_case(case)
        return artifact

    def update_status(self, case_id: str, status: CaseStatus) -> None:
        case = self.store.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        case.status = status
        self.store.update_case(case)

    def close_case(self, case_id: str, resolution_notes: str, author: str = "Analyst", false_positive: bool = False) -> None:
        case = self.store.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        case.status = CaseStatus.FALSE_POSITIVE if false_positive else CaseStatus.CLOSED
        case.resolution_notes = resolution_notes
        case.closed_at = datetime.now(timezone.utc)
        self.store.update_case(case)
        self.add_note(case_id, f"Case closed. Resolution:\n{resolution_notes}", author=author)

    def export_case_markdown(self, case_id: str, path: Path) -> Path:
        case = self.store.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        
        lines = [
            f"# Case: {case.title}",
            f"**ID**: `{case.id}` | **Status**: {case.status.value} | **Priority**: {case.priority.value}",
            f"**Created**: {case.created_at.isoformat()} | **Updated**: {case.updated_at.isoformat()}",
            "",
            "## Summary",
            f"- **Severity**: {case.severity}",
            f"- **Alert ID**: {case.alert_id or 'None'}",
            f"- **Report ID**: {case.report_id or 'None'}",
            f"- **Assigned To**: {case.assigned_to or 'Unassigned'}",
            "",
            "## Assets & IOCs",
            "**Affected Assets**:",
            *(f"- {a}" for a in case.affected_assets),
            "",
            "**IOCs**:",
            *(f"- `{i}`" for i in case.iocs),
            "",
            "## Notes",
        ]
        
        for note in case.notes:
            lines.extend([
                f"### {note.timestamp.isoformat()} - {note.author}",
                note.content,
                ""
            ])
            
        if case.artifacts:
            lines.extend(["", "## Artifacts"])
            for art in case.artifacts:
                lines.append(f"- **{art.name}** ({art.artifact_type}): {art.path or 'No path'} (Hash: {art.hash_value or 'None'})")
                
        if case.resolution_notes:
            lines.extend(["", "## Resolution", case.resolution_notes])
            
        path.write_text("\n".join(lines))
        return path

    def close(self) -> None:
        self.store.close()
