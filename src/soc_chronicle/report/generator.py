"""Report export engine — Markdown, HTML, JSON."""

from __future__ import annotations

import json
from pathlib import Path

from soc_chronicle.models.report import InvestigationReport


class ReportGenerator:
    """Export investigation reports in multiple formats."""

    def export_json(self, report: InvestigationReport, path: Path) -> Path:
        path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
        return path

    def export_markdown(self, report: InvestigationReport, path: Path) -> Path:
        path.write_text(self.to_markdown(report))
        return path

    def export_html(self, report: InvestigationReport, path: Path) -> Path:
        md = self.to_markdown(report)
        html = (
            "<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<title>Investigation Report</title>"
            "<style>body{font-family:sans-serif;max-width:900px;margin:2rem auto;line-height:1.6}"
            "table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:8px}"
            "code{background:#f4f4f4;padding:2px 4px}</style></head><body>"
            f"<pre>{md}</pre></body></html>"
        )
        path.write_text(html)
        return path

    def to_markdown(self, report: InvestigationReport) -> str:
        lines = [
            f"# Investigation Report: {report.alert.title}",
            "",
            f"**Report ID:** `{report.id}`  ",
            f"**Created:** {report.created_at.isoformat()}  ",
            f"**Severity:** {report.alert.severity}  ",
            f"**Risk Score:** {report.risk.total_score}/100 ({report.risk.severity_label})",
            "",
            "## Executive Summary",
            "",
            report.executive_summary,
            "",
            "## Technical Summary",
            "",
            report.summary,
            "",
            "## Incident Narrative",
            "",
            report.narrative,
            "",
            "## Root Cause",
            "",
            report.root_cause or "_Not determined_",
            "",
            f"**Patient Zero:** {report.patient_zero or 'Unknown'}  ",
            f"**Blast Radius:** {report.blast_radius} connected entities",
            "",
            "## Timeline",
            "",
        ]
        for entry in report.timeline.sorted_entries():
            lines.append(
                f"- `{entry.timestamp.strftime('%H:%M:%S')}` [{entry.phase or 'activity'}] "
                f"{entry.summary}"
            )

        lines.extend(["", "## MITRE ATT&CK Mapping", ""])
        if report.mitre_mappings:
            lines.append("| Technique | Name | Tactic | Confidence |")
            lines.append("|-----------|------|--------|------------|")
            for m in report.mitre_mappings:
                lines.append(
                    f"| {m.technique_id} | {m.technique_name} | {m.tactic} | {m.confidence:.0%} |"
                )
        else:
            lines.append("_No mappings_")

        lines.extend(["", "## IOCs", ""])
        if report.iocs:
            lines.append("| Type | Value | Confidence |")
            lines.append("|------|-------|------------|")
            for ioc in report.iocs:
                lines.append(f"| {ioc.type.value} | `{ioc.value}` | {ioc.confidence:.0%} |")
        else:
            lines.append("_No IOCs extracted_")

        lines.extend(["", "## Risk Factors", ""])
        for factor in report.risk.factors:
            lines.append(f"- **+{factor.score}** {factor.label}")

        lines.extend(["", "## Affected Assets", ""])
        for asset in report.affected_assets or ["Unknown"]:
            lines.append(f"- {asset}")

        lines.extend(["", "## Recommended Actions", ""])
        for action in report.recommended_actions:
            lines.append(f"- **[{action.priority.upper()}]** {action.action} — _{action.rationale}_")

        lines.extend(["", "## Attack Graph", ""])
        lines.append(
            f"_{report.graph.node_count()} nodes, {report.graph.edge_count()} edges_"
        )

        lines.extend(["", "## Evidence Appendix", ""])
        for ev in report.evidence[:20]:
            lines.append(f"- `{ev.id[:8]}` **{ev.summary}** _(source: {ev.source})_")

        return "\n".join(lines)
