"""Professional SOC report generator — Markdown, interactive HTML, JSON, PDF, ATT&CK Navigator."""

from __future__ import annotations

import json
from pathlib import Path

from soc_chronicle.models.report import InvestigationReport


class ReportGenerator:
    """Export investigation reports in multiple professional formats."""

    def export_json(self, report: InvestigationReport, path: Path) -> Path:
        """Export full investigation report as JSON."""
        path.write_text(json.dumps(report.to_dict(), indent=2, default=str))
        return path

    def export_markdown(self, report: InvestigationReport, path: Path) -> Path:
        """Export investigation report as Markdown."""
        path.write_text(self.to_markdown(report))
        return path

    def export_html(self, report: InvestigationReport, path: Path) -> Path:
        """Export as a professional interactive HTML report with D3.js attack graph."""
        path.write_text(self.to_html(report))
        return path

    def export_navigator_layer(self, report: InvestigationReport, path: Path) -> Path:
        """Export MITRE ATT&CK Navigator layer JSON."""
        from soc_chronicle.mitre.mapper import MitreMapper
        mapper = MitreMapper()
        layer = mapper.generate_navigator_layer(
            report.mitre_mappings,
            name=f"SOC-Chronicle: {report.alert.title}",
            description=report.executive_summary[:200],
        )
        path.write_text(json.dumps(layer, indent=2))
        return path

    def export_pdf(self, report: InvestigationReport, path: Path) -> Path:
        """Export as PDF. Requires: pip install 'soc-chronicle[pdf]'"""
        try:
            import weasyprint  # type: ignore[import]
        except ImportError as e:
            msg = "PDF export requires weasyprint. Install with: pip install 'soc-chronicle[pdf]'"
            raise ImportError(msg) from e
        html_content = self.to_html(report)
        weasyprint.HTML(string=html_content).write_pdf(str(path))
        return path

    def to_markdown(self, report: InvestigationReport) -> str:
        """Generate a comprehensive Markdown report."""
        lines = [
            f"# Investigation Report: {report.alert.title}",
            "",
            f"**Report ID:** `{report.id}`  ",
            f"**Created:** {report.created_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
            f"**Severity:** {report.alert.severity.upper()}  ",
            f"**Risk Score:** {report.risk.total_score}/100 ({report.risk.severity_label.upper()})",
            "",
            "---",
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
            "## Root Cause Analysis",
            "",
            report.root_cause or "_Not determined_",
            "",
            f"**Patient Zero:** `{report.patient_zero or 'Unknown'}`  ",
            f"**Blast Radius:** {report.blast_radius} connected entities",
            "",
        ]

        # Timeline
        lines.extend(["## Attack Timeline", ""])
        lines.extend([
            "| Time (UTC) | Phase | Event |",
            "|-----------|-------|-------|",
        ])
        for entry in report.timeline.sorted_entries():
            ts = entry.timestamp.strftime("%H:%M:%S")
            phase = entry.phase or "activity"
            lines.append(f"| `{ts}` | {phase} | {entry.summary} |")

        # MITRE
        lines.extend(["", "## MITRE ATT&CK Mapping", ""])
        if report.mitre_mappings:
            lines.extend([
                "| Technique | Name | Tactic | Confidence |",
                "|-----------|------|--------|------------|",
            ])
            for m in report.mitre_mappings:
                lines.append(f"| [{m.technique_id}](https://attack.mitre.org/techniques/{m.technique_id.replace('.', '/')}) | {m.technique_name} | {m.tactic} | {m.confidence:.0%} |")
        else:
            lines.append("_No MITRE mappings detected_")

        # IOCs
        lines.extend(["", "## Indicators of Compromise", ""])
        if report.iocs:
            lines.extend([
                "| Type | Indicator | Confidence |",
                "|------|-----------|------------|",
            ])
            for ioc in report.iocs:
                lines.append(f"| {ioc.type.value} | `{ioc.value}` | {ioc.confidence:.0%} |")
        else:
            lines.append("_No IOCs extracted_")

        # Risk factors
        lines.extend(["", "## Risk Factors", ""])
        for factor in report.risk.factors:
            lines.append(f"- **+{factor.score}** {factor.label}")

        # Affected assets
        lines.extend(["", "## Affected Assets", ""])
        for asset in report.affected_assets or ["Unknown"]:
            lines.append(f"- `{asset}`")

        # Recommended actions
        lines.extend(["", "## Recommended Actions", ""])
        for action in report.recommended_actions:
            lines.append(f"- **[{action.priority.upper()}]** {action.action}  \n  _{action.rationale}_")

        # Attack graph summary
        lines.extend(["", "## Attack Graph", ""])
        lines.append(f"_{report.graph.node_count()} nodes, {report.graph.edge_count()} edges_")

        # Evidence appendix
        lines.extend(["", "## Evidence Appendix", ""])
        for ev in report.evidence[:30]:
            lines.append(f"- `{ev.id[:8]}` **{ev.summary}** _(source: {ev.source})_")

        return "\n".join(lines)

    def to_html(self, report: InvestigationReport) -> str:
        """Generate a professional interactive HTML report."""
        # Build D3.js graph data
        graph_data = self._build_d3_data(report)

        # Severity color
        severity_colors = {
            "critical": "#ef4444",
            "high": "#f97316",
            "medium": "#eab308",
            "low": "#22c55e",
            "informational": "#3b82f6",
        }
        severity_color = severity_colors.get(report.risk.severity_label, "#6b7280")

        # Timeline rows
        timeline_rows = ""
        phase_colors = {
            "initial_access": "#8b5cf6",
            "execution": "#ef4444",
            "persistence": "#f97316",
            "lateral_movement": "#ec4899",
            "command_and_control": "#06b6d4",
            "discovery": "#10b981",
            "collection": "#eab308",
            "exfiltration": "#f43f5e",
            "impact": "#dc2626",
            "activity": "#6b7280",
        }
        for entry in report.timeline.sorted_entries():
            phase = entry.phase or "activity"
            color = phase_colors.get(phase, "#6b7280")
            ts = entry.timestamp.strftime("%H:%M:%S")
            timeline_rows += f"""
            <tr>
                <td class="ts">{entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")}</td>
                <td><span class="phase-badge" style="background:{color}">{phase.replace("_", " ").title()}</span></td>
                <td>{entry.summary}</td>
            </tr>"""

        # MITRE rows
        mitre_rows = ""
        for m in report.mitre_mappings:
            conf_pct = int(m.confidence * 100)
            mitre_rows += f"""
            <tr>
                <td><a href="https://attack.mitre.org/techniques/{m.technique_id.replace(".", "/")}" target="_blank" class="technique-link">{m.technique_id}</a></td>
                <td>{m.technique_name}</td>
                <td><span class="tactic-badge">{m.tactic}</span></td>
                <td>
                    <div class="conf-bar">
                        <div class="conf-fill" style="width:{conf_pct}%"></div>
                        <span>{conf_pct}%</span>
                    </div>
                </td>
            </tr>"""

        # IOC rows
        ioc_rows = ""
        type_colors = {
            "ipv4": "#06b6d4", "ipv6": "#0ea5e9", "domain": "#8b5cf6",
            "sha256": "#10b981", "sha1": "#10b981", "md5": "#10b981",
            "url": "#f97316", "email": "#ec4899", "file_path": "#eab308",
            "registry_key": "#6b7280", "process": "#ef4444", "user": "#3b82f6",
        }
        for ioc in report.iocs:
            color = type_colors.get(ioc.type.value, "#6b7280")
            ioc_rows += f"""
            <tr>
                <td><span class="ioc-type-badge" style="background:{color}">{ioc.type.value}</span></td>
                <td class="ioc-value"><code>{ioc.value}</code></td>
                <td>{int(ioc.confidence * 100)}%</td>
            </tr>"""

        # Risk factors
        risk_factors_html = ""
        for f in report.risk.factors:
            risk_factors_html += f"""
            <div class="risk-factor">
                <span class="risk-score-badge">+{f.score}</span>
                <span class="risk-label">{f.label}</span>
            </div>"""

        # Recommended actions
        actions_html = ""
        priority_colors = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308", "low": "#22c55e"}
        for action in report.recommended_actions:
            p_color = priority_colors.get(action.priority.lower(), "#6b7280")
            actions_html += f"""
            <div class="action-item">
                <span class="priority-badge" style="background:{p_color}">{action.priority.upper()}</span>
                <div>
                    <div class="action-text">{action.action}</div>
                    <div class="action-rationale">{action.rationale}</div>
                </div>
            </div>"""

        # Affected assets
        assets_html = "".join(f'<span class="asset-tag">{a}</span>' for a in (report.affected_assets or ["Unknown"]))

        # Evidence items
        evidence_html = ""
        for ev in report.evidence[:25]:
            evidence_html += f"""
            <div class="evidence-item">
                <code class="ev-id">{ev.id[:8]}</code>
                <div class="ev-content">
                    <div class="ev-summary">{ev.summary}</div>
                    <div class="ev-source">Source: {ev.source} · {ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
                </div>
            </div>"""

        # Risk gauge SVG
        gauge_angle = int((report.risk.total_score / 100) * 180)
        gauge_color = severity_color

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC-Chronicle Report — {report.alert.title}</title>
<meta name="description" content="Security incident investigation report generated by SOC-Chronicle">
<style>
  :root {{
    --bg: #0f1117;
    --bg2: #1a1d2e;
    --bg3: #242840;
    --border: #2d3154;
    --text: #e2e8f0;
    --text2: #94a3b8;
    --accent: #6366f1;
    --accent2: #818cf8;
    --font: 'Inter', 'Segoe UI', system-ui, sans-serif;
    --mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--accent2); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* Layout */
  .report-header {{ background: linear-gradient(135deg, #1e1b4b 0%, #0f1117 60%); border-bottom: 1px solid var(--border); padding: 2rem 2.5rem; }}
  .header-brand {{ color: var(--accent2); font-size: 0.75rem; font-weight: 600; letter-spacing: 0.15em; text-transform: uppercase; margin-bottom: 0.5rem; }}
  .header-title {{ font-size: 1.75rem; font-weight: 700; color: #fff; margin-bottom: 0.5rem; }}
  .header-meta {{ display: flex; gap: 1.5rem; flex-wrap: wrap; color: var(--text2); font-size: 0.8rem; margin-top: 0.75rem; }}
  .header-meta span {{ display: flex; align-items: center; gap: 0.25rem; }}

  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem 2.5rem; }}

  /* Cards */
  .card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .card-title {{ font-size: 0.7rem; font-weight: 700; letter-spacing: 0.12em; text-transform: uppercase; color: var(--text2); margin-bottom: 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}

  /* Summary grid */
  .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
  .metric-card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; text-align: center; }}
  .metric-label {{ font-size: 0.65rem; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: var(--text2); margin-bottom: 0.5rem; }}
  .metric-value {{ font-size: 1.5rem; font-weight: 800; }}
  .metric-sub {{ font-size: 0.75rem; color: var(--text2); margin-top: 0.25rem; }}

  /* Risk gauge */
  .risk-section {{ display: grid; grid-template-columns: 220px 1fr; gap: 1.5rem; align-items: start; }}
  .gauge-wrapper {{ text-align: center; }}
  .gauge-svg {{ display: block; margin: 0 auto; }}
  .gauge-score {{ font-size: 2.5rem; font-weight: 900; }}
  .gauge-label {{ font-size: 0.8rem; color: var(--text2); }}
  .risk-factors {{ flex: 1; }}
  .risk-factor {{ display: flex; align-items: flex-start; gap: 0.75rem; padding: 0.6rem 0; border-bottom: 1px solid var(--border); }}
  .risk-factor:last-child {{ border-bottom: none; }}
  .risk-score-badge {{ background: #ef4444; color: #fff; font-size: 0.7rem; font-weight: 700; padding: 0.2rem 0.5rem; border-radius: 6px; white-space: nowrap; }}
  .risk-label {{ font-size: 0.85rem; color: var(--text); }}

  /* Narrative */
  .narrative-text {{ white-space: pre-wrap; font-size: 0.9rem; line-height: 1.8; color: var(--text); }}

  /* Tables */
  .data-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  .data-table th {{ background: var(--bg3); color: var(--text2); font-weight: 600; font-size: 0.7rem; letter-spacing: 0.08em; text-transform: uppercase; padding: 0.6rem 0.8rem; text-align: left; border-bottom: 1px solid var(--border); }}
  .data-table td {{ padding: 0.6rem 0.8rem; border-bottom: 1px solid var(--border); vertical-align: middle; }}
  .data-table tr:last-child td {{ border-bottom: none; }}
  .data-table tr:hover td {{ background: var(--bg3); }}
  .ts {{ font-family: var(--mono); font-size: 0.78rem; color: var(--text2); white-space: nowrap; }}

  /* Badges */
  .phase-badge {{ display: inline-block; font-size: 0.65rem; font-weight: 700; letter-spacing: 0.05em; padding: 0.15rem 0.5rem; border-radius: 4px; color: #fff; text-transform: uppercase; }}
  .tactic-badge {{ display: inline-block; background: var(--bg3); border: 1px solid var(--border); font-size: 0.7rem; padding: 0.15rem 0.5rem; border-radius: 4px; color: var(--text2); }}
  .ioc-type-badge {{ display: inline-block; font-size: 0.65rem; font-weight: 700; padding: 0.15rem 0.45rem; border-radius: 4px; color: #fff; text-transform: uppercase; }}
  .technique-link {{ color: var(--accent2); font-family: var(--mono); font-weight: 600; }}
  .ioc-value code {{ font-family: var(--mono); font-size: 0.8rem; color: #a5f3fc; }}
  .priority-badge {{ display: inline-block; font-size: 0.65rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 4px; color: #fff; }}

  /* Confidence bar */
  .conf-bar {{ display: flex; align-items: center; gap: 0.5rem; }}
  .conf-bar > div {{ flex: 1; height: 6px; background: var(--bg3); border-radius: 3px; overflow: hidden; }}
  .conf-fill {{ height: 100%; background: linear-gradient(90deg, #6366f1, #818cf8); border-radius: 3px; }}
  .conf-bar > span {{ font-size: 0.75rem; color: var(--text2); min-width: 30px; }}

  /* Actions */
  .action-item {{ display: flex; gap: 1rem; padding: 0.75rem 0; border-bottom: 1px solid var(--border); align-items: flex-start; }}
  .action-item:last-child {{ border-bottom: none; }}
  .action-text {{ font-size: 0.9rem; font-weight: 600; color: var(--text); }}
  .action-rationale {{ font-size: 0.8rem; color: var(--text2); margin-top: 0.25rem; }}

  /* Assets */
  .asset-tags {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
  .asset-tag {{ background: var(--bg3); border: 1px solid var(--border); border-radius: 6px; font-family: var(--mono); font-size: 0.78rem; padding: 0.25rem 0.6rem; color: #a5f3fc; }}

  /* Evidence */
  .evidence-item {{ display: flex; gap: 0.75rem; padding: 0.6rem 0; border-bottom: 1px solid var(--border); }}
  .evidence-item:last-child {{ border-bottom: none; }}
  .ev-id {{ font-family: var(--mono); font-size: 0.75rem; background: var(--bg3); padding: 0.1rem 0.4rem; border-radius: 4px; color: var(--text2); white-space: nowrap; }}
  .ev-summary {{ font-size: 0.85rem; color: var(--text); }}
  .ev-source {{ font-size: 0.75rem; color: var(--text2); margin-top: 0.2rem; }}

  /* Graph */
  #graph-container {{ width: 100%; height: 500px; background: var(--bg); border-radius: 8px; border: 1px solid var(--border); overflow: hidden; position: relative; }}
  .graph-legend {{ display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1rem; }}
  .legend-item {{ display: flex; align-items: center; gap: 0.4rem; font-size: 0.75rem; color: var(--text2); }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; }}
  .graph-stats {{ display: flex; gap: 1.5rem; margin-top: 0.75rem; }}
  .graph-stat {{ font-size: 0.8rem; color: var(--text2); }}
  .graph-stat strong {{ color: var(--text); }}

  /* Section headers */
  .section-title {{ font-size: 1.1rem; font-weight: 700; color: #fff; margin-bottom: 0.25rem; }}
  .section-desc {{ font-size: 0.8rem; color: var(--text2); margin-bottom: 1rem; }}

  /* Footer */
  .report-footer {{ border-top: 1px solid var(--border); padding: 1.5rem 2.5rem; text-align: center; color: var(--text2); font-size: 0.75rem; margin-top: 2rem; }}
  .report-footer a {{ color: var(--accent2); }}

  /* Severity strip */
  .severity-strip {{ height: 4px; background: {severity_color}; }}

  @media (max-width: 768px) {{
    .risk-section {{ grid-template-columns: 1fr; }}
    .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .container {{ padding: 1rem; }}
  }}
</style>
</head>
<body>

<div class="severity-strip"></div>

<div class="report-header">
  <div class="header-brand">⚡ SOC-Chronicle · Investigation Report</div>
  <div class="header-title">{report.alert.title}</div>
  <div class="header-meta">
    <span>📋 Report ID: <code style="color:#a5f3fc">{report.id[:16]}...</code></span>
    <span>📅 {report.created_at.strftime("%Y-%m-%d %H:%M UTC")}</span>
    <span>🏷️ Alert ID: <code style="color:#a5f3fc">{report.alert.id[:20]}</code></span>
    <span>🔗 Rule: {report.alert.rule_name or "—"}</span>
  </div>
</div>

<div class="container">

  <!-- Metrics Row -->
  <div class="summary-grid">
    <div class="metric-card" style="border-color:{severity_color}40">
      <div class="metric-label">Risk Score</div>
      <div class="metric-value" style="color:{severity_color}">{report.risk.total_score}<span style="font-size:1rem;color:var(--text2)">/100</span></div>
      <div class="metric-sub">{report.risk.severity_label.upper()}</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Events Analyzed</div>
      <div class="metric-value">{report.metadata.get("event_count", len(report.evidence))}</div>
      <div class="metric-sub">normalized events</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">IOCs</div>
      <div class="metric-value">{len(report.iocs)}</div>
      <div class="metric-sub">indicators extracted</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">MITRE Techniques</div>
      <div class="metric-value">{len(report.mitre_mappings)}</div>
      <div class="metric-sub">techniques detected</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Blast Radius</div>
      <div class="metric-value">{report.blast_radius}</div>
      <div class="metric-sub">connected entities</div>
    </div>
    <div class="metric-card">
      <div class="metric-label">Patient Zero</div>
      <div class="metric-value" style="font-size:0.9rem;word-break:break-all">{report.patient_zero or "Unknown"}</div>
      <div class="metric-sub">initial compromise host</div>
    </div>
  </div>

  <!-- Executive Summary -->
  <div class="card">
    <div class="card-title">Executive Summary</div>
    <p class="narrative-text">{report.executive_summary}</p>
  </div>

  <!-- Risk Assessment -->
  <div class="card">
    <div class="card-title">Risk Assessment</div>
    <div class="risk-section">
      <div class="gauge-wrapper">
        <svg class="gauge-svg" width="200" height="115" viewBox="0 0 200 115">
          <defs>
            <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" style="stop-color:#22c55e"/>
              <stop offset="50%" style="stop-color:#eab308"/>
              <stop offset="100%" style="stop-color:#ef4444"/>
            </linearGradient>
          </defs>
          <path d="M20,100 A80,80 0 0,1 180,100" fill="none" stroke="#1e2235" stroke-width="18" stroke-linecap="round"/>
          <path d="M20,100 A80,80 0 0,1 180,100" fill="none" stroke="url(#gaugeGrad)" stroke-width="18" stroke-linecap="round"
                stroke-dasharray="251.2" stroke-dashoffset="{int(251.2 * (1 - report.risk.total_score/100))}"/>
          <text x="100" y="90" text-anchor="middle" fill="{severity_color}" font-size="32" font-weight="900" font-family="system-ui">{report.risk.total_score}</text>
          <text x="100" y="108" text-anchor="middle" fill="#64748b" font-size="11" font-family="system-ui">{report.risk.severity_label.upper()}</text>
        </svg>
      </div>
      <div class="risk-factors">
        {risk_factors_html if risk_factors_html else '<div style="color:var(--text2);font-size:0.85rem">No risk factors triggered</div>'}
      </div>
    </div>
  </div>

  <!-- Incident Narrative -->
  <div class="card">
    <div class="card-title">Incident Narrative</div>
    <p class="narrative-text">{report.narrative}</p>
  </div>

  <!-- Root Cause -->
  <div class="card">
    <div class="card-title">Root Cause Analysis</div>
    <p style="font-size:0.9rem;margin-bottom:1rem">{report.root_cause or "<em style='color:var(--text2)'>Root cause could not be determined from available evidence</em>"}</p>
    <div style="display:flex;gap:2rem;flex-wrap:wrap">
      <div><span style="color:var(--text2);font-size:0.75rem">PATIENT ZERO</span><div style="font-family:var(--mono);color:#a5f3fc;font-size:0.9rem;margin-top:0.25rem">{report.patient_zero or "Unknown"}</div></div>
      <div><span style="color:var(--text2);font-size:0.75rem">BLAST RADIUS</span><div style="font-size:0.9rem;margin-top:0.25rem"><strong>{report.blast_radius}</strong> connected entities</div></div>
      <div><span style="color:var(--text2);font-size:0.75rem">AFFECTED ASSETS</span><div class="asset-tags" style="margin-top:0.25rem">{assets_html}</div></div>
    </div>
  </div>

  <!-- Attack Timeline -->
  <div class="card">
    <div class="card-title">Attack Timeline</div>
    <div class="section-desc">{len(list(report.timeline.sorted_entries()))} events · chronological order</div>
    <div style="overflow-x:auto">
      <table class="data-table">
        <thead><tr><th>Timestamp (UTC)</th><th>Phase</th><th>Event</th></tr></thead>
        <tbody>{timeline_rows if timeline_rows else "<tr><td colspan='3' style='color:var(--text2);text-align:center;padding:1rem'>No timeline events</td></tr>"}</tbody>
      </table>
    </div>
  </div>

  <!-- MITRE ATT&CK -->
  <div class="card">
    <div class="card-title">MITRE ATT&CK Mapping</div>
    {f'<div class="section-desc">{len(report.mitre_mappings)} techniques detected across {len(set(m.tactic for m in report.mitre_mappings))} tactics · <a href="https://mitre-attack.github.io/attack-navigator/" target="_blank">Open in ATT&CK Navigator ↗</a></div>' if report.mitre_mappings else ''}
    <div style="overflow-x:auto">
      <table class="data-table">
        <thead><tr><th>Technique ID</th><th>Name</th><th>Tactic</th><th>Confidence</th></tr></thead>
        <tbody>{mitre_rows if mitre_rows else "<tr><td colspan='4' style='color:var(--text2);text-align:center;padding:1rem'>No MITRE mappings detected</td></tr>"}</tbody>
      </table>
    </div>
  </div>

  <!-- IOCs -->
  <div class="card">
    <div class="card-title">Indicators of Compromise</div>
    <div class="section-desc">{len(report.iocs)} indicators extracted</div>
    <div style="overflow-x:auto">
      <table class="data-table">
        <thead><tr><th>Type</th><th>Indicator</th><th>Confidence</th></tr></thead>
        <tbody>{ioc_rows if ioc_rows else "<tr><td colspan='3' style='color:var(--text2);text-align:center;padding:1rem'>No IOCs extracted</td></tr>"}</tbody>
      </table>
    </div>
  </div>

  <!-- Attack Graph -->
  <div class="card">
    <div class="card-title">Attack Graph</div>
    <div class="graph-legend">
      <div class="legend-item"><div class="legend-dot" style="background:#ef4444"></div>Process</div>
      <div class="legend-item"><div class="legend-dot" style="background:#3b82f6"></div>Device/Host</div>
      <div class="legend-item"><div class="legend-dot" style="background:#22c55e"></div>User</div>
      <div class="legend-item"><div class="legend-dot" style="background:#f97316"></div>File</div>
      <div class="legend-item"><div class="legend-dot" style="background:#8b5cf6"></div>Domain/IP</div>
      <div class="legend-item"><div class="legend-dot" style="background:#6b7280"></div>Registry</div>
    </div>
    <div id="graph-container"></div>
    <div class="graph-stats">
      <div class="graph-stat"><strong>{report.graph.node_count()}</strong> nodes</div>
      <div class="graph-stat"><strong>{report.graph.edge_count()}</strong> edges</div>
      <div class="graph-stat">Blast radius: <strong>{report.blast_radius}</strong></div>
    </div>
  </div>

  <!-- Recommended Actions -->
  <div class="card">
    <div class="card-title">Recommended Actions</div>
    <div>{actions_html if actions_html else "<div style='color:var(--text2);font-size:0.85rem'>No actions generated</div>"}</div>
  </div>

  <!-- Evidence Appendix -->
  <div class="card">
    <div class="card-title">Evidence Appendix</div>
    <div class="section-desc">Showing {min(25, len(report.evidence))} of {len(report.evidence)} evidence items</div>
    <div>{evidence_html if evidence_html else "<div style='color:var(--text2);font-size:0.85rem'>No evidence collected</div>"}</div>
  </div>

</div>

<div class="report-footer">
  Generated by <a href="https://github.com/Sazidul0/SOC-Chronicle" target="_blank">SOC-Chronicle</a> ·
  Report ID: <code>{report.id}</code> ·
  {report.created_at.strftime("%Y-%m-%d %H:%M UTC")}
</div>

<script>
// D3.js attack graph visualization
const graphData = {json.dumps(graph_data)};

(function() {{
  const container = document.getElementById('graph-container');
  if (!container || !graphData.nodes || graphData.nodes.length === 0) {{
    container.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#64748b;font-size:0.85rem">No graph data available</div>';
    return;
  }}

  const W = container.clientWidth || 800;
  const H = 500;

  const nodeColors = {{
    'process': '#ef4444', 'device': '#3b82f6', 'user': '#22c55e',
    'file': '#f97316', 'domain': '#8b5cf6', 'ip': '#8b5cf6',
    'registry': '#6b7280', 'service': '#ec4899', 'scheduled_task': '#eab308'
  }};

  const edgeColors = {{
    'executed': '#ef4444', 'spawned': '#f97316', 'authenticated': '#22c55e',
    'connected': '#06b6d4', 'created': '#f97316', 'modified': '#eab308',
    'downloaded': '#8b5cf6', 'injected': '#ec4899'
  }};

  // Simple force-directed layout
  const nodes = graphData.nodes.map(n => ({{...n, x: W/2 + (Math.random()-0.5)*300, y: H/2 + (Math.random()-0.5)*200}}));
  const links = graphData.links || [];
  const nodeMap = {{}};
  nodes.forEach(n => nodeMap[n.id] = n);

  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('width', W);
  svg.setAttribute('height', H);
  svg.style.display = 'block';

  // Arrow markers
  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  ['#64748b', '#ef4444', '#06b6d4', '#22c55e', '#f97316'].forEach((color, i) => {{
    const m = document.createElementNS('http://www.w3.org/2000/svg', 'marker');
    m.setAttribute('id', `arrow${{i}}`);
    m.setAttribute('markerWidth', '8');
    m.setAttribute('markerHeight', '6');
    m.setAttribute('refX', '8');
    m.setAttribute('refY', '3');
    m.setAttribute('orient', 'auto');
    const p = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
    p.setAttribute('points', '0 0, 8 3, 0 6');
    p.setAttribute('fill', color);
    m.appendChild(p);
    defs.appendChild(m);
  }});
  svg.appendChild(defs);

  const edgeGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  const nodeGroup = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  svg.appendChild(edgeGroup);
  svg.appendChild(nodeGroup);

  // Draw edges
  const lineEls = links.map(link => {{
    const src = nodeMap[link.source] || nodeMap[typeof link.source === 'object' ? link.source.id : link.source];
    const tgt = nodeMap[link.target] || nodeMap[typeof link.target === 'object' ? link.target.id : link.target];
    if (!src || !tgt) return null;
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    const color = edgeColors[link.type] || '#475569';
    line.setAttribute('stroke', color);
    line.setAttribute('stroke-width', '1.5');
    line.setAttribute('stroke-opacity', '0.7');
    line.setAttribute('marker-end', 'url(#arrow0)');
    edgeGroup.appendChild(line);
    return {{ el: line, src, tgt }};
  }}).filter(Boolean);

  // Draw nodes
  const nodeEls = nodes.map(node => {{
    const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
    g.style.cursor = 'pointer';

    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    const color = nodeColors[node.type] || '#6b7280';
    const r = node.type === 'device' ? 14 : (node.type === 'process' ? 10 : 8);
    circle.setAttribute('r', r);
    circle.setAttribute('fill', color);
    circle.setAttribute('fill-opacity', '0.85');
    circle.setAttribute('stroke', '#fff');
    circle.setAttribute('stroke-width', '1.5');

    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('dy', r + 14);
    text.setAttribute('fill', '#cbd5e1');
    text.setAttribute('font-size', '10');
    text.setAttribute('font-family', 'monospace');
    const label = (node.label || node.id).split(':').pop() || node.id;
    text.textContent = label.length > 18 ? label.slice(0, 15) + '...' : label;

    g.appendChild(circle);
    g.appendChild(text);
    nodeGroup.appendChild(g);

    // Tooltip
    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = `${{node.type}}: ${{node.label || node.id}}`;
    g.appendChild(title);

    return {{ el: g, node, circle, r }};
  }});

  container.appendChild(svg);

  // Simple physics simulation
  function simulate() {{
    for (let iter = 0; iter < 80; iter++) {{
      // Repulsion
      for (let i = 0; i < nodes.length; i++) {{
        for (let j = i + 1; j < nodes.length; j++) {{
          const dx = nodes[j].x - nodes[i].x;
          const dy = nodes[j].y - nodes[i].y;
          const dist = Math.sqrt(dx*dx + dy*dy) || 1;
          const force = Math.min(3000 / (dist*dist), 15);
          nodes[i].x -= dx/dist * force;
          nodes[i].y -= dy/dist * force;
          nodes[j].x += dx/dist * force;
          nodes[j].y += dy/dist * force;
        }}
      }}
      // Attraction
      links.forEach(link => {{
        const src = nodeMap[link.source] || nodeMap[typeof link.source === 'object' ? link.source.id : link.source];
        const tgt = nodeMap[link.target] || nodeMap[typeof link.target === 'object' ? link.target.id : link.target];
        if (!src || !tgt) return;
        const dx = tgt.x - src.x;
        const dy = tgt.y - src.y;
        const dist = Math.sqrt(dx*dx + dy*dy) || 1;
        const force = (dist - 100) * 0.03;
        src.x += dx/dist * force;
        src.y += dy/dist * force;
        tgt.x -= dx/dist * force;
        tgt.y -= dy/dist * force;
      }});
      // Center gravity
      nodes.forEach(n => {{
        n.x += (W/2 - n.x) * 0.01;
        n.y += (H/2 - n.y) * 0.01;
        // Bounds
        n.x = Math.max(20, Math.min(W-20, n.x));
        n.y = Math.max(20, Math.min(H-20, n.y));
      }});
    }}
  }}

  simulate();

  function render() {{
    lineEls.forEach(le => {{
      if (!le) return;
      const s = le.src, t = le.tgt;
      le.el.setAttribute('x1', s.x);
      le.el.setAttribute('y1', s.y);
      le.el.setAttribute('x2', t.x);
      le.el.setAttribute('y2', t.y);
    }});
    nodeEls.forEach(ne => {{
      ne.el.setAttribute('transform', `translate(${{ne.node.x}},${{ne.node.y}})`);
    }});
  }}
  render();

  // Drag
  let dragging = null, ox = 0, oy = 0;
  svg.addEventListener('mousedown', e => {{
    nodeEls.forEach(ne => {{
      const b = ne.el.getBoundingClientRect();
      if (e.clientX >= b.left && e.clientX <= b.right && e.clientY >= b.top && e.clientY <= b.bottom) {{
        dragging = ne.node;
        ox = e.clientX - ne.node.x;
        oy = e.clientY - ne.node.y;
      }}
    }});
  }});
  svg.addEventListener('mousemove', e => {{
    if (!dragging) return;
    dragging.x = e.clientX - ox;
    dragging.y = e.clientY - oy;
    render();
  }});
  svg.addEventListener('mouseup', () => dragging = null);
}})();
</script>

</body>
</html>"""

    def _build_d3_data(self, report: InvestigationReport) -> dict:
        """Build D3.js compatible graph data from InvestigationGraph."""
        nodes = [
            {
                "id": n.id,
                "type": n.type.value if hasattr(n.type, "value") else str(n.type),
                "label": n.label,
                **{k: str(v) for k, v in (n.properties or {}).items()},
            }
            for n in report.graph.nodes
        ]
        links = [
            {
                "source": e.source,
                "target": e.target,
                "type": e.type.value if hasattr(e.type, "value") else str(e.type),
                "timestamp": str(e.timestamp) if e.timestamp else None,
            }
            for e in report.graph.edges
        ]
        return {"nodes": nodes, "links": links}
