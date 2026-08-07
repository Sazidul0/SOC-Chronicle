"""soc-chronicle CLI."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from soc_chronicle.engine import InvestigationEngine
from soc_chronicle.ioc.engine import IOCExtractionEngine
from soc_chronicle.logging import configure_logging
from soc_chronicle.normalization.engine import LogNormalizationEngine
from soc_chronicle.report.generator import ReportGenerator

app = typer.Typer(
    name="chronicle",
    help="soc-chronicle — Attack Investigation & Incident Narrative Engine",
    no_args_is_help=True,
)
case_app = typer.Typer(name="case", help="Case management and triage")
ingest_app = typer.Typer(name="ingest", help="Live ingest connectors")
app.add_typer(case_app)
app.add_typer(ingest_app)

console = Console()


@app.callback()
def main(
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable debug logging")] = False,
) -> None:
    configure_logging("DEBUG" if verbose else "INFO")


@app.command()
def investigate(
    alert: Annotated[Path, typer.Argument(help="Alert file (JSON/YAML) or inline JSON path")],
    logs: Annotated[Path | None, typer.Option("--logs", "-l", help="Log directory or file")] = None,
    enrich: Annotated[bool, typer.Option("--enrich", help="Enable threat intel enrichment")] = False,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write report to file")] = None,
    format: Annotated[str, typer.Option("--format", "-f", help="Output format (markdown, html, json)")] = "markdown",
) -> None:
    """Run a full investigation on an alert."""
    engine = InvestigationEngine()
    with console.status("[bold green]Investigating..."):
        report = engine.investigate(alert=alert, logs=logs, enrich=enrich)

    console.print(Panel(report.executive_summary, title="Executive Summary", border_style="red"))
    console.print(f"\n[bold]Risk Score:[/bold] {report.risk.total_score}/100 ({report.risk.severity_label})")
    console.print(f"[bold]Patient Zero:[/bold] {report.patient_zero or 'Unknown'}")
    console.print(f"[bold]Events:[/bold] {report.metadata.get('event_count', 0)}")
    console.print(f"\n{report.narrative}\n")

    if output:
        gen = ReportGenerator()
        if format == "json":
            gen.export_json(report, output)
        elif format == "html":
            gen.export_html(report, output)
        else:
            gen.export_markdown(report, output)
        console.print(f"[green]Report written to[/green] {output}")


@app.command()
def enrich(
    indicators: Annotated[Path, typer.Argument(help="File with one indicator per line")],
) -> None:
    """Extract and display IOCs from a text file."""
    text = indicators.read_text()
    engine = IOCExtractionEngine()
    iocs = engine.extract_from_texts([text], source=str(indicators))

    table = Table(title="Extracted IOCs")
    table.add_column("Type")
    table.add_column("Value")
    table.add_column("Confidence")
    for ioc in iocs:
        table.add_row(ioc.type.value, ioc.value, f"{ioc.confidence:.0%}")
    console.print(table)


@app.command()
def timeline(
    logs: Annotated[Path, typer.Argument(help="Log directory or file")],
) -> None:
    """Build and display a timeline from logs."""
    normalizer = LogNormalizationEngine()
    events = (
        normalizer.normalize_directory(logs)
        if logs.is_dir()
        else normalizer.normalize_file(logs)
    )
    engine = InvestigationEngine()
    tl = engine.timeline_engine.build(events)

    table = Table(title=f"Timeline ({len(tl.entries)} events)")
    table.add_column("Time")
    table.add_column("Phase")
    table.add_column("Event")
    for entry in tl.sorted_entries():
        table.add_row(
            entry.timestamp.strftime("%H:%M:%S"),
            entry.phase or "-",
            entry.summary,
        )
    console.print(table)


@app.command()
def graph(
    logs: Annotated[Path, typer.Argument(help="Log directory or file")],
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Build attack graph from logs."""
    normalizer = LogNormalizationEngine()
    events = (
        normalizer.normalize_directory(logs)
        if logs.is_dir()
        else normalizer.normalize_file(logs)
    )
    engine = InvestigationEngine()
    g = engine.graph_engine.build(events)
    console.print(f"[bold]Graph:[/bold] {g.node_count()} nodes, {g.edge_count()} edges")
    if output:
        output.write_text(json.dumps(g.model_dump(), indent=2, default=str))
        console.print(f"[green]Graph written to[/green] {output}")


@app.command(name="report")
def report_cmd(
    incident: Annotated[Path, typer.Argument(help="Investigation JSON report")],
    output: Annotated[Path, typer.Option("--output", "-o", help="Path to write the report")],
    format: Annotated[str, typer.Option("--format", "-f", help="Output format (markdown, html, json)")] = "markdown",
) -> None:
    """Re-export an existing investigation report to a specified format (markdown, html, json)."""
    from soc_chronicle.models.report import InvestigationReport

    data = json.loads(incident.read_text())
    report = InvestigationReport.model_validate(data)
    gen = ReportGenerator()
    if format == "json":
        gen.export_json(report, output)
    elif format == "html":
        gen.export_html(report, output)
    else:
        gen.export_markdown(report, output)
    console.print(f"[green]Report exported to[/green] {output}")

# ── Cases CLI ─────────────────────────────────────────────────────────────────

@case_app.command("new")
def case_new(
    title: Annotated[str | None, typer.Option("--title", "-t")] = None,
    from_report: Annotated[Path | None, typer.Option("--from-report", help="Create from report JSON")] = None,
) -> None:
    """Create a new case."""
    from soc_chronicle.cases.manager import CaseManager
    from soc_chronicle.models.report import InvestigationReport
    
    manager = CaseManager("chronicle.duckdb")
    if from_report:
        report_data = json.loads(from_report.read_text())
        report = InvestigationReport.model_validate(report_data)
        case = manager.create_from_report(report)
        console.print(f"[green]Created Case {case.id} from report {report.id}[/green]")
    elif title:
        case = manager.create_case(title)
        console.print(f"[green]Created Case {case.id}[/green]")
    else:
        console.print("[red]Must provide --title or --from-report[/red]")

@case_app.command("list")
def case_list(
    status: Annotated[str | None, typer.Option("--status", help="Filter by status (open, closed, etc)")] = None,
    priority: Annotated[str | None, typer.Option("--priority", help="Filter by priority")] = None,
) -> None:
    """List cases."""
    from soc_chronicle.cases.manager import CaseManager
    from soc_chronicle.cases.models import CasePriority, CaseStatus
    
    manager = CaseManager("chronicle.duckdb")
    s = CaseStatus(status) if status else None
    p = CasePriority(priority) if priority else None
    cases = manager.list_cases(status=s, priority=p)
    
    table = Table(title="Cases")
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Status")
    table.add_column("Priority")
    table.add_column("Severity")
    for c in cases:
        table.add_row(c.id, c.title, c.status.value, c.priority.value, c.severity)
    console.print(table)

@case_app.command("view")
def case_view(case_id: str) -> None:
    """View case details."""
    from soc_chronicle.cases.manager import CaseManager
    manager = CaseManager("chronicle.duckdb")
    case = manager.get_case(case_id)
    if not case:
        console.print(f"[red]Case {case_id} not found[/red]")
        return
    console.print(f"[bold]Case {case.id}:[/bold] {case.title}")
    console.print(f"Status: {case.status.value} | Priority: {case.priority.value}")
    console.print(f"Created: {case.created_at}")
    for note in case.notes:
        console.print(f"\n[cyan]{note.timestamp}[/cyan] by {note.author}:\n{note.content}")

@case_app.command("note")
def case_note(case_id: str, text: str) -> None:
    """Add a note to a case."""
    from soc_chronicle.cases.manager import CaseManager
    manager = CaseManager("chronicle.duckdb")
    manager.add_note(case_id, text)
    console.print(f"[green]Added note to {case_id}[/green]")

@case_app.command("close")
def case_close(case_id: str, resolution: str = typer.Option(..., "--resolution")) -> None:
    """Close a case."""
    from soc_chronicle.cases.manager import CaseManager
    manager = CaseManager("chronicle.duckdb")
    manager.close_case(case_id, resolution)
    console.print(f"[green]Closed {case_id}[/green]")

@case_app.command("export")
def case_export(case_id: str, format: str = typer.Option("markdown", "--format", help="Output format (markdown, json)")) -> None:
    """Export a case to a specific format."""
    from soc_chronicle.cases.manager import CaseManager
    manager = CaseManager("chronicle.duckdb")
    
    if format == "json":
        path = Path(f"{case_id}.json")
        manager.export_case_json(case_id, path)
    else:
        path = Path(f"{case_id}.md")
        manager.export_case_markdown(case_id, path)
        
    console.print(f"[green]Exported to {path}[/green]")

# ── Search CLI ────────────────────────────────────────────────────────────────

@app.command()
def search(
    query: Annotated[str, typer.Option("--query", "-q", help="Search string")],
    field: Annotated[str | None, typer.Option("--field", "-f", help="Specific field to search")] = None,
) -> None:
    """Search DuckDB event store."""
    from soc_chronicle.search.engine import SearchEngine
    engine = SearchEngine("chronicle.duckdb")
    fields = [field] if field else None
    results = engine.search(query, fields)
    
    table = Table(title=f"Search Results for '{query}' ({len(results)})")
    table.add_column("Time")
    table.add_column("Activity")
    table.add_column("Host")
    table.add_column("User")
    table.add_column("Process")
    for r in results[:50]:
        table.add_row(
            r.get("timestamp", ""),
            r.get("activity_name", ""),
            r.get("host", ""),
            r.get("user", ""),
            r.get("process_name", "")
        )
    console.print(table)

# ── Ingest Connectors CLI ─────────────────────────────────────────────────────

@ingest_app.command("evtx")
def ingest_evtx(file_path: str) -> None:
    """Parse EVTX to normalized events."""
    import asyncio

    from soc_chronicle.connectors.base import ConnectorConfig
    from soc_chronicle.connectors.evtx_connector import EvtxConnector
    
    async def run() -> None:
        cfg = ConnectorConfig(source_name="evtx")
        connector = EvtxConnector(cfg, file_path)
        await connector.connect()
        count = 0
        async for _ in connector.stream():
            count += 1
            if count % 1000 == 0:
                console.print(f"Processed {count} events...")
        console.print(f"[green]Finished processing {count} EVTX events[/green]")
    asyncio.run(run())

@ingest_app.command("watch")
def ingest_watch(directory: str) -> None:
    """Live watch directory for logs."""
    import asyncio

    from soc_chronicle.connectors.base import ConnectorConfig
    from soc_chronicle.connectors.filewatch import FileWatchConnector
    
    async def run() -> None:
        cfg = ConnectorConfig(source_name="filewatch")
        connector = FileWatchConnector(cfg, directory)
        await connector.connect()
        console.print(f"[bold green]Watching directory:[/bold green] {directory}")
        async for record in connector.stream():
            console.print(record)
    asyncio.run(run())

@ingest_app.command("syslog")
def ingest_syslog(port: int = typer.Option(514, "--port")) -> None:
    """Start syslog receiver."""
    import asyncio

    from soc_chronicle.connectors.base import ConnectorConfig
    from soc_chronicle.connectors.syslog import SyslogConnector
    
    async def run() -> None:
        cfg = ConnectorConfig(source_name="syslog")
        connector = SyslogConnector(cfg, port=port)
        await connector.connect()
        console.print(f"[bold green]Listening for syslog on port {port}...[/bold green]")
        async for record in connector.stream():
            console.print(record)
    asyncio.run(run())

@app.command("serve")
def serve(port: int = typer.Option(8514, "--port")) -> None:
    """Start webhook receiver."""
    import asyncio

    from soc_chronicle.connectors.base import ConnectorConfig
    from soc_chronicle.connectors.webhook import WebhookConnector
    
    async def run() -> None:
        cfg = ConnectorConfig(source_name="webhook")
        connector = WebhookConnector(cfg, port=port)
        await connector.connect()
        console.print(f"[bold green]Listening for webhooks on port {port}...[/bold green]")
        # Keep running
        await asyncio.Event().wait()
    asyncio.run(run())

# ── Hunting CLI ───────────────────────────────────────────────────────────────

@app.command()
def hunt(
    logs: Annotated[Path, typer.Option("--logs", "-l", help="Log directory")],
    alert: Annotated[Path | None, typer.Option("--alert", "-a", help="Alert file for context")] = None,
) -> None:
    """Run hunting generator and display queries."""
    from soc_chronicle.hunting.generator import HuntingGenerator
    
    gen = HuntingGenerator()
    console.print("[bold green]Hunting pack generated![/bold green] (Example output)")
    # Placeholder since hunting generator generates dict of queries
    queries = gen.generate([], [])
    console.print(f"[{'wazuh'.upper()}] {queries.get('wazuh', '')}")
