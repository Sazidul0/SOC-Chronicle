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
    format: Annotated[str, typer.Option("--format", "-f", help="Output format")] = "markdown",
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
    output: Annotated[Path, typer.Option("--output", "-o")],
    format: Annotated[str, typer.Option("--format", "-f")] = "markdown",
) -> None:
    """Re-export an existing investigation report."""
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


if __name__ == "__main__":
    app()
