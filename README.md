<p align="center">
  <img src="https://github.com/Sazidul0/SOC-Chronicle/raw/main/soc-chronicle-lockup.svg" alt="soc-chronicle banner" width="600"/>
</p>

<p align="center">
  <a href="https://pypi.org/project/soc-chronicle/"><img src="https://img.shields.io/pypi/v/soc-chronicle.svg?color=blue" alt="PyPI version"></a>
  <a href="https://pypi.org/project/soc-chronicle/"><img src="https://img.shields.io/pypi/pyversions/soc-chronicle.svg" alt="Python versions"></a>
  <a href="https://github.com/Sazidul0/SOC-Chronicle/actions"><img src="https://github.com/Sazidul0/SOC-Chronicle/actions/workflows/ci.yml/badge.svg" alt="Build Status"></a>
  <a href="https://github.com/Sazidul0/SOC-Chronicle/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Sazidul0/SOC-Chronicle.svg" alt="License"></a>
  <a href="https://github.com/Sazidul0/SOC-Chronicle/stargazers"><img src="https://img.shields.io/github/stars/Sazidul0/SOC-Chronicle.svg" alt="GitHub Stars"></a>
  <a href="https://github.com/Sazidul0/SOC-Chronicle/issues"><img src="https://img.shields.io/github/issues/Sazidul0/SOC-Chronicle.svg" alt="GitHub Issues"></a>
</p>

<p align="center">
  Open-source <strong>Professional Attack Investigation & Incident Narrative Engine</strong> — transforms raw cybersecurity alerts into complete, evidence-driven attack narratives.
</p>

## Vision

SOC-Chronicle sits between existing detection platforms (SIEM, EDR, XDR, Cloud Security, IDS/IPS) and incident response workflows. Unlike traditional SIEMs that collect and search logs, SOC-Chronicle focuses on:

- **Investigation automation** — correlate events, build attack graphs, reconstruct timelines
- **Evidence correlation** — every conclusion traces back to supporting evidence
- **Root cause analysis** — patient zero, initial compromise, blast radius
- **Deterministic analysis** — explainable outputs, no black-box scoring

## Key Capabilities (v0.2.0)

- **Unified Log Normalization**: Maps logs from Sysmon, Microsoft Sentinel, Okta, PAN-OS, CEF, Zeek, Windows Security, and more into an OCSF-aligned schema with large file stream support.
- **Automated Correlation**: Links events temporally and directionally using an in-memory or DuckDB-powered correlation engine.
- **MITRE ATT&CK Mapping**: High-fidelity detection of over 70+ techniques including LOLBin abuse, credential access tools, network C2, and lateral movement.
- **Threat Intelligence**: Built-in free enrichment from VirusTotal, Shodan InternetDB, IP-API, AlienVault OTX, and GreyNoise.
- **Interactive Reporting**: Generates a professional HTML report featuring a dynamic D3.js attack graph, risk gauge, IOC tables, and a chronological attack narrative.
- **Case Management**: Triage workflow allowing creation of cases, attaching notes/artifacts, and exporting case summaries.
- **Live Ingestion**: Supports parsing Windows EVTX files, watching log directories, Syslog UDP/TCP, and HTTP webhooks.

## Installation

```bash
# Install from PyPI
pip install soc-chronicle
```

Install with optional live ingest connectors and PDF export capability:
```bash
pip install soc-chronicle[all]
```

Or pick specific dependencies: `[evtx]`, `[watch]`, `[serve]`, `[pdf]`.

## Quick Start

Run a full automated investigation and generate a professional interactive HTML report:

```bash
chronicle investigate examples/alert.json --logs examples/logs/ --enrich -o report.html --format html
```

## Triage & Case Management Workflow

Create a case directly from an investigation report:
```bash
chronicle case new --from-report report.json
```

List active cases:
```bash
chronicle case list --status open
```

Add investigation notes:
```bash
chronicle case note CASE-A1B2C3D4 "Confirmed lateral movement via SMB."
```

## Supported Ingest Connectors

| Connector | Description | Usage |
|-----------|-------------|-------|
| EVTX | Parse Windows Event Log binary files | `chronicle ingest evtx file.evtx` |
| File Watch | Stream from growing local log directories | `chronicle ingest watch /var/log/syslog` |
| Syslog | Receive RFC 5424/3164 Syslog (UDP) | `chronicle ingest syslog --port 514` |
| Webhook | Receive JSON HTTP POSTs | `chronicle serve --port 8514` |

## Threat Hunting Pack

Automatically generate pivoting queries across Sigma, Splunk, Sentinel, and Elastic for IOCs identified in the alert:

```bash
chronicle hunt --alert alert.json --logs /path/to/logs
```

## Advanced Search

Search the normalized event database (DuckDB) quickly:

```bash
chronicle search --query "powershell.exe" --field process
```

## Python API

```python
from soc_chronicle import InvestigationEngine

engine = InvestigationEngine()
report = engine.investigate(
    alert="examples/alert.json",
    logs="./examples/logs",
)

print(report.summary)
print(report.narrative)
print(f"Risk: {report.risk.total_score}/100")
print(f"Patient zero: {report.patient_zero}")
```

## Architecture

```
Security Alert → Alert Intake → IOC Extraction + Log Normalization (OCSF)
                                      ↓
                              Correlation Engine (DuckDB)
                                      ↓
              Attack Graph ← Timeline Engine → Risk Engine
                                      ↓
                        Incident Narrative Generator
                                      ↓
                    Interactive HTML / JSON / Markdown Reports
```

## Configuration

Create `chronicle.yaml`:

```yaml
log_level: INFO
correlation_window_seconds: 3600
threat_intel:
  virustotal:
    enabled: true
    api_key: "${VT_API_KEY}"
```

## Plugin Development

Register plugins via entry points in `pyproject.toml`:

```toml
[project.entry-points."soc_chronicle.plugins"]
my_parser = "my_package:MyLogParser"
```

Implement `LogParserPlugin`, `EnrichmentProviderPlugin`, or `ExporterPlugin` from `soc_chronicle.plugins.registry`.

## Development

```bash
pip install -e ".[dev,all]"
pytest
ruff check src tests
mypy src/soc_chronicle
mkdocs serve
```
