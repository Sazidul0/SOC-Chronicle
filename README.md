# soc-chronicle

[![PyPI version](https://img.shields.io/pypi/v/soc-chronicle.svg?color=blue)](https://pypi.org/project/soc-chronicle/)
[![Python versions](https://img.shields.io/pypi/pyversions/soc-chronicle.svg)](https://pypi.org/project/soc-chronicle/)
[![Build Status](https://github.com/Sazidul0/SOC-Chronicle/actions/workflows/ci.yml/badge.svg)](https://github.com/Sazidul0/SOC-Chronicle/actions)
[![License](https://img.shields.io/github/license/Sazidul0/SOC-Chronicle.svg)](https://github.com/Sazidul0/SOC-Chronicle/blob/main/LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/Sazidul0/SOC-Chronicle.svg)](https://github.com/Sazidul0/SOC-Chronicle/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/Sazidul0/SOC-Chronicle.svg)](https://github.com/Sazidul0/SOC-Chronicle/issues)

Open-source **Attack Investigation & Incident Narrative Engine** — transforms raw cybersecurity alerts into complete, evidence-driven attack narratives.

## Vision

soc-chronicle sits between existing detection platforms (SIEM, EDR, XDR, Cloud Security, IDS/IPS) and incident response workflows. Unlike traditional SIEMs that collect and search logs, soc-chronicle focuses on:

- **Investigation automation** — correlate events, build attack graphs, reconstruct timelines
- **Evidence correlation** — every conclusion traces back to supporting evidence
- **Root cause analysis** — patient zero, initial compromise, blast radius
- **Deterministic analysis** — explainable outputs, no black-box scoring

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Run an investigation
chronicle investigate examples/alert.json --logs examples/logs

# Export report
chronicle investigate examples/alert.json --logs examples/logs -o report.md

# Extract IOCs
chronicle enrich indicators.txt

# Build timeline from logs
chronicle timeline examples/logs/
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
                              Correlation Engine
                                      ↓
              Attack Graph ← Timeline Engine → Risk Engine
                                      ↓
                        Incident Narrative Generator
                                      ↓
                    Markdown / JSON / HTML Reports
```

## Core Modules

| Module | Description |
|--------|-------------|
| `intake` | Alert ingestion (JSON, YAML, files) with deduplication |
| `ioc` | IOC extraction with regex pipelines and defanging |
| `normalization` | Log parsing (Sysmon, CrowdStrike, ECS, CloudTrail, etc.) → OCSF |
| `correlation` | Temporal and entity-based event correlation |
| `graph` | Attack graph construction and analysis (NetworkX) |
| `timeline` | Chronological attack reconstruction |
| `root_cause` | Patient zero and initial compromise analysis |
| `risk` | Evidence-based, explainable risk scoring |
| `mitre` | MITRE ATT&CK technique mapping |
| `narrative` | Analyst-friendly incident narratives with citations |
| `hunting` | Sigma, Splunk, Elastic, Sentinel, Wazuh query generation |
| `report` | Markdown, HTML, JSON export |
| `threat_intel` | Async enrichment (VirusTotal, AbuseIPDB, pluggable) |
| `plugins` | Extensible parser, enrichment, and exporter plugins |

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
pip install -e ".[dev]"
pytest
ruff check src tests
mypy src/soc_chronicle
mkdocs serve
```

## Docker

```bash
docker build -t soc-chronicle .
docker run soc-chronicle investigate /app/examples/alert.json --logs /app/examples/logs
```

## Design Principles

- **Deterministic** over probabilistic reasoning
- **Explainable** outputs backed by evidence
- **Vendor-neutral** architecture
- **Plugin-based** extensibility
- **Offline-capable** local processing
- **Security-first** design

## License

Apache-2.0
