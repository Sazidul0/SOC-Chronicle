# SOC-Chronicle

Professional SOC Investigation, Threat Hunting, and Incident Narrative Engine.

SOC-Chronicle is an open-source security engineering project designed to automatically correlate raw logs from disparate security tools, normalize them into a unified schema, and generate actionable investigation reports.

## Key Capabilities

- **Unified Log Normalization**: Maps logs from Sysmon, Microsoft Sentinel, Okta, PAN-OS, CEF, Zeek, Windows Security, and more into an OCSF-aligned schema.
- **Automated Correlation**: Links events temporally and directionally using an in-memory or DuckDB-powered correlation engine.
- **MITRE ATT&CK Mapping**: High-fidelity detection of over 70+ techniques including LOLBin abuse, credential access tools, network C2, and lateral movement.
- **Threat Intelligence**: Built-in free enrichment from VirusTotal, Shodan InternetDB, IP-API, AlienVault OTX, and GreyNoise.
- **Interactive Reporting**: Generates a professional HTML report featuring a dynamic D3.js attack graph, risk gauge, IOC tables, and a chronological attack narrative.
- **Case Management**: Triage workflow allowing creation of cases, attaching notes/artifacts, and exporting case summaries.
- **Live Ingestion**: Supports parsing Windows EVTX files, watching log directories, Syslog UDP/TCP, and HTTP webhooks.

## Installation

```bash
pip install soc-chronicle
```

Install with all optional connectors and PDF export capability:
```bash
pip install soc-chronicle[all]
```

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

## Development

Set up a local development environment:

```bash
hatch shell
pytest tests/
```
