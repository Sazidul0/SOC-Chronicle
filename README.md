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

## Core System Capabilities

- **IOC Extraction**: Parses domains, IP addresses (IPv4/IPv6), hashes (MD5, SHA1, SHA256, SHA512, IMPHASH, SSDEEP, TLSH), TLS fingerprints, vulnerabilities (CVE IDs), ASNs, CIDR blocks, and cryptocurrency wallets. Dynamically un-defangs indicators and decodes Base64-encoded PowerShell payloads.
- **Threat Intelligence Integration**: Queries 9 intelligence providers. Unauthenticated providers (MalwareBazaar, URLhaus, ThreatFox, Shodan InternetDB, IP-API) are enabled by default. Integrates with API-gated providers (VirusTotal, AbuseIPDB, AlienVault OTX, GreyNoise). Implements disk-backed TTL caching and rate limiting.
- **MITRE ATT&CK Mapping (v15)**: Maps process execution, PowerShell usage, network C2 activity, Linux persistence, and cloud activity to specific sub-techniques to evaluate tactical attack chains.
- **Log Normalization**: Ingests and normalizes logs from Windows Security, Sysmon, Zeek, Auditd, Azure Activity, AWS VPC Flow, GCP Cloud Logging, GitHub Audit, K8s Audit, Microsoft Defender for Endpoint, Cisco IOS, FortiGate, LEEF (QRadar), and Apache/Nginx CLF into an OCSF-aligned schema.
- **Risk Assessment**: Calculates composite risk scores based on MITRE tactic progressions, asset criticality, temporal clustering, and malware family associations.
- **Threat Hunting Artifact Generation**: Translates investigation findings into operational hunting queries formatted as Sigma, YARA, Elastic EQL, KQL, Splunk SPL, QRadar AQL, and OpenSearch DSL.

## Installation

```bash
# Install from PyPI
pip install soc-chronicle
```

Install with optional live ingest connectors and PDF export capability:
```bash
pip install soc-chronicle[all]
```

## Detailed Use Cases

### Use Case 1: Automated SIEM Alert Investigation
When a generic SIEM alert triggers, investigators traditionally spend hours piecing together logs. SOC-Chronicle automates this by correlating events to a timeline and extracting indicators:
```bash
chronicle investigate examples/alert.json --logs examples/logs/ --enrich -o report.html --format html
```
**Outcome**: You receive an interactive HTML report with a full D3.js timeline, graph of the attack, patient zero identification, and integrated Threat Intelligence scores from tools like MalwareBazaar and URLhaus.

### Use Case 2: Proactive Threat Hunting Pivot
During an investigation, you discover a suspicious binary or C2 IP. Rather than manually crafting queries to sweep the rest of your environment, SOC-Chronicle generates them for you:
```bash
chronicle hunt --alert alert.json --logs /path/to/logs
```
**Outcome**: Automatic generation of:
- **Sigma Rules** for process tracking.
- **YARA Rules** using file hashes and string extraction.
- **KQL/Splunk/EQL/AQL Queries** covering network IPs, domain connections, and parent-child execution chains.

### Use Case 3: Behavioral Chain Risk Assessment
If an attacker triggers multiple low-severity alerts (e.g. Discovery -> Credential Access -> Lateral Movement), standard systems may ignore them individually. SOC-Chronicle correlates them and provides a *Tactic Chain Bonus* and *Asset Criticality Multiplier*:
```python
from soc_chronicle import InvestigationEngine
engine = InvestigationEngine()
report = engine.investigate(alert="examples/alert.json", logs="./examples/logs")
print(f"Risk Severity: {report.risk.severity}")
print(f"Justification: {report.risk.severity_justification}")
```
**Outcome**: The script accurately identifies the multi-stage tactic chain against a high-value asset and appropriately classifies the incident as `CRITICAL` risk.

### Use Case 4: Incident Triage & Case Management
Analysts can instantly create cases from investigations and track notes collaboratively over time:
```bash
chronicle case new --from-report report.json
chronicle case list --status open
chronicle case note CASE-A1B2C3D4 "Confirmed lateral movement via SMB."
```

## Supported Ingest Connectors

| Connector | Description | Usage |
|-----------|-------------|-------|
| EVTX | Parse Windows Event Log binary files | `chronicle ingest evtx file.evtx` |
| File Watch | Stream from growing local log directories | `chronicle ingest watch /var/log/syslog` |
| Syslog | Receive RFC 5424/3164 Syslog (UDP) | `chronicle ingest syslog --port 514` |
| Webhook | Receive JSON HTTP POSTs | `chronicle serve --port 8514` |

## Architecture

```
Security Alert → Alert Intake → IOC Extraction + Log Normalization (OCSF)
                                      ↓
                              Correlation Engine (DuckDB)
                                      ↓
              Attack Graph ← Timeline Engine → Risk Engine
                                      ↓
                        Incident Narrative Generator + Threat Hunt Artifacts
                                      ↓
                    Interactive HTML / JSON / Markdown Reports
```

## Configuration

Create `chronicle.yaml` for advanced behavior control:

```yaml
log_level: INFO
correlation_window_seconds: 3600
cache_ttl_seconds: 14400
max_enrichment_concurrency: 10
threat_intel:
  virustotal:
    enabled: true
    api_key: "${VT_API_KEY}"
  otx:
    enabled: true
    api_key: "${OTX_API_KEY}"
```

## Plugin Development

Register custom log parsers or exporters via entry points in `pyproject.toml`:

```toml
[project.entry-points."soc_chronicle.plugins"]
my_parser = "my_package:MyLogParser"
```

## Development & Testing

```bash
pip install -e ".[dev,all]"
pytest
ruff check src tests
mypy src/soc_chronicle
mkdocs serve
```
