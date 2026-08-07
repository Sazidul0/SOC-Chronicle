"""Threat hunting artifact generator — industry-standard multi-platform queries."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

from soc_chronicle.models.event import NormalizedEvent
from soc_chronicle.models.ioc import IOC, IOCType


class HuntingGenerator:
    """Generate hunting artifacts from observed attack behavior.

    Produces:
    - Sigma rules (full YAML with ATT&CK tags)
    - YARA rules from file hashes
    - EQL sequences (Elastic)
    - KQL hunting queries (Defender/Sentinel)
    - Splunk SPL with tstats
    - QRadar AQL
    - OpenSearch DSL JSON
    """

    def generate(
        self, events: list[NormalizedEvent], iocs: list[IOC]
    ) -> dict[str, Any]:
        """Generate hunting artifacts from events and IOCs."""
        processes = sorted({e.process_name.split("\\")[-1].lower() for e in events if e.process_name})
        hashes_256 = [i.value for i in iocs if i.type == IOCType.SHA256]
        hashes_md5 = [i.value for i in iocs if i.type == IOCType.MD5]
        domains = [i.value for i in iocs if i.type == IOCType.DOMAIN]
        ips = [i.value for i in iocs if i.type == IOCType.IPV4]
        cves = [i.value for i in iocs if i.type == IOCType.CVE]
        hosts = sorted({e.host for e in events if e.host})
        users = sorted({e.user for e in events if e.user})

        return {
            "sigma": self._sigma_rules(processes, hashes_256, ips, domains, events),
            "yara": self._yara_rules(hashes_256, hashes_md5, processes),
            "eql": self._eql_queries(processes, hashes_256, events),
            "kql_defender": self._kql_defender(processes, hashes_256, ips, domains, users, hosts),
            "kql_sentinel": self._kql_sentinel(processes, hashes_256, ips, domains, users, hosts),
            "splunk_spl": self._splunk_spl(processes, hashes_256, ips, domains),
            "qradar_aql": self._qradar_aql(processes, ips, domains),
            "opensearch_dsl": self._opensearch_dsl(processes, hashes_256, ips),
            "observed_ips": ips,
            "observed_domains": domains,
            "observed_cves": cves,
            "observed_hashes": hashes_256,
        }

    # ── Sigma Rules ─────────────────────────────────────────────────────────

    def _sigma_rules(self, processes: list[str], hashes: list[str],
                     ips: list[str], domains: list[str],
                     events: list[NormalizedEvent]) -> list[str]:
        rules: list[str] = []
        today = datetime.now(tz=UTC).strftime("%Y/%m/%d")

        if processes:
            process_list = "".join(f"      - '{p}'\n" for p in processes[:10])
            rules.append(
                f"title: Hunt - Observed Suspicious Processes\n"
                f"id: {uuid.uuid4()}\n"
                f"status: experimental\n"
                f"description: Detects processes observed during SOC-Chronicle investigation\n"
                f"date: {today}\n"
                f"author: soc-chronicle\n"
                f"references:\n"
                f"  - https://attack.mitre.org/\n"
                f"logsource:\n"
                f"  category: process_creation\n"
                f"  product: windows\n"
                f"detection:\n"
                f"  selection:\n"
                f"    Image|endswith:\n"
                f"{process_list}"
                f"  condition: selection\n"
                f"falsepositives:\n"
                f"  - Legitimate administrator activity\n"
                f"level: high\n"
                f"tags:\n"
                f"  - attack.execution\n"
                f"  - attack.t1059\n"
            )

        if hashes:
            hash_list = "".join(f"      - '{h}'\n" for h in hashes[:10])
            rules.append(
                f"title: Hunt - Known Malicious File Hashes\n"
                f"id: {uuid.uuid4()}\n"
                f"status: experimental\n"
                f"description: Detects known malicious SHA256 hashes from investigation\n"
                f"date: {today}\n"
                f"author: soc-chronicle\n"
                f"logsource:\n"
                f"  category: file_event\n"
                f"  product: windows\n"
                f"detection:\n"
                f"  selection:\n"
                f"    Hashes|contains:\n"
                f"{hash_list}"
                f"  condition: selection\n"
                f"falsepositives:\n"
                f"  - None expected\n"
                f"level: critical\n"
                f"tags:\n"
                f"  - attack.defense_evasion\n"
                f"  - attack.t1036\n"
            )

        if ips:
            ip_list = "".join(f"      - '{ip}'\n" for ip in ips[:10])
            rules.append(
                f"title: Hunt - Suspicious Network Connections to Known Bad IPs\n"
                f"id: {uuid.uuid4()}\n"
                f"status: experimental\n"
                f"description: Detects network connections to malicious IPs from investigation\n"
                f"date: {today}\n"
                f"author: soc-chronicle\n"
                f"logsource:\n"
                f"  category: network_connection\n"
                f"  product: windows\n"
                f"detection:\n"
                f"  selection:\n"
                f"    DestinationIp:\n"
                f"{ip_list}"
                f"  condition: selection\n"
                f"falsepositives:\n"
                f"  - CDN IP ranges overlap\n"
                f"level: high\n"
                f"tags:\n"
                f"  - attack.command_and_control\n"
                f"  - attack.t1071\n"
            )

        if domains:
            domain_list = "".join(f"      - '{d}'\n" for d in domains[:10])
            rules.append(
                f"title: Hunt - DNS Queries to Suspicious Domains\n"
                f"id: {uuid.uuid4()}\n"
                f"status: experimental\n"
                f"description: Detects DNS queries to domains identified in investigation\n"
                f"date: {today}\n"
                f"author: soc-chronicle\n"
                f"logsource:\n"
                f"  category: dns\n"
                f"detection:\n"
                f"  selection:\n"
                f"    query|endswith:\n"
                f"{domain_list}"
                f"  condition: selection\n"
                f"falsepositives:\n"
                f"  - Legitimate CDN domains\n"
                f"level: medium\n"
                f"tags:\n"
                f"  - attack.command_and_control\n"
                f"  - attack.t1071.004\n"
            )

        return rules

    # ── YARA Rules ────────────────────────────────────────────────────────────

    def _yara_rules(self, hashes_256: list[str], hashes_md5: list[str],
                    processes: list[str]) -> str:
        if not hashes_256 and not hashes_md5 and not processes:
            return ""
        today = datetime.now(tz=UTC).strftime("%Y-%m-%d")
        rule_name = f"soc_chronicle_investigation_{today.replace('-', '_')}"
        conditions: list[str] = []
        strings: list[str] = []

        for i, h in enumerate(hashes_256[:5]):
            conditions.append(f"hash.sha256(0, filesize) == \"{h}\"")

        for i, p in enumerate(processes[:5]):
            safe = p.replace(".", "_").replace("-", "_")
            strings.append(f'    $proc_{i} = "{p}" nocase wide ascii')
        if strings:
            conditions.append("any of ($proc_*)")

        strings_block = "\n".join(strings) if strings else "    $ = \"placeholder\""
        conditions_block = " or\n        ".join(conditions) if conditions else "false"

        return (
            f"rule {rule_name}\n"
            f"{{\n"
            f"    meta:\n"
            f"        description = \"IOC hunt rule generated by soc-chronicle\"\n"
            f"        date = \"{today}\"\n"
            f"        author = \"soc-chronicle\"\n"
            f"        hash_count = \"{len(hashes_256)}\"\n"
            f"    strings:\n"
            f"{strings_block}\n"
            f"    condition:\n"
            f"        {conditions_block}\n"
            f"}}\n"
        )

    # ── EQL (Elastic) ──────────────────────────────────────────────────────────

    def _eql_queries(self, processes: list[str], hashes: list[str],
                     events: list[NormalizedEvent]) -> list[str]:
        queries: list[str] = []
        if processes:
            proc_filter = " or ".join(f'process.name == "{p}"' for p in processes[:5])
            queries.append(
                f"/* Hunt: Observed Process Execution */\n"
                f"process where event.type == \"start\" and (\n"
                f"  {proc_filter}\n"
                f")"
            )
        if len(processes) >= 2:
            parent = processes[0]
            child = processes[1]
            queries.append(
                f"/* Hunt: Parent-Child Process Chain */\n"
                f"sequence by host.name with maxspan=1m\n"
                f"  [process where process.name == \"{parent}\"]\n"
                f"  [process where process.name == \"{child}\"]"
            )
        if hashes:
            hash_filter = " or ".join(f'process.hash.sha256 == "{h}"' for h in hashes[:3])
            queries.append(
                f"/* Hunt: Known Malicious Hash */\n"
                f"any where (\n"
                f"  {hash_filter}\n"
                f")"
            )
        return queries

    # ── KQL (Microsoft Defender for Endpoint) ─────────────────────────────

    def _kql_defender(self, processes: list[str], hashes: list[str],
                      ips: list[str], domains: list[str],
                      users: list[str], hosts: list[str]) -> str:
        lines = ["// SOC-Chronicle Hunt: MDE Advanced Hunting"]
        if processes:
            proc_filter = " or ".join(f'InitiatingProcessFileName has "{p}"' for p in processes[:5])
            lines.append(
                f"let suspiciousProcesses = datatable(name: string)\n"
                + "".join(f'  ["{p}"]\n' for p in processes[:10])
                + ";\n"
                f"DeviceProcessEvents\n"
                f"| where Timestamp > ago(7d)\n"
                f"| where ({proc_filter})\n"
                f"| summarize count() by DeviceName, InitiatingProcessFileName, ProcessCommandLine\n"
                f"| sort by count_ desc"
            )
        if hashes:
            hash_filter = " or ".join(f'SHA256 =~ "{h}"' for h in hashes[:5])
            lines.append(
                f"// Hash Hunt\n"
                f"DeviceFileEvents\n"
                f"| where Timestamp > ago(30d)\n"
                f"| where ({hash_filter})\n"
                f"| project Timestamp, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessFileName"
            )
        if ips:
            ip_filter = " or ".join(f'RemoteIP == "{ip}"' for ip in ips[:10])
            lines.append(
                f"// Network IOC Hunt\n"
                f"DeviceNetworkEvents\n"
                f"| where Timestamp > ago(7d)\n"
                f"| where ({ip_filter})\n"
                f"| summarize count(), make_set(InitiatingProcessFileName) by RemoteIP, RemotePort, DeviceName"
            )
        return "\n\n".join(lines)

    # ── KQL (Microsoft Sentinel) ────────────────────────────────────────

    def _kql_sentinel(self, processes: list[str], hashes: list[str],
                      ips: list[str], domains: list[str],
                      users: list[str], hosts: list[str]) -> str:
        lines = ["// SOC-Chronicle Hunt: Microsoft Sentinel"]
        if processes:
            proc_filter = " or ".join(f'ProcessName has "{p}"' for p in processes[:5])
            lines.append(
                f"SecurityEvent\n"
                f"| where TimeGenerated > ago(7d)\n"
                f"| where EventID == 4688\n"
                f"| where ({proc_filter})\n"
                f"| summarize count() by Computer, Account, NewProcessName, ParentProcessName\n"
                f"| sort by count_ desc"
            )
        if ips:
            ip_filter = " or ".join(f'DestinationIP == \"{ip}\"' for ip in ips[:10])
            lines.append(
                f"// Network IOC Sentinel Hunt\n"
                f"CommonSecurityLog\n"
                f"| where TimeGenerated > ago(7d)\n"
                f"| where ({ip_filter})\n"
                f"| summarize TotalConnections=count() by DestinationIP, DestinationPort, SourceIP, DeviceVendor"
            )
        return "\n\n".join(lines)

    # ── Splunk SPL ────────────────────────────────────────────────────────────

    def _splunk_spl(self, processes: list[str], hashes: list[str],
                    ips: list[str], domains: list[str]) -> str:
        queries: list[str] = []
        if processes:
            proc_terms = " OR ".join(f'Image="*{p}"' for p in processes[:5])
            queries.append(
                f"| tstats summariesonly=false count min(_time) as firstSeen max(_time) as lastSeen\n"
                f"  from datamodel=Endpoint.Processes\n"
                f"  where ({proc_terms})\n"
                f"  by Processes.dest Processes.user Processes.process_name Processes.parent_process_name\n"
                f"| rename Processes.* as *\n"
                f"| eval risk_level=\"HIGH\"\n"
                f"| sort - count"
            )
        if hashes:
            hash_terms = " OR ".join(f'file_hash="{h}"' for h in hashes[:5])
            queries.append(
                f"index=* ({hash_terms})\n"
                f"| eval ioc_type=\"sha256_hash\"\n"
                f"| stats count min(_time) as firstSeen max(_time) as lastSeen by host user file_hash file_name\n"
                f"| sort - count"
            )
        if ips:
            ip_terms = " OR ".join(f'dest_ip="{ip}"' for ip in ips[:10])
            queries.append(
                f"| tstats summariesonly=false count\n"
                f"  from datamodel=Network_Traffic.All_Traffic\n"
                f"  where ({ip_terms})\n"
                f"  by All_Traffic.src All_Traffic.dest All_Traffic.dest_port All_Traffic.app\n"
                f"| rename All_Traffic.* as *\n"
                f"| sort - count"
            )
        if domains:
            domain_terms = " OR ".join(f'query="*{d}"' for d in domains[:10])
            queries.append(
                f"index=* sourcetype=stream:dns ({domain_terms})\n"
                f"| stats count by src_ip query answer\n"
                f"| sort - count"
            )
        return "\n\n".join(queries)

    # ── QRadar AQL ───────────────────────────────────────────────────────────

    def _qradar_aql(self, processes: list[str], ips: list[str], domains: list[str]) -> str:
        queries: list[str] = []
        if processes:
            proc_filter = " OR ".join(f"processname ILIKE '%{p}%'" for p in processes[:5])
            queries.append(
                f"SELECT sourceip, destinationip, processname, username, DATEFORMAT(devicetime,'YYYY-MM-dd HH:mm:ss') AS event_time\n"
                f"FROM events\n"
                f"WHERE ({proc_filter})\n"
                f"  AND DATEFORMAT(devicetime,'YYYY-MM-dd') >= DATEADD('day', -7, NOW())\n"
                f"ORDER BY devicetime DESC\n"
                f"LIMIT 1000"
            )
        if ips:
            ip_filter = ", ".join(f"'{ip}'" for ip in ips[:20])
            queries.append(
                f"SELECT sourceip, destinationip, destinationport, eventcount, DATEFORMAT(devicetime,'YYYY-MM-dd HH:mm:ss') AS event_time\n"
                f"FROM events\n"
                f"WHERE destinationip IN ({ip_filter})\n"
                f"  AND DATEFORMAT(devicetime,'YYYY-MM-dd') >= DATEADD('day', -7, NOW())\n"
                f"ORDER BY eventcount DESC\n"
                f"LIMIT 1000"
            )
        return "\n\n".join(queries)

    # ── OpenSearch DSL ─────────────────────────────────────────────────────

    def _opensearch_dsl(self, processes: list[str], hashes: list[str],
                        ips: list[str]) -> dict[str, Any]:
        should: list[dict[str, Any]] = []
        for p in processes[:5]:
            should.append({"match": {"process.name": {"query": p, "boost": 2.0}}})
        for h in hashes[:5]:
            should.append({"term": {"file.hash.sha256": h}})
        for ip in ips[:10]:
            should.append({"term": {"destination.ip": ip}})

        return {
            "query": {
                "bool": {
                    "should": should or [{"match_all": {}}],
                    "minimum_should_match": 1,
                    "filter": [
                        {"range": {"@timestamp": {"gte": "now-7d", "lte": "now"}}}
                    ],
                }
            },
            "size": 500,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": [
                "@timestamp", "host.name", "user.name",
                "process.name", "process.command_line",
                "file.hash.sha256", "destination.ip", "destination.port",
            ],
        }
