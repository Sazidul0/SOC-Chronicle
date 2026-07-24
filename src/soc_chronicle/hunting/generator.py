"""Threat hunting artifact generator."""

from __future__ import annotations

from soc_chronicle.models.event import NormalizedEvent
from soc_chronicle.models.ioc import IOC, IOCType


class HuntingGenerator:
    """Generate hunting queries from observed attack behavior."""

    def generate(
        self, events: list[NormalizedEvent], iocs: list[IOC]
    ) -> dict[str, str | list[str]]:
        processes = sorted({e.process_name for e in events if e.process_name})
        hashes = [i.value for i in iocs if i.type == IOCType.SHA256]
        domains = [i.value for i in iocs if i.type == IOCType.DOMAIN]
        ips = [i.value for i in iocs if i.type == IOCType.IPV4]

        sigma_rules: list[str] = []
        if processes:
            proc_list = "|".join(processes)
            sigma_rules.append(
                f"title: Hunt - Observed Processes\n"
                f"logsource:\n  category: process_creation\n"
                f"detection:\n  selection:\n    Image|endswith:\n"
                + "\n".join(f"      - '{p}'" for p in processes[:5])
                + "\n  condition: selection"
            )
        if hashes:
            sigma_rules.append(
                "title: Hunt - Observed File Hashes\n"
                "logsource:\n  category: file_event\n"
                "detection:\n  selection:\n    Hashes|contains:\n"
                + "\n".join(f"      - '{h}'" for h in hashes[:5])
                + "\n  condition: selection"
            )

        splunk = " OR ".join(f'Image="*{p}"' for p in processes[:5]) if processes else "*"
        elastic_kql = " or ".join(f'process.name : "{p}"' for p in processes[:5]) if processes else "*"
        sentinel_kql = elastic_kql
        wazuh = " OR ".join(f'syscheck.path="*{h[:8]}*"' for h in hashes[:3]) if hashes else "*"

        return {
            "sigma": sigma_rules,
            "splunk_spl": f'index=main ({splunk}) | stats count by host, user, Image',
            "elastic_kql": f"event.category : process and ({elastic_kql})",
            "sentinel_kql": f"DeviceProcessEvents | where {sentinel_kql}",
            "wazuh": f"SELECT * FROM syscheck WHERE {wazuh}" if hashes else "",
            "observed_ips": ips,
            "observed_domains": domains,
        }
