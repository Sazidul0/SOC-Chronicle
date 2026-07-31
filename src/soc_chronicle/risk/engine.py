"""Evidence-based risk assessment engine with configurable rules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from soc_chronicle.models.event import NormalizedEvent, OCSFClass
from soc_chronicle.models.evidence import EvidenceRef
from soc_chronicle.models.ioc import IOC, IOCType
from soc_chronicle.models.report import RiskAssessment, RiskFactor

# Default built-in rules: (rule_id, score, description)
_DEFAULT_RULES: list[tuple[str, int, str]] = [
    ("known_malicious_hash", 25, "Known malicious hash observed"),
    ("high_vt_detections", 20, "High VirusTotal detection count"),
    ("office_to_powershell", 20, "Office application spawned PowerShell"),
    ("credential_dumping", 20, "Credential dumping behavior detected"),
    ("external_c2", 15, "External command-and-control connection"),
    ("persistence", 15, "Persistence mechanism created"),
    ("lateral_movement", 15, "Lateral movement activity detected"),
    ("privilege_escalation", 15, "Privilege escalation indicators"),
    ("discovery_activity", 10, "System/network discovery activity"),
    ("living_off_the_land", 10, "Living-off-the-land binary abuse"),
    ("nonstandard_port_c2", 15, "C2 over non-standard port"),
    ("dns_tunneling_indicator", 15, "DNS tunneling indicator"),
    ("scheduled_task_creation", 10, "Scheduled task created for persistence"),
    ("multiple_failed_logins", 10, "Multiple authentication failures"),
]

# Processes associated with privilege escalation
_PRIVESC_PROCESSES = {
    "getsystem", "incognito", "bypassuac", "akagi64.exe", "akagi32.exe",
    "fodhelper.exe", "eventvwr.exe", "sdclt.exe", "cmstp.exe",
}
# LOLBins used for "living off the land"
_LOLBIN_PROCESSES = {
    "certutil.exe", "bitsadmin.exe", "regsvr32.exe", "installutil.exe",
    "msbuild.exe", "mavinject.exe", "cmstp.exe", "odbcconf.exe",
    "regasm.exe", "regsvcs.exe", "msiexec.exe", "wmic.exe",
}
# Discovery tool processes
_DISCOVERY_PROCESSES = {
    "whoami.exe", "systeminfo.exe", "ipconfig.exe", "netstat.exe",
    "tasklist.exe", "arp.exe", "nslookup.exe", "nltest.exe",
    "dsquery.exe", "adfind.exe", "bloodhound", "sharphound.exe",
    "net.exe", "net1.exe",
}
# Non-standard C2 ports (not 80/443/8080)
_C2_PORTS = {4444, 1234, 8888, 9999, 1337, 31337, 4321, 6666, 7777, 8443, 1080}
_CRED_DUMP_PROCESSES = {"lsass.exe", "mimikatz", "procdump.exe", "comsvcs.dll", "wce.exe", "fgdump.exe", "pwdump"}
_PERSISTENCE_PATHS = {"run", "runonce", "services", "schedule", "currentversion\\run", "winlogon", "appinit_dlls"}
_SCHEDULED_TASK_PROCESSES = {"schtasks.exe", "at.exe"}


class RiskAssessmentEngine:
    """Deterministic, explainable risk scoring with configurable rules.

    Rules can be overridden by providing a YAML config file with structure::

        rules:
          - id: known_malicious_hash
            score: 30
            description: Custom label for malicious hash

    All rules fire at most once per assessment (deduplicated by rule_id).
    """

    def __init__(self, rules_path: Path | None = None) -> None:
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, path: Path | None) -> dict[str, tuple[int, str]]:
        """Load rules from YAML or fall back to built-in defaults."""
        rules: dict[str, tuple[int, str]] = {r[0]: (r[1], r[2]) for r in _DEFAULT_RULES}
        if path and path.exists():
            try:
                with path.open() as f:
                    data: dict[str, Any] = yaml.safe_load(f) or {}
                for rule in data.get("rules", []):
                    rid = rule.get("id", "")
                    score = int(rule.get("score", 10))
                    desc = rule.get("description", rid)
                    if score and desc:
                        rules[rid] = (score, desc)
            except Exception:  # noqa: BLE001  # nosec B110
                pass
        return rules

    def _score(self, rule_id: str) -> int:
        return self.rules.get(rule_id, (10, ""))[0]

    def _label(self, rule_id: str) -> str:
        return self.rules.get(rule_id, (10, rule_id))[1]

    def assess(
        self,
        events: list[NormalizedEvent],
        iocs: list[IOC],
        enrichment_malicious: set[str] | None = None,
        enrichment_results: list[dict[str, Any]] | None = None,
    ) -> RiskAssessment:
        """Run all risk rules and return a scored, evidence-traced assessment."""
        enrichment_malicious = enrichment_malicious or set()
        enrichment_results = enrichment_results or []
        factors: list[RiskFactor] = []
        triggered: set[str] = set()

        def add(rule_id: str, evts: list[NormalizedEvent], detail: str) -> None:
            if rule_id not in triggered:
                triggered.add(rule_id)
                factors.append(self._factor(rule_id, evts, detail))

        # ── Known malicious hash ──────────────────────────────────────────────
        hash_iocs = {i.value for i in iocs if i.type in {IOCType.SHA256, IOCType.SHA1, IOCType.MD5}}
        if hash_iocs & enrichment_malicious:
            matched = hash_iocs & enrichment_malicious
            add("known_malicious_hash", events, f"Hash matched threat intel: {next(iter(matched))[:16]}...")

        # ── High VT detection count from enrichment ───────────────────────────
        for result in enrichment_results:
            for r in result.get("results", []):
                if r.get("provider") == "virustotal" and r.get("malicious", 0) > 5:
                    add("high_vt_detections", events, f"VT: {r['malicious']} engines detected {result.get('ioc', '?')}")
                    break

        # ── Credential dumping ────────────────────────────────────────────────
        for event in events:
            proc = (event.process_name or "").lower().split("\\")[-1]
            if any(c in proc for c in _CRED_DUMP_PROCESSES):
                add("credential_dumping", [event], f"Suspicious process: {event.process_name}")
                break

        # ── Office → PowerShell / macro execution ─────────────────────────────
        for event in events:
            parent = (event.parent_process_name or "").lower().split("\\")[-1]
            child = (event.process_name or "").lower().split("\\")[-1]
            if parent in {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"} and (
                "powershell" in child or "cmd" in child or "wscript" in child or "mshta" in child
            ):
                add("office_to_powershell", [event], f"{parent} → {child}")
                break

        # ── External C2 connection ─────────────────────────────────────────────
        for event in events:
            if event.class_uid == OCSFClass.NETWORK_ACTIVITY:
                dst = event.dst_ip or event.domain or ""
                dst_str = str(dst)
                if dst_str and not dst_str.startswith(("10.", "172.16.", "172.17.", "172.18.",
                                                       "172.19.", "172.20.", "172.21.", "172.22.",
                                                       "172.23.", "172.24.", "172.25.", "172.26.",
                                                       "172.27.", "172.28.", "172.29.", "172.30.",
                                                       "172.31.", "192.168.", "127.", "0.", "::1",
                                                       "fc00:", "fe80:")):
                    add("external_c2", [event], f"Connection to external address: {dst_str}")
                    break

        # ── Non-standard C2 port ──────────────────────────────────────────────
        for event in events:
            if event.class_uid in {OCSFClass.NETWORK_ACTIVITY, OCSFClass.HTTP_ACTIVITY}:
                port = event.dst_port
                if port and port in _C2_PORTS:
                    add("nonstandard_port_c2", [event], f"C2 on non-standard port {port} to {event.dst_ip or event.domain}")
                    break

        # ── Registry persistence ───────────────────────────────────────────────
        for event in events:
            reg = (event.registry_key or "").lower()
            if event.class_uid in {OCSFClass.REGISTRY_KEY_ACTIVITY, OCSFClass.REGISTRY_VALUE_ACTIVITY} and any(
                p in reg for p in _PERSISTENCE_PATHS
            ):
                add("persistence", [event], f"Registry persistence key: {event.registry_key}")
                break

        # ── Scheduled task persistence ────────────────────────────────────────
        for event in events:
            proc = (event.process_name or "").lower().split("\\")[-1]
            if proc in _SCHEDULED_TASK_PROCESSES:
                add("scheduled_task_creation", [event], f"Scheduled task created by {event.process_name}")
                break

        # ── Privilege escalation ──────────────────────────────────────────────
        for event in events:
            proc = (event.process_name or "").lower().split("\\")[-1]
            cmdline = str(event.raw.get("CommandLine") or event.raw.get("command_line") or "").lower()
            if proc in _PRIVESC_PROCESSES or "whoami /priv" in cmdline or "seimpersonateprivilege" in cmdline:
                add("privilege_escalation", [event], f"Privilege escalation indicator: {event.process_name or cmdline[:40]}")
                break

        # ── LOLBin abuse ──────────────────────────────────────────────────────
        for event in events:
            proc = (event.process_name or "").lower().split("\\")[-1]
            if proc in _LOLBIN_PROCESSES:
                add("living_off_the_land", [event], f"LOLBin abuse: {event.process_name}")
                break

        # ── Discovery activity ─────────────────────────────────────────────────
        disc_events = [
            e for e in events
            if (e.process_name or "").lower().split("\\")[-1] in _DISCOVERY_PROCESSES
        ]
        if disc_events:
            add("discovery_activity", disc_events[:3], f"Discovery tools: {', '.join({e.process_name for e in disc_events if e.process_name}|set())[:60]}")

        # ── Lateral movement (auth across multiple hosts) ─────────────────────
        auth_hosts = {e.host for e in events if e.class_uid == OCSFClass.AUTHENTICATION and e.host}
        if len(auth_hosts) > 1:
            auth_events = [e for e in events if e.class_uid == OCSFClass.AUTHENTICATION]
            add(
                "lateral_movement",
                auth_events[:3],
                f"Authentication events across {len(auth_hosts)} hosts: {', '.join(sorted(auth_hosts)[:3])}",
            )

        # ── Multiple failed logins ────────────────────────────────────────────
        failed_auth = [e for e in events if e.class_uid == OCSFClass.AUTHENTICATION and "fail" in e.activity_name.lower()]
        if len(failed_auth) >= 3:
            add("multiple_failed_logins", failed_auth[:3], f"{len(failed_auth)} authentication failures observed")

        # ── DNS tunneling indicators ───────────────────────────────────────────
        for event in events:
            if event.class_uid == OCSFClass.DNS_ACTIVITY:
                domain = event.domain or ""
                # Unusually long domain or many subdomels = possible DNS tunnel
                if len(domain) > 50 or domain.count(".") > 4:
                    add("dns_tunneling_indicator", [event], f"Suspicious long DNS query: {domain[:50]}...")
                    break

        total = min(sum(f.score for f in factors), 100)
        return RiskAssessment(total_score=total, factors=factors)

    def _factor(self, rule_id: str, events: list[NormalizedEvent], detail: str) -> RiskFactor:
        score = self._score(rule_id)
        label = self._label(rule_id)
        evidence = [
            EvidenceRef(
                id=e.id,
                summary=detail,
                source="risk_engine",
                timestamp=e.timestamp,
            )
            for e in events[:3]
        ]
        return RiskFactor(label=f"{label}: {detail}", score=score, evidence=evidence)
