"""Evidence-based risk assessment engine."""

from __future__ import annotations

from soc_chronicle.models.evidence import Evidence, EvidenceRef
from soc_chronicle.models.event import NormalizedEvent, OCSFClass
from soc_chronicle.models.ioc import IOC, IOCType
from soc_chronicle.models.report import RiskAssessment, RiskFactor


class RiskAssessmentEngine:
    """Deterministic, explainable risk scoring."""

    RULES: list[tuple[str, int, str]] = [
        ("known_malicious_hash", 25, "Known malicious hash observed"),
        ("office_to_powershell", 20, "Office application spawned PowerShell"),
        ("external_c2", 15, "External command-and-control connection"),
        ("persistence", 15, "Persistence mechanism created"),
        ("credential_dumping", 20, "Credential dumping behavior detected"),
        ("lateral_movement", 15, "Lateral movement activity detected"),
        ("privilege_escalation", 15, "Privilege escalation indicators"),
    ]

    CRED_DUMP_PROCESSES = {"lsass.exe", "mimikatz", "procdump.exe", "comsvcs.dll"}
    PERSISTENCE_PATHS = {"run", "runonce", "services", "schedule", "currentversion"}

    def assess(
        self,
        events: list[NormalizedEvent],
        iocs: list[IOC],
        enrichment_malicious: set[str] | None = None,
    ) -> RiskAssessment:
        enrichment_malicious = enrichment_malicious or set()
        factors: list[RiskFactor] = []

        hash_iocs = {i.value for i in iocs if i.type in {IOCType.SHA256, IOCType.SHA1, IOCType.MD5}}
        if hash_iocs & enrichment_malicious:
            factors.append(
                self._factor("known_malicious_hash", events, "Malicious hash matched threat intel")
            )

        for event in events:
            parent = (event.parent_process_name or "").lower()
            child = (event.process_name or "").lower()
            if parent.endswith(("winword.exe", "excel.exe")) and "powershell" in child:
                factors.append(
                    self._factor("office_to_powershell", [event], f"{parent} → {child}")
                )
                break

        for event in events:
            if event.class_uid == OCSFClass.NETWORK_ACTIVITY:
                dst = event.dst_ip or event.domain
                if dst and not str(dst).startswith(("10.", "172.", "192.168.")):
                    factors.append(
                        self._factor("external_c2", [event], f"Connection to external {dst}")
                    )
                    break

        for event in events:
            reg = (event.registry_key or "").lower()
            if event.class_uid == OCSFClass.REGISTRY_KEY_ACTIVITY and any(
                p in reg for p in self.PERSISTENCE_PATHS
            ):
                factors.append(
                    self._factor("persistence", [event], f"Registry persistence: {event.registry_key}")
                )
                break

        for event in events:
            proc = (event.process_name or "").lower()
            if any(c in proc for c in self.CRED_DUMP_PROCESSES):
                factors.append(
                    self._factor("credential_dumping", [event], f"Suspicious process: {proc}")
                )
                break

        auth_hosts = {e.host for e in events if e.class_uid == OCSFClass.AUTHENTICATION and e.host}
        if len(auth_hosts) > 1:
            factors.append(
                self._factor(
                    "lateral_movement",
                    [e for e in events if e.class_uid == OCSFClass.AUTHENTICATION],
                    f"Authentication across {len(auth_hosts)} hosts",
                )
            )

        # Deduplicate by label
        unique: dict[str, RiskFactor] = {}
        for factor in factors:
            rule_key = next((r[0] for r in self.RULES if r[2] == factor.label or r[1] == factor.score), factor.label)
            if rule_key not in unique:
                unique[rule_key] = factor

        total = min(sum(f.score for f in unique.values()), 100)
        return RiskAssessment(total_score=total, factors=list(unique.values()))

    def _factor(self, rule_id: str, events: list[NormalizedEvent], detail: str) -> RiskFactor:
        score = next(r[1] for r in self.RULES if r[0] == rule_id)
        label = next(r[2] for r in self.RULES if r[0] == rule_id)
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
