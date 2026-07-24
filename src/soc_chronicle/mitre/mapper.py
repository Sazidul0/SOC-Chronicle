"""MITRE ATT&CK mapping engine."""

from __future__ import annotations

from soc_chronicle.models.event import NormalizedEvent, OCSFClass
from soc_chronicle.models.evidence import EvidenceRef
from soc_chronicle.models.mitre import MitreMapping


class MitreMapper:
    """Map observed behaviors to MITRE ATT&CK techniques."""

    PROCESS_MAP: dict[str, tuple[str, str, str]] = {
        "powershell.exe": ("T1059.001", "PowerShell", "Execution"),
        "cmd.exe": ("T1059.003", "Windows Command Shell", "Execution"),
        "wscript.exe": ("T1059.005", "Visual Basic", "Execution"),
        "mshta.exe": ("T1218.005", "Mshta", "Defense Evasion"),
        "rundll32.exe": ("T1218.011", "Rundll32", "Defense Evasion"),
        "psexec.exe": ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
        "mimikatz": ("T1003", "OS Credential Dumping", "Credential Access"),
        "procdump.exe": ("T1003.001", "LSASS Memory", "Credential Access"),
    }

    ACTIVITY_MAP: dict[OCSFClass, tuple[str, str, str]] = {
        OCSFClass.REGISTRY_KEY_ACTIVITY: ("T1547.001", "Registry Run Keys", "Persistence"),
        OCSFClass.NETWORK_ACTIVITY: ("T1071", "Application Layer Protocol", "Command and Control"),
        OCSFClass.AUTHENTICATION: ("T1021", "Remote Services", "Lateral Movement"),
        OCSFClass.FILE_ACTIVITY: ("T1204", "User Execution", "Execution"),
    }

    OFFICE_SPAWN = ("T1566.001", "Spearphishing Attachment", "Initial Access")

    def map_events(self, events: list[NormalizedEvent]) -> list[MitreMapping]:
        mappings: list[MitreMapping] = []
        seen: set[str] = set()

        for event in events:
            proc = (event.process_name or "").lower()
            parent = (event.parent_process_name or "").lower()

            if parent.endswith(("winword.exe", "excel.exe", "powerpnt.exe")) and proc:
                self._add(mappings, seen, self.OFFICE_SPAWN, event, "Office document spawned subprocess")

            if proc in self.PROCESS_MAP:
                tid, name, tactic = self.PROCESS_MAP[proc]
                self._add(mappings, seen, (tid, name, tactic), event, f"Process {proc} observed")

            if event.class_uid in self.ACTIVITY_MAP:
                tid, name, tactic = self.ACTIVITY_MAP[event.class_uid]
                self._add(mappings, seen, (tid, name, tactic), event, event.activity_name)

        return mappings

    def _add(
        self,
        mappings: list[MitreMapping],
        seen: set[str],
        technique: tuple[str, str, str],
        event: NormalizedEvent,
        description: str,
    ) -> None:
        tid, name, tactic = technique
        if tid in seen:
            return
        seen.add(tid)
        mappings.append(
            MitreMapping(
                technique_id=tid,
                technique_name=name,
                tactic=tactic,
                confidence=0.9,
                description=description,
                evidence=[
                    EvidenceRef(
                        id=event.id,
                        summary=description,
                        source="mitre_mapper",
                        timestamp=event.timestamp,
                    )
                ],
            )
        )
