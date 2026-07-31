"""MITRE ATT&CK mapping engine — comprehensive technique detection."""

from __future__ import annotations

import json
from typing import Any

from soc_chronicle.models.event import NormalizedEvent, OCSFClass
from soc_chronicle.models.evidence import EvidenceRef
from soc_chronicle.models.mitre import MitreMapping


class MitreMapper:
    """Map observed behaviors to MITRE ATT&CK techniques.

    Covers 50+ techniques across Execution, Persistence, Defense Evasion,
    Credential Access, Discovery, Lateral Movement, Collection, C2, Exfiltration,
    and Impact tactics.
    """

    # Process name → (technique_id, technique_name, tactic)
    PROCESS_MAP: dict[str, tuple[str, str, str]] = {
        # Execution — T1059 Command and Scripting Interpreter
        "powershell.exe": ("T1059.001", "PowerShell", "Execution"),
        "pwsh.exe": ("T1059.001", "PowerShell", "Execution"),
        "cmd.exe": ("T1059.003", "Windows Command Shell", "Execution"),
        "wscript.exe": ("T1059.005", "Visual Basic", "Execution"),
        "cscript.exe": ("T1059.005", "Visual Basic", "Execution"),
        "msbuild.exe": ("T1127.001", "MSBuild", "Defense Evasion"),
        "python.exe": ("T1059.006", "Python", "Execution"),
        "python3": ("T1059.006", "Python", "Execution"),
        "bash": ("T1059.004", "Unix Shell", "Execution"),
        "sh": ("T1059.004", "Unix Shell", "Execution"),
        "zsh": ("T1059.004", "Unix Shell", "Execution"),

        # LOLBins — Defense Evasion
        "mshta.exe": ("T1218.005", "Mshta", "Defense Evasion"),
        "rundll32.exe": ("T1218.011", "Rundll32", "Defense Evasion"),
        "regsvr32.exe": ("T1218.010", "Regsvr32", "Defense Evasion"),
        "certutil.exe": ("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion"),
        "bitsadmin.exe": ("T1197", "BITS Jobs", "Defense Evasion"),
        "wmic.exe": ("T1047", "Windows Management Instrumentation", "Execution"),
        "cmstp.exe": ("T1218.003", "CMSTP", "Defense Evasion"),
        "installutil.exe": ("T1218.004", "InstallUtil", "Defense Evasion"),
        "regasm.exe": ("T1218.009", "Regasm", "Defense Evasion"),
        "odbcconf.exe": ("T1218.008", "Odbcconf", "Defense Evasion"),
        "mavinject.exe": ("T1055", "Process Injection", "Defense Evasion"),
        "appinstaller.exe": ("T1218", "System Binary Proxy Execution", "Defense Evasion"),
        "forfiles.exe": ("T1059.003", "Windows Command Shell", "Execution"),
        "pcalua.exe": ("T1218", "System Binary Proxy Execution", "Defense Evasion"),

        # Lateral Movement
        "psexec.exe": ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
        "psexesvc.exe": ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
        "wmiexec.py": ("T1047", "Windows Management Instrumentation", "Lateral Movement"),
        "smbclient": ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
        "net.exe": ("T1021", "Remote Services", "Lateral Movement"),
        "net1.exe": ("T1021", "Remote Services", "Lateral Movement"),
        "xfreerdp": ("T1021.001", "Remote Desktop Protocol", "Lateral Movement"),
        "mstsc.exe": ("T1021.001", "Remote Desktop Protocol", "Lateral Movement"),
        "ssh": ("T1021.004", "SSH", "Lateral Movement"),
        "rdesktop": ("T1021.001", "Remote Desktop Protocol", "Lateral Movement"),

        # Credential Access
        "mimikatz.exe": ("T1003", "OS Credential Dumping", "Credential Access"),
        "mimikatz": ("T1003", "OS Credential Dumping", "Credential Access"),
        "procdump.exe": ("T1003.001", "LSASS Memory", "Credential Access"),
        "procdump64.exe": ("T1003.001", "LSASS Memory", "Credential Access"),
        "wce.exe": ("T1003", "OS Credential Dumping", "Credential Access"),
        "fgdump.exe": ("T1003", "OS Credential Dumping", "Credential Access"),
        "pwdump.exe": ("T1003", "OS Credential Dumping", "Credential Access"),
        "lazagne.exe": ("T1555", "Credentials from Password Stores", "Credential Access"),
        "hashcat.exe": ("T1110.002", "Password Cracking", "Credential Access"),
        "hydra": ("T1110.003", "Password Spraying", "Credential Access"),
        "crackmapexec": ("T1110", "Brute Force", "Credential Access"),

        # Discovery
        "ipconfig.exe": ("T1016", "System Network Configuration Discovery", "Discovery"),
        "netstat.exe": ("T1049", "System Network Connections Discovery", "Discovery"),
        "whoami.exe": ("T1033", "System Owner/User Discovery", "Discovery"),
        "systeminfo.exe": ("T1082", "System Information Discovery", "Discovery"),
        "tasklist.exe": ("T1057", "Process Discovery", "Discovery"),
        "quser.exe": ("T1033", "System Owner/User Discovery", "Discovery"),
        "arp.exe": ("T1018", "Remote System Discovery", "Discovery"),
        "nslookup.exe": ("T1018", "Remote System Discovery", "Discovery"),
        "ping.exe": ("T1018", "Remote System Discovery", "Discovery"),
        "nmap": ("T1046", "Network Service Discovery", "Discovery"),
        "nltest.exe": ("T1482", "Domain Trust Discovery", "Discovery"),
        "dsquery.exe": ("T1087.002", "Domain Account Discovery", "Discovery"),
        "adfind.exe": ("T1087.002", "Domain Account Discovery", "Discovery"),
        "bloodhound": ("T1087.002", "Domain Account Discovery", "Discovery"),
        "sharphound.exe": ("T1087.002", "Domain Account Discovery", "Discovery"),

        # Collection / Exfiltration
        "robocopy.exe": ("T1005", "Data from Local System", "Collection"),
        "7z.exe": ("T1560.001", "Archive via Utility", "Collection"),
        "winrar.exe": ("T1560.001", "Archive via Utility", "Collection"),
        "curl.exe": ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
        "wget.exe": ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
        "certreq.exe": ("T1105", "Ingress Tool Transfer", "Command and Control"),

        # Persistence / Scheduled Tasks
        "schtasks.exe": ("T1053.005", "Scheduled Task", "Persistence"),
        "at.exe": ("T1053.002", "At", "Persistence"),
        "sc.exe": ("T1543.003", "Windows Service", "Persistence"),
        "reg.exe": ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
    }

    # OCSF class → technique (default when no process match)
    ACTIVITY_MAP: dict[OCSFClass, tuple[str, str, str]] = {
        OCSFClass.REGISTRY_KEY_ACTIVITY: ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
        OCSFClass.REGISTRY_VALUE_ACTIVITY: ("T1112", "Modify Registry", "Defense Evasion"),
        OCSFClass.NETWORK_ACTIVITY: ("T1071", "Application Layer Protocol", "Command and Control"),
        OCSFClass.DNS_ACTIVITY: ("T1071.004", "DNS", "Command and Control"),
        OCSFClass.HTTP_ACTIVITY: ("T1071.001", "Web Protocols", "Command and Control"),
        OCSFClass.AUTHENTICATION: ("T1021", "Remote Services", "Lateral Movement"),
        OCSFClass.FILE_ACTIVITY: ("T1204", "User Execution", "Execution"),
    }

    # Parent process patterns → technique mapping
    OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
    OFFICE_SPAWN = ("T1566.001", "Spearphishing Attachment", "Initial Access")

    # Registry key patterns → persistence techniques
    REGISTRY_PERSISTENCE_MAP: list[tuple[list[str], tuple[str, str, str]]] = [
        (["\\run\\", "\\runonce\\"], ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence")),
        (["\\services\\"], ("T1543.003", "Windows Service", "Persistence")),
        (["\\currentversion\\image file execution"], ("T1546.012", "Image File Execution Options Injection", "Privilege Escalation")),
        (["\\winlogon\\"], ("T1547.004", "Winlogon Helper DLL", "Persistence")),
        (["\\appinit_dlls"], ("T1546.010", "AppInit DLLs", "Privilege Escalation")),
        (["\\screensaver"], ("T1546.002", "Screensaver", "Persistence")),
    ]

    # Network port → technique
    PORT_TECHNIQUE_MAP: dict[int, tuple[str, str, str]] = {
        4444: ("T1571", "Non-Standard Port", "Command and Control"),
        8080: ("T1071.001", "Web Protocols", "Command and Control"),
        1080: ("T1090", "Proxy", "Command and Control"),
        1337: ("T1571", "Non-Standard Port", "Command and Control"),
        31337: ("T1571", "Non-Standard Port", "Command and Control"),
        53: ("T1071.004", "DNS", "Command and Control"),
        443: ("T1071.001", "Web Protocols", "Command and Control"),
    }

    def map_events(self, events: list[NormalizedEvent]) -> list[MitreMapping]:
        """Map events to MITRE ATT&CK techniques with evidence references."""
        mappings: list[MitreMapping] = []
        seen: set[str] = set()

        for event in events:
            proc = (event.process_name or "").lower()
            parent = (event.parent_process_name or "").lower()

            # Check for office macro initial access
            parent_basename = parent.split("\\")[-1].split("/")[-1]
            if parent_basename in self.OFFICE_PROCESSES and proc:
                self._add(mappings, seen, self.OFFICE_SPAWN, event, f"{parent_basename} spawned {proc}")

            # Check process name against LOLBin/tool map
            proc_basename = proc.split("\\")[-1].split("/")[-1]
            if proc_basename in self.PROCESS_MAP:
                tid, name, tactic = self.PROCESS_MAP[proc_basename]
                self._add(mappings, seen, (tid, name, tactic), event, f"Process '{proc_basename}' observed")

            # Registry-based persistence detection
            if event.class_uid in {OCSFClass.REGISTRY_KEY_ACTIVITY, OCSFClass.REGISTRY_VALUE_ACTIVITY}:
                reg = (event.registry_key or "").lower()
                for patterns, technique in self.REGISTRY_PERSISTENCE_MAP:
                    if any(p in reg for p in patterns):
                        self._add(mappings, seen, technique, event, f"Registry modification: {event.registry_key}")
                        break
                else:
                    # Default registry mapping
                    if event.class_uid in self.ACTIVITY_MAP:
                        tid, name, tactic = self.ACTIVITY_MAP[event.class_uid]
                        self._add(mappings, seen, (tid, name, tactic), event, event.activity_name)

            # Network-based C2 detection
            elif event.class_uid in {OCSFClass.NETWORK_ACTIVITY, OCSFClass.DNS_ACTIVITY, OCSFClass.HTTP_ACTIVITY}:
                dst_port = event.dst_port
                if dst_port and dst_port in self.PORT_TECHNIQUE_MAP:
                    technique = self.PORT_TECHNIQUE_MAP[dst_port]
                    self._add(mappings, seen, technique, event, f"Port {dst_port} connection to {event.dst_ip or event.domain}")
                elif event.class_uid in self.ACTIVITY_MAP:
                    tid, name, tactic = self.ACTIVITY_MAP[event.class_uid]
                    self._add(mappings, seen, (tid, name, tactic), event, event.activity_name)

            # Authentication lateral movement
            elif event.class_uid == OCSFClass.AUTHENTICATION:
                if event.class_uid in self.ACTIVITY_MAP:
                    tid, name, tactic = self.ACTIVITY_MAP[event.class_uid]
                    self._add(mappings, seen, (tid, name, tactic), event, event.activity_name)

            # File activity
            elif event.class_uid == OCSFClass.FILE_ACTIVITY:
                if event.class_uid in self.ACTIVITY_MAP:
                    tid, name, tactic = self.ACTIVITY_MAP[event.class_uid]
                    self._add(mappings, seen, (tid, name, tactic), event, event.activity_name)

        return mappings

    def generate_navigator_layer(
        self,
        mappings: list[MitreMapping],
        name: str = "SOC-Chronicle Investigation",
        description: str = "",
    ) -> dict[str, Any]:
        """Export MITRE ATT&CK Navigator layer JSON for browser visualization.

        The resulting dict can be saved as a .json file and loaded at
        https://mitre-attack.github.io/attack-navigator/
        """
        techniques = []
        for m in mappings:
            color = "#ff0000" if m.confidence >= 0.9 else ("#ff8800" if m.confidence >= 0.7 else "#ffcc00")
            techniques.append({
                "techniqueID": m.technique_id,
                "tactic": m.tactic.lower().replace(" ", "-") if m.tactic else None,
                "color": color,
                "comment": m.description or "",
                "enabled": True,
                "metadata": [{"name": "confidence", "value": f"{m.confidence:.0%}"}],
                "showSubtechniques": True,
            })

        return {
            "name": name,
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": description or f"Generated by soc-chronicle — {len(mappings)} techniques detected",
            "filters": {"platforms": ["Windows", "Linux", "macOS"]},
            "sorting": 0,
            "layout": {"layout": "side", "showID": True, "showName": True},
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ffffff", "#ff0000"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "High Confidence (≥90%)", "color": "#ff0000"},
                {"label": "Medium Confidence (≥70%)", "color": "#ff8800"},
                {"label": "Low Confidence (<70%)", "color": "#ffcc00"},
            ],
            "metadata": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#205b8c",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": True,
        }

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
