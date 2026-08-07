"""MITRE ATT&CK v15 mapping engine — comprehensive behavioral detection."""

from __future__ import annotations

import re
from typing import Any

from soc_chronicle.models.event import NormalizedEvent, OCSFClass
from soc_chronicle.models.evidence import EvidenceRef
from soc_chronicle.models.mitre import MitreMapping

# ATT&CK v15 version marker
ATTACK_VERSION = "15"

# Tactic kill-chain ordering for chain detection
TACTIC_CHAIN_ORDER = [
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# PowerShell command-line detection patterns
_PS_ENCODED_RE = re.compile(r"-(?:enc(?:odedcommand)?|en)\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE)
_PS_HIDDEN_RE = re.compile(r"-w(?:indowstyle)?\s+hid(?:den)?", re.IGNORECASE)
_PS_BYPASS_RE = re.compile(r"-exec(?:utionpolicy)?\s+bypass", re.IGNORECASE)
_PS_IEX_RE = re.compile(r"(?:iex|invoke-expression)\s*[\.\(]", re.IGNORECASE)
_PS_DOWNLOAD_RE = re.compile(
    r"(?:invoke-webrequest|iwr|net\.webclient|downloadstring|downloadfile"
    r"|start-bitstransfer|invoke-restmethod)\s*[\(\s\"']",
    re.IGNORECASE,
)
_PS_AMSI_RE = re.compile(r"amsi(?:InitFailed|ScanBuffer|Context)", re.IGNORECASE)
_PS_MIMIKATZ_RE = re.compile(r"(?:invoke-mimikatz|sekurlsa|lsadump|kerberos::)", re.IGNORECASE)
_PS_REFLECTIVE_RE = re.compile(r"(?:reflective|invoke-assembly|loadlibrary|virtualalloc)", re.IGNORECASE)

# Shell command patterns (Linux/macOS)
_SHELL_PIPE_DOWNLOAD_RE = re.compile(r"(?:curl|wget).*\|.*(?:bash|sh|python)", re.IGNORECASE)
_SHELL_TMP_EXEC_RE = re.compile(r"(?:chmod|execute).*(?:/tmp/|/dev/shm/)", re.IGNORECASE)
_CRON_PATTERN_RE = re.compile(r"(?:crontab\s+-[le]|/etc/cron)", re.IGNORECASE)
_PASSWD_READ_RE = re.compile(r"(?:cat|head|tail|less|more)\s+(?:/etc/(?:passwd|shadow|group))", re.IGNORECASE)

# Cloud action patterns for CloudTrail/Azure
_CLOUD_STORAGE_ACTIONS = frozenset({
    "GetObject", "PutObject", "ListBuckets", "ListObjects",
    "ListObjectsV2", "GetBucketAcl", "PutBucketAcl",
    "Microsoft.Storage/storageAccounts/listKeys/action",
    "microsoft.storage/storageaccounts/blobservices/containers/read",
})
_CLOUD_ACCOUNT_ACTIONS = frozenset({
    "AssumeRole", "AssumeRoleWithWebIdentity", "GetFederationToken",
    "CreateUser", "AttachUserPolicy", "AddUserToGroup",
    "Microsoft.Authorization/roleAssignments/write",
})
_CLOUD_SECRETSMGR_ACTIONS = frozenset({
    "GetSecretValue", "ListSecrets", "DescribeSecret",
    "GetParameter", "GetParameters",
})


class MitreMapper:
    """Map observed behaviors to MITRE ATT&CK v15 techniques.

    Coverage:
    - 80+ process name → technique mappings
    - Command-line behavioral analysis (PowerShell, bash, cloud CLIs)
    - Registry persistence patterns
    - Network C2 port heuristics
    - Linux/macOS technique detection
    - Cloud (AWS CloudTrail / Azure Activity) technique mapping
    - Behavioral chain detection (tactic sequence bonus)
    - ATT&CK v15 sub-technique precision
    """

    # Process name → (technique_id, technique_name, tactic)
    PROCESS_MAP: dict[str, tuple[str, str, str]] = {
        # ── Execution: T1059 Command and Scripting Interpreter ─────────────
        "powershell.exe": ("T1059.001", "PowerShell", "Execution"),
        "pwsh.exe": ("T1059.001", "PowerShell", "Execution"),
        "cmd.exe": ("T1059.003", "Windows Command Shell", "Execution"),
        "wscript.exe": ("T1059.005", "Visual Basic", "Execution"),
        "cscript.exe": ("T1059.005", "Visual Basic", "Execution"),
        "msbuild.exe": ("T1127.001", "MSBuild", "Defense Evasion"),
        "python.exe": ("T1059.006", "Python", "Execution"),
        "python3": ("T1059.006", "Python", "Execution"),
        "python": ("T1059.006", "Python", "Execution"),
        "bash": ("T1059.004", "Unix Shell", "Execution"),
        "sh": ("T1059.004", "Unix Shell", "Execution"),
        "zsh": ("T1059.004", "Unix Shell", "Execution"),
        "dash": ("T1059.004", "Unix Shell", "Execution"),
        "ksh": ("T1059.004", "Unix Shell", "Execution"),
        "node": ("T1059.007", "JavaScript", "Execution"),
        "node.exe": ("T1059.007", "JavaScript", "Execution"),

        # ── Defense Evasion: LOLBins ───────────────────────────────────────
        "mshta.exe": ("T1218.005", "Mshta", "Defense Evasion"),
        "rundll32.exe": ("T1218.011", "Rundll32", "Defense Evasion"),
        "regsvr32.exe": ("T1218.010", "Regsvr32", "Defense Evasion"),
        "certutil.exe": ("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion"),
        "bitsadmin.exe": ("T1197", "BITS Jobs", "Defense Evasion"),
        "wmic.exe": ("T1047", "Windows Management Instrumentation", "Execution"),
        "cmstp.exe": ("T1218.003", "CMSTP", "Defense Evasion"),
        "installutil.exe": ("T1218.004", "InstallUtil", "Defense Evasion"),
        "regasm.exe": ("T1218.009", "Regasm", "Defense Evasion"),
        "regsvcs.exe": ("T1218.009", "Regsvcs", "Defense Evasion"),
        "odbcconf.exe": ("T1218.008", "Odbcconf", "Defense Evasion"),
        "mavinject.exe": ("T1055", "Process Injection", "Defense Evasion"),
        "appinstaller.exe": ("T1218", "System Binary Proxy Execution", "Defense Evasion"),
        "forfiles.exe": ("T1059.003", "Windows Command Shell", "Execution"),
        "pcalua.exe": ("T1218", "System Binary Proxy Execution", "Defense Evasion"),
        "msiexec.exe": ("T1218.007", "Msiexec", "Defense Evasion"),
        "wermgr.exe": ("T1036", "Masquerading", "Defense Evasion"),
        "dllhost.exe": ("T1218.011", "Rundll32", "Defense Evasion"),
        "eventvwr.exe": ("T1548.002", "Bypass User Account Control", "Privilege Escalation"),
        "sdclt.exe": ("T1548.002", "Bypass User Account Control", "Privilege Escalation"),
        "fodhelper.exe": ("T1548.002", "Bypass User Account Control", "Privilege Escalation"),
        "control.exe": ("T1218", "System Binary Proxy Execution", "Defense Evasion"),
        "expand.exe": ("T1218", "System Binary Proxy Execution", "Defense Evasion"),

        # ── Lateral Movement ───────────────────────────────────────────────
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
        "pth-winexe": ("T1550.002", "Pass the Hash", "Lateral Movement"),
        "impacket-wmiexec": ("T1047", "Windows Management Instrumentation", "Lateral Movement"),
        "impacket-smbexec": ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
        "impacket-atexec": ("T1053.002", "At", "Lateral Movement"),

        # ── Credential Access ──────────────────────────────────────────────
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
        "responder": ("T1557.001", "LLMNR/NBT-NS Poisoning", "Credential Access"),
        "inveigh": ("T1557.001", "LLMNR/NBT-NS Poisoning", "Credential Access"),
        "rubeus.exe": ("T1558.003", "Kerberoasting", "Credential Access"),
        "kerbrute": ("T1558.003", "Kerberoasting", "Credential Access"),
        "impacket-getsttkt": ("T1558.001", "Golden Ticket", "Credential Access"),

        # ── Discovery ──────────────────────────────────────────────────────
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
        "adrecon.ps1": ("T1087.002", "Domain Account Discovery", "Discovery"),
        "ldapsearch": ("T1087.002", "Domain Account Discovery", "Discovery"),
        "enum4linux": ("T1087.002", "Domain Account Discovery", "Discovery"),

        # ── Collection / Exfiltration ──────────────────────────────────────
        "robocopy.exe": ("T1005", "Data from Local System", "Collection"),
        "xcopy.exe": ("T1005", "Data from Local System", "Collection"),
        "7z.exe": ("T1560.001", "Archive via Utility", "Collection"),
        "7za.exe": ("T1560.001", "Archive via Utility", "Collection"),
        "winrar.exe": ("T1560.001", "Archive via Utility", "Collection"),
        "tar": ("T1560.001", "Archive via Utility", "Collection"),
        "zip": ("T1560.001", "Archive via Utility", "Collection"),
        "curl.exe": ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
        "wget.exe": ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
        "curl": ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
        "wget": ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
        "certreq.exe": ("T1105", "Ingress Tool Transfer", "Command and Control"),
        "rclone.exe": ("T1537", "Transfer Data to Cloud Account", "Exfiltration"),
        "rclone": ("T1537", "Transfer Data to Cloud Account", "Exfiltration"),

        # ── Persistence ────────────────────────────────────────────────────
        "schtasks.exe": ("T1053.005", "Scheduled Task", "Persistence"),
        "at.exe": ("T1053.002", "At", "Persistence"),
        "sc.exe": ("T1543.003", "Windows Service", "Persistence"),
        "reg.exe": ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),

        # ── Impact ─────────────────────────────────────────────────────────
        "vssadmin.exe": ("T1490", "Inhibit System Recovery", "Impact"),
        "wbadmin.exe": ("T1490", "Inhibit System Recovery", "Impact"),
        "bcdedit.exe": ("T1490", "Inhibit System Recovery", "Impact"),
        "cipher.exe": ("T1485", "Data Destruction", "Impact"),
        "format.exe": ("T1485", "Data Destruction", "Impact"),
        "fsutil.exe": ("T1485", "Data Destruction", "Impact"),
    }

    OFFICE_PROCESSES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe"}
    OFFICE_SPAWN = ("T1566.001", "Spearphishing Attachment", "Initial Access")

    REGISTRY_PERSISTENCE_MAP: list[tuple[list[str], tuple[str, str, str]]] = [
        (["\\run\\", "\\runonce\\"], ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence")),
        (["\\services\\"], ("T1543.003", "Windows Service", "Persistence")),
        (["\\currentversion\\image file execution"], ("T1546.012", "Image File Execution Options Injection", "Privilege Escalation")),
        (["\\winlogon\\"], ("T1547.004", "Winlogon Helper DLL", "Persistence")),
        (["\\appinit_dlls"], ("T1546.010", "AppInit DLLs", "Privilege Escalation")),
        (["\\screensaver"], ("T1546.002", "Screensaver", "Persistence")),
        (["\\shell\\open\\command"], ("T1546.001", "Change Default File Association", "Persistence")),
        (["\\policies\\explorer\\run"], ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence")),
        (["\\environment", "\\userinitmprlogonscript"], ("T1037", "Boot or Logon Initialization Scripts", "Persistence")),
        (["\\lsa\\", "\\security packages"], ("T1547.005", "Security Support Provider", "Persistence")),
    ]

    PORT_TECHNIQUE_MAP: dict[int, tuple[str, str, str]] = {
        4444:  ("T1571", "Non-Standard Port", "Command and Control"),
        4445:  ("T1571", "Non-Standard Port", "Command and Control"),
        8080:  ("T1071.001", "Web Protocols", "Command and Control"),
        1080:  ("T1090", "Proxy", "Command and Control"),
        1337:  ("T1571", "Non-Standard Port", "Command and Control"),
        31337: ("T1571", "Non-Standard Port", "Command and Control"),
        4321:  ("T1571", "Non-Standard Port", "Command and Control"),
        6666:  ("T1571", "Non-Standard Port", "Command and Control"),
        7777:  ("T1571", "Non-Standard Port", "Command and Control"),
        8443:  ("T1071.001", "Web Protocols", "Command and Control"),
        53:    ("T1071.004", "DNS", "Command and Control"),
        443:   ("T1071.001", "Web Protocols", "Command and Control"),
        80:    ("T1071.001", "Web Protocols", "Command and Control"),
        8888:  ("T1571", "Non-Standard Port", "Command and Control"),
        9999:  ("T1571", "Non-Standard Port", "Command and Control"),
        2222:  ("T1021.004", "SSH", "Lateral Movement"),
        3389:  ("T1021.001", "Remote Desktop Protocol", "Lateral Movement"),
        5985:  ("T1021.006", "Windows Remote Management", "Lateral Movement"),
        5986:  ("T1021.006", "Windows Remote Management", "Lateral Movement"),
        445:   ("T1021.002", "SMB/Windows Admin Shares", "Lateral Movement"),
    }

    # Cobalt Strike default malleable C2 URI patterns
    _CS_URI_PATTERNS = re.compile(
        r"(?:/pixel\.gif|/submit\.php|/jquery-3\.3\.1\.min\.js|/updates\.rss"
        r"|/___utm\.gif|/visit\.js|/load|/storage/|/static/admin|/api/2/"
        r"|/updates|/functionalstatus|/dpixel\.png)",
        re.IGNORECASE,
    )

    # ACTIVITY_MAP fallback: OCSF class → technique
    ACTIVITY_MAP: dict[OCSFClass, tuple[str, str, str]] = {
        OCSFClass.REGISTRY_KEY_ACTIVITY:   ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence"),
        OCSFClass.REGISTRY_VALUE_ACTIVITY: ("T1112", "Modify Registry", "Defense Evasion"),
        OCSFClass.NETWORK_ACTIVITY:        ("T1071", "Application Layer Protocol", "Command and Control"),
        OCSFClass.DNS_ACTIVITY:            ("T1071.004", "DNS", "Command and Control"),
        OCSFClass.HTTP_ACTIVITY:           ("T1071.001", "Web Protocols", "Command and Control"),
        OCSFClass.AUTHENTICATION:          ("T1078", "Valid Accounts", "Initial Access"),
        OCSFClass.FILE_ACTIVITY:           ("T1204", "User Execution", "Execution"),
    }

    def map_events(self, events: list[NormalizedEvent]) -> list[MitreMapping]:
        """Map events to MITRE ATT&CK v15 techniques with evidence references."""
        mappings: list[MitreMapping] = []
        seen: set[str] = set()

        for event in events:
            proc = (event.process_name or "").lower()
            parent = (event.parent_process_name or "").lower()
            proc_basename = proc.split("\\")[-1].split("/")[-1]
            parent_basename = parent.split("\\")[-1].split("/")[-1]
            cmdline = event.raw.get("CommandLine") or event.raw.get("cmdline") or ""

            # ── Office macro initial access ────────────────────────────────
            if parent_basename in self.OFFICE_PROCESSES and proc:
                self._add(mappings, seen, self.OFFICE_SPAWN, event,
                          f"{parent_basename} spawned {proc}", confidence=0.90)

            # ── Process name → technique ───────────────────────────────────
            if proc_basename in self.PROCESS_MAP:
                tid, name, tactic = self.PROCESS_MAP[proc_basename]
                self._add(mappings, seen, (tid, name, tactic), event,
                          f"Process '{proc_basename}' observed", confidence=0.95)

            # ── Command-line behavioral analysis ──────────────────────────
            if cmdline:
                self._analyze_cmdline(mappings, seen, event, cmdline, proc_basename)

            # ── Registry-based persistence ─────────────────────────────────
            if event.class_uid in {OCSFClass.REGISTRY_KEY_ACTIVITY, OCSFClass.REGISTRY_VALUE_ACTIVITY}:
                reg = (event.registry_key or "").lower()
                matched = False
                for patterns, technique in self.REGISTRY_PERSISTENCE_MAP:
                    if any(p in reg for p in patterns):
                        self._add(mappings, seen, technique, event,
                                  f"Registry modification: {event.registry_key}", confidence=0.88)
                        matched = True
                        break
                if not matched and event.class_uid in self.ACTIVITY_MAP:
                    tid, name, tactic = self.ACTIVITY_MAP[event.class_uid]
                    self._add(mappings, seen, (tid, name, tactic), event, event.activity_name, confidence=0.70)

            # ── Network-based C2 detection ─────────────────────────────────
            elif event.class_uid in {OCSFClass.NETWORK_ACTIVITY, OCSFClass.DNS_ACTIVITY, OCSFClass.HTTP_ACTIVITY}:
                self._analyze_network(mappings, seen, event)

            # ── Cloud activity (CloudTrail / Azure) ────────────────────────
            elif event.class_uid == OCSFClass.AUTHENTICATION and event.source_type in {"cloudtrail", "azure_activity", "gcp_cloud_logging"}:
                self._analyze_cloud(mappings, seen, event)

            # ── Authentication ─────────────────────────────────────────────
            elif event.class_uid == OCSFClass.AUTHENTICATION:
                self._analyze_auth(mappings, seen, event)

            # ── File Activity ──────────────────────────────────────────────
            elif event.class_uid == OCSFClass.FILE_ACTIVITY:
                self._analyze_file(mappings, seen, event)

        return mappings

    def _analyze_cmdline(self, mappings: list[MitreMapping], seen: set[str],
                          event: NormalizedEvent, cmdline: str, proc_basename: str) -> None:
        """Detect ATT&CK techniques from command-line arguments."""
        # PowerShell encoded command
        if _PS_ENCODED_RE.search(cmdline):
            self._add(mappings, seen, ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
                      event, "PowerShell encoded command observed", confidence=0.93)
            self._add(mappings, seen, ("T1059.001", "PowerShell", "Execution"),
                      event, "PowerShell -EncodedCommand execution", confidence=0.95)

        # PowerShell hidden window
        if _PS_HIDDEN_RE.search(cmdline):
            self._add(mappings, seen, ("T1564.003", "Hidden Window", "Defense Evasion"),
                      event, "PowerShell hidden window style", confidence=0.88)

        # Execution policy bypass
        if _PS_BYPASS_RE.search(cmdline):
            self._add(mappings, seen, ("T1059.001", "PowerShell", "Execution"),
                      event, "PowerShell execution policy bypass", confidence=0.90)

        # Download cradle
        if _PS_DOWNLOAD_RE.search(cmdline):
            self._add(mappings, seen, ("T1105", "Ingress Tool Transfer", "Command and Control"),
                      event, "PowerShell download cradle observed", confidence=0.92)

        # IEX / Invoke-Expression
        if _PS_IEX_RE.search(cmdline):
            self._add(mappings, seen, ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
                      event, "Invoke-Expression (IEX) code execution", confidence=0.87)

        # AMSI bypass
        if _PS_AMSI_RE.search(cmdline):
            self._add(mappings, seen, ("T1562.001", "Disable or Modify Tools", "Defense Evasion"),
                      event, "AMSI bypass pattern detected", confidence=0.92)

        # Mimikatz invocation via PS
        if _PS_MIMIKATZ_RE.search(cmdline):
            self._add(mappings, seen, ("T1003", "OS Credential Dumping", "Credential Access"),
                      event, "Invoke-Mimikatz / Mimikatz module invocation", confidence=0.96)

        # Reflective loading
        if _PS_REFLECTIVE_RE.search(cmdline):
            self._add(mappings, seen, ("T1055", "Process Injection", "Defense Evasion"),
                      event, "Reflective assembly loading", confidence=0.85)

        # Linux: curl/wget pipe to shell
        if _SHELL_PIPE_DOWNLOAD_RE.search(cmdline):
            self._add(mappings, seen, ("T1105", "Ingress Tool Transfer", "Command and Control"),
                      event, "Shell pipe download cradle (curl/wget | bash)", confidence=0.90)

        # Linux: execution from /tmp or /dev/shm
        if _SHELL_TMP_EXEC_RE.search(cmdline):
            self._add(mappings, seen, ("T1059.004", "Unix Shell", "Execution"),
                      event, "Execution from volatile filesystem path (/tmp, /dev/shm)", confidence=0.85)

        # Linux: cron persistence
        if _CRON_PATTERN_RE.search(cmdline):
            self._add(mappings, seen, ("T1053.003", "Cron", "Persistence"),
                      event, "Cron job modification detected", confidence=0.88)

        # Linux: /etc/passwd or /etc/shadow read
        if _PASSWD_READ_RE.search(cmdline):
            self._add(mappings, seen, ("T1003.008", "/etc/passwd and /etc/shadow", "Credential Access"),
                      event, "Reading /etc/passwd or /etc/shadow", confidence=0.90)

    def _analyze_network(self, mappings: list[MitreMapping], seen: set[str],
                          event: NormalizedEvent) -> None:
        """Detect network-based C2 and lateral movement techniques."""
        dst_port = event.dst_port
        url_path = event.raw.get("url") or event.raw.get("uri") or event.raw.get("http.request.url") or ""

        if dst_port and dst_port in self.PORT_TECHNIQUE_MAP:
            technique = self.PORT_TECHNIQUE_MAP[dst_port]
            confidence = 0.65 if dst_port in {80, 443} else 0.80
            self._add(mappings, seen, technique, event,
                      f"Port {dst_port} connection to {event.dst_ip or event.domain}",
                      confidence=confidence)
        elif event.class_uid in self.ACTIVITY_MAP:
            tid, name, tactic = self.ACTIVITY_MAP[event.class_uid]
            self._add(mappings, seen, (tid, name, tactic), event, event.activity_name, confidence=0.65)

        # Cobalt Strike URI fingerprint
        if url_path and self._CS_URI_PATTERNS.search(url_path):
            self._add(mappings, seen, ("T1071.001", "Web Protocols", "Command and Control"),
                      event, f"Potential Cobalt Strike C2 URI: {url_path}", confidence=0.80)

    def _analyze_cloud(self, mappings: list[MitreMapping], seen: set[str],
                        event: NormalizedEvent) -> None:
        """Detect cloud-specific ATT&CK techniques from CloudTrail/Azure activity."""
        action = event.activity_name or ""

        if action in _CLOUD_ACCOUNT_ACTIONS:
            self._add(mappings, seen, ("T1078.004", "Cloud Accounts", "Initial Access"),
                      event, f"Cloud account action: {action}", confidence=0.80)

        if action in _CLOUD_STORAGE_ACTIONS:
            self._add(mappings, seen, ("T1530", "Data from Cloud Storage", "Collection"),
                      event, f"Cloud storage access: {action}", confidence=0.78)

        if action in _CLOUD_SECRETSMGR_ACTIONS:
            self._add(mappings, seen, ("T1552.001", "Credentials In Files", "Credential Access"),
                      event, f"Cloud secrets manager access: {action}", confidence=0.85)

        # Generic cloud authentication
        self._add(mappings, seen, ("T1078.004", "Cloud Accounts", "Initial Access"),
                  event, f"Cloud authentication event: {action}", confidence=0.60)

    def _analyze_auth(self, mappings: list[MitreMapping], seen: set[str],
                       event: NormalizedEvent) -> None:
        """Detect lateral movement and initial access from auth events."""
        activity = (event.activity_name or "").lower()
        src_ip = event.src_ip or ""

        if "fail" in activity or "invalid" in activity:
            self._add(mappings, seen, ("T1110", "Brute Force", "Credential Access"),
                      event, f"Authentication failure from {src_ip}", confidence=0.70)
        else:
            self._add(mappings, seen, ("T1078", "Valid Accounts", "Initial Access"),
                      event, "Successful authentication event", confidence=0.55)

    def _analyze_file(self, mappings: list[MitreMapping], seen: set[str],
                       event: NormalizedEvent) -> None:
        """Detect file-based execution and collection techniques."""
        path = (event.file_path or "").lower()

        if any(p in path for p in ["/tmp/", "/dev/shm/", "/var/tmp/"]):  # nosec B108
            self._add(mappings, seen, ("T1059.004", "Unix Shell", "Execution"),
                      event, f"File activity in volatile path: {event.file_path}", confidence=0.75)

        if path.endswith((".ps1", ".vbs", ".js", ".hta", ".wsf")):
            self._add(mappings, seen, ("T1059", "Command and Scripting Interpreter", "Execution"),
                      event, f"Script file: {event.file_path}", confidence=0.80)

        if path.endswith(".lnk"):
            self._add(mappings, seen, ("T1547.009", "Shortcut Modification", "Persistence"),
                      event, f"LNK shortcut file: {event.file_path}", confidence=0.78)

    def get_tactic_chain(self, mappings: list[MitreMapping]) -> list[str]:
        """Return observed tactics in kill-chain order."""
        observed = {m.tactic for m in mappings if m.tactic}
        return [t for t in TACTIC_CHAIN_ORDER if t in observed]

    def chain_score(self, mappings: list[MitreMapping]) -> float:
        """Return a chain score bonus based on tactic breadth (0.0 - 1.0)."""
        chain = self.get_tactic_chain(mappings)
        if len(chain) <= 1:
            return 0.0
        return min(1.0, len(chain) / len(TACTIC_CHAIN_ORDER))

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
                "metadata": [
                    {"name": "confidence", "value": f"{m.confidence:.0%}"},
                    {"name": "source", "value": "soc-chronicle"},
                ],
                "showSubtechniques": True,
            })

        chain = self.get_tactic_chain(mappings)
        return {
            "name": name,
            "versions": {"attack": ATTACK_VERSION, "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": description or (
                f"Generated by soc-chronicle — {len(mappings)} techniques detected"
                f" | Tactic chain: {' → '.join(chain)}"
            ),
            "filters": {"platforms": ["Windows", "Linux", "macOS", "AWS", "Azure", "GCP"]},
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
            "metadata": [
                {"name": "generated_by", "value": "soc-chronicle"},
                {"name": "attack_version", "value": ATTACK_VERSION},
            ],
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
        confidence: float = 0.90,
    ) -> None:
        tid, name, tactic = technique
        # Allow same technique from different tactics (dedupe by tid+tactic)
        key = f"{tid}:{tactic}"
        if key in seen:
            return
        seen.add(key)
        mappings.append(
            MitreMapping(
                technique_id=tid,
                technique_name=name,
                tactic=tactic,
                confidence=confidence,
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
