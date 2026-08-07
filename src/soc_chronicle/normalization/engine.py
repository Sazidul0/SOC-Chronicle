"""Log normalization engine — maps heterogeneous logs to OCSF-like events."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from soc_chronicle.models.event import NormalizedEvent, OCSFClass
from soc_chronicle.models.ocsf.validators import serialize_raw_data

_SHA256_RE = re.compile(r'SHA256=([0-9a-fA-F]{64})', re.IGNORECASE)
_MD5_RE = re.compile(r'MD5=([0-9a-fA-F]{32})', re.IGNORECASE)


class LogNormalizationEngine:
    """Parse and normalize logs from multiple security platforms."""

    PARSER_REGISTRY: dict[str, str] = {
        "sysmon": "_parse_sysmon",
        "windows_security": "_parse_windows_security",
        "auditd": "_parse_auditd",
        "macos_unified": "_parse_macos_unified",
        "android_log": "_parse_android_log",
        "zeek": "_parse_zeek",
        "web_server": "_parse_web_server",
        "firewall": "_parse_firewall",
        "wazuh": "_parse_wazuh",
        "splunk": "_parse_splunk",
        "azure_activity": "_parse_azure_activity",
        "crowdstrike": "_parse_crowdstrike",
        "elastic_ecs": "_parse_elastic_ecs",
        "cloudtrail": "_parse_cloudtrail",
        "suricata": "_parse_suricata",
        "okta": "_parse_okta",
        "sentinel": "_parse_sentinel",
        "cef": "_parse_cef",
        "paloalto": "_parse_paloalto",
        "aws_vpc_flow": "_parse_aws_vpc_flow",
        "gcp_cloud_logging": "_parse_gcp_cloud_logging",
        "github_audit": "_parse_github_audit",
        "k8s_audit": "_parse_k8s_audit",
        "mde": "_parse_mde",
        "cisco_ios": "_parse_cisco_ios",
        "fortigate": "_parse_fortigate",
        "leef": "_parse_leef",
        "clf": "_parse_clf",
        "windows_dhcp": "_parse_windows_dhcp",
        "generic": "_parse_generic",
    }

    def normalize_file(self, path: Path, parser: str | None = None) -> list[NormalizedEvent]:
        with path.open() as f:
            if path.suffix.lower() == ".json":
                content = json.load(f)
                if isinstance(content, list):
                    parsed = [self.normalize_record(r, parser) for r in content]
                    return [e for e in parsed if e is not None]
                res = self.normalize_record(content, parser)
                return [res] if res is not None else []
            events: list[NormalizedEvent] = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    record = {"message": line, "raw_source": path.name}
                
                norm_evt = self.normalize_record(record, parser)
                if norm_evt is not None:
                    events.append(norm_evt)
            return events

    def normalize_directory(self, directory: Path, parser: str | None = None) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for path in sorted(directory.glob("**/*")):
            if path.is_file() and path.suffix.lower() in {".json", ".jsonl", ".log", ".ndjson"}:
                events.extend(self.normalize_file(path, parser))
        return events

    def normalize_record(
        self, record: dict[str, Any], parser: str | None = None
    ) -> NormalizedEvent | None:
        detected = parser or self._detect_parser(record)
        method_name = self.PARSER_REGISTRY.get(detected, "_parse_generic")
        return cast(NormalizedEvent | None, getattr(self, method_name)(record))

    def _detect_parser(self, record: dict[str, Any]) -> str:
        # Okta System Log — check early (has `actor` + `eventType` keys)
        if "actor" in record and "eventType" in record:
            return "okta"
        # Microsoft Sentinel raw exports — TimeGenerated is the canonical field
        if "TimeGenerated" in record and (
            "InitiatingProcessFileName" in record or "Computer" in record
        ):
            return "sentinel"
        # PAN-OS: type in TRAFFIC/THREAT/SYSTEM + serial or device_name
        if str(record.get("type") or "").upper() in {"TRAFFIC", "THREAT", "SYSTEM", "CONFIG"} and (
            "serial" in record or "device_name" in record or "src" in record
        ):
            return "paloalto"
        # CEF: DeviceVendor field present or raw string starts with 'CEF:'
        if "DeviceVendor" in record or str(record.get("raw", "") or "").startswith("CEF:"):
            return "cef"
        # Sysmon / Windows Security
        if "EventID" in record or record.get("source") == "Microsoft-Windows-Sysmon" or "event_id" in record:
            channel = str(record.get("Channel") or record.get("channel") or "").lower()
            if channel == "security":
                return "windows_security"
            if record.get("source") == "Microsoft-Windows-Sysmon" or "EventID" in record:
                return "sysmon"
        if "type" in record and str(record.get("type", "")).lower() in ("auditd", "syscall", "execve"):
            return "auditd"
        if "logType" in record and record.get("logType") == "macOS":
            return "macos_unified"
        if "logcat" in record or (record.get("tag") and "pid" in record and "message" in record):
            return "android_log"
        if "_path" in record and "ts" in record:
            return "zeek"
        if "status" in record and ("clientip" in record or "remote_addr" in record or "request" in record):
            return "web_server"
        if "rule" in record and "agent" in record and "id" in record.get("rule", {}):
            return "wazuh"
        if "sourcetype" in record:
            return "splunk"
        if "tenantId" in record and "operationName" in record:
            return "azure_activity"
        if "event_simpleName" in record or "aid" in record:
            return "crowdstrike"
        if "event.action" in record or record.get("ecs", {}).get("version"):
            return "elastic_ecs"
        if "eventSource" in record and record.get("eventSource") == "cloudtrail.amazonaws.com":
            return "cloudtrail"
        if "event_type" in record and "src_ip" in record:
            return "suricata"
        if record.get("action") in ("allow", "deny", "block", "drop") and "src_ip" in record and "dst_ip" in record:
            return "firewall"
        # AWS VPC Flow Logs: has 'version', 'account-id', 'interface-id' or 'srcaddr'
        if "srcaddr" in record and "dstaddr" in record and "interface-id" in record:
            return "aws_vpc_flow"
        if record.get("version") == "1" and "srcaddr" in record and "dstaddr" in record:
            return "aws_vpc_flow"
        # GCP Cloud Logging: has 'logName' and 'protoPayload' or 'jsonPayload'
        if "logName" in record and ("protoPayload" in record or "jsonPayload" in record or "httpRequest" in record):
            return "gcp_cloud_logging"
        # GitHub Audit Log: has 'action' and 'actor' and 'org'/'repo'
        if "action" in record and "actor" in record and ("org" in record or "repo" in record):
            return "github_audit"
        # Kubernetes Audit: has 'apiVersion' with 'audit.k8s.io'
        if str(record.get("apiVersion", "")).startswith("audit.k8s.io"):
            return "k8s_audit"
        if "requestURI" in record and "user" in record and "verb" in record:
            return "k8s_audit"
        # MDE (Microsoft Defender for Endpoint): has 'DeviceId' and 'MachineGroup'
        if "DeviceId" in record and ("MachineGroup" in record or "TenantId" in record):
            return "mde"
        if "DeviceId" in record and "DeviceName" in record and "ActionType" in record:
            return "mde"
        # FortiGate: has 'devname' and 'logid'
        if "devname" in record and "logid" in record and "type" in record:
            return "fortigate"
        # LEEF (IBM QRadar): raw message starts with 'LEEF:'
        if str(record.get("raw", "") or "").startswith("LEEF:"):
            return "leef"
        if "leef_version" in record or record.get("DeviceEventClassID") and record.get("DeviceVendor"):
            return "leef"
        # Windows DHCP: has 'QResult' and 'Probationtime'
        if "QResult" in record and "Probationtime" in record:
            return "windows_dhcp"
        # Apache/Nginx CLF: has 'remote_addr' or 'clientip' with 'request' and 'status'
        if ("remote_addr" in record or "clientip" in record) and "request" in record and "status" in record:
            return "clf"
        # Cisco IOS/ASA: has 'facility' and 'mnemonic', or syslog with '%ASA-' or '%PIX-'
        if ("mnemonic" in record and "facility" in record) or "%ASA-" in str(record.get("message", "")):
            return "cisco_ios"
        return "generic"

    def _parse_sysmon(self, record: dict[str, Any]) -> NormalizedEvent:
        event_id = int(record.get("EventID") or record.get("event_id") or 0)
        class_uid = OCSFClass.PROCESS_ACTIVITY
        activity = "Process Activity"
        if event_id == 3:
            class_uid = OCSFClass.NETWORK_ACTIVITY
            activity = "Network Connection"
        elif event_id in {11, 23}:
            class_uid = OCSFClass.FILE_ACTIVITY
            activity = "File Created"
        elif event_id in {12, 13, 14}:
            class_uid = OCSFClass.REGISTRY_KEY_ACTIVITY if event_id == 12 else OCSFClass.REGISTRY_VALUE_ACTIVITY
            activity = "Registry Activity"
        return NormalizedEvent(
            class_uid=class_uid,
            activity_name=activity,
            timestamp=self._parse_ts(record),
            host=record.get("Computer") or record.get("host"),
            user=record.get("User") or record.get("user"),
            process_name=record.get("Image") or record.get("process_name"),
            process_pid=self._int_or_none(record.get("ProcessId") or record.get("pid")),
            process_guid=record.get("ProcessGuid") or record.get("process_guid"),
            parent_process_name=record.get("ParentImage") or record.get("parent_process"),
            parent_process_pid=self._int_or_none(record.get("ParentProcessId")),
            parent_process_guid=record.get("ParentProcessGuid") or record.get("parent_process_guid"),
            file_path=record.get("TargetFilename") or record.get("file_path"),
            file_hash=self._extract_sha256_from_hashes(record.get("Hashes") or record.get("sha256") or ""),
            src_ip=record.get("SourceIp") or record.get("src_ip"),
            src_port=self._int_or_none(record.get("SourcePort") or record.get("src_port")),
            dst_ip=record.get("DestinationIp") or record.get("dst_ip"),
            dst_port=self._int_or_none(record.get("DestinationPort") or record.get("dst_port")),
            protocol=record.get("Protocol") or record.get("protocol"),
            registry_key=record.get("TargetObject") or record.get("registry_key"),
            source_type="sysmon",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_windows_security(self, record: dict[str, Any]) -> NormalizedEvent:
        event_id = int(record.get("EventID") or record.get("event_id") or 0)
        class_uid = OCSFClass.DETECTION_FINDING
        activity = f"Windows Security Event {event_id}"
        if event_id in {4624, 4625}:
            class_uid = OCSFClass.AUTHENTICATION
            activity = "Logon Success" if event_id == 4624 else "Logon Failed"
        elif event_id == 4688:
            class_uid = OCSFClass.PROCESS_ACTIVITY
            activity = "Process Creation"

        return NormalizedEvent(
            class_uid=class_uid,
            activity_name=activity,
            timestamp=self._parse_ts(record),
            host=record.get("Computer") or record.get("host"),
            user=record.get("TargetUserName") or record.get("SubjectUserName") or record.get("user"),
            process_name=record.get("NewProcessName") or record.get("process_name"),
            process_pid=self._int_or_none(record.get("NewProcessId") or record.get("pid")),
            parent_process_name=record.get("ParentProcessName"),
            parent_process_pid=self._int_or_none(record.get("CreatorProcessId")),
            src_ip=record.get("IpAddress") or record.get("src_ip"),
            src_port=self._int_or_none(record.get("IpPort") or record.get("src_port")),
            auth_id=record.get("TargetLogonId") or record.get("LogonId"),
            source_type="windows_security",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_auditd(self, record: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            class_uid=OCSFClass.PROCESS_ACTIVITY,
            activity_name="Linux Auditd Event",
            timestamp=self._parse_ts(record),
            host=record.get("host") or record.get("node"),
            user=record.get("auid") or record.get("uid"),
            process_name=record.get("exe") or record.get("comm"),
            process_pid=self._int_or_none(record.get("pid")),
            parent_process_pid=self._int_or_none(record.get("ppid")),
            file_path=record.get("path") or record.get("name"),
            source_type="auditd",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_macos_unified(self, record: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            class_uid=OCSFClass.DETECTION_FINDING,
            activity_name=record.get("eventMessage") or "macOS Unified Log",
            timestamp=self._parse_ts(record),
            host=record.get("hostname"),
            process_name=record.get("processImagePath") or record.get("processImageUUID"),
            process_pid=self._int_or_none(record.get("pid")),
            source_type="macos_unified",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_android_log(self, record: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            class_uid=OCSFClass.DETECTION_FINDING,
            activity_name=record.get("message") or "Android System Log",
            timestamp=self._parse_ts(record),
            host=record.get("device") or "android_device",
            process_name=record.get("tag"),
            process_pid=self._int_or_none(record.get("pid")),
            source_type="android_log",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_zeek(self, record: dict[str, Any]) -> NormalizedEvent:
        path = record.get("_path")
        class_uid = OCSFClass.NETWORK_ACTIVITY
        activity = "Zeek Network Connection"
        domain = None
        if path == "http":
            class_uid = OCSFClass.HTTP_ACTIVITY
            activity = "Zeek HTTP Request"
            domain = record.get("host")
        elif path == "dns":
            class_uid = OCSFClass.DNS_ACTIVITY
            activity = "Zeek DNS Query"
            domain = record.get("query")
        return NormalizedEvent(
            class_uid=class_uid,
            activity_name=activity,
            timestamp=self._parse_ts(record),
            src_ip=record.get("id.orig_h") or record.get("src_ip"),
            src_port=self._int_or_none(record.get("id.orig_p") or record.get("src_port")),
            dst_ip=record.get("id.resp_h") or record.get("dst_ip"),
            dst_port=self._int_or_none(record.get("id.resp_p") or record.get("dst_port")),
            protocol=record.get("proto") or record.get("protocol"),
            domain=domain,
            session_id=record.get("uid"),
            source_type="zeek",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_web_server(self, record: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            class_uid=OCSFClass.HTTP_ACTIVITY,
            activity_name="Web Server Access",
            timestamp=self._parse_ts(record),
            src_ip=record.get("clientip") or record.get("remote_addr") or record.get("src_ip"),
            user=record.get("remote_user") or record.get("user"),
            domain=record.get("host") or record.get("server_name"),
            source_type="web_server",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_firewall(self, record: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            class_uid=OCSFClass.NETWORK_ACTIVITY,
            activity_name=f"Firewall Action: {record.get('action', 'unknown')}",
            timestamp=self._parse_ts(record),
            src_ip=record.get("src_ip") or record.get("source_ip"),
            src_port=self._int_or_none(record.get("src_port") or record.get("source_port")),
            dst_ip=record.get("dst_ip") or record.get("destination_ip"),
            dst_port=self._int_or_none(record.get("dst_port") or record.get("destination_port")),
            protocol=record.get("protocol") or record.get("proto"),
            source_type="firewall",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_wazuh(self, record: dict[str, Any]) -> NormalizedEvent:
        rule = record.get("rule", {})
        agent = record.get("agent", {})
        data = record.get("data", {})
        return NormalizedEvent(
            class_uid=OCSFClass.DETECTION_FINDING,
            activity_name=rule.get("description") or "Wazuh Alert",
            timestamp=self._parse_ts(record),
            host=agent.get("name") or record.get("location"),
            user=data.get("srcuser") or data.get("dstuser") or data.get("user"),
            src_ip=data.get("srcip") or record.get("srcip"),
            dst_ip=data.get("dstip"),
            process_name=data.get("process") or data.get("program"),
            source_type="wazuh",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_splunk(self, record: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            class_uid=OCSFClass.DETECTION_FINDING,
            activity_name=record.get("action") or record.get("message") or "Splunk Event",
            timestamp=self._parse_ts(record),
            host=record.get("host") or record.get("dest"),
            user=record.get("user") or record.get("src_user"),
            process_name=record.get("process") or record.get("app"),
            src_ip=record.get("src_ip") or record.get("src"),
            dst_ip=record.get("dst_ip") or record.get("dest_ip"),
            source_type="splunk",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_azure_activity(self, record: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            class_uid=OCSFClass.AUTHENTICATION,
            activity_name=record.get("operationName") or "Azure Activity",
            timestamp=self._parse_ts(record),
            user=record.get("caller") or record.get("identity", {}).get("claims", {}).get("upn"),
            src_ip=record.get("callerIpAddress") or record.get("clientIpAddress"),
            source_type="azure_activity",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_crowdstrike(self, record: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            class_uid=OCSFClass.PROCESS_ACTIVITY,
            activity_name=str(record.get("event_simpleName") or "Process Activity"),
            timestamp=self._parse_ts(record),
            host=record.get("ComputerName") or record.get("hostname"),
            user=record.get("UserName") or record.get("user"),
            process_name=record.get("FileName") or record.get("ImageFileName"),
            process_pid=self._int_or_none(record.get("ProcessId")),
            parent_process_name=record.get("ParentProcessName"),
            file_hash=record.get("SHA256HashData"),
            source_type="crowdstrike",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_elastic_ecs(self, record: dict[str, Any]) -> NormalizedEvent:
        process = record.get("process") or {}
        host = record.get("host") or {}
        user = record.get("user") or {}
        network = record.get("network") or {}
        file = record.get("file") or {}
        return NormalizedEvent(
            class_uid=OCSFClass.PROCESS_ACTIVITY,
            activity_name=str(record.get("event", {}).get("action") or "Activity"),
            timestamp=self._parse_ts(record),
            host=host.get("name"),
            user=user.get("name"),
            process_name=process.get("name"),
            process_pid=self._int_or_none(process.get("pid")),
            parent_process_name=(process.get("parent") or {}).get("name"),
            file_path=file.get("path"),
            file_hash=file.get("hash", {}).get("sha256") if isinstance(file.get("hash"), dict) else None,
            src_ip=(record.get("source") or {}).get("ip"),
            dst_ip=(record.get("destination") or {}).get("ip"),
            dst_port=self._int_or_none((record.get("destination") or {}).get("port")),
            domain=(network.get("protocol") and record.get("dns", {}).get("question", {}).get("name")),
            source_type="elastic_ecs",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_cloudtrail(self, record: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            class_uid=OCSFClass.AUTHENTICATION,
            activity_name=str(record.get("eventName") or "API Call"),
            timestamp=self._parse_ts(record),
            user=record.get("userIdentity", {}).get("userName"),
            src_ip=record.get("sourceIPAddress"),
            source_type="cloudtrail",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_suricata(self, record: dict[str, Any]) -> NormalizedEvent:
        return NormalizedEvent(
            class_uid=OCSFClass.NETWORK_ACTIVITY,
            activity_name=str(record.get("event_type") or "Network Activity"),
            timestamp=self._parse_ts(record),
            src_ip=record.get("src_ip"),
            dst_ip=record.get("dest_ip") or record.get("dst_ip"),
            dst_port=self._int_or_none(record.get("dest_port") or record.get("dst_port")),
            source_type="suricata",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_generic(self, record: dict[str, Any]) -> NormalizedEvent:
        source = record.get("raw_source", "generic")
        return NormalizedEvent(
            class_uid=OCSFClass.DETECTION_FINDING,
            activity_name=str(record.get("activity") or record.get("message") or "Event"),
            timestamp=self._parse_ts(record),
            host=record.get("host") or record.get("hostname"),
            user=record.get("user") or record.get("username"),
            process_name=record.get("process") or record.get("process_name"),
            file_path=record.get("file") or record.get("file_path"),
            src_ip=record.get("src_ip") or record.get("source_ip"),
            dst_ip=record.get("dst_ip") or record.get("destination_ip"),
            source_type=str(source),
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    @staticmethod
    def _parse_ts(record: dict[str, Any]) -> datetime:
        from datetime import UTC

        for key in ("timestamp", "@timestamp", "eventTime", "time", "UtcTime", "event_time"):
            if key in record and record[key]:
                value = record[key]
                if isinstance(value, datetime):
                    if value.tzinfo is None:
                        return value.replace(tzinfo=UTC)
                    return value.astimezone(UTC)
                text = str(value).replace("Z", "+00:00")
                try:
                    parsed = datetime.fromisoformat(text)
                    if parsed.tzinfo is None:
                        return parsed.replace(tzinfo=UTC)
                    return parsed.astimezone(UTC)
                except ValueError:
                    continue
        return datetime.now(tz=UTC)


    @staticmethod
    def _int_or_none(value: Any) -> int | None:
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _extract_sha256_from_hashes(hashes_str: str) -> str | None:
        """Extract SHA256 from Sysmon/CrowdStrike Hashes field.

        The Hashes field is typically: ``'MD5=abc...,SHA256=def...,SHA1=xyz...'``.
        Returns the bare SHA256 hex string, or the original value if it's already
        a valid 64-char hex digest.
        """
        if not hashes_str:
            return None
        # Already a bare sha256
        if len(hashes_str) == 64 and all(c in '0123456789abcdefABCDEF' for c in hashes_str):
            return hashes_str.lower()
        m = _SHA256_RE.search(hashes_str)
        if m:
            return m.group(1).lower()
        m = _MD5_RE.search(hashes_str)
        if m:
            return m.group(1).lower()  # fallback: return MD5 if no SHA256
        return None

    def normalize_stream(
        self, path: Path, parser: str | None = None, batch_size: int = 1000
    ) -> Iterator[list[NormalizedEvent]]:
        """Stream-normalize a large log file in configurable batches.

        Yields lists of up to *batch_size* :class:`NormalizedEvent` objects,
        avoiding loading the entire file into memory. Suitable for 1GB+ log files.
        """
        batch: list[NormalizedEvent] = []
        with path.open(encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    record = {"message": line, "raw_source": path.name}
                event = self.normalize_record(record, parser)
                if event is not None:
                    batch.append(event)
                if len(batch) >= batch_size:
                    yield batch
                    batch = []
        if batch:
            yield batch

    # ── New parsers ───────────────────────────────────────────────────────────

    def _parse_okta(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse Okta System Log events."""
        actor = record.get("actor") or {}
        client = record.get("client") or {}
        record.get("outcome") or {}
        geo = client.get("geographicalContext") or {}
        return NormalizedEvent(
            class_uid=OCSFClass.AUTHENTICATION,
            activity_name=str(record.get("eventType") or "Okta Event"),
            timestamp=self._parse_ts(record),
            user=actor.get("displayName") or actor.get("alternateId"),
            src_ip=client.get("ipAddress"),
            host=f"{geo.get('city', '')},{geo.get('country', '')}".strip(",") or None,
            session_id=record.get("uuid"),
            source_type="okta",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_sentinel(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse Microsoft Sentinel raw table exports."""
        tbl = str(record.get("Type") or record.get("TableName") or "").lower()
        class_uid = OCSFClass.PROCESS_ACTIVITY
        if "network" in tbl:
            class_uid = OCSFClass.NETWORK_ACTIVITY
        elif "auth" in tbl or "logon" in tbl:
            class_uid = OCSFClass.AUTHENTICATION
        elif "file" in tbl:
            class_uid = OCSFClass.FILE_ACTIVITY
        return NormalizedEvent(
            class_uid=class_uid,
            activity_name=str(record.get("ActionType") or record.get("Type") or "Sentinel Event"),
            timestamp=self._parse_ts(record),
            host=record.get("DeviceName") or record.get("Computer") or record.get("ComputerName"),
            user=record.get("AccountName") or record.get("Account") or record.get("TargetUserName"),
            process_name=record.get("InitiatingProcessFileName") or record.get("ProcessName"),
            process_pid=self._int_or_none(record.get("InitiatingProcessId") or record.get("ProcessId")),
            parent_process_name=record.get("InitiatingProcessParentFileName"),
            src_ip=record.get("RemoteIP") or record.get("IPAddress"),
            dst_port=self._int_or_none(record.get("RemotePort")),
            file_hash=self._extract_sha256_from_hashes(record.get("SHA256") or record.get("InitiatingProcessSHA256") or ""),
            registry_key=record.get("RegistryKey"),
            source_type="sentinel",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_cef(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse CEF (ArcSight Common Event Format) records."""
        ext = record.get("extension") or {}
        if isinstance(ext, str):
            # Parse space-separated key=value extension block
            ext = {}
            for kv in record["extension"].split(" "):
                if "=" in kv:
                    k, _, v = kv.partition("=")
                    ext[k.strip()] = v.strip()
        return NormalizedEvent(
            class_uid=OCSFClass.DETECTION_FINDING,
            activity_name=str(record.get("name") or record.get("Name") or "CEF Event"),
            timestamp=self._parse_ts(record),
            src_ip=ext.get("src") or ext.get("sourceAddress"),
            src_port=self._int_or_none(ext.get("spt") or ext.get("sourcePort")),
            dst_ip=ext.get("dst") or ext.get("destinationAddress"),
            dst_port=self._int_or_none(ext.get("dpt") or ext.get("destinationPort")),
            host=ext.get("dhost") or ext.get("deviceHostName") or record.get("deviceHostName"),
            user=ext.get("suser") or ext.get("sourceUserName"),
            process_name=ext.get("sproc") or ext.get("sourceProcessName"),
            file_path=ext.get("filePath") or ext.get("fname"),
            file_hash=self._extract_sha256_from_hashes(ext.get("fileHash") or ""),
            protocol=ext.get("proto"),
            source_type="cef",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_paloalto(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse Palo Alto Networks PAN-OS traffic and threat logs."""
        log_type = str(record.get("type") or record.get("LogType") or "").lower()
        class_uid = OCSFClass.NETWORK_ACTIVITY
        activity = f"PAN-OS {log_type.title() or 'Traffic'} Log"
        if "threat" in log_type:
            class_uid = OCSFClass.DETECTION_FINDING
        return NormalizedEvent(
            class_uid=class_uid,
            activity_name=activity,
            timestamp=self._parse_ts(record),
            src_ip=record.get("src") or record.get("srcip") or record.get("src_ip"),
            src_port=self._int_or_none(record.get("sport") or record.get("src_port")),
            dst_ip=record.get("dst") or record.get("dstip") or record.get("dst_ip"),
            dst_port=self._int_or_none(record.get("dport") or record.get("dst_port")),
            protocol=record.get("proto") or record.get("protocol"),
            user=record.get("srcuser") or record.get("src_user") or record.get("dstuser"),
            host=record.get("device_name") or record.get("hostname") or record.get("devicename"),
            domain=record.get("url") or record.get("threat_name"),
            source_type="paloalto",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_aws_vpc_flow(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse AWS VPC Flow Log records (v2-v5 format)."""
        action = str(record.get("action") or record.get("action-status") or "ACCEPT").upper()
        protocol_num = str(record.get("protocol") or "")
        proto_map = {"6": "tcp", "17": "udp", "1": "icmp"}
        protocol = proto_map.get(protocol_num, protocol_num)
        return NormalizedEvent(
            class_uid=OCSFClass.NETWORK_ACTIVITY,
            activity_name=f"VPC Flow {action}",
            timestamp=self._parse_ts(record),
            src_ip=record.get("srcaddr") or record.get("src-addr"),
            src_port=self._int_or_none(record.get("srcport") or record.get("src-port")),
            dst_ip=record.get("dstaddr") or record.get("dst-addr"),
            dst_port=self._int_or_none(record.get("dstport") or record.get("dst-port")),
            protocol=protocol,
            host=record.get("instance-id") or record.get("interface-id"),
            source_type="aws_vpc_flow",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_gcp_cloud_logging(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse GCP Cloud Logging (Stackdriver) records."""
        proto_payload = record.get("protoPayload") or {}
        json_payload = record.get("jsonPayload") or {}
        http_req = record.get("httpRequest") or {}
        log_name = record.get("logName", "")
        resource = record.get("resource") or {}
        resource_labels = resource.get("labels") or {}

        class_uid = OCSFClass.AUTHENTICATION
        if "http_request" in log_name.lower() or http_req:
            class_uid = OCSFClass.HTTP_ACTIVITY
        elif "data_access" in log_name.lower():
            class_uid = OCSFClass.FILE_ACTIVITY

        principal_email = (
            proto_payload.get("authenticationInfo", {}).get("principalEmail")
            or json_payload.get("actor", {}).get("user")
        )
        return NormalizedEvent(
            class_uid=class_uid,
            activity_name=str(proto_payload.get("methodName") or record.get("logName") or "GCP Event"),
            timestamp=self._parse_ts(record),
            user=principal_email,
            src_ip=(
                proto_payload.get("requestMetadata", {}).get("callerIp")
                or http_req.get("remoteIp")
            ),
            host=resource_labels.get("instance_id") or resource_labels.get("project_id"),
            source_type="gcp_cloud_logging",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_github_audit(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse GitHub Audit Log events."""
        action = str(record.get("action") or "github_event")
        return NormalizedEvent(
            class_uid=OCSFClass.AUTHENTICATION,
            activity_name=action,
            timestamp=self._parse_ts(record),
            user=str(record.get("actor") or record.get("user") or ""),
            src_ip=record.get("_source_ip") or record.get("ip"),
            host=record.get("org") or record.get("business"),
            source_type="github_audit",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_k8s_audit(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse Kubernetes API Server Audit Log events."""
        user_info = record.get("user") or {}
        src_ips = record.get("sourceIPs") or []
        src_ip = src_ips[0] if src_ips else None
        verb = str(record.get("verb") or "")
        resource = str((record.get("objectRef") or {}).get("resource") or "")
        activity = f"k8s.{verb}.{resource}" if resource else f"k8s.{verb}"

        class_uid = OCSFClass.PROCESS_ACTIVITY
        if verb in {"get", "list", "watch"}:
            class_uid = OCSFClass.FILE_ACTIVITY
        elif verb in {"create", "delete", "patch", "update"}:
            class_uid = OCSFClass.PROCESS_ACTIVITY

        return NormalizedEvent(
            class_uid=class_uid,
            activity_name=activity,
            timestamp=self._parse_ts(record),
            user=user_info.get("username"),
            src_ip=src_ip,
            host=record.get("requestURI"),
            source_type="k8s_audit",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_mde(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse Microsoft Defender for Endpoint (MDE / Advanced Hunting) records."""
        action = str(record.get("ActionType") or "ProcessActivity")
        class_uid = OCSFClass.PROCESS_ACTIVITY
        if "Network" in action:
            class_uid = OCSFClass.NETWORK_ACTIVITY
        elif "File" in action:
            class_uid = OCSFClass.FILE_ACTIVITY
        elif "Registry" in action:
            class_uid = OCSFClass.REGISTRY_KEY_ACTIVITY
        elif "Logon" in action or "Auth" in action:
            class_uid = OCSFClass.AUTHENTICATION
        return NormalizedEvent(
            class_uid=class_uid,
            activity_name=action,
            timestamp=self._parse_ts(record),
            host=record.get("DeviceName") or record.get("ComputerName"),
            user=record.get("AccountName") or record.get("InitiatingProcessAccountName"),
            process_name=record.get("InitiatingProcessFileName") or record.get("ProcessCommandLine"),
            process_pid=self._int_or_none(record.get("InitiatingProcessId")),
            parent_process_name=record.get("InitiatingProcessParentFileName"),
            file_hash=self._extract_sha256_from_hashes(record.get("SHA256") or record.get("InitiatingProcessSHA256") or ""),
            src_ip=record.get("RemoteIP") or record.get("LocalIP"),
            dst_port=self._int_or_none(record.get("RemotePort")),
            registry_key=record.get("RegistryKey"),
            source_type="mde",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_cisco_ios(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse Cisco IOS/ASA syslog records."""
        message = str(record.get("message") or record.get("msg") or "")
        # Try to extract src/dst from ASA message format
        import re as _re
        src_ip_m = _re.search(r"src\s+(?:interface)?:?\s*([\d.]+)", message, _re.IGNORECASE)
        dst_ip_m = _re.search(r"dst\s+(?:interface)?:?\s*([\d.]+)", message, _re.IGNORECASE)
        return NormalizedEvent(
            class_uid=OCSFClass.NETWORK_ACTIVITY,
            activity_name=str(record.get("mnemonic") or record.get("facility") or "Cisco IOS Event"),
            timestamp=self._parse_ts(record),
            src_ip=src_ip_m.group(1) if src_ip_m else record.get("src_ip"),
            dst_ip=dst_ip_m.group(1) if dst_ip_m else record.get("dst_ip"),
            host=record.get("hostname") or record.get("host"),
            source_type="cisco_ios",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_fortigate(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse FortiGate firewall / UTM logs."""
        logtype = str(record.get("type") or record.get("subtype") or "").lower()
        class_uid = OCSFClass.NETWORK_ACTIVITY
        if "utm" in logtype or "ips" in logtype or "av" in logtype:
            class_uid = OCSFClass.DETECTION_FINDING
        elif "event" in logtype:
            class_uid = OCSFClass.PROCESS_ACTIVITY
        return NormalizedEvent(
            class_uid=class_uid,
            activity_name=str(record.get("action") or record.get("subtype") or "FortiGate Event"),
            timestamp=self._parse_ts(record),
            src_ip=record.get("srcip") or record.get("src_ip"),
            src_port=self._int_or_none(record.get("srcport") or record.get("src_port")),
            dst_ip=record.get("dstip") or record.get("dst_ip"),
            dst_port=self._int_or_none(record.get("dstport") or record.get("dst_port")),
            protocol=record.get("proto") or record.get("protocol"),
            user=record.get("srcuser") or record.get("user"),
            host=record.get("devname"),
            domain=record.get("hostname") or record.get("url"),
            source_type="fortigate",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_leef(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse LEEF (Log Event Enhanced Format) from IBM QRadar."""
        # LEEF format: LEEF:version|vendor|product|version|eventId|key=val\tkey=val
        raw_msg = str(record.get("raw") or record.get("message") or "")
        attrs: dict[str, str] = dict(record)  # start with parsed fields
        if raw_msg.startswith("LEEF:"):
            try:
                parts = raw_msg.split("|", 5)
                if len(parts) >= 6:
                    ext_raw = parts[5]
                    sep = "\t" if "\t" in ext_raw else " "
                    for kv in ext_raw.split(sep):
                        if "=" in kv:
                            k, _, v = kv.partition("=")
                            attrs[k.strip()] = v.strip()
            except Exception:  # noqa: BLE001 # nosec B110
                pass
        return NormalizedEvent(
            class_uid=OCSFClass.DETECTION_FINDING,
            activity_name=str(attrs.get("devEventId") or attrs.get("cat") or "LEEF Event"),
            timestamp=self._parse_ts(record),
            src_ip=attrs.get("src") or attrs.get("sourceAddress"),
            src_port=self._int_or_none(attrs.get("srcPort") or attrs.get("spt")),
            dst_ip=attrs.get("dst") or attrs.get("destinationAddress"),
            dst_port=self._int_or_none(attrs.get("dstPort") or attrs.get("dpt")),
            user=attrs.get("usrName") or attrs.get("userName"),
            host=attrs.get("dvchost") or attrs.get("deviceHostName"),
            process_name=attrs.get("procName") or attrs.get("sourceProcessName"),
            source_type="leef",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_clf(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse Apache/Nginx Combined Log Format (CLF) records."""
        request = str(record.get("request") or "")
        method = verb = ""
        if request:
            parts = request.split(" ", 2)
            method = parts[0] if parts else ""
            verb = parts[1] if len(parts) > 1 else ""
        return NormalizedEvent(
            class_uid=OCSFClass.HTTP_ACTIVITY,
            activity_name=f"HTTP {method} {verb}" if method else "Web Request",
            timestamp=self._parse_ts(record),
            src_ip=record.get("remote_addr") or record.get("clientip") or record.get("client_ip"),
            user=record.get("remote_user") or record.get("ident"),
            domain=record.get("host") or record.get("server_name"),
            source_type="clf",
            raw_data=serialize_raw_data(record),
            raw=record,
        )

    def _parse_windows_dhcp(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse Windows DHCP Server log records."""
        event_id = self._int_or_none(record.get("ID") or record.get("EventID"))
        action_map = {
            10: "DHCP Assigned",
            11: "DHCP Renew",
            12: "DHCP Released",
            13: "DHCP Not Found",
            14: "DHCP Declined",
            15: "DHCP Lease Expired",
        }
        return NormalizedEvent(
            class_uid=OCSFClass.NETWORK_ACTIVITY,
            activity_name=action_map.get(event_id or 0, f"DHCP Event {event_id}"),
            timestamp=self._parse_ts(record),
            src_ip=record.get("IPAddress") or record.get("ip_address"),
            host=record.get("HostName") or record.get("hostname"),
            source_type="windows_dhcp",
            raw_data=serialize_raw_data(record),
            raw=record,
        )
