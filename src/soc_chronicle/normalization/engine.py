"""Log normalization engine — maps heterogeneous logs to OCSF-like events."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from soc_chronicle.models.event import NormalizedEvent, OCSFClass
from soc_chronicle.models.ocsf.validators import serialize_raw_data


class LogNormalizationEngine:
    """Parse and normalize logs from multiple security platforms."""

    PARSER_REGISTRY: dict[str, str] = {
        "sysmon": "_parse_sysmon",
        "crowdstrike": "_parse_crowdstrike",
        "elastic_ecs": "_parse_elastic_ecs",
        "cloudtrail": "_parse_cloudtrail",
        "suricata": "_parse_suricata",
        "generic": "_parse_generic",
    }

    def normalize_file(self, path: Path, parser: str | None = None) -> list[NormalizedEvent]:
        with path.open() as f:
            if path.suffix.lower() == ".json":
                content = json.load(f)
                if isinstance(content, list):
                    return [self.normalize_record(r, parser) for r in content]
                return [self.normalize_record(content, parser)]
            events: list[NormalizedEvent] = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    record = {"message": line, "raw_source": path.name}
                events.append(self.normalize_record(record, parser))
            return events

    def normalize_directory(self, directory: Path, parser: str | None = None) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        for path in sorted(directory.glob("**/*")):
            if path.is_file() and path.suffix.lower() in {".json", ".jsonl", ".log", ".ndjson"}:
                events.extend(self.normalize_file(path, parser))
        return events

    def normalize_record(
        self, record: dict[str, Any], parser: str | None = None
    ) -> NormalizedEvent:
        detected = parser or self._detect_parser(record)
        method_name = self.PARSER_REGISTRY.get(detected, "_parse_generic")
        return getattr(self, method_name)(record)

    def _detect_parser(self, record: dict[str, Any]) -> str:
        if "EventID" in record or record.get("source") == "Microsoft-Windows-Sysmon":
            return "sysmon"
        if "event_simpleName" in record or "aid" in record:
            return "crowdstrike"
        if "event.action" in record or record.get("ecs", {}).get("version"):
            return "elastic_ecs"
        if "eventSource" in record and record.get("eventSource") == "cloudtrail.amazonaws.com":
            return "cloudtrail"
        if "event_type" in record and "src_ip" in record:
            return "suricata"
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
        elif event_id == 13:
            class_uid = OCSFClass.REGISTRY_KEY_ACTIVITY
            activity = "Registry Value Set"
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
            file_hash=record.get("Hashes") or record.get("sha256"),
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
