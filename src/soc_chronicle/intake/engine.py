"""Alert intake engine — accepts alerts from multiple sources."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from soc_chronicle.models.alert import Alert, AlertSource


class AlertIntakeEngine:
    """Validate, detect schema, deduplicate, and normalize incoming alerts."""

    def __init__(self) -> None:
        self._seen_ids: set[str] = set()

    def ingest(self, source: str | Path | dict[str, Any]) -> Alert:
        if isinstance(source, dict):
            return self._from_dict(source, AlertSource.UNKNOWN)
        path = Path(source)
        if not path.exists():
            msg = f"Alert source not found: {path}"
            raise FileNotFoundError(msg)
        if path.suffix.lower() in {".yaml", ".yml"}:
            return self.ingest_yaml(path)
        return self.ingest_json(path)

    def ingest_json(self, path: Path) -> Alert:
        with path.open() as f:
            data = json.load(f)
        return self._from_dict(data, AlertSource.JSON)

    def ingest_yaml(self, path: Path) -> Alert:
        with path.open() as f:
            data = yaml.safe_load(f)
        return self._from_dict(data or {}, AlertSource.YAML)

    def ingest_batch(self, sources: list[str | Path | dict[str, Any]]) -> list[Alert]:
        alerts: list[Alert] = []
        for source in sources:
            alert = self.ingest(source)
            if self._deduplicate(alert):
                alerts.append(alert)
        return alerts

    def _deduplicate(self, alert: Alert) -> bool:
        key = alert.id
        if key in self._seen_ids:
            return False
        self._seen_ids.add(key)
        return True

    def _from_dict(self, data: dict[str, Any], source: AlertSource) -> Alert:
        alert_id = str(data.get("id") or data.get("alert_id") or data.get("_id", ""))
        title = str(data.get("title") or data.get("name") or data.get("rule_name") or "Untitled Alert")
        timestamp = self._parse_timestamp(data.get("timestamp") or data.get("@timestamp"))
        return Alert(
            id=alert_id or str(uuid.uuid4()),
            title=title,
            description=data.get("description") or data.get("message"),
            severity=str(data.get("severity") or data.get("level") or "medium").lower(),
            source=source,
            timestamp=timestamp,
            raw=data,
            host=data.get("host") or data.get("hostname") or data.get("device"),
            user=data.get("user") or data.get("username"),
            rule_id=data.get("rule_id"),
            rule_name=data.get("rule_name") or data.get("rule"),
            tags=list(data.get("tags") or []),
        )

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        if value is None:
            return datetime.now(tz=UTC)
        if isinstance(value, datetime):
            return value
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=UTC)
        text = str(value).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return datetime.now(tz=UTC)
