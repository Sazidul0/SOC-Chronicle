"""Windows EVTX connector."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

from soc_chronicle.connectors.base import ConnectorConfig, IngestConnector

try:
    import Evtx.Evtx as evtx
    import xmltodict
except ImportError:
    evtx = None
    xmltodict = None


class EvtxConnector(IngestConnector):
    """Parses Windows EVTX binary log files."""
    
    def __init__(self, config: ConnectorConfig, file_path: str) -> None:
        super().__init__(config)
        if evtx is None or xmltodict is None:
            raise ImportError("EvtxConnector requires python-evtx and xmltodict. Install with 'pip install python-evtx xmltodict'")
        self.file_path = Path(file_path)
        
    async def connect(self) -> None:
        if not self.file_path.exists():
            raise FileNotFoundError(f"EVTX file not found: {self.file_path}")

    async def stream(self) -> AsyncGenerator[dict[str, Any], None]:
        # Process EVTX synchronously in a thread to avoid blocking event loop
        def parse_file() -> list[dict[str, Any]]:
            records = []
            with evtx.Evtx(str(self.file_path)) as log:
                for record in log.records():
                    try:
                        xml_str = record.xml()
                        # Simple XML to dict conversion
                        d = xmltodict.parse(xml_str)
                        if "Event" in d:
                            event = d["Event"]
                            sys = event.get("System", {})
                            data = event.get("EventData", {})
                            # Flatten structure for normalization engine
                            flat_record = {
                                "EventID": sys.get("EventID", {}).get("#text") if isinstance(sys.get("EventID"), dict) else sys.get("EventID"),
                                "Computer": sys.get("Computer"),
                                "Channel": sys.get("Channel"),
                                "TimeCreated": sys.get("TimeCreated", {}).get("@SystemTime"),
                                "source": sys.get("Provider", {}).get("@Name", "Windows"),
                            }
                            if isinstance(data, dict) and "Data" in data:
                                event_data = data["Data"]
                                if isinstance(event_data, list):
                                    for item in event_data:
                                        if "@Name" in item and "#text" in item:
                                            flat_record[item["@Name"]] = item["#text"]
                                elif isinstance(event_data, dict) and "@Name" in event_data and "#text" in event_data:
                                     flat_record[event_data["@Name"]] = event_data["#text"]
                            records.append(flat_record)
                    except Exception:
                        pass
            return records
            
        records = await asyncio.to_thread(parse_file)
        for r in records:
            yield r
            
    async def close(self) -> None:
        pass
