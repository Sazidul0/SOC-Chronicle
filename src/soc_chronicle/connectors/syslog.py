"""Syslog UDP/TCP receiver."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import AsyncGenerator
from typing import Any

from soc_chronicle.connectors.base import ConnectorConfig, IngestConnector

_SYSLOG_RE = re.compile(r'<(\d+)>(?:1 )?(\S+) (\S+) (\S+) (\S+) (?:-|-|.*?) - (.*)')

class SyslogConnector(IngestConnector):
    """Receives Syslog messages over UDP."""
    
    def __init__(self, config: ConnectorConfig, port: int = 514, host: str = "0.0.0.0") -> None:  # nosec B104
        super().__init__(config)
        self.port = port
        self.host = host
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.transport = None
        
    async def connect(self) -> None:
        class SyslogProtocol(asyncio.DatagramProtocol):
            def __init__(self, queue: asyncio.Queue[str]) -> None:
                self.queue = queue
                
            def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
                try:
                    msg = data.decode("utf-8")
                    self.queue.put_nowait(msg)
                except Exception as e:
                    import logging
                    logging.getLogger(__name__).debug("Syslog datagram decode error: %s", e)
                    
        loop = asyncio.get_running_loop()
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: SyslogProtocol(self.queue),
            local_addr=(self.host, self.port)
        )

    async def stream(self) -> AsyncGenerator[dict[str, Any], None]:
        while True:
            try:
                line = await self.queue.get()
                m = _SYSLOG_RE.match(line)
                if m:
                    yield {
                        "priority": m.group(1),
                        "timestamp": m.group(2),
                        "host": m.group(3),
                        "app": m.group(4),
                        "pid": m.group(5),
                        "message": m.group(6),
                        "raw_source": "syslog",
                    }
                else:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        yield {"message": line, "raw_source": "syslog"}
            except asyncio.CancelledError:
                break
                
    async def close(self) -> None:
        if self.transport:
            self.transport.close()
