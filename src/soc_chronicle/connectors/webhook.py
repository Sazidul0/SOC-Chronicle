"""HTTP webhook receiver."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator
from typing import Any

from soc_chronicle.connectors.base import ConnectorConfig, IngestConnector

try:
    from aiohttp import web  # type: ignore
except ImportError:
    web = None


class WebhookConnector(IngestConnector):
    """HTTP server accepting JSON POSTs (e.g., from Filebeat/Logstash)."""
    
    def __init__(self, config: ConnectorConfig, port: int = 8514, host: str = "0.0.0.0", secret: str | None = None) -> None:  # nosec B104
        super().__init__(config)
        if web is None:
            raise ImportError("WebhookConnector requires aiohttp. Install with 'pip install aiohttp'")
        self.port = port
        self.host = host
        self.secret = secret
        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self.runner: web.AppRunner | None = None
        self.site: web.TCPSite | None = None
        
    async def connect(self) -> None:
        assert web is not None
        app = web.Application()
        app.router.add_post("/ingest", self.handle_ingest)
        
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        
    async def handle_ingest(self, request: web.Request) -> web.Response:
        if self.secret:
            auth = request.headers.get("Authorization")
            if auth != f"Bearer {self.secret}":
                return web.Response(status=401, text="Unauthorized")
                
        try:
            data = await request.json()
            if isinstance(data, list):
                for item in data:
                    self.queue.put_nowait(item)
            elif isinstance(data, dict):
                self.queue.put_nowait(data)
            return web.Response(status=202, text="Accepted")
        except Exception as e:
            return web.Response(status=400, text=str(e))

    async def stream(self) -> AsyncGenerator[dict[str, Any], None]:
        while True:
            try:
                record = await self.queue.get()
                yield record
            except asyncio.CancelledError:
                break
                
    async def close(self) -> None:
        if self.runner:
            await self.runner.cleanup()
