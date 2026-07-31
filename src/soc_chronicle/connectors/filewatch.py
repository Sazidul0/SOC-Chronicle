"""File-watching ingest connector."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Any

from soc_chronicle.connectors.base import ConnectorConfig, IngestConnector

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    Observer = None  # type: ignore
    FileSystemEventHandler = None # type: ignore


class FileWatchConnector(IngestConnector):
    """Watches a directory for new log files and streams them."""
    
    def __init__(self, config: ConnectorConfig, directory: str) -> None:
        super().__init__(config)
        self.directory = Path(directory)
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.observer: Any | None = None
        self.positions: dict[str, int] = {}
        
    async def connect(self) -> None:
        if not self.directory.exists() or not self.directory.is_dir():
            raise FileNotFoundError(f"Directory not found: {self.directory}")
            
        if Observer:
            class Handler(FileSystemEventHandler):
                def __init__(self, queue: asyncio.Queue[str], loop: asyncio.AbstractEventLoop) -> None:
                    self.queue = queue
                    self.loop = loop
                    self.positions: dict[str, int] = {}
                    
                def on_modified(self, event: Any) -> None:
                    if not event.is_directory:
                        if str(event.src_path).endswith((".log", ".json", ".txt")):
                            self.loop.call_soon_threadsafe(self.process_file, str(event.src_path))
                    
                def process_file(self, path: str) -> None:
                    try:
                        pos = self.positions.get(path, 0)
                        with open(path, encoding="utf-8", errors="replace") as f:
                            f.seek(pos)
                            for line in f:
                                line = line.strip()
                                if line:
                                    self.queue.put_nowait(line)
                            self.positions[path] = f.tell()
                    except Exception as e:
                        import logging
                        logging.getLogger(__name__).debug("Failed to read watched file: %s", e)
                        
            self.observer = Observer()
            handler = Handler(self.queue, asyncio.get_running_loop())
            self.observer.schedule(handler, str(self.directory), recursive=True)
            self.observer.start()
        else:
            # Fallback polling (omitted for brevity, assume watchdog is required)
            raise ImportError("FileWatchConnector requires watchdog. Install with 'pip install watchdog'")

    async def stream(self) -> AsyncGenerator[dict[str, Any], None]:
        while True:
            try:
                line = await self.queue.get()
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    yield {"message": line, "raw_source": "filewatch"}
            except asyncio.CancelledError:
                break
                
    async def close(self) -> None:
        if self.observer:
            self.observer.stop()
            self.observer.join()
