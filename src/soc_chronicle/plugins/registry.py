"""Plugin system for extensibility."""

from __future__ import annotations

import importlib
import importlib.metadata
from abc import ABC, abstractmethod
from typing import Any

from soc_chronicle.models.event import NormalizedEvent


class LogParserPlugin(ABC):
    """Plugin interface for custom log parsers."""

    name: str = "custom_parser"

    @abstractmethod
    def parse(self, record: dict[str, Any]) -> NormalizedEvent:
        """Parse a raw log record into a normalized event."""


class EnrichmentProviderPlugin(ABC):
    """Plugin interface for custom enrichment providers."""

    name: str = "custom_enrichment"

    @abstractmethod
    async def enrich(self, indicator: str, indicator_type: str) -> dict[str, Any]:
        """Enrich an indicator."""


class ExporterPlugin(ABC):
    """Plugin interface for custom report exporters."""

    name: str = "custom_exporter"
    format_name: str = "custom"

    @abstractmethod
    def export(self, report_data: dict[str, Any], output_path: str) -> None:
        """Export report data."""


class PluginRegistry:
    """Discover and register soc-chronicle plugins via entry points."""

    ENTRY_POINT_GROUP = "soc_chronicle.plugins"

    def __init__(self) -> None:
        self.log_parsers: dict[str, LogParserPlugin] = {}
        self.enrichment_providers: dict[str, EnrichmentProviderPlugin] = {}
        self.exporters: dict[str, ExporterPlugin] = {}

    def discover(self) -> None:
        try:
            eps = importlib.metadata.entry_points(group=self.ENTRY_POINT_GROUP)
        except TypeError:
            eps = importlib.metadata.entry_points().get(self.ENTRY_POINT_GROUP, [])  # type: ignore[union-attr]
        for ep in eps:
            plugin = ep.load()
            instance = plugin() if isinstance(plugin, type) else plugin
            if isinstance(instance, LogParserPlugin):
                self.log_parsers[instance.name] = instance
            elif isinstance(instance, EnrichmentProviderPlugin):
                self.enrichment_providers[instance.name] = instance
            elif isinstance(instance, ExporterPlugin):
                self.exporters[instance.format_name] = instance

    def register_parser(self, plugin: LogParserPlugin) -> None:
        self.log_parsers[plugin.name] = plugin

    def register_enrichment(self, plugin: EnrichmentProviderPlugin) -> None:
        self.enrichment_providers[plugin.name] = plugin

    def register_exporter(self, plugin: ExporterPlugin) -> None:
        self.exporters[plugin.format_name] = plugin
