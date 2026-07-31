"""Correlation engine — temporal and entity-based event correlation."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from soc_chronicle.correlation.duckdb_store import DuckDBCorrelationStore
from soc_chronicle.models.event import NormalizedEvent


class CorrelationEngine:
    """Correlate events by host, user, process, network, and temporal proximity.

    Supports two backends:

    * **Python (default):** In-memory grouping for lightweight investigations.
    * **DuckDB:** High-performance SQL JOIN correlation via :class:`DuckDBCorrelationStore`.
    """

    CORRELATION_FIELDS = (
        "host",
        "user",
        "process_name",
        "parent_process_name",
        "process_pid",
        "parent_process_pid",
        "process_guid",
        "parent_process_guid",
        "file_hash",
        "registry_key",
        "session_id",
        "auth_id",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "protocol",
        "domain",
    )

    def __init__(
        self,
        window_seconds: int = 3600,
        *,
        use_duckdb: bool = False,
        db_path: str = ":memory:",
    ) -> None:
        self.window_seconds = window_seconds
        self.use_duckdb = use_duckdb
        self.db_path = db_path
        self._store: DuckDBCorrelationStore | None = None

    @property
    def store(self) -> DuckDBCorrelationStore:
        """Lazy DuckDB store for SQL-based correlation."""
        if self._store is None:
            self._store = DuckDBCorrelationStore(
                self.db_path, window_seconds=self.window_seconds
            )
        return self._store

    def correlate(self, events: list[NormalizedEvent]) -> list[list[NormalizedEvent]]:
        """Group correlated events within the configured temporal window."""
        if not events:
            return []
        if self.use_duckdb:
            return self._correlate_duckdb(events)
        return self._correlate_python(events)

    def _correlate_duckdb(
        self, events: list[NormalizedEvent]
    ) -> list[list[NormalizedEvent]]:
        """Correlate events using DuckDB entity index and SQL joins."""
        self.store.bulk_insert(events)
        id_groups = self.store.correlate_groups(self.window_seconds)
        by_id = {event.event_id: event for event in events}
        groups: list[list[NormalizedEvent]] = []
        for group_ids in id_groups:
            group = [by_id[eid] for eid in group_ids if eid in by_id]
            if group:
                groups.append(sorted(group, key=lambda e: e.timestamp))
        return groups

    def _correlate_python(
        self, events: list[NormalizedEvent]
    ) -> list[list[NormalizedEvent]]:
        """Correlate events using in-memory index grouping."""
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        groups: list[list[NormalizedEvent]] = []
        index: dict[str, list[int]] = defaultdict(list)

        for event in sorted_events:
            matched_groups: set[int] = set()
            for field in self.CORRELATION_FIELDS:
                value = getattr(event, field)
                if value is None:
                    continue
                key = f"{field}:{value}"
                for group_idx in index[key]:
                    anchor = groups[group_idx][0]
                    if abs((event.timestamp - anchor.timestamp).total_seconds()) <= self.window_seconds:
                        matched_groups.add(group_idx)

            if not matched_groups:
                groups.append([event])
                new_idx = len(groups) - 1
            else:
                primary = min(matched_groups)
                groups[primary].append(event)
                for extra in sorted(matched_groups - {primary}, reverse=True):
                    groups[primary].extend(groups.pop(extra))
                # Re-sort the merged group so anchor (groups[primary][0]) is always earliest
                groups[primary].sort(key=lambda e: e.timestamp)
                self._reindex(groups, index)
                new_idx = primary

            for field in self.CORRELATION_FIELDS:
                value = getattr(event, field)
                if value is not None:
                    index[f"{field}:{value}"].append(new_idx)

        return [sorted(g, key=lambda e: e.timestamp) for g in groups if g]

    def process_lineage(
        self, events: list[NormalizedEvent] | None = None
    ) -> dict[str, list[str]] | list[Any]:
        """Build parent -> child process relationships.

        When DuckDB is enabled, returns structured :class:`ProcessLineageLink` rows
        from SQL joins. Otherwise returns a name-based lineage dictionary.
        """
        if self.use_duckdb:
            if events:
                self.store.bulk_insert(events)
            return self.store.process_lineage(self.window_seconds)

        target = events or []
        lineage: dict[str, list[str]] = defaultdict(list)
        for event in target:
            parent = event.parent_process_name
            child = event.process_name
            if parent and child and parent.lower() != child.lower():
                lineage[parent.lower()].append(child.lower())
        return dict(lineage)

    def identity_chain(self, events: list[NormalizedEvent]) -> list[str]:
        """Return ordered unique users involved in correlated authentication."""
        users: list[str] = []
        seen: set[str] = set()
        for event in sorted(events, key=lambda e: e.timestamp):
            if event.user and event.user.lower() not in seen:
                users.append(event.user)
                seen.add(event.user.lower())
        return users

    def network_to_process(self, events: list[NormalizedEvent] | None = None) -> list[Any]:
        """Link network events to processes (DuckDB only)."""
        if not self.use_duckdb:
            return []
        if events:
            self.store.bulk_insert(events)
        return self.store.network_to_process(self.window_seconds)

    def identity_correlation(self, events: list[NormalizedEvent] | None = None) -> list[Any]:
        """Bind IPs to users via auth log joins (DuckDB only)."""
        if not self.use_duckdb:
            return []
        if events:
            self.store.bulk_insert(events)
        return self.store.identity_correlation(self.window_seconds)

    def close(self) -> None:
        """Close the DuckDB connection if open."""
        if self._store is not None:
            self._store.close()
            self._store = None

    @staticmethod
    def _reindex(
        groups: list[list[NormalizedEvent]], index: dict[str, list[int]]
    ) -> None:
        index.clear()
        for idx, group in enumerate(groups):
            for event in group:
                for field in CorrelationEngine.CORRELATION_FIELDS:
                    value = getattr(event, field)
                    if value is not None:
                        index[f"{field}:{value}"].append(idx)
