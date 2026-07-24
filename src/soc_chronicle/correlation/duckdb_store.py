"""DuckDB-backed correlation store for high-performance event linking."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from soc_chronicle.correlation.queries import (
    ALL_EVENTS_SQL,
    ENTITY_CORRELATION_SQL,
    IDENTITY_CORRELATION_SQL,
    NETWORK_TO_PROCESS_SQL,
    PROCESS_LINEAGE_SQL,
)
from soc_chronicle.models.event import NormalizedEvent, OCSFClass

TableName = Literal["processes", "network", "auth", "files", "registry", "events"]

# OCSF class to DuckDB table routing.
CLASS_TABLE_MAP: dict[OCSFClass, TableName] = {
    OCSFClass.PROCESS_ACTIVITY: "processes",
    OCSFClass.SCHEDULED_JOB_ACTIVITY: "processes",
    OCSFClass.NETWORK_ACTIVITY: "network",
    OCSFClass.HTTP_ACTIVITY: "network",
    OCSFClass.DNS_ACTIVITY: "network",
    OCSFClass.AUTHENTICATION: "auth",
    OCSFClass.FILE_ACTIVITY: "files",
    OCSFClass.REGISTRY_KEY_ACTIVITY: "registry",
    OCSFClass.REGISTRY_VALUE_ACTIVITY: "registry",
    OCSFClass.DETECTION_FINDING: "events",
}


@dataclass(frozen=True, slots=True)
class ProcessLineageLink:
    """A parent-child process relationship discovered via SQL join."""

    child_event_id: str
    parent_event_id: str
    host: str | None
    child_process: str | None
    parent_process: str | None
    child_guid: str | None
    parent_guid: str | None
    child_timestamp: datetime
    parent_timestamp: datetime


@dataclass(frozen=True, slots=True)
class NetworkProcessLink:
    """A network event linked to a process on the same host."""

    network_event_id: str
    process_event_id: str
    host: str | None
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    network_timestamp: datetime
    process_timestamp: datetime
    process_name: str | None
    process_pid: int | None


@dataclass(frozen=True, slots=True)
class IdentityLink:
    """An authentication event bound to a network event by IP and time window."""

    auth_event_id: str
    network_event_id: str
    host: str | None
    user: str | None
    src_ip: str | None
    network_src_ip: str | None
    dst_ip: str | None
    auth_timestamp: datetime
    network_timestamp: datetime
    session_id: str | None


@dataclass(frozen=True, slots=True)
class EntityCorrelationLink:
    """Two events sharing a correlation key within the temporal window."""

    event_a_id: str
    event_b_id: str
    table_a: str
    table_b: str
    correlation_key: str
    correlation_value: str
    delta_seconds: float


class DuckDBCorrelationStore:
    """Embedded DuckDB store for bulk event loading and deterministic SQL correlation.

    Parameters
    ----------
    db_path:
        Path to a DuckDB database file. Use ``":memory:"`` for ephemeral storage.
    window_seconds:
        Default temporal window for join-based correlation queries.
    """

    SCHEMA_VERSION = 1

    def __init__(
        self,
        db_path: str | Path = ":memory:",
        *,
        window_seconds: int = 3600,
    ) -> None:
        self.db_path = str(db_path)
        self.window_seconds = window_seconds
        self._conn: Any | None = None

    @property
    def conn(self) -> Any:
        """Lazy DuckDB connection; raises ``ImportError`` if duckdb is not installed."""
        if self._conn is None:
            try:
                import duckdb
            except ImportError as exc:
                msg = (
                    "duckdb is required for DuckDBCorrelationStore. "
                    "Install with: pip install 'soc-chronicle[analytics]'"
                )
                raise ImportError(msg) from exc
            self._conn = duckdb.connect(self.db_path)
            self._initialize_schema()
        return self._conn

    def close(self) -> None:
        """Close the DuckDB connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> DuckDBCorrelationStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _initialize_schema(self) -> None:
        """Create typed tables and indexes for correlation."""
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_meta (
                version INTEGER NOT NULL
            )
            """
        )
        existing = self.conn.execute(
            "SELECT version FROM schema_meta LIMIT 1"
        ).fetchone()
        if existing:
            return

        self.conn.execute(
            """
            CREATE TABLE processes (
                event_id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                source_type VARCHAR NOT NULL,
                class_uid INTEGER NOT NULL,
                activity_name VARCHAR NOT NULL,
                host VARCHAR,
                user VARCHAR,
                process_name VARCHAR,
                process_pid INTEGER,
                process_guid VARCHAR,
                parent_process_name VARCHAR,
                parent_process_pid INTEGER,
                parent_process_guid VARCHAR,
                src_ip VARCHAR,
                src_port INTEGER,
                dst_ip VARCHAR,
                dst_port INTEGER,
                protocol VARCHAR,
                raw_data VARCHAR NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE network (
                event_id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                source_type VARCHAR NOT NULL,
                class_uid INTEGER NOT NULL,
                activity_name VARCHAR NOT NULL,
                host VARCHAR,
                user VARCHAR,
                process_name VARCHAR,
                process_pid INTEGER,
                src_ip VARCHAR,
                src_port INTEGER,
                dst_ip VARCHAR,
                dst_port INTEGER,
                protocol VARCHAR,
                domain VARCHAR,
                raw_data VARCHAR NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE auth (
                event_id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                source_type VARCHAR NOT NULL,
                class_uid INTEGER NOT NULL,
                activity_name VARCHAR NOT NULL,
                host VARCHAR,
                user VARCHAR,
                src_ip VARCHAR,
                session_id VARCHAR,
                auth_id VARCHAR,
                raw_data VARCHAR NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE files (
                event_id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                source_type VARCHAR NOT NULL,
                class_uid INTEGER NOT NULL,
                activity_name VARCHAR NOT NULL,
                host VARCHAR,
                user VARCHAR,
                process_name VARCHAR,
                process_pid INTEGER,
                file_path VARCHAR,
                file_hash VARCHAR,
                raw_data VARCHAR NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE registry (
                event_id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                source_type VARCHAR NOT NULL,
                class_uid INTEGER NOT NULL,
                activity_name VARCHAR NOT NULL,
                host VARCHAR,
                user VARCHAR,
                process_name VARCHAR,
                process_pid INTEGER,
                registry_key VARCHAR,
                raw_data VARCHAR NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE events (
                event_id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                source_type VARCHAR NOT NULL,
                class_uid INTEGER NOT NULL,
                activity_name VARCHAR NOT NULL,
                host VARCHAR,
                user VARCHAR,
                raw_data VARCHAR NOT NULL
            )
            """
        )
        self.conn.execute(
            """
            CREATE TABLE correlation_index (
                event_id VARCHAR NOT NULL,
                table_name VARCHAR NOT NULL,
                correlation_key VARCHAR NOT NULL,
                correlation_value VARCHAR NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                PRIMARY KEY (event_id, correlation_key)
            )
            """
        )
        self.conn.execute("INSERT INTO schema_meta (version) VALUES (?)", [self.SCHEMA_VERSION])

    def bulk_insert(self, events: list[NormalizedEvent]) -> int:
        """Bulk insert normalized events into typed DuckDB tables.

        Returns the number of events inserted.
        """
        if not events:
            return 0

        buckets: dict[TableName, list[dict[str, Any]]] = {
            "processes": [],
            "network": [],
            "auth": [],
            "files": [],
            "registry": [],
            "events": [],
        }
        index_rows: list[tuple[str, str, str, str, datetime]] = []

        for event in events:
            table = CLASS_TABLE_MAP.get(event.class_uid, "events")
            row = self._event_to_row(event, table)
            buckets[table].append(row)
            for key, value in event.correlation_keys().items():
                index_rows.append(
                    (event.event_id, table, key, str(value), event.timestamp)
                )

        for table, rows in buckets.items():
            if rows:
                self._insert_rows(table, rows)

        if index_rows:
            self.conn.executemany(
                """
                INSERT OR REPLACE INTO correlation_index
                    (event_id, table_name, correlation_key, correlation_value, timestamp)
                VALUES (?, ?, ?, ?, ?)
                """,
                index_rows,
            )

        return len(events)

    def process_lineage(
        self, window_seconds: int | None = None
    ) -> list[ProcessLineageLink]:
        """Find parent-child process relationships via deterministic SQL joins."""
        window = window_seconds if window_seconds is not None else self.window_seconds
        rows = self.conn.execute(PROCESS_LINEAGE_SQL, [window]).fetchall()
        return [
            ProcessLineageLink(
                child_event_id=row[0],
                parent_event_id=row[1],
                host=row[2],
                child_process=row[3],
                parent_process=row[4],
                child_guid=row[5],
                parent_guid=row[6],
                child_timestamp=row[7],
                parent_timestamp=row[8],
            )
            for row in rows
        ]

    def network_to_process(
        self, window_seconds: int | None = None
    ) -> list[NetworkProcessLink]:
        """Link network events to process activity on the same host."""
        window = window_seconds if window_seconds is not None else self.window_seconds
        rows = self.conn.execute(NETWORK_TO_PROCESS_SQL, [window]).fetchall()
        return [
            NetworkProcessLink(
                network_event_id=row[0],
                process_event_id=row[1],
                host=row[2],
                src_ip=row[3],
                src_port=row[4],
                dst_ip=row[5],
                dst_port=row[6],
                network_timestamp=row[7],
                process_timestamp=row[8],
                process_name=row[9],
                process_pid=row[10],
            )
            for row in rows
        ]

    def identity_correlation(
        self, window_seconds: int | None = None
    ) -> list[IdentityLink]:
        """Bind IP addresses to users using authentication log joins."""
        window = window_seconds if window_seconds is not None else self.window_seconds
        rows = self.conn.execute(IDENTITY_CORRELATION_SQL, [window]).fetchall()
        return [
            IdentityLink(
                auth_event_id=row[0],
                network_event_id=row[1],
                host=row[2],
                user=row[3],
                src_ip=row[4],
                network_src_ip=row[5],
                dst_ip=row[6],
                auth_timestamp=row[7],
                network_timestamp=row[8],
                session_id=row[9],
            )
            for row in rows
        ]

    def entity_correlation(
        self, window_seconds: int | None = None
    ) -> list[EntityCorrelationLink]:
        """Find event pairs sharing correlation keys within a temporal window."""
        window = window_seconds if window_seconds is not None else self.window_seconds
        rows = self.conn.execute(ENTITY_CORRELATION_SQL, [window]).fetchall()
        return [
            EntityCorrelationLink(
                event_a_id=row[0],
                event_b_id=row[1],
                table_a=row[2],
                table_b=row[3],
                correlation_key=row[4],
                correlation_value=row[5],
                delta_seconds=float(row[6]),
            )
            for row in rows
        ]

    def correlate_groups(
        self, window_seconds: int | None = None
    ) -> list[list[str]]:
        """Return event ID groups correlated via shared keys and time proximity.

        Uses union-find over entity correlation links for deterministic grouping.
        """
        links = self.entity_correlation(window_seconds)
        if not links:
            event_ids = self.conn.execute(
                "SELECT event_id FROM correlation_index ORDER BY timestamp"
            ).fetchall()
            return [[row[0]] for row in event_ids]

        parent: dict[str, str] = {}

        def find(node: str) -> str:
            parent.setdefault(node, node)
            if parent[node] != node:
                parent[node] = find(parent[node])
            return parent[node]

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        for link in links:
            union(link.event_a_id, link.event_b_id)

        groups: dict[str, list[str]] = {}
        for event_id in parent:
            root = find(event_id)
            groups.setdefault(root, []).append(event_id)

        # Include singleton events not present in any link.
        all_ids = {
            row[0]
            for row in self.conn.execute(
                "SELECT event_id FROM correlation_index"
            ).fetchall()
        }
        grouped_ids = {eid for group in groups.values() for eid in group}
        for orphan in sorted(all_ids - grouped_ids):
            groups[orphan] = [orphan]

        return [sorted(g) for g in groups.values()]

    def fetch_all_events(self) -> list[dict[str, Any]]:
        """Return all events across tables ordered by timestamp."""
        rows = self.conn.execute(ALL_EVENTS_SQL).fetchall()
        columns = [
            "event_id",
            "timestamp",
            "host",
            "user",
            "class_uid",
            "activity_name",
            "source_type",
            "table_name",
        ]
        return [dict(zip(columns, row, strict=True)) for row in rows]

    def event_count(self) -> int:
        """Total number of events across all tables."""
        total = 0
        for table in ("processes", "network", "auth", "files", "registry", "events"):
            count = self.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            total += int(count)
        return total

    @staticmethod
    def _event_to_row(event: NormalizedEvent, table: TableName) -> dict[str, Any]:
        """Map a NormalizedEvent to a table-specific row dictionary."""
        base = {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "source_type": event.source_type,
            "class_uid": int(event.class_uid),
            "activity_name": event.activity_name,
            "host": event.host,
            "user": event.user,
            "raw_data": event.raw_data,
        }
        if table == "processes":
            base.update(
                {
                    "process_name": event.process_name,
                    "process_pid": event.process_pid,
                    "process_guid": event.process_guid,
                    "parent_process_name": event.parent_process_name,
                    "parent_process_pid": event.parent_process_pid,
                    "parent_process_guid": event.parent_process_guid,
                    "src_ip": event.src_ip,
                    "src_port": event.src_port,
                    "dst_ip": event.dst_ip,
                    "dst_port": event.dst_port,
                    "protocol": event.protocol,
                }
            )
        elif table == "network":
            base.update(
                {
                    "process_name": event.process_name,
                    "process_pid": event.process_pid,
                    "src_ip": event.src_ip,
                    "src_port": event.src_port,
                    "dst_ip": event.dst_ip,
                    "dst_port": event.dst_port,
                    "protocol": event.protocol,
                    "domain": event.domain,
                }
            )
        elif table == "auth":
            base.update(
                {
                    "src_ip": event.src_ip,
                    "session_id": event.session_id,
                    "auth_id": event.auth_id,
                }
            )
        elif table == "files":
            base.update(
                {
                    "process_name": event.process_name,
                    "process_pid": event.process_pid,
                    "file_path": event.file_path,
                    "file_hash": event.file_hash,
                }
            )
        elif table == "registry":
            base.update(
                {
                    "process_name": event.process_name,
                    "process_pid": event.process_pid,
                    "registry_key": event.registry_key,
                }
            )
        return base

    def _insert_rows(self, table: TableName, rows: list[dict[str, Any]]) -> None:
        """Insert rows into a typed table using parameterized bulk insert."""
        if not rows:
            return
        columns = list(rows[0].keys())
        placeholders = ", ".join("?" for _ in columns)
        col_list = ", ".join(columns)
        sql = f"INSERT OR REPLACE INTO {table} ({col_list}) VALUES ({placeholders})"
        values = [tuple(row[col] for col in columns) for row in rows]
        self.conn.executemany(sql, values)
