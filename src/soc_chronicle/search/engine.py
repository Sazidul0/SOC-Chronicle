"""Search Engine for SOC-Chronicle utilizing DuckDB."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from soc_chronicle.models.event import NormalizedEvent, OCSFClass

try:
    import duckdb
except ImportError:
    duckdb = None  # type: ignore


class SearchEngine:
    """Fast full-text search and pivot queries across normalized events."""

    def __init__(self, db_path: str = ":memory:") -> None:
        if duckdb is None:
            raise ImportError("SearchEngine requires duckdb. Install with 'pip install duckdb'")
        self.db_path = db_path
        self._conn = duckdb.connect(db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS search_events (
                event_id VARCHAR PRIMARY KEY,
                class_uid INTEGER,
                activity_name VARCHAR,
                timestamp TIMESTAMP,
                host VARCHAR,
                user VARCHAR,
                process_name VARCHAR,
                process_pid INTEGER,
                parent_process_name VARCHAR,
                file_hash VARCHAR,
                src_ip VARCHAR,
                dst_ip VARCHAR,
                domain VARCHAR,
                registry_key VARCHAR,
                raw_data JSON
            )
        """)
        # Create indexes for fast pivoting
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_host ON search_events (host)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_user ON search_events (user)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_hash ON search_events (file_hash)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_src_ip ON search_events (src_ip)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_dst_ip ON search_events (dst_ip)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_domain ON search_events (domain)")

    def index_events(self, events: list[NormalizedEvent]) -> None:
        if not events:
            return
        
        rows = []
        for e in events:
            rows.append((
                e.event_id, e.class_uid.value, e.activity_name, e.timestamp,
                e.host, e.user, e.process_name, e.process_pid, e.parent_process_name,
                e.file_hash, e.src_ip, e.dst_ip, e.domain, e.registry_key,
                e.raw_data
            ))
            
        self._conn.executemany(
            """
            INSERT OR REPLACE INTO search_events 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows
        )

    def search(self, query: str, fields: list[str] | None = None) -> list[dict[str, Any]]:
        """Full-text search across normalized fields."""
        search_fields = fields or ["host", "user", "process_name", "file_hash", "src_ip", "dst_ip", "domain"]
        conds = []
        params = []
        q = f"%{query}%"
        for field in search_fields:
            conds.append(f"{field} LIKE ?")
            params.append(q)
            
        where_clause = " OR ".join(conds)
        sql = f"SELECT * FROM search_events WHERE {where_clause} ORDER BY timestamp DESC LIMIT 1000"
        
        results = self._conn.execute(sql, params).fetch_df().to_dict('records')
        return self._format_results(results)

    def pivot_by_hash(self, sha256: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM search_events WHERE file_hash = ? ORDER BY timestamp DESC"
        results = self._conn.execute(sql, [sha256]).fetch_df().to_dict('records')
        return self._format_results(results)

    def pivot_by_ip(self, ip: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM search_events WHERE src_ip = ? OR dst_ip = ? ORDER BY timestamp DESC"
        results = self._conn.execute(sql, [ip, ip]).fetch_df().to_dict('records')
        return self._format_results(results)

    def pivot_by_user(self, username: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM search_events WHERE user = ? ORDER BY timestamp DESC"
        results = self._conn.execute(sql, [username]).fetch_df().to_dict('records')
        return self._format_results(results)

    def pivot_by_host(self, hostname: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM search_events WHERE host = ? ORDER BY timestamp DESC"
        results = self._conn.execute(sql, [hostname]).fetch_df().to_dict('records')
        return self._format_results(results)

    def pivot_by_domain(self, domain: str) -> list[dict[str, Any]]:
        sql = "SELECT * FROM search_events WHERE domain = ? ORDER BY timestamp DESC"
        results = self._conn.execute(sql, [domain]).fetch_df().to_dict('records')
        return self._format_results(results)

    def pivot_by_mitre(self, technique_id: str) -> list[dict[str, Any]]:
        # This requires joining with mitre mappings or searching in raw_data if embedded
        # For now, simplistic search in raw_data
        q = f"%{technique_id}%"
        sql = "SELECT * FROM search_events WHERE raw_data LIKE ? ORDER BY timestamp DESC"
        results = self._conn.execute(sql, [q]).fetch_df().to_dict('records')
        return self._format_results(results)

    def _format_results(self, df_records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        # Clean up Pandas/DuckDB output for JSON serialization
        for r in df_records:
            if 'timestamp' in r and r['timestamp']:
                try:
                    # Handle pandas Timestamp
                    r['timestamp'] = r['timestamp'].replace(tzinfo=timezone.utc).isoformat()
                except Exception:
                    pass
            if 'raw_data' in r and isinstance(r['raw_data'], str):
                try:
                    r['raw_data'] = json.loads(r['raw_data'])
                except json.JSONDecodeError:
                    pass
        return df_records

    def close(self) -> None:
        self._conn.close()
