"""DuckDB-backed case store."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from soc_chronicle.cases.models import TLP, Case, CaseArtifact, CaseNote, CasePriority, CaseStatus

try:
    import duckdb
except ImportError:
    duckdb = None  # type: ignore


class CaseStore:
    """DuckDB-backed storage for cases, notes, and artifacts."""

    def __init__(self, db_path: str = ":memory:") -> None:
        if duckdb is None:
            raise ImportError("CaseStore requires duckdb. Install with 'pip install duckdb'")
        self.db_path = db_path
        self._conn = duckdb.connect(db_path)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS cases (
                id VARCHAR PRIMARY KEY,
                title VARCHAR,
                status VARCHAR,
                priority VARCHAR,
                alert_id VARCHAR,
                report_id VARCHAR,
                created_at TIMESTAMP,
                updated_at TIMESTAMP,
                assigned_to VARCHAR,
                severity VARCHAR,
                tlp VARCHAR,
                iocs JSON,
                affected_assets JSON,
                resolution_notes VARCHAR,
                closed_at TIMESTAMP
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS case_notes (
                id VARCHAR PRIMARY KEY,
                case_id VARCHAR,
                timestamp TIMESTAMP,
                author VARCHAR,
                content VARCHAR,
                evidence_refs JSON
            )
        """)
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS case_artifacts (
                id VARCHAR PRIMARY KEY,
                case_id VARCHAR,
                name VARCHAR,
                artifact_type VARCHAR,
                path VARCHAR,
                hash_value VARCHAR,
                timestamp TIMESTAMP
            )
        """)

    def _parse_json(self, value: Any) -> Any:
        if value is None:
            return []
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return []
        return value

    def create_case(self, case: Case) -> None:
        self._conn.execute(
            """
            INSERT INTO cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                case.id, case.title, case.status.value, case.priority.value,
                case.alert_id, case.report_id,
                case.created_at, case.updated_at,
                case.assigned_to, case.severity, case.tlp.value,
                json.dumps(case.iocs), json.dumps(case.affected_assets),
                case.resolution_notes, case.closed_at
            ]
        )
        for note in case.notes:
            self.add_note(note)
        for artifact in case.artifacts:
            self.add_artifact(artifact)

    def get_case(self, case_id: str) -> Case | None:
        result = self._conn.execute("SELECT * FROM cases WHERE id = ?", [case_id]).fetchone()
        if not result:
            return None
        
        c = Case(
            id=result[0], title=result[1], status=CaseStatus(result[2]), priority=CasePriority(result[3]),
            alert_id=result[4], report_id=result[5], created_at=result[6].replace(tzinfo=UTC),
            updated_at=result[7].replace(tzinfo=UTC), assigned_to=result[8], severity=result[9],
            tlp=TLP(result[10]), iocs=self._parse_json(result[11]), affected_assets=self._parse_json(result[12]),
            resolution_notes=result[13], closed_at=result[14].replace(tzinfo=UTC) if result[14] else None
        )
        c.notes = self.get_notes(case_id)
        c.artifacts = self.get_artifacts(case_id)
        return c

    def update_case(self, case: Case) -> None:
        case.updated_at = datetime.now(UTC)
        self._conn.execute(
            """
            UPDATE cases SET
                title = ?, status = ?, priority = ?, alert_id = ?, report_id = ?,
                updated_at = ?, assigned_to = ?, severity = ?, tlp = ?,
                iocs = ?, affected_assets = ?, resolution_notes = ?, closed_at = ?
            WHERE id = ?
            """,
            [
                case.title, case.status.value, case.priority.value, case.alert_id, case.report_id,
                case.updated_at, case.assigned_to, case.severity, case.tlp.value,
                json.dumps(case.iocs), json.dumps(case.affected_assets),
                case.resolution_notes, case.closed_at, case.id
            ]
        )

    def list_cases(self, status: CaseStatus | None = None, priority: CasePriority | None = None) -> list[Case]:
        query = "SELECT id FROM cases"
        params = []
        conds = []
        if status:
            conds.append("status = ?")
            params.append(status.value)
        if priority:
            conds.append("priority = ?")
            params.append(priority.value)
        if conds:
            query += " WHERE " + " AND ".join(conds)
        
        results = self._conn.execute(query, params).fetchall()
        cases = []
        for row in results:
            c = self.get_case(row[0])
            if c:
                cases.append(c)
        return cases

    def search_cases(self, query: str) -> list[Case]:
        q = f"%{query}%"
        results = self._conn.execute(
            """
            SELECT id FROM cases 
            WHERE title LIKE ? OR id LIKE ? OR alert_id LIKE ? OR report_id LIKE ?
            """,
            [q, q, q, q]
        ).fetchall()
        cases = []
        for row in results:
            c = self.get_case(row[0])
            if c:
                cases.append(c)
        return cases

    def add_note(self, note: CaseNote) -> None:
        self._conn.execute(
            "INSERT INTO case_notes VALUES (?, ?, ?, ?, ?, ?)",
            [note.id, note.case_id, note.timestamp, note.author, note.content, json.dumps(note.evidence_refs)]
        )

    def get_notes(self, case_id: str) -> list[CaseNote]:
        results = self._conn.execute("SELECT * FROM case_notes WHERE case_id = ? ORDER BY timestamp ASC", [case_id]).fetchall()
        return [
            CaseNote(
                id=r[0], case_id=r[1], timestamp=r[2].replace(tzinfo=UTC),
                author=r[3], content=r[4], evidence_refs=self._parse_json(r[5])
            )
            for r in results
        ]

    def add_artifact(self, artifact: CaseArtifact) -> None:
        self._conn.execute(
            "INSERT INTO case_artifacts VALUES (?, ?, ?, ?, ?, ?, ?)",
            [artifact.id, artifact.case_id, artifact.name, artifact.artifact_type, artifact.path, artifact.hash_value, artifact.timestamp]
        )

    def get_artifacts(self, case_id: str) -> list[CaseArtifact]:
        results = self._conn.execute("SELECT * FROM case_artifacts WHERE case_id = ? ORDER BY timestamp ASC", [case_id]).fetchall()
        return [
            CaseArtifact(
                id=r[0], case_id=r[1], name=r[2], artifact_type=r[3], path=r[4], hash_value=r[5], timestamp=r[6].replace(tzinfo=UTC)
            )
            for r in results
        ]

    def close(self) -> None:
        self._conn.close()
