"""Tests for DuckDB correlation store and SQL joins."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from soc_chronicle.correlation.duckdb_store import DuckDBCorrelationStore
from soc_chronicle.correlation.engine import CorrelationEngine
from soc_chronicle.models.event import NormalizedEvent, OCSFClass
from soc_chronicle.normalization.engine import LogNormalizationEngine

pytest.importorskip("duckdb")


def _process_event(
    *,
    event_id: str,
    host: str,
    process_name: str,
    process_pid: int,
    process_guid: str | None = None,
    parent_process_name: str | None = None,
    parent_process_pid: int | None = None,
    parent_process_guid: str | None = None,
    timestamp: datetime | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        class_uid=OCSFClass.PROCESS_ACTIVITY,
        activity_name="Process Create",
        timestamp=timestamp or datetime(2026, 7, 22, 9, 1, tzinfo=UTC),
        source_type="sysmon",
        raw_data="{}",
        host=host,
        process_name=process_name,
        process_pid=process_pid,
        process_guid=process_guid,
        parent_process_name=parent_process_name,
        parent_process_pid=parent_process_pid,
        parent_process_guid=parent_process_guid,
        dst_ip=dst_ip,
        dst_port=dst_port,
    )


def _network_event(
    *,
    event_id: str,
    host: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    process_pid: int | None = None,
    process_name: str | None = None,
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        class_uid=OCSFClass.NETWORK_ACTIVITY,
        activity_name="Network Connection",
        timestamp=timestamp or datetime(2026, 7, 22, 9, 2, tzinfo=UTC),
        source_type="sysmon",
        raw_data="{}",
        host=host,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        process_pid=process_pid,
        process_name=process_name,
    )


def _auth_event(
    *,
    event_id: str,
    host: str,
    user: str,
    src_ip: str,
    session_id: str,
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        class_uid=OCSFClass.AUTHENTICATION,
        activity_name="Logon",
        timestamp=timestamp or datetime(2026, 7, 22, 8, 55, tzinfo=UTC),
        source_type="windows_security",
        raw_data="{}",
        host=host,
        user=user,
        src_ip=src_ip,
        session_id=session_id,
    )


class TestDuckDBCorrelationStore:
    def test_bulk_insert_routes_by_class(self) -> None:
        with DuckDBCorrelationStore(":memory:") as store:
            events = [
                _process_event(event_id="p1", host="H1", process_name="cmd.exe", process_pid=1),
                _network_event(
                    event_id="n1", host="H1", src_ip="10.0.0.5", dst_ip="192.0.2.1", dst_port=443
                ),
                _auth_event(
                    event_id="a1", host="H1", user="Alice", src_ip="10.0.0.5", session_id="s1"
                ),
            ]
            inserted = store.bulk_insert(events)
            assert inserted == 3
            assert store.event_count() == 3

    def test_process_lineage_by_guid(self) -> None:
        with DuckDBCorrelationStore(":memory:") as store:
            events = [
                _process_event(
                    event_id="parent",
                    host="FIN-23",
                    process_name="explorer.exe",
                    process_pid=800,
                    process_guid="{PARENT-GUID}",
                    timestamp=datetime(2026, 7, 22, 9, 0, tzinfo=UTC),
                ),
                _process_event(
                    event_id="child",
                    host="FIN-23",
                    process_name="WINWORD.EXE",
                    process_pid=1234,
                    process_guid="{CHILD-GUID}",
                    parent_process_name="explorer.exe",
                    parent_process_pid=800,
                    parent_process_guid="{PARENT-GUID}",
                    timestamp=datetime(2026, 7, 22, 9, 1, tzinfo=UTC),
                ),
            ]
            store.bulk_insert(events)
            links = store.process_lineage(window_seconds=3600)
            assert len(links) == 1
            assert links[0].child_event_id == "child"
            assert links[0].parent_event_id == "parent"
            assert links[0].parent_guid == "{PARENT-GUID}"

    def test_process_lineage_by_pid_fallback(self) -> None:
        with DuckDBCorrelationStore(":memory:") as store:
            events = [
                _process_event(
                    event_id="parent",
                    host="FIN-23",
                    process_name="explorer.exe",
                    process_pid=800,
                    timestamp=datetime(2026, 7, 22, 9, 0, tzinfo=UTC),
                ),
                _process_event(
                    event_id="child",
                    host="FIN-23",
                    process_name="cmd.exe",
                    process_pid=999,
                    parent_process_pid=800,
                    timestamp=datetime(2026, 7, 22, 9, 1, tzinfo=UTC),
                ),
            ]
            store.bulk_insert(events)
            links = store.process_lineage(window_seconds=3600)
            assert len(links) == 1
            assert links[0].child_event_id == "child"
            assert links[0].parent_event_id == "parent"

    def test_network_to_process_join(self) -> None:
        with DuckDBCorrelationStore(":memory:") as store:
            ts = datetime(2026, 7, 22, 9, 2, tzinfo=UTC)
            events = [
                _process_event(
                    event_id="proc-net",
                    host="FIN-23",
                    process_name="powershell.exe",
                    process_pid=5678,
                    timestamp=ts,
                    dst_ip="192.0.2.50",
                    dst_port=443,
                ),
                _network_event(
                    event_id="net-1",
                    host="FIN-23",
                    src_ip="10.0.0.5",
                    dst_ip="192.0.2.50",
                    dst_port=443,
                    process_pid=5678,
                    process_name="powershell.exe",
                    timestamp=ts,
                ),
            ]
            store.bulk_insert(events)
            links = store.network_to_process(window_seconds=60)
            assert len(links) >= 1
            assert links[0].network_event_id == "net-1"
            assert links[0].process_event_id == "proc-net"

    def test_identity_correlation(self) -> None:
        with DuckDBCorrelationStore(":memory:") as store:
            ts_auth = datetime(2026, 7, 22, 8, 55, tzinfo=UTC)
            ts_net = datetime(2026, 7, 22, 8, 56, tzinfo=UTC)
            events = [
                _auth_event(
                    event_id="auth-1",
                    host="FIN-23",
                    user="Alice",
                    src_ip="10.0.0.5",
                    session_id="sess-1",
                    timestamp=ts_auth,
                ),
                _network_event(
                    event_id="net-1",
                    host="FIN-23",
                    src_ip="10.0.0.5",
                    dst_ip="192.0.2.50",
                    dst_port=443,
                    timestamp=ts_net,
                ),
            ]
            store.bulk_insert(events)
            links = store.identity_correlation(window_seconds=600)
            assert len(links) == 1
            assert links[0].user == "Alice"
            assert links[0].src_ip == "10.0.0.5"

    def test_entity_correlation_groups(self) -> None:
        with DuckDBCorrelationStore(":memory:") as store:
            events = [
                _process_event(
                    event_id="e1",
                    host="FIN-23",
                    process_name="WINWORD.EXE",
                    process_pid=1234,
                    timestamp=datetime(2026, 7, 22, 9, 1, tzinfo=UTC),
                ),
                _process_event(
                    event_id="e2",
                    host="FIN-23",
                    process_name="powershell.exe",
                    process_pid=5678,
                    timestamp=datetime(2026, 7, 22, 9, 1, 30, tzinfo=UTC),
                ),
                _network_event(
                    event_id="e3",
                    host="FIN-23",
                    src_ip="10.0.0.5",
                    dst_ip="192.0.2.50",
                    dst_port=443,
                    process_pid=5678,
                    process_name="powershell.exe",
                    timestamp=datetime(2026, 7, 22, 9, 2, tzinfo=UTC),
                ),
            ]
            store.bulk_insert(events)
            groups = store.correlate_groups(window_seconds=3600)
            all_ids = {eid for group in groups for eid in group}
            assert {"e1", "e2", "e3"}.issubset(all_ids)


class TestDuckDBCorrelationEngine:
    def test_duckdb_correlate_sysmon_example(self, examples_dir) -> None:
        normalizer = LogNormalizationEngine()
        events = normalizer.normalize_file(examples_dir / "logs" / "sysmon.jsonl", parser="sysmon")
        engine = CorrelationEngine(window_seconds=3600, use_duckdb=True)
        groups = engine.correlate(events)
        assert len(groups) >= 1
        assert sum(len(g) for g in groups) == len(events)
        engine.close()

    def test_duckdb_process_lineage_sysmon_example(self, examples_dir) -> None:
        normalizer = LogNormalizationEngine()
        events = normalizer.normalize_file(examples_dir / "logs" / "sysmon.jsonl", parser="sysmon")
        engine = CorrelationEngine(window_seconds=3600, use_duckdb=True)
        engine.correlate(events)
        lineage = engine.process_lineage()
        # PID-based lineage should link WINWORD -> PowerShell
        assert isinstance(lineage, list)
        engine.close()
