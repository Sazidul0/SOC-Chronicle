"""Deterministic SQL queries for event correlation in DuckDB."""

from __future__ import annotations

# Process lineage: child process linked to parent via GUID or PID on same host.
PROCESS_LINEAGE_SQL = """
SELECT
    child.event_id AS child_event_id,
    parent.event_id AS parent_event_id,
    child.host,
    child.process_name AS child_process,
    parent.process_name AS parent_process,
    child.process_guid AS child_guid,
    parent.process_guid AS parent_guid,
    child.timestamp AS child_timestamp,
    parent.timestamp AS parent_timestamp
FROM processes child
INNER JOIN processes parent
    ON child.host = parent.host
    AND (
        (child.parent_process_guid IS NOT NULL AND child.parent_process_guid = parent.process_guid)
        OR (
            child.parent_process_pid IS NOT NULL
            AND child.parent_process_pid = parent.process_pid
            AND child.parent_process_guid IS NULL
        )
    )
    AND child.event_id != parent.event_id
    AND ABS(EPOCH(child.timestamp) - EPOCH(parent.timestamp)) <= ?
ORDER BY child.timestamp, parent.timestamp
"""

# Network-to-process: join network events to Sysmon-style process network activity.
NETWORK_TO_PROCESS_SQL = """
SELECT
    net.event_id AS network_event_id,
    proc.event_id AS process_event_id,
    net.host,
    net.src_ip,
    net.src_port,
    net.dst_ip,
    net.dst_port,
    net.timestamp AS network_timestamp,
    proc.timestamp AS process_timestamp,
    proc.process_name,
    proc.process_pid
FROM network net
INNER JOIN processes proc
    ON net.host = proc.host
    AND (
        (net.process_pid IS NOT NULL AND net.process_pid = proc.process_pid)
        OR (net.process_name IS NOT NULL AND net.process_name = proc.process_name)
    )
    AND COALESCE(net.src_ip, '') = COALESCE(proc.src_ip, net.src_ip, '')
    AND COALESCE(net.dst_ip, '') = COALESCE(proc.dst_ip, net.dst_ip, '')
    AND COALESCE(net.dst_port, -1) = COALESCE(proc.dst_port, net.dst_port, -1)
    AND ABS(EPOCH(net.timestamp) - EPOCH(proc.timestamp)) <= ?
ORDER BY net.timestamp, proc.timestamp
"""

# Identity correlation: bind IP addresses to users via authentication events.
IDENTITY_CORRELATION_SQL = """
SELECT
    auth.event_id AS auth_event_id,
    net.event_id AS network_event_id,
    auth.host,
    auth.user,
    auth.src_ip,
    net.src_ip AS network_src_ip,
    net.dst_ip,
    auth.timestamp AS auth_timestamp,
    net.timestamp AS network_timestamp,
    auth.session_id
FROM auth auth
INNER JOIN network net
    ON auth.host = net.host
    AND auth.src_ip IS NOT NULL
    AND (
        auth.src_ip = net.src_ip
        OR auth.src_ip = net.dst_ip
    )
    AND ABS(EPOCH(auth.timestamp) - EPOCH(net.timestamp)) <= ?
ORDER BY auth.timestamp, net.timestamp
"""

# Temporal entity correlation: group events sharing correlation keys within a window.
ENTITY_CORRELATION_SQL = """
SELECT
    a.event_id AS event_a_id,
    b.event_id AS event_b_id,
    a.table_name AS table_a,
    b.table_name AS table_b,
    a.correlation_key,
    a.correlation_value,
    ABS(EPOCH(a.timestamp) - EPOCH(b.timestamp)) AS delta_seconds
FROM correlation_index a
INNER JOIN correlation_index b
    ON a.correlation_key = b.correlation_key
    AND a.correlation_value = b.correlation_value
    AND a.event_id < b.event_id
    AND ABS(EPOCH(a.timestamp) - EPOCH(b.timestamp)) <= ?
ORDER BY a.correlation_key, a.correlation_value, a.timestamp
"""

# All events unified view for blast-radius and timeline queries.
ALL_EVENTS_SQL = """
SELECT event_id, timestamp, host, user, class_uid, activity_name, source_type, table_name
FROM (
    SELECT event_id, timestamp, host, user, class_uid, activity_name, source_type, 'processes' AS table_name
    FROM processes
    UNION ALL
    SELECT event_id, timestamp, host, user, class_uid, activity_name, source_type, 'network'
    FROM network
    UNION ALL
    SELECT event_id, timestamp, host, user, class_uid, activity_name, source_type, 'auth'
    FROM auth
    UNION ALL
    SELECT event_id, timestamp, host, user, class_uid, activity_name, source_type, 'files'
    FROM files
    UNION ALL
    SELECT event_id, timestamp, host, user, class_uid, activity_name, source_type, 'registry'
    FROM registry
    UNION ALL
    SELECT event_id, timestamp, host, user, class_uid, activity_name, source_type, 'events'
    FROM events
) unified
ORDER BY timestamp
"""
