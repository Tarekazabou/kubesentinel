import os
import sqlite3
import threading

# Default runtime directory for persistent data on the host
DB_DIR = "/var/lib/kubesentinel"
os.makedirs(DB_DIR, exist_ok=True)

DB_PATH = os.environ.get(
    "STAGING_DB_PATH",
    os.path.join(DB_DIR, "staging.db")
)

_local = threading.local()


def _init_schema(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS incident_staging (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id          TEXT NOT NULL,
            timestamp            TEXT NOT NULL,
            raw_event            TEXT NOT NULL,
            if_score             REAL NOT NULL,
            container_id         TEXT,
            container_name       TEXT,
            pod_name             TEXT,
            namespace            TEXT,
            rule                 TEXT,
            status               TEXT NOT NULL DEFAULT 'pending',
            triage_reason        TEXT,
            severity             TEXT,
            mitre_tactic         TEXT,
            enriched_description TEXT,
            remediation          TEXT,
            triaged_at           TEXT,
            created_at           TEXT NOT NULL DEFAULT (datetime('now'))
        )
        """
    )
    conn.commit()


def get_db():
    if not hasattr(_local, "conn"):
        _local.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _local.conn.row_factory = sqlite3.Row
        _local.conn.execute("PRAGMA journal_mode=WAL;")
        _init_schema(_local.conn)
    return _local.conn
