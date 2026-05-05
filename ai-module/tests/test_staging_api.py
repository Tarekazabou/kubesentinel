import os
import tempfile
import json
import sqlite3
from datetime import datetime

import sys
import os
import pytest

# Ensure ai-module is on path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server import app, write_to_staging
import db as staging_db
import triage_worker


@pytest.fixture(autouse=True)
def env_tmp_dir(tmp_path, monkeypatch):
    # Setup a temp staging DB and ensure passthrough mode
    db_path = str(tmp_path / "staging_test.db")
    monkeypatch.setenv("STAGING_DB_PATH", db_path)
    monkeypatch.setenv("ENRICH_WITH_GEMINI", "false")
    # Ensure server uses the same DB
    staging_db._local = staging_db.threading.local()
    staging_db.DB_PATH = db_path
    yield


def test_staging_list_detail_and_passthrough():
    # Minimal incident payload
    incident = {
        "id": "test-incident-1",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "incident_type": "TestRule",
        "severity": "medium",
        "risk_score": 0.9,
        "description": "Test incident",
        "container": {"id": "c1", "name": "ctr1", "pod_name": "pod1", "namespace": "default"},
        "metadata": {"process_name": "bash"},
        "events": [{"rule": "TestRule", "output": "test output"}],
    }

    # Insert into staging using server helper
    write_to_staging(incident, 0.9)

    client = app.test_client()

    # List staging rows
    res = client.get("/api/staging")
    assert res.status_code == 200
    data = res.get_json()
    assert data["total"] == 1
    row = data["staging"][0]
    row_id = row["id"]

    # Fetch detail
    res2 = client.get(f"/api/staging/{row_id}")
    assert res2.status_code == 200
    detail = res2.get_json()
    assert detail["incident_id"] == "test-incident-1"

    # Run worker to process pending (passthrough mode -> confirm)
    worker = triage_worker.TriageWorker(poll_interval=1, batch_size=10)
    # Run one batch synchronously
    worker._process_batch()

    # Check staging row updated to confirmed and raw_event.metadata.triage_source == 'passthrough'
    conn = staging_db.get_db()
    updated = conn.execute("SELECT * FROM incident_staging WHERE id = ?", (row_id,)).fetchone()
    assert updated is not None
    assert updated["status"] == "confirmed"
    # Passthrough mode should set triage_reason to indicate auto-confirmation
    assert updated["triage_reason"] is not None
    assert "passthrough" in updated["triage_reason"].lower()
