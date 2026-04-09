import importlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("TRAINING_API_TOKEN", "test-token")
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
    monkeypatch.setenv("ENRICH_WITH_GEMINI", "false")

    models_dir = tmp_path / "models"
    models_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(tmp_path)

    if "server" in sys.modules:
        module = importlib.reload(sys.modules["server"])
    else:
        module = importlib.import_module("server")

    module.detector.model_path = str(models_dir / "baseline.pkl")
    test_client = module.app.test_client()
    yield test_client


def _auth_headers():
    return {"Authorization": "Bearer test-token"}


def test_predict_requires_auth(client):
    resp = client.post("/predict", json={"features": {"process_frequency": 1}})
    assert resp.status_code == 401


def test_predict_rejects_unexpected_keys(client):
    resp = client.post(
        "/predict",
        json={"features": {"bad_key": 1}},
        headers=_auth_headers(),
    )
    assert resp.status_code == 400
    assert "unexpected feature key" in resp.get_json()["error"]


def test_predict_accepts_valid_payload(client):
    resp = client.post(
        "/predict",
        json={
            "features": {
                "process_frequency": 2,
                "file_access_count": 3,
                "network_count": 1,
                "sensitive_files": 0,
                "time_of_day": 10,
                "day_of_week": 2,
                "container_age": 5,
                "unique_syscalls": 4,
            }
        },
        headers=_auth_headers(),
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert "is_anomaly" in body
    assert "score" in body


def test_train_requires_auth(client):
    resp = client.post("/train", json={"training_data": [{"process_frequency": 1}]})
    assert resp.status_code == 401


def test_train_validates_sample_size(client):
    payload = {"training_data": [{"process_frequency": 1}] * 5001}
    resp = client.post("/train", json=payload, headers=_auth_headers())
    assert resp.status_code == 400


def test_train_accepts_valid_payload(client):
    sample = {
        "process_frequency": 5,
        "file_access_count": 7,
        "network_count": 1,
        "sensitive_files": 0,
        "time_of_day": 12,
        "day_of_week": 3,
        "container_age": 20,
        "unique_syscalls": 6,
    }
    resp = client.post("/train", json={"training_data": [sample, sample]}, headers=_auth_headers())
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "success"
