#!/usr/bin/env python3
"""AI/ML Service for KubeSentinel."""

from __future__ import annotations

import glob
import json
import logging
import os
import pickle
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Iterable, List

import numpy as np
import pandas as pd
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import google.generativeai as genai

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MAX_FEATURE_KEYS = 16
MAX_FEATURE_VALUE_LEN = 1024
MAX_TRAINING_SAMPLES = 5000
MAX_REQUEST_BYTES = 1024 * 256
ALLOWED_FEATURE_KEYS = {
    "process_frequency",
    "file_access_count",
    "network_count",
    "sensitive_files",
    "time_of_day",
    "day_of_week",
    "container_age",
    "unique_syscalls",
    "process_name",
    "syscall_counts",
    "user_id",
}


def parse_allowed_origins() -> List[str]:
    raw = os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000")
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    return origins or ["http://localhost:3000"]


app = Flask(__name__)
CORS(app, origins=parse_allowed_origins())


def get_api_token() -> str:
    return os.getenv("TRAINING_API_TOKEN", "").strip()


def require_api_token(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        configured = get_api_token()
        if not configured:
            logger.error("TRAINING_API_TOKEN is not configured")
            return jsonify({"error": "Service authentication is not configured"}), 503

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header[7:].strip()
        if token != configured:
            return jsonify({"error": "Invalid token"}), 403

        return fn(*args, **kwargs)

    return wrapped


class AnomalyDetector:
    """Anomaly detection using Isolation Forest."""

    MODEL_VERSION = 3

    def __init__(self, model_path: str = "models/baseline.pkl"):
        self.model_path = model_path
        self.model: IsolationForest | None = None
        self.scaler = StandardScaler()
        self.feature_names = [
            "process_frequency",
            "file_access_count",
            "network_count",
            "sensitive_files",
            "time_of_day",
            "day_of_week",
            "container_age",
            "unique_syscalls",
        ]
        self.warmup_complete = False
        self.warmup_samples = 0
        self.warmup_threshold = 300
        self.load_or_create_model()

    def load_or_create_model(self) -> None:
        if os.path.exists(self.model_path):
            try:
                logger.info("Loading model from %s", self.model_path)
                with open(self.model_path, "rb") as f:
                    saved_data = pickle.load(f)
                self.model = saved_data["model"]
                self.scaler = saved_data["scaler"]
                metadata = saved_data.get("metadata", {})
                model_version = int(metadata.get("model_version", 1))
                if model_version < self.MODEL_VERSION or self._model_is_degenerate():
                    logger.warning("Loaded model is outdated or degenerate, rebuilding baseline")
                    self._initialize_model()
                    self.save_model()
                return
            except Exception as exc:
                logger.warning("Failed to load existing model, rebuilding: %s", exc)

        self._initialize_model()
        self.save_model()

    def _initialize_model(self) -> None:
        self.model = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=100,
            max_samples="auto",
            max_features=1.0,
        )

        baseline_data = self._load_real_baseline()
        self.scaler.fit(baseline_data)
        self.model.fit(self.scaler.transform(baseline_data))

    def _load_real_baseline(self) -> np.ndarray:
        baseline_csv = Path(self.model_path).parent / "normal_baseline.csv"
        try:
            df = pd.read_csv(baseline_csv)
            data = df[self.feature_names].values
            if len(data) >= 10:
                logger.info("Loaded %d baseline samples from %s", len(data), baseline_csv)
                return data
        except Exception as exc:
            logger.warning("Could not load baseline CSV: %s", exc)
        return self._create_bootstrap_data(500)

    def _create_bootstrap_data(self, size: int) -> np.ndarray:
        process_frequency = np.random.poisson(lam=8, size=size)
        file_access_count = np.clip(np.random.normal(loc=35, scale=15, size=size), 0, None)
        network_count = np.random.poisson(lam=6, size=size)
        sensitive_files = np.random.binomial(n=2, p=0.05, size=size)
        time_of_day = np.random.randint(0, 24, size=size)
        day_of_week = np.random.randint(0, 7, size=size)
        container_age = np.clip(np.random.exponential(scale=48, size=size), 0, 720)
        unique_syscalls = np.random.poisson(lam=50, size=size)

        return np.column_stack(
            [
                process_frequency,
                file_access_count,
                network_count,
                sensitive_files,
                time_of_day,
                day_of_week,
                container_age,
                unique_syscalls,
            ]
        )

    def _model_is_degenerate(self) -> bool:
        if self.model is None:
            return True

        baseline_probe = self._create_bootstrap_data(200)
        baseline_probe_scaled = self.scaler.transform(baseline_probe)
        predictions = self.model.predict(baseline_probe_scaled)
        anomaly_ratio = float(np.mean(predictions == -1))
        logger.info("Model baseline anomaly ratio check: %.3f", anomaly_ratio)
        return anomaly_ratio > 0.70

    def save_model(self) -> None:
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, "wb") as f:
            pickle.dump(
                {
                    "model": self.model,
                    "scaler": self.scaler,
                    "metadata": {
                        "model_version": self.MODEL_VERSION,
                        "updated_at": datetime.now().isoformat(),
                    },
                },
                f,
            )
        logger.info("Model saved to %s", self.model_path)

    def extract_features(self, feature_dict: Dict[str, Any]) -> np.ndarray:
        def safe_float(key: str, default: float = 0.0) -> float:
            val = feature_dict.get(key, default)
            try:
                return float(val)
            except (TypeError, ValueError):
                return float(default)

        features = [
            safe_float("process_frequency", 0),
            safe_float("file_access_count", 0),
            safe_float("network_count", 0),
            safe_float("sensitive_files", 0),
            safe_float("time_of_day", 12),
            safe_float("day_of_week", 0),
            safe_float("container_age", 0),
            safe_float("unique_syscalls", 0),
        ]
        return np.array(features, dtype=float).reshape(1, -1)

    def predict(self, features: Dict[str, Any]) -> Dict[str, Any]:
        X = self.extract_features(features)

        if not self.warmup_complete:
            self.warmup_samples += 1
            if self.warmup_samples >= self.warmup_threshold:
                self.warmup_complete = True
                self.save_model()
            return {
                "is_anomaly": False,
                "score": 0.0,
                "confidence": 1.0,
                "reason": f"Warm-up phase ({self.warmup_samples}/{self.warmup_threshold})",
                "suggestions": ["Baseline collection in progress"],
            }

        X_scaled = self.scaler.transform(X)
        prediction = self.model.predict(X_scaled)[0]
        score = self.model.score_samples(X_scaled)[0]
        normalized_score = 1 / (1 + np.exp(score))
        is_anomaly = prediction == -1

        return {
            "is_anomaly": bool(is_anomaly),
            "score": float(normalized_score),
            "confidence": float(abs(score)),
            "reason": self._generate_reason(features, is_anomaly, normalized_score),
            "suggestions": self._generate_suggestions(features, is_anomaly),
        }

    def _generate_reason(self, features: Dict[str, Any], is_anomaly: bool, score: float) -> str:
        if not is_anomaly:
            return "Behavior matches normal baseline patterns"

        reasons = []
        if float(features.get("sensitive_files", 0) or 0) > 0:
            reasons.append(f"Access to {features.get('sensitive_files')} sensitive file(s)")
        if float(features.get("network_count", 0) or 0) > 20:
            reasons.append(f"Unusually high network activity ({features.get('network_count')} connections)")
        if float(features.get("file_access_count", 0) or 0) > 100:
            reasons.append(f"Excessive file access ({features.get('file_access_count')} operations)")
        process_name = str(features.get("process_name", ""))
        if process_name in {"nc", "netcat", "ncat", "wget", "curl", "bash", "sh"}:
            reasons.append(f"Suspicious process detected: {process_name}")

        if not reasons:
            reasons.append(f"Behavioral anomaly detected (score: {score:.2f})")
        return "; ".join(reasons)

    def _generate_suggestions(self, features: Dict[str, Any], is_anomaly: bool) -> List[str]:
        if not is_anomaly:
            return []

        suggestions = []
        if float(features.get("sensitive_files", 0) or 0) > 0:
            suggestions.append("Review file access patterns and restrict unnecessary permissions")
        if float(features.get("network_count", 0) or 0) > 20:
            suggestions.append("Investigate network connections and apply network policies")
        process_name = str(features.get("process_name", ""))
        if process_name in {"bash", "sh", "nc", "netcat"}:
            suggestions.append(f"Investigate why {process_name} is running in container")

        suggestions.append("Review container security context and capabilities")
        suggestions.append("Check for unauthorized access or container escape attempts")
        return suggestions

    def train(self, training_data: Iterable[Dict[str, Any]]) -> bool:
        vectors = np.array([self.extract_features(sample)[0] for sample in training_data], dtype=float)
        self.scaler.fit(vectors)
        self.model.fit(self.scaler.transform(vectors))
        self.save_model()
        logger.info("Model retrained with %d samples", len(vectors))
        return True


detector = AnomalyDetector()
ENRICH_WITH_GEMINI = os.getenv("ENRICH_WITH_GEMINI", "false").lower() in {"true", "1", "yes"}
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if ENRICH_WITH_GEMINI and GEMINI_API_KEY:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_model = genai.GenerativeModel("gemini-2.5-flash")
        logger.info("Gemini LLM initialized")
    except Exception as exc:
        logger.warning("Failed to initialize Gemini: %s", exc)
        gemini_model = None
else:
    gemini_model = None


def _validate_json_payload(required_key: str) -> tuple[Dict[str, Any] | None, Any | None, Any | None]:
    if request.content_length and request.content_length > MAX_REQUEST_BYTES:
        return None, jsonify({"error": "Request payload too large"}), 413

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or required_key not in data:
        return None, jsonify({"error": f"Missing {required_key} in request"}), 400

    value = data[required_key]
    return data, value, None


def _validate_feature_dict(features: Any) -> str | None:
    if not isinstance(features, dict):
        return "features must be an object"
    if len(features) > MAX_FEATURE_KEYS:
        return "too many feature keys"
    for key in features:
        if key not in ALLOWED_FEATURE_KEYS:
            return f"unexpected feature key: {key}"
        value = features[key]
        if isinstance(value, str) and len(value) > MAX_FEATURE_VALUE_LEN:
            return f"feature value too long: {key}"
    return None


@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "healthy", "model_loaded": detector.model is not None})


@app.route("/warmup/status", methods=["GET"])
def warmup_status():
    return jsonify(
        {
            "warmup_complete": detector.warmup_complete,
            "samples_collected": detector.warmup_samples,
            "threshold": detector.warmup_threshold,
        }
    )


@app.route("/predict", methods=["POST"])
@require_api_token
def predict():
    _, features, error = _validate_json_payload("features")
    if error:
        return error

    validation_error = _validate_feature_dict(features)
    if validation_error:
        return jsonify({"error": validation_error}), 400

    result = detector.predict(features)
    return jsonify(result)


@app.route("/train", methods=["POST"])
@require_api_token
def train():
    _, training_data, error = _validate_json_payload("training_data")
    if error:
        return error

    if not isinstance(training_data, list) or not training_data:
        return jsonify({"error": "training_data must be a non-empty list"}), 400
    if len(training_data) > MAX_TRAINING_SAMPLES:
        return jsonify({"error": "too many training samples"}), 400

    for idx, sample in enumerate(training_data):
        validation_error = _validate_feature_dict(sample)
        if validation_error:
            return jsonify({"error": f"training_data[{idx}]: {validation_error}"}), 400

    detector.train(training_data)
    return jsonify(
        {
            "status": "success",
            "samples": len(training_data),
            "timestamp": datetime.now().isoformat(),
        }
    )


@app.route("/model/info", methods=["GET"])
def model_info():
    return jsonify(
        {
            "type": "IsolationForest",
            "features": detector.feature_names,
            "n_estimators": detector.model.n_estimators if detector.model else None,
            "contamination": detector.model.contamination if detector.model else None,
            "model_path": detector.model_path,
        }
    )


@app.route("/api/incidents", methods=["GET"])
@require_api_token
def get_ai_incidents():
    try:
        forensics_dir = Path(__file__).parent.parent / "forensics"
        if not forensics_dir.exists():
            return jsonify(
                {
                    "incidents": [],
                    "error": "forensics folder not found",
                    "last_analysis": datetime.now().isoformat(),
                }
            )

        incidents = []
        for json_file in sorted(glob.glob(str(forensics_dir / "*.json")), reverse=True)[:100]:
            with open(json_file, "r", encoding="utf-8") as file_handle:
                data = json.load(file_handle)

            metadata = data.get("metadata", {})
            events = data.get("events", [{}])
            incident = {
                "id": data.get("id", Path(json_file).stem),
                "timestamp": data.get("timestamp", ""),
                "incident_type": data.get("incident_type", "Unknown Event"),
                "severity": data.get("severity", "medium").lower(),
                "risk_score": round(data.get("risk_score", 0.5) * 100),
                "description": events[0].get("output", "No description available")[:220] + "..." if events else "No output",
                "container_name": data.get("container", {}).get("name", "N/A"),
                "pod_name": data.get("container", {}).get("pod_name", "N/A"),
                "ai_analysis": metadata.get("gemini_reason", "Behavioral anomaly detected."),
                "anomalies": [],
                "related_events": len(events),
                "raw_file": Path(json_file).name,
            }

            if ENRICH_WITH_GEMINI and gemini_model and len(incident["ai_analysis"]) < 100:
                try:
                    prompt = (
                        "Analyze this Kubernetes security incident and explain why it is suspicious in 2-4 sentences.\n"
                        f"Incident Type: {incident['incident_type']}\n"
                        f"Severity: {incident['severity']}\n"
                        f"Description: {incident['description']}\n"
                    )
                    response = gemini_model.generate_content(prompt)
                    enhanced = response.text.strip()
                    if len(enhanced) > 50:
                        incident["ai_analysis"] = enhanced
                except Exception as exc:
                    logger.warning("Gemini enhancement failed for %s: %s", incident["id"], exc)

            incidents.append(incident)

        return jsonify(
            {
                "incidents": incidents,
                "last_analysis": datetime.now().isoformat(),
                "total": len(incidents),
                "using_gemini_enrichment": ENRICH_WITH_GEMINI and gemini_model is not None,
            }
        )
    except Exception as exc:
        logger.error("Error in /api/incidents: %s", exc)
        return jsonify({"incidents": [], "error": str(exc), "last_analysis": datetime.now().isoformat()}), 500


if __name__ == "__main__":
    os.makedirs("models", exist_ok=True)
    logger.info("Starting AI/ML service on port 5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
