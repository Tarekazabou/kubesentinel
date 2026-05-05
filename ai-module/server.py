#!/usr/bin/env python3
# This is a test from codex
"""
AI/ML Service for KubeSentinel
Provides behavioral anomaly detection using scikit-learn
"""

from flask import Flask, request, jsonify, send_from_directory
from sklearn.ensemble import IsolationForest
from flask_cors import CORS
from sklearn.preprocessing import StandardScaler
import numpy as np
import pickle
import pandas as pd
import json
import logging
from datetime import datetime
import os
import time
import google.generativeai as genai
from pathlib import Path
import glob
from collections import deque
from threading import Lock
from dotenv import load_dotenv
from functools import wraps
from db import get_db

# Load environment variables from .env file
load_dotenv()

# Configure Flask to serve static files from dashboard directory
dashboard_dir = Path(__file__).parent / "dashboard"
app = Flask(__name__, 
            static_folder=str(dashboard_dir),
            static_url_path='/static')

_default_origins = ','.join([
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5000',
    'http://127.0.0.1:5000',
    'http://localhost:8080',
    'http://127.0.0.1:8080',
])
_cors_origins = [
    origin.strip()
    for origin in os.getenv('CORS_ALLOWED_ORIGINS', _default_origins).split(',')
    if origin.strip()
]
# When behind Cloudflare Tunnel, also accept any *.pages.dev or *.trycloudflare.com origin
import re as _re
_cors_origins.append(_re.compile(r'https://.*\.(pages\.dev|trycloudflare\.com)$'))
CORS(app, origins=_cors_origins)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
ENRICH_WITH_GEMINI = os.getenv('ENRICH_WITH_GEMINI', 'false').lower() in ('true', '1', 'yes')
GEMINI_RATE_LIMIT_PER_MINUTE = int(os.getenv('GEMINI_RATE_LIMIT_PER_MINUTE', '25'))
_gemini_call_timestamps = deque()
_gemini_rate_lock = Lock()
detector_lock = Lock()
triage_worker = None


def can_call_gemini() -> bool:
    """Allow up to GEMINI_RATE_LIMIT_PER_MINUTE calls within a rolling 60-second window."""
    now = time.time()
    cutoff = now - 60

    with _gemini_rate_lock:
        while _gemini_call_timestamps and _gemini_call_timestamps[0] < cutoff:
            _gemini_call_timestamps.popleft()

        if len(_gemini_call_timestamps) >= GEMINI_RATE_LIMIT_PER_MINUTE:
            return False

        _gemini_call_timestamps.append(now)
        return True


class AnomalyDetector:
    """Anomaly detection using Isolation Forest"""
    MODEL_VERSION = 2
    
    def __init__(self, model_path='models/baseline.pkl'):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.feature_names = [
            'process_frequency',
            'file_access_count',
            'network_count',
            'sensitive_files',
            'time_of_day',
            'day_of_week',
            'container_age',
            'unique_syscalls'
        ]
        self.load_or_create_model()
        self.warmup_complete = False
        self.warmup_samples = 0
        self.warmup_threshold = int(os.getenv('WARMUP_THRESHOLD', '50'))
    def load_or_create_model(self):
        """Load existing model or create new one"""
        if os.path.exists(self.model_path):
            logger.info(f"Loading model from {self.model_path}")
            with open(self.model_path, 'rb') as f:
                saved_data = pickle.load(f)
                self.model = saved_data['model']
                self.scaler = saved_data['scaler']

                metadata = saved_data.get('metadata', {})
                model_version = metadata.get('model_version', 1)
                if model_version < self.MODEL_VERSION and self._model_is_degenerate():
                    logger.warning(
                        "Loaded legacy baseline model appears degenerate; rebuilding baseline model"
                    )
                    self._initialize_model()
                    self.save_model()
        else:
            logger.info("Creating new Isolation Forest model")
            self.model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100,
                max_samples='auto',
                max_features=1.0
            )
            # Initialize with dummy data
            try:
                df = pd.read_csv('models/normal_baseline.csv')
                # Use exactly the 8 features we have
                X = df[self.feature_names].values
                self.scaler.fit(X)
                self.model.fit(self.scaler.transform(X))
                logger.info(f"Successfully trained on {len(df)} real normal events")
            except Exception as e:
                logger.warning(f"Could not load normal_baseline.csv: {e}. Falling back to tiny dummy.")
                dummy_data = np.random.randn(50, len(self.feature_names))
                self.scaler.fit(dummy_data)
                self.model.fit(self.scaler.transform(dummy_data))
            self.save_model()

    def _initialize_model(self):
        """Initialize model with realistic baseline behavior."""
        self.model = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            max_features=1.0
        )

        baseline_data = self._create_bootstrap_data(500)
        self.scaler.fit(baseline_data)
        self.model.fit(self.scaler.transform(baseline_data))

    def _create_bootstrap_data(self, size):
        """Create synthetic but realistic baseline data for cold-start training."""
        process_frequency = np.random.poisson(lam=8, size=size)
        file_access_count = np.clip(np.random.normal(loc=35, scale=15, size=size), 0, None)
        network_count = np.random.poisson(lam=6, size=size)
        sensitive_files = np.random.binomial(n=2, p=0.05, size=size)
        time_of_day = np.random.randint(0, 24, size=size)
        day_of_week = np.random.randint(0, 7, size=size)
        container_age = np.clip(np.random.exponential(scale=48, size=size), 0, 720)
        unique_syscalls = np.random.poisson(lam=50, size=size)

        return np.column_stack([
            process_frequency,
            file_access_count,
            network_count,
            sensitive_files,
            time_of_day,
            day_of_week,
            container_age,
            unique_syscalls,
        ])

    def _model_is_degenerate(self):
        """Detect cold-start models that classify almost everything as anomalous."""
        if self.model is None:
            return True

        baseline_probe = self._create_bootstrap_data(200)
        baseline_probe_scaled = self.scaler.transform(baseline_probe)
        predictions = self.model.predict(baseline_probe_scaled)
        anomaly_ratio = float(np.mean(predictions == -1))

        logger.info(f"Model baseline anomaly ratio check: {anomaly_ratio:.3f}")
        return anomaly_ratio > 0.70
    
    def save_model(self):
        """Save model to disk"""
        model_dir = os.path.dirname(self.model_path) or '.'
        os.makedirs(model_dir, exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'metadata': {
                    'model_version': self.MODEL_VERSION,
                    'updated_at': datetime.now().isoformat()
                }
            }, f)
        logger.info(f"Model saved to {self.model_path}")
    
    
    def extract_features(self, feature_dict):
        """Extract numerical features — safe against bad types"""
        def safe_float(key, default=0.0):
            val = feature_dict.get(key, default)
            try:
                return float(val)
            except (TypeError, ValueError):
                return float(default)

        features = [
            safe_float('process_frequency', 0),
            safe_float('file_access_count', 0),
            safe_float('network_count', 0),
            safe_float('sensitive_files', 0),
            safe_float('time_of_day', 12),
            safe_float('day_of_week', 0),
            safe_float('container_age', 0),
            safe_float('unique_syscalls', 0),
        ]
    
        return np.array(features).reshape(1, -1)
    
    def predict(self, features):
        """Predict if behavior is anomalous – with warm-up phase"""
        try:
            X = self.extract_features(features)
            X_scaled = self.scaler.transform(X)

            if not self.warmup_complete:
                # === WARM-UP PHASE ===
                # Treat as normal and incrementally improve the model
                # We fit on a small batch including this sample to avoid single-point overfitting
                # Stack raw feature data (not pre-scaled) and scale once before fitting
                batch_raw = np.vstack([X[0], self._create_bootstrap_data(10)])
                batch_scaled = self.scaler.transform(batch_raw)
                self.model.fit(batch_scaled)   # incremental fit

                self.warmup_samples += 1
                if self.warmup_samples >= self.warmup_threshold:
                    self.warmup_complete = True
                    self.save_model()
                    logger.info(f"Warm-up complete after {self.warmup_samples} samples. Anomaly detection now active.")

                return {
                    'is_anomaly': False,
                    'score': 0.0,
                    'confidence': 1.0,
                    'reason': f"Warm-up phase – collecting baseline ({self.warmup_samples}/{self.warmup_threshold})",
                    'suggestions': ["Baseline collection in progress – AI scoring will activate soon"]
                }

            # === NORMAL ANOMALY SCORING PHASE ===
            prediction = self.model.predict(X_scaled)[0]
            score = self.model.score_samples(X_scaled)[0]
            # Linear mapping: score > 0 → 0.0 (normal), score = -0.5 → 1.0 (anomaly)
            normalized_score = float(np.clip(-score * 2, 0.0, 1.0))

            is_anomaly = prediction == -1
            confidence = abs(score)

            reason = self._generate_reason(features, is_anomaly, normalized_score)
            suggestions = self._generate_suggestions(features, is_anomaly)

            return {
                'is_anomaly': bool(is_anomaly),
                'score': float(normalized_score),
                'confidence': float(confidence),
                'reason': reason,
                'suggestions': suggestions
            }

        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            raise
    
    def _generate_reason(self, features, is_anomaly, score):
        """Generate human-readable reason for prediction"""
        if not is_anomaly:
            return "Behavior matches normal baseline patterns"
        
        reasons = []
        
        if features.get('sensitive_files', 0) > 0:
            reasons.append(f"Access to {features['sensitive_files']} sensitive file(s)")
        
        if features.get('network_count', 0) > 20:
            reasons.append(f"Unusually high network activity ({features['network_count']} connections)")
        
        if features.get('file_access_count', 0) > 100:
            reasons.append(f"Excessive file access ({features['file_access_count']} operations)")
        
        process_name = features.get('process_name', '')
        suspicious_processes = ['nc', 'netcat', 'ncat', 'wget', 'curl', 'bash', 'sh']
        if process_name in suspicious_processes:
            reasons.append(f"Suspicious process detected: {process_name}")
        
        if not reasons:
            reasons.append(f"Behavioral anomaly detected (score: {score:.2f})")
        
        return "; ".join(reasons)
    
    def _generate_suggestions(self, features, is_anomaly):
        """Generate remediation suggestions"""
        if not is_anomaly:
            return []
        
        suggestions = []
        
        if features.get('sensitive_files', 0) > 0:
            suggestions.append("Review file access patterns and restrict unnecessary permissions")
        
        if features.get('network_count', 0) > 20:
            suggestions.append("Investigate network connections and apply network policies")
        
        process_name = features.get('process_name', '')
        if process_name in ['bash', 'sh', 'nc', 'netcat']:
            suggestions.append(f"Investigate why {process_name} is running in container")
        
        suggestions.append("Review container security context and capabilities")
        suggestions.append("Check for unauthorized access or container escape attempts")
        
        return suggestions
    
    def train(self, training_data):
        """Retrain model with new data"""
        try:
            # Extract features from training data
            X = []
            for sample in training_data:
                features = self.extract_features(sample)
                X.append(features[0])
            
            X = np.array(X)
            
            # Fit scaler and model
            self.scaler.fit(X)
            X_scaled = self.scaler.transform(X)
            self.model.fit(X_scaled)
            
            # Save updated model
            self.save_model()
            
            logger.info(f"Model retrained with {len(training_data)} samples")
            return True
        except Exception as e:
            logger.error(f"Training error: {str(e)}")
            raise

# Initialize detector
detector = AnomalyDetector()

# ============== AUTHENTICATION SETUP ==============
TRAINING_API_TOKEN = os.environ.get('TRAINING_API_TOKEN')
ALLOW_UNAUTHENTICATED_API = os.environ.get('ALLOW_UNAUTHENTICATED_API', 'false').lower() in ('true', '1', 'yes')

def require_train_token(f):
    """Decorator to verify training API token (optional for demo mode)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Explicit demo mode only.
        if ALLOW_UNAUTHENTICATED_API:
            return f(*args, **kwargs)
        if not TRAINING_API_TOKEN:
            logger.error("TRAINING_API_TOKEN is required when ALLOW_UNAUTHENTICATED_API is false")
            return jsonify({'error': 'Server misconfiguration: auth token required'}), 503

        auth_header = request.headers.get('Authorization', '')
        
        # Check Bearer token format
        if not auth_header.startswith('Bearer '):
            logger.warning("Missing or invalid Authorization header format")
            return jsonify({'error': 'Missing or invalid Authorization header'}), 401
        
        token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        # Verify token matches
        if token != TRAINING_API_TOKEN:
            logger.warning(f"Invalid training token attempt")
            return jsonify({'error': 'Invalid token'}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

# ============== GEMINI LLM SETUP ==============
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')

try:
    if not GEMINI_API_KEY:
        raise ValueError("GEMINI_API_KEY environment variable not set")
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-2.5-flash')   # or gemini-2.5-flash if available
    logger.info("✅ Gemini LLM initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Gemini: {e}")
    gemini_model = None


def resolve_forensics_dir() -> Path:
    """Return the runtime forensics directory with local-dev fallback."""
    primary = Path("/app/forensics")
    if primary.exists():
        return primary
    return Path(__file__).parent.parent / "forensics"


def write_incident_to_forensics(incident_data: dict):
    """Persist an incident JSON file using the existing forensics vault format."""
    forensics_dir = resolve_forensics_dir()
    forensics_dir.mkdir(parents=True, exist_ok=True)

    incident_id = str(incident_data.get("id") or int(time.time() * 1000))
    safe_id = incident_id.replace("/", "_").replace("\\", "_")
    file_path = forensics_dir / f"incident_{safe_id}.json"

    with open(file_path, "w", encoding="utf-8") as handle:
        json.dump(incident_data, handle, indent=2, ensure_ascii=False, default=str)

    return str(file_path)


def write_to_staging(incident_data: dict, if_score: float):
    """
    incident_data is the full incident dict that would have been written
    to the forensics vault directly.
    """
    conn = get_db()
    conn.execute(
        """
        INSERT INTO incident_staging
        (incident_id, timestamp, raw_event, if_score,
         container_id, container_name, pod_name, namespace, rule)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident_data.get("id"),
            incident_data.get("timestamp"),
            json.dumps(incident_data),
            if_score,
            incident_data.get("container", {}).get("id"),
            incident_data.get("container", {}).get("name"),
            incident_data.get("container", {}).get("pod_name"),
            incident_data.get("container", {}).get("namespace"),
            incident_data.get("events", [{}])[0].get("rule") if incident_data.get("events") else None,
        ),
    )
    conn.commit()


def _staging_row_to_dict(row):
    row_dict = dict(row)
    raw_event = row_dict.get("raw_event")
    if isinstance(raw_event, str):
        try:
            row_dict["raw_event"] = json.loads(raw_event)
        except Exception:
            pass
    return row_dict


def _get_triage_worker_instance(start_if_needed: bool = False):
    global triage_worker
    if triage_worker is None:
        from triage_worker import TriageWorker

        triage_worker = TriageWorker(
            poll_interval=int(os.environ.get("TRIAGE_POLL_INTERVAL", "30")),
            batch_size=int(os.environ.get("TRIAGE_BATCH_SIZE", "10")),
            gemini_model=gemini_model,
            can_call_gemini=can_call_gemini,
            write_forensics_fn=write_incident_to_forensics,
        )

    if start_if_needed:
        triage_worker.start()

    return triage_worker
    

# Update the existing route if needed
@app.route('/')
def index():
    return send_from_directory('dashboard', 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files from dashboard directory"""
    try:
        return send_from_directory('dashboard', filename)
    except Exception as e:
        logger.warning(f"Static file not found: {filename}")
        # Return index.html as fallback (SPA support)
        return send_from_directory('dashboard', 'index.html')

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': detector.model is not None
    })

@app.route('/api/diagnostics', methods=['GET'])
def diagnostics():
    """Diagnostic endpoint to help debug deployment issues"""
    import os
    forensics_paths = [
        Path("/app/forensics"),
        Path(__file__).parent.parent / "forensics"
    ]
    
    forensics_info = []
    for path in forensics_paths:
        forensics_info.append({
            "path": str(path),
            "exists": path.exists(),
            "files": len(list(path.glob("*.json"))) if path.exists() else 0
        })
    
    return jsonify({
        "dashboard_dir": str(Path(__file__).parent / "dashboard"),
        "dashboard_exists": (Path(__file__).parent / "dashboard").exists(),
        "forensics_paths": forensics_info,
        "cwd": os.getcwd(),
        "env_cors": os.getenv('CORS_ALLOWED_ORIGINS', 'Not set'),
        "gemini_enabled": ENRICH_WITH_GEMINI,
        "model_loaded": detector.model is not None
    })

@app.route('/warmup/status', methods=['GET'])
def warmup_status():
    with detector_lock:
        return jsonify({
            "warmup_complete": detector.warmup_complete,
            "samples_collected": detector.warmup_samples,
            "threshold": detector.warmup_threshold
        })
@app.route('/models/baseline.pkl', methods=['GET'])
@require_train_token
def download_model():
    """Download model file - requires Bearer token authorization"""
    return send_from_directory('models', 'baseline.pkl', as_attachment=True)
@app.route('/predict', methods=['POST'])
@require_train_token
def predict():
    """Anomaly prediction endpoint - requires Bearer token authorization"""
    try:
        data = request.get_json()
        
        if not data or 'features' not in data:
            return jsonify({'error': 'Missing features in request'}), 400
        
        features = data['features']
        with detector_lock:
            result = detector.predict(features)

        incident_data = data.get('incident_data')
        if result.get('is_anomaly') and isinstance(incident_data, dict):
            try:
                write_to_staging(incident_data, float(result.get('score', 0.0)))
                logger.info("Anomalous incident queued in staging vault: %s", incident_data.get('id'))
            except Exception as staging_error:
                logger.error("Failed to write incident to staging vault: %s", staging_error)
        
        logger.info(f"Prediction: anomaly={result['is_anomaly']}, score={result['score']:.3f}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in prediction: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/train', methods=['POST'])
@require_train_token
def train():
    """Model training endpoint - requires Bearer token authorization"""
    try:
        data = request.get_json()
        
        if not data or 'training_data' not in data:
            return jsonify({'error': 'Missing training_data in request'}), 400
        
        training_data = data['training_data']
        with detector_lock:
            detector.train(training_data)
        
        return jsonify({
            'status': 'success',
            'samples': len(training_data),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error in training: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/model/info', methods=['GET'])
def model_info():
    """Get model information"""
    with detector_lock:
        return jsonify({
            'type': 'IsolationForest',
            'features': detector.feature_names,
            'n_estimators': detector.model.n_estimators if detector.model else None,
            'contamination': detector.model.contamination if detector.model else None,
            'model_path': detector.model_path
        })


@app.route('/api/staging', methods=['GET'])
def get_staging_rows():
    """List staged incidents with optional filtering by status/namespace."""
    try:
        status = request.args.get('status')
        namespace = request.args.get('namespace')

        query = "SELECT * FROM incident_staging WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status)

        if namespace:
            query += " AND namespace = ?"
            params.append(namespace)

        query += " ORDER BY created_at DESC, id DESC"

        conn = get_db()
        rows = conn.execute(query, tuple(params)).fetchall()
        staging = [_staging_row_to_dict(row) for row in rows]

        return jsonify({
            'staging': staging,
            'total': len(staging),
        })
    except Exception as e:
        logger.error(f"Error in /api/staging: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/staging/<int:row_id>', methods=['GET'])
def get_staging_row(row_id: int):
    """Fetch one staged incident by numeric row id."""
    try:
        conn = get_db()
        row = conn.execute(
            "SELECT * FROM incident_staging WHERE id = ?",
            (row_id,),
        ).fetchone()

        if row is None:
            return jsonify({'error': 'Staging row not found'}), 404

        return jsonify(_staging_row_to_dict(row))
    except Exception as e:
        logger.error(f"Error in /api/staging/{row_id}: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/staging/<int:row_id>/override', methods=['POST'])
@require_train_token
def override_staging_row(row_id: int):
    """Allow manual override to confirm or reject a staged incident."""
    try:
        body = request.get_json(silent=True) or {}
        verdict = str(body.get('verdict', '')).strip().lower()
        reason = body.get('reason')

        if verdict not in ('confirmed', 'rejected'):
            return jsonify({'error': 'verdict must be confirmed or rejected'}), 400

        conn = get_db()
        row = conn.execute(
            "SELECT * FROM incident_staging WHERE id = ?",
            (row_id,),
        ).fetchone()

        if row is None:
            return jsonify({'error': 'Staging row not found'}), 404

        worker = _get_triage_worker_instance(start_if_needed=False)
        triage_result = {
            'reason': reason,
            'severity': None,
            'mitre_tactic': None,
            'enriched_description': None,
            'remediation': None,
            'triage_source': 'passthrough',
        }

        if verdict == 'confirmed':
            worker._write_confirmed_to_forensics(row, triage_result)

        worker._update_staging_row(conn, row_id, verdict, triage_result)
        return jsonify({'status': 'ok', 'verdict': verdict})
    except Exception as e:
        logger.error(f"Error in /api/staging/{row_id}/override: {e}")
        return jsonify({'error': str(e)}), 500


def build_gemini_prompt(incident, metadata):
    return f"""
Analyze this Kubernetes security incident and provide a clear, professional explanation (2-4 sentences):
Incident Type: {incident['incident_type']}
Severity: {incident['severity']}
Description: {incident['description']}
Process: {metadata.get('process_name', 'N/A')}
Container: {incident['container_name']} in pod {incident['pod_name']}

Focus on why this is suspicious and what the security team should investigate.
"""
@app.route('/api/incidents', methods=['GET'])
def get_ai_incidents():
    """Read incidents from forensics/ and enrich with Gemini where helpful"""
    try:
        # Prefer mounted runtime forensics path in container, fallback to repo path for local dev.
        forensics_dir = resolve_forensics_dir()
        
        logger.info(f"Checking for forensics at: {forensics_dir} (exists: {forensics_dir.exists()})")
        
        if not forensics_dir.exists():
            error_msg = f"Forensics folder not found at {forensics_dir}"
            logger.error(error_msg)
            return jsonify({
                "incidents": [], 
                "error": error_msg, 
                "last_analysis": datetime.now().isoformat(),
                "forensics_path_checked": str(forensics_dir)
            })

        incidents = []
        json_files = sorted(glob.glob(str(forensics_dir / "*.json")), reverse=True)[:100]
        logger.info(f"Found {len(json_files)} incident JSON files in {forensics_dir}")
        
        for json_file in json_files:
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                metadata = data.get("metadata", {})
                events = data.get("events", [{}])
                
                # Base incident object
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
                    "raw_file": Path(json_file).name
                }
                if ENRICH_WITH_GEMINI and gemini_model and (len(incident["ai_analysis"]) < 100 or "explicitly stated" in incident["ai_analysis"].lower()):
                    try:
                        if can_call_gemini():
                            prompt = build_gemini_prompt(incident, metadata)
                            response = gemini_model.generate_content(prompt)
                            enhanced = response.text.strip()
                            if len(enhanced) > 50:
                                incident["ai_analysis"] = enhanced
                        else:
                            logger.info("Gemini rate limit reached (25/min). Skipping enrichment for %s", incident['id'])
                    except Exception as gemini_err:
                        logger.warning(f"Gemini enhancement failed for {incident['id']}: {gemini_err}")
                
                # Optional ML enrichment (uncomment if you want fresh IsolationForest score)
                try:
                    features = metadata
                    with detector_lock:
                        ml_result = detector.predict(features)
                    incident["risk_score"] = round(ml_result["score"] * 100)
                    if ml_result.get("reason"):
                        incident["ai_analysis"] += f" ML Insight: {ml_result['reason']}"
                except Exception:
                    pass
                
                incidents.append(incident)
                
            except Exception as e:
                logger.warning(f"Failed to process {json_file}: {e}")
                continue
        
        return jsonify({
            "incidents": incidents,
            "last_analysis": datetime.now().isoformat(),
            "total": len(incidents),
            "using_gemini_enrichment": ENRICH_WITH_GEMINI and gemini_model is not None
        })
        
    except Exception as e:
        logger.error(f"Error in /api/incidents: {e}")
        return jsonify({"incidents": [], "error": str(e), "last_analysis": datetime.now().isoformat()}), 500

if __name__ == '__main__':
    # Create models directory
    os.makedirs('models', exist_ok=True)
    
    # Start worker once (avoid Flask debug reloader duplicate workers).
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        _get_triage_worker_instance(start_if_needed=True)

    # Start server
    logger.info("Starting AI/ML service on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
