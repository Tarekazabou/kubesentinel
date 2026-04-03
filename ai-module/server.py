#!/usr/bin/env python3
"""
AI/ML Service for KubeSentinel
Provides behavioral anomaly detection using scikit-learn
"""

from email.policy import default

from flask import Flask, request, jsonify , send_from_directory
from sklearn.ensemble import IsolationForest
from flask_cors import CORS
from sklearn.preprocessing import StandardScaler
from flask import send_from_directory
import numpy as np
import pickle
import pandas as pd
import json
import logging
from datetime import datetime
import os
import google.generativeai as genai
from pathlib import Path
import glob

app = Flask(__name__)
CORS(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

        return np.column_stack([
            process_frequency,
            file_access_count,
            network_count,
            sensitive_files,
            time_of_day,
            day_of_week,
            container_age,
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
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
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
        """Predict if behavior is anomalous"""
        try:
            # Extract and scale features
            X = self.extract_features(features)
            X_scaled = self.scaler.transform(X)
            
            # Get prediction (-1 for anomaly, 1 for normal)
            prediction = self.model.predict(X_scaled)[0]
            
            # Get anomaly score (lower is more anomalous)
            score = self.model.score_samples(X_scaled)[0]
            
            # Convert score to 0-1 range (higher is more anomalous)
            normalized_score = 1 / (1 + np.exp(score))
            
            is_anomaly = prediction == -1
            confidence = abs(score)
            
            # Generate reason
            reason = self._generate_reason(features, is_anomaly, normalized_score)
            
            # Generate suggestions
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
# ============== GEMINI LLM SETUP ==============
GEMINI_API_KEY = "AIzaSyAF8xky2TpK56DcAJ9wZme6Ne7wJE5zwVw"   # from your config.yaml

try:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel('gemini-2.5-flash')   # or gemini-2.5-flash if available
    logger.info("✅ Gemini LLM initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Gemini: {e}")
    gemini_model = None
    

# Update the existing route if needed
@app.route('/')
def index():
    return send_from_directory('dashboard', 'index.html')

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'model_loaded': detector.model is not None
    })
@app.route('/models/baseline.pkl', methods=['GET'])
def download_model():
    return send_from_directory('models', 'baseline.pkl', as_attachment=True)
@app.route('/predict', methods=['POST'])
def predict():
    """Anomaly prediction endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'features' not in data:
            return jsonify({'error': 'Missing features in request'}), 400
        
        features = data['features']
        result = detector.predict(features)
        
        logger.info(f"Prediction: anomaly={result['is_anomaly']}, score={result['score']:.3f}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in prediction: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/train', methods=['POST'])
def train():
    """Model training endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'training_data' not in data:
            return jsonify({'error': 'Missing training_data in request'}), 400
        
        training_data = data['training_data']
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
    return jsonify({
        'type': 'IsolationForest',
        'features': detector.feature_names,
        'n_estimators': detector.model.n_estimators if detector.model else None,
        'contamination': detector.model.contamination if detector.model else None,
        'model_path': detector.model_path
    })
@app.route('/api/incidents', methods=['GET'])
def get_ai_incidents():
    """Read incidents from forensics/ and enrich with Gemini where helpful"""
    try:
        forensics_dir = Path(__file__).parent.parent / "forensics"
        if not forensics_dir.exists():
            return jsonify({"incidents": [], "error": "forensics folder not found", "last_analysis": datetime.now().isoformat()})

        incidents = []
        
        for json_file in sorted(glob.glob(str(forensics_dir / "*.json")), reverse=True)[:100]:  # limit to latest 100
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
                
                # Optional: Enhance ai_analysis with fresh Gemini call if the existing reason is too short/weak
                if gemini_model and (len(incident["ai_analysis"]) < 100 or "explicitly stated" in incident["ai_analysis"].lower()):
                    try:
                        prompt = f"""
                        Analyze this Kubernetes security incident and provide a clear, professional explanation (2-4 sentences):
                        Incident Type: {incident['incident_type']}
                        Severity: {incident['severity']}
                        Description: {incident['description']}
                        Process: {metadata.get('process_name', 'N/A')}
                        Container: {incident['container_name']} in pod {incident['pod_name']}
                        
                        Focus on why this is suspicious and what the security team should investigate.
                        """
                        response = gemini_model.generate_content(prompt)
                        enhanced = response.text.strip()
                        if len(enhanced) > 50:
                            incident["ai_analysis"] = enhanced
                    except Exception as gemini_err:
                        logger.warning(f"Gemini enhancement failed for {incident['id']}: {gemini_err}")
                
                # Optional ML enrichment (uncomment if you want fresh IsolationForest score)
                # try:
                #     features = metadata
                #     ml_result = detector.predict(features)
                #     incident["risk_score"] = round(ml_result["score"] * 100)
                #     if ml_result.get("reason"):
                #         incident["ai_analysis"] += f" ML Insight: {ml_result['reason']}"
                # except:
                #     pass
                
                incidents.append(incident)
                
            except Exception as e:
                logger.warning(f"Failed to process {json_file}: {e}")
                continue
        
        return jsonify({
            "incidents": incidents,
            "last_analysis": datetime.now().isoformat(),
            "total": len(incidents),
            "using_gemini": gemini_model is not None
        })
        
    except Exception as e:
        logger.error(f"Error in /api/incidents: {e}")
        return jsonify({"incidents": [], "error": str(e), "last_analysis": datetime.now().isoformat()}), 500

if __name__ == '__main__':
    # Create models directory
    os.makedirs('models', exist_ok=True)
    
    # Start server
    logger.info("Starting AI/ML service on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
