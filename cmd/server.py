#!/usr/bin/env python3
"""
AI/ML Service for KubeSentinel
Provides behavioral anomaly detection using scikit-learn
"""

from flask import Flask, request, jsonify
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import pickle
import json
import logging
from datetime import datetime
import os

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AnomalyDetector:
    """Anomaly detection using Isolation Forest"""
    
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
            'container_age'
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
            dummy_data = np.random.randn(100, len(self.feature_names))
            self.scaler.fit(dummy_data)
            self.model.fit(self.scaler.transform(dummy_data))
            self.save_model()
    
    def save_model(self):
        """Save model to disk"""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler
            }, f)
        logger.info(f"Model saved to {self.model_path}")
    
    def extract_features(self, feature_dict):
        """Extract numerical features from feature vector"""
        features = []
        
        # Process frequency
        features.append(feature_dict.get('process_frequency', 0))
        
        # File access count
        features.append(feature_dict.get('file_access_count', 0))
        
        # Network count
        features.append(feature_dict.get('network_count', 0))
        
        # Sensitive files count
        features.append(feature_dict.get('sensitive_files', 0))
        
        # Time of day (0-23)
        features.append(feature_dict.get('time_of_day', 12))
        
        # Day of week (0-6)
        features.append(feature_dict.get('day_of_week', 0))
        
        # Container age (seconds)
        features.append(feature_dict.get('container_age', 0))
        
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

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'model_loaded': detector.model is not None
    })

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

if __name__ == '__main__':
    # Create models directory
    os.makedirs('models', exist_ok=True)
    
    # Start server
    logger.info("Starting AI/ML service on port 5000")
    app.run(host='0.0.0.0', port=5000, debug=False)
