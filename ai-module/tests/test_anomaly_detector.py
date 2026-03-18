"""
Basic pytest suite for the AnomalyDetector class in server.py
"""

import pytest
import numpy as np
import os

# Import from parent directory (server.py is in ai-module/)
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from server import AnomalyDetector


@pytest.fixture
def detector():
    """Create a fresh detector instance using a temporary model path"""
    temp_model_path = "models/test_baseline.pkl"
    
    # Clean up any leftover test file
    if os.path.exists(temp_model_path):
        os.remove(temp_model_path)
    
    det = AnomalyDetector(model_path=temp_model_path)
    yield det
    
    # Cleanup after test
    if os.path.exists(temp_model_path):
        os.remove(temp_model_path)


def test_detector_initialization(detector):
    """Basic smoke test: object creation and basic attributes"""
    assert detector is not None
    assert detector.model is not None
    assert detector.scaler is not None
    assert len(detector.feature_names) == 7
    assert detector.feature_names == [
        'process_frequency',
        'file_access_count',
        'network_count',
        'sensitive_files',
        'time_of_day',
        'day_of_week',
        'container_age'
    ]


def test_extract_features(detector):
    """Verify feature extraction shape and selected values"""
    sample = {
        'process_frequency': 15,
        'file_access_count': 42,
        'network_count': 8,
        'sensitive_files': 1,
        'time_of_day': 14,
        'day_of_week': 2,
        'container_age': 3600,
        'process_name': 'cat',           # ignored extra field
        'random_garbage': True
    }
    
    X = detector.extract_features(sample)
    assert X.shape == (1, 7)
    assert np.allclose(X[0, 0], 15)      # process_frequency
    assert np.allclose(X[0, 1], 42)      # file_access_count
    assert np.allclose(X[0, 3], 1)       # sensitive_files
    assert np.allclose(X[0, 4], 14)      # time_of_day


def test_predict_normal_behavior(detector):
    """Low-risk input should produce a valid result (even if flagged due to dummy training)"""
    normal_sample = {
        'process_frequency': 3,
        'file_access_count': 5,
        'network_count': 2,
        'sensitive_files': 0,
        'time_of_day': 10,
        'day_of_week': 1,
        'container_age': 7200,
    }
    
    result = detector.predict(normal_sample)
    
    assert isinstance(result, dict)
    assert 'is_anomaly' in result
    assert 'score' in result
    assert 0 <= result['score'] <= 1.0
    assert isinstance(result['reason'], str)
    assert isinstance(result['suggestions'], list)
    assert 'confidence' in result


def test_predict_suspicious_behavior(detector):
    """High-risk pattern should produce a valid anomaly-like result"""
    suspicious = {
        'process_frequency': 80,
        'file_access_count': 250,
        'network_count': 45,
        'sensitive_files': 3,
        'time_of_day': 3,               # middle of night
        'day_of_week': 6,
        'container_age': 300,           # very young container
    }
    
    result = detector.predict(suspicious)
    
    assert isinstance(result, dict)
    assert 'is_anomaly' in result
    assert 'score' in result
    assert 0 <= result['score'] <= 1.0
    assert isinstance(result['reason'], str)
    assert isinstance(result['suggestions'], list)
    # Relaxed check — at least one suggestion or a descriptive reason
    assert len(result['suggestions']) >= 1 or "anomaly" in result['reason'].lower()


def test_model_persistence(detector):
    """Verify that model can be saved and loaded"""
    # Force save
    detector.save_model()
    
    assert os.path.exists(detector.model_path)
    assert os.path.getsize(detector.model_path) > 5000  # rough minimum size for pickled IsolationForest
    
    # Load in a new instance
    new_detector = AnomalyDetector(model_path=detector.model_path)
    
    assert new_detector.model is not None
    assert new_detector.scaler is not None


@pytest.mark.parametrize("bad_input", [
    {},                                     # completely empty
    {"process_frequency": "hello"},         # wrong type
    {"file_access_count": -5},              # negative value
    {"time_of_day": 999},                   # unrealistic value
    {"process_frequency": None},            # None value
])
def test_predict_handles_bad_input_gracefully(detector, bad_input):
    """
    Should not crash on malformed input — uses .get() defaults and safe conversion
    """
    try:
        result = detector.predict(bad_input)
        assert isinstance(result, dict)
        assert 'is_anomaly' in result
        assert 'score' in result
        assert 0 <= result['score'] <= 1.0
        assert isinstance(result['reason'], str)
        assert isinstance(result['suggestions'], list)
    except Exception as e:
        pytest.fail(
            f"predict() crashed unexpectedly on input: {bad_input}\n"
            f"Error: {type(e).__name__}: {str(e)}"
        )


def test_predict_extremely_bad_input(detector):
    """Test really nasty input that should still be handled safely"""
    horrible = {
        'process_frequency': ['evil', 'list'],
        'file_access_count': {'nested': 'dict'},
        'network_count': object(),
        'sensitive_files': None,
        'time_of_day': "midnight",
    }
    
    result = detector.predict(horrible)
    
    assert isinstance(result, dict)
    assert 'is_anomaly' in result
    assert 'score' in result
    assert 0 <= result['score'] <= 1.0
    assert isinstance(result['reason'], str)


if __name__ == "__main__":
    pytest.main(["-v", __file__])